#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include <sys/epoll.h>

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>

#include <assert.h>

#define CRLF "\r\n\r\n"
#define CRLF_LEN 4

enum req_state {
	NET_RECEIVING,
	NET_SENDING,
	FS_RECEIVING,
};
struct request {
	int net_fd;
	int fs_fd;
	void *response;
	unsigned int response_size;
	uint8_t *request;
	uint8_t *request_p;
	unsigned int request_size;
	enum req_state state;
};
void sigint_handler(int arg __attribute__((unused)))
{
	exit(0);
}

struct configuration {
	unsigned short port;
	char bind_address[17]; 		/* dotted IP address */
	unsigned int max_request_size; 	/* in bytes */
	unsigned int socket_timeout; 	/* in seconds */
};
static struct configuration config = {	.port = 8080,
					.bind_address = "0.0.0.0",
					.max_request_size = 16384,
					.socket_timeout = 3000 };

#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))
static struct request *reqs[1024 * 100];
static void req_del(int fd)
{
	close(reqs[fd]->net_fd);
	free(reqs[fd]->request);
	//free(reqs[fd]->response);
	free(reqs[fd]);
	reqs[fd] = NULL;
}
static void req_add(struct request *req)
{
	reqs[req->net_fd] = req;
}
static struct request *req_get_from_net_fd(int fd)
{
	return reqs[fd];
}

int main()
{
	int ret, optval;
	int server;
	struct sockaddr_in server_addr;
	struct epoll_event ev, *events;
	int maxevents = 64;
	int poll_fd;
	static char rep[1024*10] = "HTTP/1.0 200 OK\r\n\r\nAZEQSDAZEQSDAZESQD";

	rep[ARRAY_SIZE(rep)-2] = '\r';
	rep[ARRAY_SIZE(rep)-1] = '\n';

	signal(SIGINT, sigint_handler);

	server = socket(PF_INET, SOCK_STREAM, IPPROTO_IP);
	if (server < 0) {
		perror("Cannot create socket");
		exit(1);
	}
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(config.port);
	server_addr.sin_addr.s_addr = inet_addr(config.bind_address);

	//setsockopt(3, SOL_SOCKET, SO_LINGER, {onoff=1, linger=0}, 8) = 0
	optval = 1;
	ret = setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
	if (ret < 0) {
		perror("setsockopt");
		exit(1);
	}


	ret = bind(server, (struct sockaddr *)&server_addr, sizeof(server_addr));
	if (ret < 0) {
		perror("Cannot bind");
		exit(1);
	}

	ret = listen(server, 10);
	if (ret < 0) {
		perror("Cannot listen");
		exit(1);
	}

	events = calloc(1, maxevents * sizeof(struct epoll_event));
	if (!events) {
		perror("Initial malloc failed");
		exit(1);
	}
	poll_fd = epoll_create(maxevents);
	if (poll_fd < 0) {
		perror("epoll_create");
		exit(1);
	}

	ev.events = EPOLLIN | EPOLLPRI | EPOLLERR | EPOLLHUP;
	ev.data.fd = server;
	ret = epoll_ctl(poll_fd, EPOLL_CTL_ADD, server, &ev);
	if (ret < 0) {
		perror("epoll_ctl");
		exit(1);
	}

	do {
		int n;
		int nfds;

		nfds = epoll_wait(poll_fd, events, maxevents, -1);

		for (n = 0; n < nfds; ++n) {
			if (events[n].data.fd == server) {
				struct sockaddr_in client_addr;
				size_t addrlen;
				int flags, client;
				struct request *req;

				addrlen = sizeof(client_addr);
				client = accept(server, (struct sockaddr *)&client_addr,
						&addrlen);
				if (client < 0){
					perror("accept");
					continue;
				}

				if ((flags = fcntl(client, F_GETFL, 0)) < 0) {
					perror("fcntl 1");
					continue;
				}


				if (fcntl(client, F_SETFL, flags | O_NONBLOCK) < 0) {
					perror("fcntl 2");
					continue;
				}

				ev.events = EPOLLIN;
				ev.data.fd = client;
				if (epoll_ctl(poll_fd, EPOLL_CTL_ADD, client, &ev) < 0) {
					fprintf(stderr, "epoll set insertion error: fd=%d\n", client);
					continue;
				}
				
				req = malloc(sizeof(struct request));
				if (!req) {
					perror("malloc");
					continue;
				}
				req->net_fd = client;
				req->state = NET_RECEIVING;
				req->request = malloc(BUFSIZ);
				req->request_p = req->request;
				req->request_size = 0;
				req->response = NULL;
				req->response_size = 0;
				req_add(req);
			} else {
				struct request *req;

				req = req_get_from_net_fd(events[n].data.fd);
				assert(req);

				switch(req->state) {
					case NET_RECEIVING:
						ret = read(req->net_fd, req->request_p, BUFSIZ);
						if (ret < 0) {
							perror("read");
							req_del(req->net_fd);
							continue;
						}
						req->request_size += ret;
						req->request_p += ret;

						/* is request too long ? */
						if (req->request_size > config.max_request_size) {
							fprintf(stderr, "Request is too long\n");
							req_del(req->net_fd);
							continue;
						}
						/* is that a full request, if yes try to parse it */
						if (req->request_size > CRLF_LEN
						    && !memcmp(&req->request_p[ret-CRLF_LEN], CRLF, CRLF_LEN)) {
							req->state = NET_SENDING;
							ev.events = EPOLLOUT;
							ev.data.fd = req->net_fd;
							if (epoll_ctl(poll_fd, EPOLL_CTL_MOD, req->net_fd, &ev) < 0) {
								perror("epoll_ctl");
								req_del(req->net_fd);
								continue;
							}
							req->response = rep;
							req->response_size = sizeof(rep);
						} else {
							/* not a request, continue */
							req->request = realloc(req->request, req->request_size + BUFSIZ);
							if (!req->request) {
								perror("realloc");
								req_del(req->net_fd);
								continue;
							}
						}
						break;
					case NET_SENDING:
						ret = write(req->net_fd, req->response, req->response_size);
						if (ret > 0 && ret != (int)req->response_size) {
							req->response += ret;
							req->response_size -= ret;
						} else {
							if (ret < 0)
								perror("write");
							req_del(req->net_fd);
						}
						break;
					default:
						assert(0);
				}
			}
		}
	} while (1);

	return ret;
}
