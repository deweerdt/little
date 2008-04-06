#define __USE_GNU

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
#include <time.h>
#include <errno.h>

#include <assert.h>

#include <pthread.h>

#define CRLF "\r\n\r\n"
#define CRLF_LEN 4

//#define BUFSIZ 4096 * 8

enum http_response_code {
	OK = 200,
	Created = 201,
	Accepted = 202,
	No_Content = 204,
	Moved_Permanently = 301,
	Moved_Temporarily = 302,
	Not_Modified = 304,
	Bad_Request = 400,
	Unauthorized = 401,
	Forbidden = 403,
	Not_Found = 404,
	Internal_Server_Error = 500,
	Not_Implemented = 501,
	Bad_Gateway = 502,
	Service_Unavailable = 503,
};

static const char STR_200[] = "HTTP/1.0 200 OK" CRLF;
static const int STR_200_LEN = 21;
static const char STR_400[] = "HTTP/1.0 400 Bad Request" CRLF CRLF;
static const int STR_400_LEN = 32;
static const char STR_404[] = "HTTP/1.0 404 Not Found" CRLF CRLF;
static const int STR_404_LEN = 30;
static const char STR_500[] = "HTTP/1.0 500 Internal Server Error" CRLF CRLF;
static const int STR_500_LEN = 42;
static const char STR_501[] = "HTTP/1.0 501 Not Implemented" CRLF CRLF;
static const int STR_501_LEN = 36;

enum req_state {
	NET_RECEIVING,
	NET_SENDING,
	NET_SENDING_STATUS,
	FS_RECEIVING,
};
struct request {
	int net_fd;
	int fs_fd;
	void *out_buf;
	unsigned int out_buf_size;
	uint8_t *request;
	unsigned int request_size;
	enum req_state state;
	time_t last_accessed; 
	enum http_response_code http_code;
};
void sigint_handler(int arg __attribute__((unused)))
{
	exit(0);
}

struct configuration {
	unsigned short port;
	char bind_address[17]; 		/* dotted IP address */
	unsigned int max_request_size; 	/* in bytes */
	double socket_timeout; 	/* in seconds */
};
static struct configuration config = {	.port = 8080,
					.bind_address = "0.0.0.0",
					.max_request_size = 16384,
					.socket_timeout = 3.0 };

#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))
static struct request **reqs;
static void req_del(int fd)
{
	close(reqs[fd]->fs_fd);
	close(reqs[fd]->net_fd);
	free(reqs[fd]->request);
	free(reqs[fd]->out_buf);
	free(reqs[fd]);
	reqs[fd] = NULL;
}
static void req_add(struct request *req)
{
	reqs[req->net_fd] = req;
}
static struct request *req_get_from_net_fd(const int fd)
{
	return reqs[fd];
}

static time_t now;
void *time_thread(void __attribute__((unused)) *arg)
{
	do {
		now = time(NULL);
		sleep(config.socket_timeout);
	} while(1);
	return NULL;
}

static void garbage_collect()
{
	unsigned int i;

	for (i=0; i < ARRAY_SIZE(reqs); i++) {
		if (reqs[i]
		    && difftime(now, reqs[i]->last_accessed) > config.socket_timeout) {
			req_del(reqs[i]->net_fd);
		}
	}
}
static const char *build_status_line(struct request *req, int *size)
{
	const char *ret = NULL;
	switch (req->http_code) {
		case OK:
			ret = STR_200;
			*size = STR_200_LEN;
			break;
		case Not_Found:
			ret = strdup(STR_404);
			*size = STR_404_LEN;
			break;
		case Internal_Server_Error:
			ret = strdup(STR_500);
			*size = STR_500_LEN;
			break;
		case Not_Implemented:
			ret = strdup(STR_501);
			*size = STR_501_LEN;
			break;
		default:
			fprintf(stderr, "unknown error code %d\n", req->http_code);
			assert(0);
	}
	return ret;
}

static char *parse_url(struct request *req)
{
	unsigned int i;
	unsigned int minimal_url_len = 5 + CRLF_LEN; /* "GET /" + CRLF */
	char *p, *url;
	
	req->http_code = OK;

	/* some sanity checks */
	if (req->request_size < minimal_url_len) {
		req->http_code = Bad_Request;
		return NULL;
	}
	if (memcmp("GET ", req->request, 4)) {
		req->http_code = Not_Implemented;
		return NULL;
	}

	p = (char *)req->request + 4;
	for (i = 0; i < req->request_size; i++) {
		if (p[i] == '\r' || p[i] == '\n' || p[i] == ' ')
			break;	
	}
	url = malloc(i + 1);
	if (!url) {
		req->http_code = Internal_Server_Error;
		return NULL;
	}

	memcpy(url, p, i);
	url[i] = '\0';
	return url;
}

static int do_fd_request(struct request *req, const char *path)
{

	req->fs_fd = open(path, O_RDONLY);
	if (req->fs_fd < 0) {
		switch (errno) {
			case ENOENT:
				req->http_code = Not_Found;
				return 0;
			default:
				req->http_code = Internal_Server_Error;
				return 0;
		}
	}

	return 1;
}

static int __attribute__((warn_unused_result)) state_to(struct request *req, enum req_state state, int poll_fd)
{
	struct epoll_event ev;
	
	switch(state) {
		case NET_SENDING:
			break;
		case NET_SENDING_STATUS:
			ev.events = EPOLLOUT;
			ev.data.fd = req->net_fd;
			if (epoll_ctl(poll_fd, EPOLL_CTL_MOD, req->net_fd, &ev) < 0) {
				perror("epoll_ctl mod");
				req_del(req->net_fd);
				return 0;
			}
			break;
		case FS_RECEIVING:
			ev.events = 0;
			ev.data.fd = req->net_fd;
			if (epoll_ctl(poll_fd, EPOLL_CTL_MOD, req->net_fd, &ev) < 0) {
				req->http_code = Internal_Server_Error;
				return 0;
			}
			ev.events = EPOLLIN;
			ev.data.fd = req->fs_fd;
			if (epoll_ctl(poll_fd, EPOLL_CTL_ADD, req->fs_fd, &ev) < 0) {
				req->http_code = Internal_Server_Error;
				return 0;
			}
			break;
		default:
			fprintf(stderr, "Unknown state %d\n", state);
			assert(0);
	}

	req->state = state;
	return 1;
}

int main()
{
	int ret, optval;
	int server;
	struct sockaddr_in server_addr;
	struct epoll_event ev, *events;
	int maxevents = 64;
	int poll_fd;
	pthread_t timethread;

	reqs = calloc(1, sizeof(struct request *) * sysconf(_SC_OPEN_MAX));
	if (!reqs) {
		perror("Cannot create socket");
		exit(1);
	}

	pthread_create(&timethread, NULL, time_thread, NULL);
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

	memset(&ev, 0, sizeof(ev));
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

		nfds = epoll_wait(poll_fd, events, maxevents, config.socket_timeout * 1000);
		if (nfds == 0) {
			garbage_collect();
		}

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
					perror("epoll_ctrl add");
					continue;
				}
				
				req = malloc(sizeof(struct request));
				if (!req) {
					perror("malloc");
					continue;
				}
				req->net_fd = client;
				req->fs_fd = 0;
				req->state = NET_RECEIVING;
				req->request = malloc(BUFSIZ);
				req->request_size = 0;
				req->out_buf = NULL;
				req->out_buf_size = 0;
				req->last_accessed = now;
				req_add(req);
			} else {
				struct request *req;

				/* check the sanity of the file descriptor */
				if (events[n].events & EPOLLERR || events[n].events & EPOLLHUP) {
					assert(0);
					req_del(req->net_fd);
					continue;
				}

				req = req_get_from_net_fd(events[n].data.fd);
				assert(req);

				req->last_accessed = now;

				switch(req->state) {
					case NET_RECEIVING:
						ret = read(req->net_fd, req->request + req->request_size, BUFSIZ);
						if (ret < 0) {
							perror("read");
							req_del(req->net_fd);
							continue;
						}
						/* remote peer unexpectedly closed the connection */
						if (ret <= 0) {
							req_del(req->net_fd);
							continue;
						}
						req->request_size += ret;

						/* is request too long ? */
						if (req->request_size > config.max_request_size) {
							fprintf(stderr, "Request is too long\n");
							req_del(req->net_fd);
							continue;
						}
						/* is that a full request, if yes try to parse it */
						if (req->request_size > CRLF_LEN
						    && !memcmp(&req->request[req->request_size-CRLF_LEN], CRLF, CRLF_LEN)) {

							char *url;

							url = parse_url(req);
							if (!url)
								continue;
							
							if (!do_fd_request(req, url))
								continue;
							free(url);

							if (!state_to(req, NET_SENDING_STATUS, poll_fd))
								continue;


							req->out_buf_size = 0;
							req->out_buf = malloc(BUFSIZ);
							if (!req->out_buf) {
								req->http_code = Internal_Server_Error;
								continue;
							}
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
					case NET_SENDING_STATUS:
						do {
							int size;
							const char *status;
							status = build_status_line(req, &size);
							ret = write(req->net_fd, status, size);
							if (ret < 0) {
								perror("write");
								req_del(req->net_fd);
							}
							if (req->http_code != OK) 
								req_del(req->net_fd);

							if (!state_to(req, NET_SENDING, poll_fd))
								req_del(req->net_fd);

						} while(0);
						break;
					case NET_SENDING:
						if (req->fs_fd) {
							ret = read(req->fs_fd, req->out_buf, BUFSIZ);
							req->out_buf_size += ret;
						}
						if (!ret) {
							req_del(req->net_fd);
							continue;
						}

						ret = write(req->net_fd, req->out_buf, req->out_buf_size);
						if (ret > 0) {
							req->out_buf_size = 0;
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
