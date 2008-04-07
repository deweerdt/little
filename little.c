#define __USE_GNU

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include <sys/epoll.h>
#include <sys/sendfile.h>

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>

#include <assert.h>
#include <pthread.h>

#include <magic.h>

#include <openssl/bio.h>
#include <openssl/evp.h>

#include "http.h"
#include "little.h"
#include "requests.h"

static struct configuration config = {	.port = 8080,
					.bind_address = "0.0.0.0",
					.max_request_size = 16384,
					.socket_timeout = 3 };

static time_t now;
static magic_t magic_cookie;

void *time_thread(void __attribute__((unused)) *arg)
{
	do {
		now = time(NULL);
		sleep(config.socket_timeout);
	} while(1);
	return NULL;
}

static const char *build_status_line(struct request *req, int *size)
{
	const char *ret = NULL;
	switch (req->http_code) {
		case OK:
			ret = STR_200;
			*size = STR_200_LEN;
			break;
		case Bad_Request:
			ret = STR_400;
			*size = STR_400_LEN;
			break;
		case Not_Found:
			ret = STR_404;
			*size = STR_404_LEN;
			break;
		case Internal_Server_Error:
			ret = STR_500;
			*size = STR_500_LEN;
			break;
		case Not_Implemented:
			ret = STR_501;
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

	/* seems Ok, try to find an URL */
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

 __attribute__((warn_unused_result))
static int open_local_file(struct request *req, const char *path)
{

	struct stat st;
	int ret;
	const char *magic_str;

  	/* notice the dup here, for some reason magic_descriptor
	 * closes the file at the end of the process */

	/* magic failed for some reason, this is non fatal, proceed anyway */
	magic_str = magic_file(magic_cookie, path);
	

	req->fs_fd = open(path, O_RDONLY);
	req->fs_fd_offset = 0;
	if (req->fs_fd < 0)
		goto err;

	ret = fstat(req->fs_fd, &st);
	if (ret < 0) 
		goto err;
	if (S_ISDIR(st.st_mode)) {
		req->http_code = Not_Found;
		return 0;
	}

	/* this is not plain text, base64 the file */
	if (magic_str && strncmp("text", magic_str, 4)) {
		BIO *b64;

		req->is_binary = 1;

		b64 = BIO_new(BIO_f_base64());
		req->bio_fd = BIO_new_socket(req->net_fd, BIO_NOCLOSE);
		req->bio_fd = BIO_push(b64, req->bio_fd);
		//BIO_set_mem_eof_return(req->bio_fd, 0);
	}

	return 1;
err:
	switch (errno) {
		case ENOENT:
			req->http_code = Not_Found;
			break;
		case EPERM:
			req->http_code = Forbidden;
			break;
		default:
			req->http_code = Internal_Server_Error;
	}
	return 0;
}

 __attribute__((warn_unused_result))
static int state_to(struct request *req, enum req_state state, int poll_fd)
{
	static struct epoll_event ev;
	
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
		default:
			fprintf(stderr, "Unknown state %d\n", state);
			assert(0);
	}

	req->state = state;
	return 1;
}

void sigint_handler(int arg __attribute__((unused)))
{
	exit(0);
}

static void process_net_receiving(struct request *req, int poll_fd)
{
	int ret;
	ret = read(req->net_fd, req->request + req->request_size, BUFSIZ);
	if (ret < 0) {
		perror("read");
		req_del(req->net_fd);
		return;
	}
	/* remote peer unexpectedly closed the connection */
	if (ret <= 0) {
		req_del(req->net_fd);
		return;
	}
	req->request_size += ret;

	/* is request too long ? */
	if (req->request_size > config.max_request_size) {
		req->http_code = Bad_Request;
		if (!state_to(req, NET_SENDING_STATUS, poll_fd)) {
			req_del(req->net_fd);
		}
		return;
	}
	/* is that a full request, if yes try to parse it */
	if (req->request_size > CRLF_LEN
	    && !memcmp(&req->request[req->request_size-CRLF_LEN], CRLF, CRLF_LEN)) {
		char *url;

		if (!state_to(req, NET_SENDING_STATUS, poll_fd))
			return;

		url = parse_url(req);
		if (!url)
			return;

		if (!open_local_file(req, url)) {
			free(url);
			return;
		}
		free(url);
	} else {
		/* not a request, continue */
		req->request = realloc(req->request, req->request_size + BUFSIZ);
		if (!req->request) {
			perror("realloc");
			req_del(req->net_fd);
			return;
		}
	}
}
static void process_net_sending_status(struct request *req, int poll_fd)
{
	int size, ret;
	const char *status;
	status = build_status_line(req, &size);
	ret = write(req->net_fd, status, size);
	if (ret < 0) {
		perror("write");
		req_del(req->net_fd);
		return;
	}
	if (req->http_code != OK) {
		req_del(req->net_fd);
		return;
	}

	if (!state_to(req, NET_SENDING, poll_fd))
		req_del(req->net_fd);

}
static void process_net_sending(struct request *req, int poll_fd)
{
	int ret;

	if (!req->is_binary) {
		ret = sendfile(req->net_fd, req->fs_fd, &req->fs_fd_offset, BUFSIZ);
		if (ret < 0) {
			req->http_code = Internal_Server_Error;
			if (!state_to(req, NET_SENDING_STATUS, poll_fd))
				req_del(req->net_fd);
			return;
		}

		/* File was sent, no more to send => close descriptor */
		if (!ret) {
			req_del(req->net_fd);
			return;
		}
	} else {
		char out_buf[BUFSIZ];

		ret = read(req->fs_fd, out_buf, sizeof(out_buf));
		if (ret < 0) {
			req->http_code = Internal_Server_Error;
			if (!state_to(req, NET_SENDING_STATUS, poll_fd))
				req_del(req->net_fd);
			return;
		}

		/* File was sent, no more to send => close descriptor */
		if (!ret) {
			req_del(req->net_fd);
			return;
		}

		ret = BIO_write(req->bio_fd, out_buf, ret);
		if (ret <= 0 ) {
			req_del(req->net_fd);
		}
	}
	return;
}

static void process_new_client(int server, int poll_fd)
{
	struct sockaddr_in client_addr;
	size_t addrlen;
	int flags, client;
	struct request *req;
	static struct epoll_event ev;

	addrlen = sizeof(client_addr);
	client = accept(server, (struct sockaddr *)&client_addr,
			&addrlen);
	if (client < 0){
		perror("accept");
		return;
	}

	if ((flags = fcntl(client, F_GETFL, 0)) < 0) {
		perror("fcntl 1");
		return;
	}


	if (fcntl(client, F_SETFL, flags | O_NONBLOCK) < 0) {
		perror("fcntl 2");
		return;
	}

	ev.events = EPOLLIN;
	ev.data.fd = client;
	if (epoll_ctl(poll_fd, EPOLL_CTL_ADD, client, &ev) < 0) {
		perror("epoll_ctrl add");
		return;
	}

	req = malloc(sizeof(struct request));
	if (!req) {
		perror("malloc");
		return;
	}
	req->net_fd = client;
	req->fs_fd = 0;
	req->state = NET_RECEIVING;
	req->request = malloc(BUFSIZ);
	req->request_size = 0;
	req->last_accessed = now;
	req->is_binary = 0;
	req_add(req);
}

int main()
{
	int ret, optval;
	int server;
	struct sockaddr_in server_addr;
	static struct epoll_event ev;
       	struct epoll_event *events;
	int maxevents = 512;
	int poll_fd;
	pthread_t timethread;

	if (!req_init()) {
		perror("Cannot init internal memory");
		exit(1);
	}

	magic_cookie = magic_open(MAGIC_MIME_TYPE);
	if (!magic_cookie) {
		perror("Cannot init magic cookie");
		exit(0);
	}
	ret = magic_load(magic_cookie, NULL);
	if (ret < 0) {
		perror("Cannot init magic database");
		exit(0);
	}

	signal(SIGINT, sigint_handler);
	signal(SIGPIPE, SIG_IGN);

	ret = pthread_create(&timethread, NULL, time_thread, NULL);
	if (ret) {
		perror("pthread_create");
		exit(1);
	}

	server = socket(PF_INET, SOCK_STREAM, IPPROTO_IP);
	if (server < 0) {
		perror("Cannot create socket");
		exit(1);
	}
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(config.port);
	server_addr.sin_addr.s_addr = inet_addr(config.bind_address);

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
		time_t last_gc = now;

		nfds = epoll_wait(poll_fd, events, maxevents, config.socket_timeout * 1000);

		/* is it time to gargabe collect ? */
		if (difftime(now, last_gc) > config.socket_timeout) {
			req_garbage_collect(now, config.socket_timeout);
			last_gc = now;
		}

		for (n = 0; n < nfds; ++n) {
			if (events[n].data.fd == server) {
				process_new_client(server, poll_fd);
			} else {
				struct request *req;

				req = req_get_from_net_fd(events[n].data.fd);
				assert(req);

				/* check the sanity of the file descriptor */
				if (events[n].events & EPOLLERR || events[n].events & EPOLLHUP) {
					req_del(req->net_fd);
					continue;
				}

				req->last_accessed = now;

				switch(req->state) {
					case NET_RECEIVING:
						process_net_receiving(req, poll_fd);
						break;
					case NET_SENDING_STATUS:
						process_net_sending_status(req, poll_fd);
						break;
					case NET_SENDING:
						process_net_sending(req, poll_fd);
						break;
					default:
						assert(0);
				}
			}
		}
	} while (1);

	return ret;
}
