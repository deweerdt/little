#define __USE_GNU

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <ev.h>

#include "http.h"
#include "little.h"
#include "requests.h"

static struct configuration config = {	.port = 8080,
					.bind_address = "0.0.0.0",
					.max_request_size = 16384,
					.root_dir = "/home/httpd/html",
					.socket_timeout = 3 };

/**
 * In conjuction with the time_thread(), it keeps track of current wall time
 * This is used for garbage collection of old sockets.
 *
 * Note that we don't bother protecting it, avoiding an unlikely extra
 * garbage collection doesn't justify the overhead of atomical sets
 */
static time_t now;

static pthread_t timethread;
static void *time_thread(void __attribute__((unused)) *arg)
{
	do {
		now = time(NULL);
		sleep(config.socket_timeout);
	} while(1);
	return NULL;
}

/**
 * Exit on SIGINT
 */
static void sigint_handler(int  __attribute__((unused)) arg)
{
	exit(0);
}

/**
 * @brief Given an HTTP error code, build the standard HTTP response header
 *
 * @param code  the HTTP code (200, 404, ...), whose string form we want
 * @param size  (out param), the size of the returned string
 *
 * @return the string representation of the HTTP error code
 * 	   an error is cosidered fatal, this function aborts
 **/
static const char *build_status_line(enum http_response_code code, int *size)
{
	const char *ret = NULL;
	switch (code) {
		case OK:
			ret = STR_200;
			*size = STR_200_LEN;
			break;
		case Bad_Request:
			ret = STR_400;
			*size = STR_400_LEN;
			break;
		case Forbidden:
			ret = STR_403;
			*size = STR_403_LEN;
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
			fprintf(stderr, "unknown error code %d\n", code);
			assert(0);
	}
	return ret;
}

 __attribute__((warn_unused_result))
static int get_type_from_url(const char *url)
{
	(void)url;
	return LOCAL_FS_REQ;
}

static char *url_to_path(const char *url)
{
	char *path;
	/* ignore those paths for now */
	if (strstr(url, "..")) {
		path = malloc(2);
		if (path)
			strcpy(path, "/");
		goto out;
	}
	path = malloc(config.max_request_size + sizeof(config.root_dir) + 2);
	if (!path)
		goto out;

	sprintf(path, "%s/%s", config.root_dir, url);

out:
	return path;
}

/**
 * @brief Given a request, examine it's contents and try to parse the URL
 *
 * @param req the request from which the URL need to be extracted
 *
 * @return the successfully extracted URL (needs to be freed), or NULL
 * 	   also req->http_code is set appropriately
 **/
 __attribute__((warn_unused_result))
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

static int open_local_file(struct request *req, const char *path)
{

	struct stat st;
	int ret;

	if (!path)
		return 0;
	/*
	 * This could be opened in non-blocking mode, but as man 2 read puts it:
	 *
	 * Many  filesystems  and  disks  were  considered to be fast enough
	 * that the implementation of O_NONBLOCK was deemed unnecessary.
	 */
	req->fs_fd = open(path, O_RDONLY);
	req->fs_fd_offset = 0;
	if (req->fs_fd < 0)
		goto err;

	ret = fstat(req->fs_fd, &st);
	if (ret < 0)
		goto err;
	if (S_ISDIR(st.st_mode)) {
		req->resp_type = LOCAL_DIR;
		return 1;
	}

	req->resp_type = LOCAL_FILE;
	return 1;
err:
	switch (errno) {
		case ENOENT:
			req->http_code = Not_Found;
			break;
		case EACCES:
			req->http_code = Forbidden;
			break;
		default:
			req->http_code = Internal_Server_Error;
	}
	return 0;
}

void req_cb(struct ev_loop *loop, struct ev_io *watcher, int events);

static int net_listen_for_in_events(struct request *req)
{
	struct ev_io *w_client;

	w_client = (struct ev_io*) malloc (sizeof(struct ev_io));

	ev_io_init(w_client, req_cb, req->net_fd, EV_READ);
	ev_io_start(req->loop, w_client);

	return 0;
}

static int net_listen_for_out_events(struct request *req)
{
	struct ev_io *w_client;

	w_client = (struct ev_io*) malloc (sizeof(struct ev_io));

	ev_io_init(w_client, req_cb, req->net_fd, EV_WRITE);
	ev_io_start(req->loop, w_client);

	return 0;
}
/**
 * @brief Switch the state of the request.
 *
 * @param req  the requests, that changes state
 * @param new_state  the new state of the request
 *
 * @return Returns 1 on success, 0 on failure (failed epoll_ctl)
 **/
 __attribute__((warn_unused_result))
static int state_to(struct request *req, enum req_state new_state)
{

	switch(new_state) {
		case NET_SENDING:
			assert(req->state == NET_SENDING_STATUS);
			break;
		case NET_SENDING_STATUS:
			assert(req->state == NET_RECEIVING);
			net_listen_for_out_events(req);
			break;
		default:
			fprintf(stderr, "Unknown state %d\n", new_state);
			assert(0);
	}

	req->state = new_state;
	return 1;
}

/**
 * @brief state == NET_RECEIVING procedure
 *
 * @param req the request being serviced
 *
 * @return
 **/
static void process_net_receiving(struct request *req)
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
		/* too long: inform the client */
		req->http_code = Bad_Request;
		if (!state_to(req, NET_SENDING_STATUS)) {
			req_del(req->net_fd);
		}
		return;
	}
	/* is that a full request? if yes try to parse it */
	if (req->request_size > CRLF_LEN
	    && !memcmp(&req->request[req->request_size-CRLF_LEN], CRLF, CRLF_LEN)) {
		char *url, *path = NULL;
		enum url_type type;

		if (!state_to(req, NET_SENDING_STATUS)) {
			req_del(req->net_fd);
			return;
		}

		url = parse_url(req);
		if (!url)
			return;


		type = get_type_from_url(url);
		switch (type) {
		case LOCAL_FS_REQ:
			path = url_to_path(url);
			open_local_file(req, path);
			free(path);
		}
		free(url);
		return;
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

/**
 * @brief state == NET_SENDING_STATUS process:
 * Send the header corresponding to the http_code
 *
 * @param req the request being serviced
 **/
static void process_net_sending_status(struct request *req)
{
	int size, ret;
	const char *status;
	status = build_status_line(req->http_code, &size);
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

	if (!state_to(req, NET_SENDING))
		req_del(req->net_fd);

}

#if !defined(__linux__)
/* Solaris function missing on Darwin.  Temporary workaround to allow building.
 * Ref http://mail.openjdk.java.net/pipermail/bsd-po...
 */
static DIR* fake_fdopendir(int dfd)
{
	(void)dfd;
	errno = ENOSYS;
	return NULL;
}
#define fdopendir fake_fdopendir
#endif

/**
 * @brief state == NET_SENDING process: read the local file and send it
 * over the socket
 *
 * @param req the request being serviced
 **/
static void process_net_sending(struct request *req)
{
	int ret;

	if (req->resp_type == LOCAL_FILE) {
		char buf[BUFSIZ];
		ret = read(req->fs_fd, buf, sizeof(buf));
		if (ret <= 0) {
			goto del_fd;
		}
		ret = write(req->net_fd, buf, ret);
		if (ret <= 0) {
			goto del_fd;
		}
		return;
del_fd:
		req_del(req->net_fd);
		return;
	} else {
		struct dirent *dirent;

		if (!req->dir) {
			char dir_header[] = "<html><body>";
			ret = write(req->net_fd, dir_header, sizeof(dir_header));
		}

		DIR *fdopendir(int fd);
		req->dir = fdopendir(req->fs_fd);
		if (!req->dir) {
			req->http_code = Internal_Server_Error;
			if (!state_to(req, NET_SENDING_STATUS)) {
				req_del(req->net_fd);
			}
			return;
		}
		/* if write was blocking, retry later */
		if (ret == -EAGAIN)
			return;

		do {
			char buf[BUFSIZ];
			int len;

			dirent = readdir(req->dir);
			if (!dirent)
				break;

			len = sprintf(buf, "<a href=\"%s\">%s</a><br>", dirent->d_name, dirent->d_name);
			ret = write(req->net_fd, buf, len);
		} while (req->dir && ret != -EAGAIN);
		if (!dirent) {
			char dir_footer[] = "</body></html>";
			ret = write(req->net_fd, dir_footer, sizeof(dir_footer));
			if (ret == -EAGAIN)
				return;
			req_del(req->net_fd);
		}
	}
}

/**
 * @brief Called upon receiving a new incoming connection
 *
 * @param server the server socket to accept from
 **/
static void process_new_client(struct ev_loop *loop, int server)
{
	struct sockaddr_in client_addr;
	unsigned int addrlen;
	int flags, client;
	struct request *req;

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

	req = malloc(sizeof(struct request));
	if (!req) {
		perror("malloc");
		return;
	}
	req->net_fd = client;
	req->fs_fd = 0;
	req->loop = loop;
	req->state = NET_RECEIVING;
	req->request = malloc(BUFSIZ);
	req->request_size = 0;
	req->last_accessed = now;
	req->dir = NULL;

	net_listen_for_in_events(req);

	req_add(req);
}

void req_cb(struct ev_loop *loop, struct ev_io *watcher, int events)
{
	struct request *req;

	(void)loop;
	(void)events;

	req = req_get_from_net_fd(watcher->fd);
	//assert(req);
	if (!req)
		return;

	req->last_accessed = now;

	switch(req->state) {
		case NET_RECEIVING:
			process_net_receiving(req);
			break;
		case NET_SENDING_STATUS:
			process_net_sending_status(req);
			break;
		case NET_SENDING:
			process_net_sending(req);
			break;
		default:
			assert(0);
	}
}


void accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	(void)revents;
	process_new_client(loop, watcher->fd);
}

int main(void)
{
	int ret, optval;
	int server;
	struct sockaddr_in server_addr;
	time_t last_gc;
	struct ev_loop *loop;
	struct ev_io fd_pool;


	chdir(config.root_dir);

	if (!req_init()) {
		perror("Cannot init internal memory");
		exit(1);
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

	ret = listen(server, 128);
	if (ret < 0) {
		perror("Cannot listen");
		exit(1);
	}

	loop = ev_default_loop(0);
	ev_io_init(&fd_pool, accept_cb, server, EV_READ);
	ev_io_start(loop, &fd_pool);

	last_gc = now;

	do {
		/* is it time to gargabe collect ? */
		if (difftime(now, last_gc) > config.socket_timeout) {
			req_garbage_collect(now, config.socket_timeout);
			last_gc = now;
		}
		ev_loop(loop, 0);
	} while (1);

	return ret;
}
