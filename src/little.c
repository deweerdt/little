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
#include <sys/epoll.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <getopt.h>

#include "http.h"
#include "little.h"
#include "log.h"
#include "requests.h"
#include "handler.h"

#define MAX_REQUEST_SIZE 16384

static 	struct configuration config = {
	.port = 8080,
	.bind_address = "0.0.0.0",
	.root_dir = "/tmp",
	.socket_timeout = 3
};

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
	} while (1);
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
 *
 * @return the string representation of the HTTP error code
 *	   an error is cosidered fatal, this function aborts
 **/
static struct string build_status_line(enum http_response_code code)
{
	switch (code) {
	case OK:
		return STR_200;
	case Bad_Request:
		return STR_400;
	case Forbidden:
		return STR_403;
	case Not_Found:
		return STR_404;
	case Internal_Server_Error:
		return STR_500;
	case Not_Implemented:
		return STR_501;
	default:
		logm(CRITICAL, NONE, "unknown error code %d\n", code);
		assert(0);
	}
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
	path = malloc(MAX_REQUEST_SIZE + sizeof(config.root_dir) + 2);
	if (!path)
		goto out;

	sprintf(path, "%s/%s", config.root_dir, url);

out:
	return path;
}

static char *unescape_url(const char *u, unsigned int len)
{
	unsigned int i, j;
	char *out;

	out = malloc(len * 3);
	for (i = 0, j = 0; i < len && u[i]; i++, j++) {
		if (u[i] == '%') {
			if (i + 2 < len) {
				char val;
				char hex[3] = { u[i + 1], u[i + 2], '\0' };
				val = (char)strtol(hex, NULL, 16);
				i += 2;
				out[j] = val;
				continue;
			}
		} else {
			out[j] = u[i];
		}
	}
	out[j] = '\0';

	return out;
}

/**
 * @brief Given a request, examine it's contents and try to parse the URL
 *
 * @param req the request from which the URL need to be extracted
 *
 * @return the successfully extracted URL (needs to be freed), or NULL
 *	   also req->response.code is set appropriately
 **/
__attribute__((warn_unused_result))
static char *parse_url(struct request *req)
{
	unsigned int i;
	unsigned int minimal_url_len = 5 + CRLF_LEN; /* "GET /" + CRLF */
	char *p, *url;

	req->response.http_code = OK;

	/* some sanity checks */
	if (req->request_size < minimal_url_len) {
		req->response.http_code = Bad_Request;
		return NULL;
	}
	if (memcmp("GET ", req->request, 4)) {
		req->response.http_code = Not_Implemented;
		return NULL;
	}

	/* seems Ok, try to find an URL */
	p = (char *)req->request + 4;
	for (i = 0; i < req->request_size; i++) {
		if (p[i] == '\r' || p[i] == '\n' || p[i] == ' ')
			break;
	}
	url = unescape_url(p, i);
	if (!url) {
		req->response.http_code = Internal_Server_Error;
		return NULL;
	}

	return url;
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
	static struct epoll_event ev;

	switch (new_state) {
	case NET_SENDING:
		assert(req->state == NET_RECEIVING);
		ev.events = EPOLLOUT;
		ev.data.fd = req->net_fd;
		if (epoll_ctl(req->poll_fd, EPOLL_CTL_MOD, req->net_fd, &ev) < 0) {
			logm(ERROR, ERRNO, "epoll_ctl mod");
			return 0;
		}
		break;
	default:
		logm(CRITICAL, NONE, "Unknown state %d\n", new_state);
		assert(0);
	}

	req->state = new_state;
	return 1;
}

enum url_type {
	LOCAL_FS_REQ,
};

enum resp_type {
	LOCAL_FILE,
	LOCAL_DIR,
};

struct file_handler_priv {
	enum resp_type resp_type;
	DIR *dir;
};

static int open_local_file(struct request *req, const char *path)
{

	struct stat st;
	int ret;
	struct file_handler_priv *handler_priv;

	if (!path)
		return 0;

	handler_priv = req->priv;

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
		handler_priv->resp_type = LOCAL_DIR;
		return 1;
	}

	handler_priv->resp_type = LOCAL_FILE;
	return 1;
err:
	switch (errno) {
	case ENOENT:
		req->response.http_code = Not_Found;
		break;
	case EACCES:
		req->response.http_code = Forbidden;
		break;
	default:
		req->response.http_code = Internal_Server_Error;
	}
	return 0;
}

int file_handler_main(struct request *req)
{
	char *path;
	int ret;
	struct file_handler_priv *handler_priv;

	/* First run */
	if (!req->priv) {
		req->priv = calloc(1, sizeof(struct file_handler_priv));
		if (!req->priv)
			return -1;

		path = url_to_path(string_charstar(req->url));

		if (!open_local_file(req, path)) {
			req->response.status = build_status_line(req->response.http_code);
			req->handler = NULL;
			return -1;
		}

		req->response.status = build_status_line(req->response.http_code);
		if (req->response.http_code != OK) {
			req->handler = NULL;
			return -1;
		}
		write(req->net_fd, req->response.status.str, req->response.status.len);
	}

	handler_priv = req->priv;

	if (handler_priv->resp_type == LOCAL_FILE) {
		ret = sendfile(req->net_fd, req->fs_fd, &req->fs_fd_offset, BUFSIZ);
		if (ret <= 0) {
			req_del(req->net_fd);
			return -1;
		}
	} else {
		struct dirent *dirent;

		char dir_header[] = "<html><body>";
		ret = write(req->net_fd, dir_header, sizeof(dir_header));

		handler_priv->dir = fdopendir(req->fs_fd);
		if (!handler_priv->dir) {
			req->response.http_code = Internal_Server_Error;
			req->handler = NULL;
			return -1;
		}
		/* if write was blocking, retry later */
		if (ret == -EAGAIN)
			return -1;

		do {
			char buf[BUFSIZ];
			int len;

			dirent = readdir(handler_priv->dir);
			if (!dirent)
				break;

			len = sprintf(buf, "<a href=\"%s\">%s</a><br>", dirent->d_name, dirent->d_name);
			ret = write(req->net_fd, buf, len);
		} while (handler_priv->dir && ret != -EAGAIN);
		if (!dirent) {
			char dir_footer[] = "</body></html>";
			ret = write(req->net_fd, dir_footer, sizeof(dir_footer));
			if (ret == -EAGAIN)
				return -1;
			req_del(req->net_fd);
		}
	}
	return 0;
}

void file_handler_cleanup(struct request *req)
{
	struct file_handler_priv *handler_priv = req->priv;

	if (!req->priv)
		return;

	closedir(handler_priv->dir);
}

struct handler file_handler = {
	.main = file_handler_main,
	.cleanup = file_handler_cleanup
};

struct handler *get_handler_from(const char *url)
{
	(void)url;

	return &file_handler;
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
		logm(ERROR, ERRNO, "read");
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
	if (req->request_size > MAX_REQUEST_SIZE) {
		/* too long: inform the client */
		req->response.http_code = Bad_Request;
		if (!state_to(req, NET_SENDING)) {
			req_del(req->net_fd);
		}
		return;
	}
	/* is that a full request? if yes try to parse it */
	if (req->request_size > CRLF_LEN
	    && !memcmp(&req->request[req->request_size-CRLF_LEN], CRLF, CRLF_LEN)) {
		char *url = NULL;

		if (!state_to(req, NET_SENDING)) {
			req_del(req->net_fd);
			return;
		}

		url = parse_url(req);
		if (!url)
			return;

		req->handler = get_handler_from(url);
		req->url = string_new(url);

		return;
	} else {
		/* not a request, continue */
		req->request = realloc(req->request, req->request_size + BUFSIZ);
		if (!req->request) {
			logm(ERROR, ERRNO, "realloc");
			req_del(req->net_fd);
			return;
		}
	}
}


/**
 * @brief state == NET_SENDING process: read the local file and send it
 * over the socket
 *
 * @param req the request being serviced
 **/
static void process_net_sending(struct request *req)
{
	if (req->handler) {
		req->handler->main(req);
	} else {
		write(req->net_fd, req->response.status.str, req->response.status.len);
		req_del(req->net_fd);
	}
}

/**
 * @brief Called upon receiving a new incoming connection
 *
 * @param server the server socket to accept from
 * @param poll_fd the epoll fd to add the new client to
 **/
static void process_new_client(int server, int poll_fd)
{
	struct sockaddr_in client_addr;
	socklen_t addrlen;
	int flags, client;
	struct request *req;
	static struct epoll_event ev;

	addrlen = sizeof(client_addr);
	client = accept(server, (struct sockaddr *)&client_addr,
			&addrlen);
	if (client < 0) {
		logm(ERROR, ERRNO, "accept");
		return;
	}

	flags = fcntl(client, F_GETFL, 0);
	if (flags < 0) {
		logm(ERROR, ERRNO, "fcntl 1");
		return;
	}


	if (fcntl(client, F_SETFL, flags | O_NONBLOCK) < 0) {
		logm(ERROR, ERRNO, "fcntl 2");
		return;
	}

	ev.events = EPOLLIN | EPOLLPRI;
	ev.data.fd = client;
	if (epoll_ctl(poll_fd, EPOLL_CTL_ADD, client, &ev) < 0) {
		logm(ERROR, ERRNO, "epoll_ctrl add");
		return;
	}

	req = calloc(1, sizeof(struct request));
	if (!req) {
		logm(ERROR, ERRNO, "malloc");
		return;
	}
	req->net_fd = client;
	req->fs_fd = 0;
	req->state = NET_RECEIVING;
	req->request = malloc(BUFSIZ);
	req->handler = NULL;
	req->request_size = 0;
	req->last_accessed = now;
	req->poll_fd = poll_fd;
	req->peer_addr = client_addr;
	req_add(req);
}

void usage(char **argv, struct option *o, char **help)
{
	int i = 0;

	fprintf(stderr, "Usage: %s\n", argv[0]);
	while (help[i]) {
		fprintf(stderr, "\t--%-15s: %-30s\n", o[i].name, help[i]);
		i++;
	}
}

int parse_cmdline(char **argv, int argc, struct configuration *config)
{
	int c;

	while (1) {
		int option_index = 0;
		char *help[] = {
			"port to listen to",
			"IP address to bind to",
			"web server root dir",
			"this help",
			NULL
		};
		struct option long_options[] = {
			{ "port", 1, 0, 'p'},
			{ "bind_address", 1, 0, 'b'},
			{ "root_dir", 1, 0, 'r'},
			{ "help", 0, 0, 'h'},
		};



		c = getopt_long(argc, argv, "p:b:r:h",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'p':
			config->port = atoi(optarg);
			break;

		case 'b':
			strncpy(config->bind_address,
				optarg, sizeof(config->bind_address) - 1);
			break;

		case 'r':
			strncpy(config->root_dir,
				optarg, sizeof(config->root_dir) - 1);
			break;

		case 'h':
		default:
			usage(argv, long_options, help);
			return -1;
		}
	}

	return 0;
}


int main(int argc, char **argv)
{
	int ret, optval;
	int server;
	struct sockaddr_in server_addr;
	static struct epoll_event ev;
	struct epoll_event *events;
	int maxevents = 512;
	int poll_fd;
	time_t last_gc;

	ret = parse_cmdline(argv, argc, &config);
	if (ret < 0)
		exit(EXIT_FAILURE);

	log_init();
	chdir(config.root_dir);

	if (!req_init()) {
		logm(ERROR, ERRNO, "Cannot init internal memory");
		exit(1);
	}

	signal(SIGINT, sigint_handler);
	signal(SIGPIPE, SIG_IGN);

	ret = pthread_create(&timethread, NULL, time_thread, NULL);
	if (ret) {
		logm(ERROR, ERRNO, "pthread_create");
		exit(1);
	}

	server = socket(PF_INET, SOCK_STREAM, IPPROTO_IP);
	if (server < 0) {
		logm(ERROR, ERRNO, "Cannot create socket");
		exit(1);
	}
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(config.port);
	server_addr.sin_addr.s_addr = inet_addr(config.bind_address);

	optval = 1;
	ret = setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
	if (ret < 0) {
		logm(ERROR, ERRNO, "setsockopt");
		exit(1);
	}


	ret = bind(server, (struct sockaddr *)&server_addr, sizeof(server_addr));
	if (ret < 0) {
		logm(ERROR, ERRNO, "Cannot bind");
		exit(1);
	}

	ret = listen(server, 128);
	if (ret < 0) {
		logm(ERROR, ERRNO, "Cannot listen");
		exit(1);
	}

	events = calloc(1, maxevents * sizeof(struct epoll_event));
	if (!events) {
		logm(ERROR, ERRNO, "Initial malloc failed");
		exit(1);
	}
	poll_fd = epoll_create(maxevents);
	if (poll_fd < 0) {
		logm(ERROR, ERRNO, "epoll_create");
		exit(1);
	}

	ev.events = EPOLLIN | EPOLLPRI;
	ev.data.fd = server;
	ret = epoll_ctl(poll_fd, EPOLL_CTL_ADD, server, &ev);
	if (ret < 0) {
		logm(ERROR, ERRNO, "epoll_ctl");
		exit(1);
	}

	last_gc = now;
	do {
		int n;
		int nfds;

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
				if (events[n].events & (EPOLLERR | EPOLLHUP)) {
					req_del(req->net_fd);
					continue;
				}

				req->last_accessed = now;

				switch (req->state) {
				case NET_RECEIVING:
					process_net_receiving(req);
					break;
				case NET_SENDING:
					process_net_sending(req);
					break;
				default:
					assert(0);
				}
			}
		}
	} while (1);

	return ret;
}
