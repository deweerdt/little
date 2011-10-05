#ifndef _REQUESTS_H_
#define _REQUESTS_H_

#include <sys/types.h>
#include <dirent.h>
#include <stdint.h>
#include <ev.h>
#include <netinet/in.h>
#include "str.h"

struct response {
	enum http_response_code http_code; 	/* the http response code */
	struct string status;
};

struct request {
	int net_fd;				/* the socket file descriptor */
	struct ev_loop *loop;
	uint8_t *request;			/* a buffer holding the recieved request */
	unsigned int request_size;		/* the size of date hold by request */
	enum req_state state;			/* the state of the request */
	time_t last_accessed;			/* last time said socket was accessed */
	struct sockaddr_in peer_addr;		/* peer's address */
	struct response response;
	struct string *url;
	struct handler *handler;
	void *priv;
};

/**
 * @brief Inits the reqs global variable holding the state of each socket
 *
 * @return 1 on success, 0 on failure
 **/
int req_init(void);

void req_flush(struct request *req);
/**
 * @brief Close the sockets that have been inactive for @timeout seconds
 *
 * @param now the time elapsed since the EPOCH in seconds
 * @param timeout the timeout value in seconds
 **/
void req_garbage_collect(time_t now, int timeout);

/**
 * @brief Deletes a requests from the serviced requests
 *	  closes all associated file descriptors and frees all associated
 *	  memory
 *
 **/
void req_del(int fd);

/**
 * @brief Add a new request to be serviced
 *
 * @param req the new request
 **/
void req_add(struct request *req);

/**
 * @brief Given @fd, find the associated struct request, holding the
 *	  state information
 *
 * @param fd the net socket associated with the request
 *
 * @return the struct request corresponding to the socket fd, or NULL
 *         if not found
 **/
struct request *req_get_from_net_fd(const int fd);

#endif /* _REQUESTS_H_ */

