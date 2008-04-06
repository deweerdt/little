#ifndef _LITTLE_H_
#define _LITTLE_H_

#include <stdint.h>
#include <time.h>

#include "http.h"

#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))

struct configuration {
	/** the port to bind to */
	unsigned short port;
	/** the address to bind to */
	char bind_address[17];
	/** max size of an incoming http request, in bytes */
	unsigned int max_request_size;
	/** for socket or file IO, in bytes */
	unsigned int buffer_size; 	
	/** delay of inactivity before closing a socket */
	int socket_timeout;
};

enum req_state {
	/** client socket just accepted, or receiving a request */
	NET_RECEIVING,
	/** request received, send status*/
	NET_SENDING_STATUS,
	/** status sent, response started */
	NET_SENDING,
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

#endif /* _LITTLE_H_ */
