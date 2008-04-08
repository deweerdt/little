#ifndef _LITTLE_H_
#define _LITTLE_H_

#include <stdint.h>
#include <time.h>

#include "http.h"

#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))

/* Holds the server configuration data */
struct configuration {
	/** the port to bind to */
	unsigned short port;
	/** the address to bind to */
	char bind_address[17];
	/** max size of an incoming http request, in bytes */
	unsigned int max_request_size;
	/** delay of inactivity before closing a socket */
	int socket_timeout;
};

/** The different states the requests go through */
enum req_state {
	/** client socket just accepted, or receiving a request */
	NET_RECEIVING,
	/** request received, send status*/
	NET_SENDING_STATUS,
	/** status sent, response started */
	NET_SENDING,
};

#endif /* _LITTLE_H_ */
