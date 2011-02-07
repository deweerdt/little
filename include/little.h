#ifndef _LITTLE_H_
#define _LITTLE_H_

#include <limits.h>
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
	/** delay of inactivity before closing a socket */
	int socket_timeout;
	/** delay of inactivity before closing a socket */
	char root_dir[_POSIX_PATH_MAX];
};

/** The different states the requests go through */
enum req_state {
	/** client socket just accepted, or receiving a request */
	NET_RECEIVING,
	/** headers sent, response started */
	NET_SENDING,
};

#endif /* _LITTLE_H_ */
