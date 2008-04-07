#ifndef _REQUESTS_H_
#define _REQUESTS_H_

#include <sys/types.h>
#include <stdint.h>
#include <openssl/bio.h>

struct request {
	int net_fd;
	int fs_fd;
	off_t fs_fd_offset;
	uint8_t *request;
	unsigned int request_size;
	enum req_state state;
	time_t last_accessed; 
	enum http_response_code http_code;
	int is_binary;
	BIO *bio_fd;
};

int req_init();
void req_garbage_collect(time_t now, int timeout);
void req_del(int fd);
void req_add(struct request *req);
struct request *req_get_from_net_fd(const int fd);

#endif /* _REQUESTS_H_ */

