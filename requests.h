#ifndef _REQUESTS_H_
#define _REQUESTS_H_

int req_init();
void req_garbage_collect(time_t now, int timeout);
void req_del(int fd);
void req_add(struct request *req);
struct request *req_get_from_net_fd(const int fd);

#endif /* _REQUESTS_H_ */

