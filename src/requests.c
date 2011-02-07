#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <assert.h>
#include <arpa/inet.h>

#include "hash.h"
#include "log.h"
#include "little.h"
#include "handler.h"
#include "requests.h"

/**
 * Holds all the handled requests, inited by req_init().
 * The array is indexed by the request->net_fd file descriptor
 */
static struct request **reqs;

int req_init()
{
	reqs = calloc(1, sizeof(struct request *) * sysconf(_SC_OPEN_MAX));
	return !!reqs;
}

void req_flush(struct request *req)
{
	(void)req;
	return;
}

void req_del(int fd)
{
	if (reqs[fd]->fs_fd > 0) {
		close(reqs[fd]->fs_fd);
	}
	if (reqs[fd]->handler
	    && reqs[fd]->handler->cleanup) {
		reqs[fd]->handler->cleanup(reqs[fd]);
	}

	close(reqs[fd]->net_fd);
	free(reqs[fd]->request);
	free(reqs[fd]);
	reqs[fd] = NULL;
}

void req_garbage_collect(time_t now, int timeout)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(reqs); i++) {
		if (reqs[i]
		    && difftime(now, reqs[i]->last_accessed) > timeout) {
			req_del(reqs[i]->net_fd);
		}
	}
}

char *req_addr_to_txt(struct request *req)
{
	static __thread char txt[256];
	char addr_txt[256];
	const char *res;

	res = inet_ntop(AF_INET, &req->peer_addr.sin_addr,
			addr_txt, sizeof(addr_txt));
	snprintf(txt, sizeof(txt), "%15s:%05d", res, ntohs(req->peer_addr.sin_port));

	return txt;
}

void req_add(struct request *req)
{
	logm(INFO, NONE, "New connection: peer: [%s]", req_addr_to_txt(req));
	reqs[req->net_fd] = req;
}

struct request *req_get_from_net_fd(const int fd)
{
	return reqs[fd];
}


