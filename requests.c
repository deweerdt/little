#include "little.h"
#include "requests.h"
#include <stdlib.h>
#include <unistd.h>

#include <openssl/bio.h>

static struct request **reqs;

int req_init()
{
	reqs = calloc(1, sizeof(struct request *) * sysconf(_SC_OPEN_MAX));
	return !!reqs;
}

void req_del(int fd)
{
	if (reqs[fd]->is_binary) {
		BIO_free_all(reqs[fd]->bio_fd);

	}
	if (reqs[fd]->fs_fd > 0)
		close(reqs[fd]->fs_fd);
	close(reqs[fd]->net_fd);
	free(reqs[fd]->request);
	free(reqs[fd]);
	reqs[fd] = NULL;
}

void req_garbage_collect(time_t now, int timeout)
{
	unsigned int i;

	for (i=0; i < ARRAY_SIZE(reqs); i++) {
		if (reqs[i]
		    && difftime(now, reqs[i]->last_accessed) > timeout) {
			req_del(reqs[i]->net_fd);
		}
	}
}

void req_add(struct request *req)
{
	reqs[req->net_fd] = req;
}

struct request *req_get_from_net_fd(const int fd)
{
	return reqs[fd];
}


