#ifndef __HANDLER_H__
#define __HANDLER_H__

struct request;

struct handler {
	int (*main)(struct request *);
	void (*cleanup)(struct request *);
};

#endif /* __HANDLER_H__ */
