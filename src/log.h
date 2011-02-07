#ifndef __LOG_H__
#define __LOG_H__

#include <stdarg.h>

enum log_flags {
	NONE = 1 << 0,
	ERRNO = 1 << 1,
};
enum log_level {
	CRITICAL,
	ERROR,
	WARN,
	INFO,
	DEBUG,
};

void log_init(void);
void logm(enum log_level ll, enum log_flags f, char *fmt, ...);

#endif /* __LOG_H__ */

