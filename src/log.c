#include "log.h"
#include <stdarg.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

static FILE *log_file;
static enum log_level cur_log_level;

void log_init(void)
{
	log_file = stderr;
	cur_log_level = WARN;
}

void logm(enum log_level ll, enum log_flags f, char *fmt, ...)
{
	va_list a;

	if (ll < cur_log_level)
		return;

	va_start(a, fmt);
	vfprintf(log_file, fmt, a);
	va_end(a);
	if (f & ERRNO) {
		char buf[256];
		strerror_r(errno, buf, sizeof(buf));
		fprintf(log_file, " errno=\"%s\"", buf);
	}
	fputc('\n', log_file);
}
