#include "log.h"
#include <stdarg.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

static FILE *log_file;
enum log_level log_level;

void log_init(void)
{
	log_file = stderr;
	log_level = INFO;
}

void logm(enum log_level ll, enum log_flags f, char *fmt, ...)
{
	va_list a;

	if (ll < log_level)
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
