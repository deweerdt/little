#ifndef __STRING_H__
#define __STRING_H__

#include <stdbool.h>
#include <stdio.h>

struct string {
	char *str;
	size_t len;
	bool null_terminated;
};

static inline char *string_charstar(struct string *s)
{
	return s->str;
}

#endif /* __STRING_H__ */
