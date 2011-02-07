#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "string.h"

struct string *string_new(const char *str)
{
	struct string *s;
	size_t len;

	len = strlen(str);
	
	s = malloc(sizeof(*s) + len);
	if (!s)
		return NULL;
	s->len = len;
	s->null_terminated = true;
	strcpy(s->str, str);
	
	return s;
}
