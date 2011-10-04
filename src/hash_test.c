#include <assert.h>
#include <stdio.h>
#include "little.h"
#include "hash.h"

int main(void)
{
	unsigned int i, j;
	struct {
		char *key;
		long value;
	} key_val[] = {	{ "1", 1 },
			{ "2", 2 },
			{ "3", 3 },
			{ "4", 4 },
			{ "5", 5 },
			{ "6", 6 },
			{ "7", 7 },
			{ "8", 8 },
			{ "9", 9 },
			{ "10", 10 },
			{ "11", 11 },
			{ "12", 12 },
			{ "13", 13 },
			{ "14", 14 },
			{ "15", 15 },
			{ "16", 16 },
			{ "17", 17 },
			{ "18", 18 },
			{ "19", 19 } };
	int sizes[] = { 1, 2, 4, 5, 7, 8, 64, 1024 };

	for (i = 0; i < ARRAY_SIZE(sizes); i++) {
		struct hash *h;
		h = string_hash_new(sizes[i]);
		for (j = 0; j < ARRAY_SIZE(key_val); j++) {
			long v;
			string_hash_put(h, key_val[j].key, (void *)key_val[j].value);
			v = (long)string_hash_get(h, key_val[j].key);
			if (v != key_val[j].value) {
				fprintf(stderr, "%ld != %ld\n", v, key_val[j].value);
				assert(0);
			}
		}
		for (j = 0; j < ARRAY_SIZE(key_val); j++) {
			long v;
			v = (long)string_hash_get(h, key_val[j].key);
			if (v != key_val[j].value) {
				fprintf(stderr, "%ld != %ld\n", v, key_val[j].value);
				assert(0);
			}
		}
		string_hash_free(h);
	}

	return 0;
}
