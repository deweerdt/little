#include <string.h>

#include "list.h"
#include "murmurhash3.h"


typedef uint32_t (*hash_hashing_fn)(void *);
typedef int (*hash_cmp_fn)(void *, void *);

struct hash;
struct hash *hash_new(unsigned int size, hash_hashing_fn hash, hash_cmp_fn cmp);
void *hash_put(struct hash *h, void *k);
void *hash_get(struct hash *h, void *k);
void hash_free(struct hash *h, void (*free_fn)(void *));


struct hash *string_hash_new(unsigned int size);
void *string_hash_put(struct hash *h, char *key, void *value);
void *string_hash_get(struct hash *h, char *key);
void string_hash_free(struct hash *h);
