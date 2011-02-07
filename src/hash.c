#include "hash.h"

struct hash_elem {
	void *data;
	struct list l;
};
struct hash {
	hash_hashing_fn hash;
	hash_cmp_fn cmp;
	unsigned int size;
	struct list buckets[0];
};


struct hash *hash_new(unsigned int size, hash_hashing_fn hash, hash_cmp_fn cmp)
{
	struct hash *h;
	unsigned int i;

	h = malloc(sizeof(*h) + sizeof(h->buckets[0]) * size);
	if (!h)
		return NULL;

	h->hash = hash;
	h->cmp = cmp;
	h->size = size;

	for (i = 0; i < size; i++) {
		list_init(&h->buckets[i]);
	}
	return h;
}

void hash_free(struct hash *h, void (*free_fn)(void *))
{
	unsigned int i;

	for (i = 0; i < h->size; i++) {
		list_foreach_safe(struct hash_elem, e, &h->buckets[i], l)
			if (free_fn)
				free_fn(e->data);
			free(e);
		end_list_foreach
	}

	free(h);
}

void *hash_put(struct hash *h, void *e)
{
	struct hash_elem *el;
	unsigned int bucket_index;

	bucket_index = h->hash(e) % h->size;

	el = malloc(sizeof(*el));
	if (!el)
		return NULL;

	el->data = e;

	list_init(&el->l);
	list_add(&h->buckets[bucket_index], &el->l);

	return el;
}

void *hash_get(struct hash *h, void *k)
{
	unsigned int bucket_index;

	bucket_index = h->hash(k) % h->size;
	if (list_empty(&h->buckets[bucket_index]))
		return NULL;

	list_foreach(struct hash_elem, e, &h->buckets[bucket_index], l)
		if (!h->cmp(e->data, k)) {
			return e->data;
		}
	end_list_foreach

	return NULL;
}

struct string_hash_elem {
	char *key;
	void *value;
};

static int string_hash_cmp(void *a1, void *a2)
{
	struct string_hash_elem *e1 = a1;
	struct string_hash_elem *e2 = a2;
	
	return strcmp(e1->key, e2->key);
}

static uint32_t string_hash_hash(void *a)
{
	char *s = a;
	uint32_t hash;

	MurmurHash3_x86_32(s, strlen(s), 0x132efef1, &hash);

	return hash;
}

struct hash *string_hash_new(unsigned int size)
{
	return hash_new(size, string_hash_hash, string_hash_cmp);	
}

void *string_hash_put(struct hash *h, char *key, void *value)
{
	struct string_hash_elem *e;

	e = malloc(sizeof(*e));
	if (!e)
		return NULL;

	e->key = key;
	e->value = value;

	return hash_put(h, e);
}

void *string_hash_get(struct hash *h, char *key)
{
	struct string_hash_elem e;
	struct string_hash_elem *res;

	e.key = key;

	res = hash_get(h, &e);
	if (!res)
		return NULL;

	return res->value;
}

static void string_hash_elem_free(void *e)
{
	free(e);
}

void string_hash_free(struct hash *h)
{
	hash_free(h, string_hash_elem_free);	
}
