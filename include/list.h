#ifndef __LIST_H__
#define __LIST_H__

struct list {
	struct list *prev, *next;
};

static inline int list_empty(struct list *l)
{
	return l->next == l;
}
static inline void list_init(struct list *n)
{
	n->next = n;
	n->prev = n;
}

static inline void list_del(struct list *n)
{
	n->next->prev = n->prev;
	n->prev->next = n->next;
}

static inline void list_add(struct list *l, struct list *n)
{
	n->next = l->next;
	n->next->prev = n;
	l->next = n;
	n->prev = l;
}

#undef offsetof
#ifdef __compiler_offsetof
#define offsetof(TYPE,MEMBER) __compiler_offsetof(TYPE,MEMBER)
#else
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

#define container_of(ptr, type, member) ({			\
	const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
	(type *)( (char *)__mptr - offsetof(type,member) );})


#define list_foreach_safe(type, e, list_head, member) do {\
	struct list *__l; \
	struct list *__next; \
	for (__l = ((list_head)->next); __l != (list_head); __l = __next) { \
		__next = __l->next; \
		type *e = container_of(__l, type, member);

#define list_foreach(type, e, list_head, member) do {\
	struct list *__l; \
	for (__l = ((list_head)->next); __l != (list_head); __l = __l->next) { \
		type *e = container_of(__l, type, member);

#define end_list_foreach } } while (0);

#endif /* __LIST_H__ */
