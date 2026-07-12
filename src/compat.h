/*
 * ipv6-relay - Compatibility layer replacing libubox
 * Copyright (C) 2026
 *
 * Licensed under GPLv2
 */

#ifndef _COMPAT_H_
#define _COMPAT_H_

#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <signal.h>

/* === Basic macros === */
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

#ifndef container_of
#define container_of(ptr, type, member) ({ \
	const typeof(((type *)0)->member) *__mptr = (ptr); \
	(type *)((char *)__mptr - offsetof(type, member)); })
#endif

#ifndef __unused
#define __unused __attribute__((unused))
#endif

/* === Simple doubly-linked list (replaces libubox/list.h) === */
struct list_head {
	struct list_head *next;
	struct list_head *prev;
};

#define LIST_HEAD_INIT(name) { &(name), &(name) }

#define LIST_HEAD(name) \
	struct list_head name = LIST_HEAD_INIT(name)

static inline void INIT_LIST_HEAD(struct list_head *list)
{
	list->next = list;
	list->prev = list;
}

static inline void list_add(struct list_head *new, struct list_head *head)
{
	new->next = head->next;
	new->prev = head;
	head->next->prev = new;
	head->next = new;
}

static inline void list_add_tail(struct list_head *new, struct list_head *head)
{
	new->next = head;
	new->prev = head->prev;
	head->prev->next = new;
	head->prev = new;
}

static inline void list_del(struct list_head *entry)
{
	entry->next->prev = entry->prev;
	entry->prev->next = entry->next;
	entry->next = NULL;
	entry->prev = NULL;
}

static inline bool list_empty(const struct list_head *head)
{
	return head->next == head;
}

#define list_for_each_entry(pos, head, member) \
	for (pos = container_of((head)->next, typeof(*pos), member); \
	     &pos->member != (head); \
	     pos = container_of(pos->member.next, typeof(*pos), member))

#define list_for_each_entry_safe(pos, n, head, member) \
	for (pos = container_of((head)->next, typeof(*pos), member), \
	     n = container_of(pos->member.next, typeof(*pos), member); \
	     &pos->member != (head); \
	     pos = n, n = container_of(n->member.next, typeof(*pos), member))

/* === Simple ordered list replacing AVL tree === */
struct avl_node {
	const void *key;
	struct avl_node *next;
	struct avl_node *prev;
};

struct avl_tree {
	struct avl_node *head;
	int (*cmp)(const void *k1, const void *k2);
};

#define AVL_TREE(name, cmp_fn, _a, _b) \
	struct avl_tree name = { .head = NULL, .cmp = cmp_fn }

static inline int avl_strcmp(const void *k1, const void *k2)
{
	return strcmp((const char *)k1, (const char *)k2);
}

static inline struct avl_node *avl_first(struct avl_tree *tree)
{
	return tree->head;
}

static inline struct avl_node *avl_next(struct avl_node *node)
{
	return node->next;
}

#define avl_for_each_element(tree, element, member) \
	for (struct avl_node *_node = (tree)->head; _node != NULL; _node = _node->next) \
		if ((element = container_of(_node, typeof(*element), member)), 1)

#define avl_for_each_element_safe(tree, element, member, tmp) \
	for (struct avl_node *_node = (tree)->head, *_next = NULL; \
	     _node != NULL && (_next = _node->next, 1); \
	     _node = _next) \
		if ((element = container_of(_node, typeof(*element), member)), 1)

#define avl_find_element(tree, _avl_key, element, member) \
	({ \
		typeof(element) _result = NULL; \
		struct avl_node *_node; \
		for (_node = (tree)->head; _node != NULL; _node = _node->next) { \
			if ((tree)->cmp(_node->key, _avl_key) == 0) { \
				_result = container_of(_node, typeof(*(element)), member); \
				break; \
			} \
		} \
		_result; \
	})

static inline void avl_insert(struct avl_tree *tree, struct avl_node *new_node)
{
	struct avl_node *node, *prev = NULL;

	for (node = tree->head; node != NULL; prev = node, node = node->next) {
		if (tree->cmp(new_node->key, node->key) < 0)
			break;
	}

	new_node->next = node;
	new_node->prev = prev;

	if (prev)
		prev->next = new_node;
	else
		tree->head = new_node;

	if (node)
		node->prev = new_node;
}

static inline void avl_delete(struct avl_tree *tree, struct avl_node *node)
{
	if (node->prev)
		node->prev->next = node->next;
	else
		tree->head = node->next;

	if (node->next)
		node->next->prev = node->prev;

	node->next = NULL;
	node->prev = NULL;
}

/* === uloop replacement using epoll === */
struct uloop_fd {
	int fd;
	void (*cb)(struct uloop_fd *u, unsigned int events);
	bool error;
	bool registered;
};

struct uloop_timeout {
	struct timespec deadline;
	void (*cb)(struct uloop_timeout *t);
	int timerfd;
	bool pending;
};

struct uloop_signal {
	int signo;
	void (*cb)(struct uloop_signal *s);
};

#define ULOOP_READ		EPOLLIN
#define ULOOP_WRITE		EPOLLOUT
#define ULOOP_EDGE_TRIGGER	EPOLLET
#define ULOOP_ERROR_CB		0x10

/* uloop API */
int uloop_init(void);
void uloop_done(void);
int uloop_run(void);
void uloop_end(void);

int uloop_fd_add(struct uloop_fd *sock, unsigned int flags);
int uloop_fd_delete(struct uloop_fd *sock);

int uloop_timeout_add(struct uloop_timeout *timeout);
int uloop_timeout_set(struct uloop_timeout *timeout, int msecs);
int uloop_timeout_cancel(struct uloop_timeout *timeout);
int uloop_timeout_remaining(struct uloop_timeout *timeout);

int uloop_signal_add(struct uloop_signal *s);

/* === utils replacement === */
/*
 * calloc_a(size, [void **ptr, size_t extra_len, ...], NULL)
 *
 * Allocates a single zeroed buffer of (size + sum of extra_len) bytes,
 * returns a pointer to the start, and writes sub-region pointers into each
 * caller-supplied void** variable.  Mirrors the libubox calloc_a() API.
 */
static inline void *calloc_a(size_t len, ...)
{
	void **arg;
	void *buf;
	char *ptr;
	size_t total = len;
	va_list ap;

	/* First pass: sum up total allocation size */
	va_start(ap, len);
	while ((arg = va_arg(ap, void **)) != NULL) {
		size_t l = va_arg(ap, size_t);
		total += l;
	}
	va_end(ap);

	buf = calloc(1, total);
	if (!buf)
		return NULL;

	ptr = (char *)buf + len;

	/* Second pass: assign sub-region pointers to caller's variables */
	va_start(ap, len);
	while ((arg = va_arg(ap, void **)) != NULL) {
		size_t l = va_arg(ap, size_t);
		*arg = ptr;
		ptr += l;
	}
	va_end(ap);

	return buf;
}

#endif /* _COMPAT_H_ */