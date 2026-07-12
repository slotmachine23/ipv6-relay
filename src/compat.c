/*
 * ipv6-relay - Compatibility layer replacing libubox
 * Copyright (C) 2026
 *
 * Licensed under GPLv2
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <sys/signalfd.h>

#include "compat.h"

static int epoll_fd = -1;
static int signal_fd = -1;
static volatile bool uloop_cancelled = false;

/* Signal handling */
static struct uloop_signal *signal_handlers[32] = {NULL};

/*
 * epoll data.ptr tagging scheme:
 *   bit 0 == 0  →  struct uloop_fd *   (regular I/O fd)
 *   bit 0 == 1  →  struct uloop_timeout * (timerfd), strip bit before use
 *   ptr == &signal_sentinel  →  signalfd event
 */
#define TIMEOUT_TAG    ((uintptr_t)1)
#define is_timeout_ptr(p)    ((uintptr_t)(p) & TIMEOUT_TAG)
#define timeout_to_ptr(t)    ((void *)((uintptr_t)(t) | TIMEOUT_TAG))
#define ptr_to_timeout(p)    ((struct uloop_timeout *)((uintptr_t)(p) & ~TIMEOUT_TAG))

static char signal_sentinel; /* unique address used as signalfd marker */

int uloop_init(void)
{
	epoll_fd = epoll_create1(EPOLL_CLOEXEC);
	if (epoll_fd < 0)
		return -1;

	/* Block signals we want to handle via signalfd */
	sigset_t mask;
	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);
	sigaddset(&mask, SIGHUP);
	sigprocmask(SIG_BLOCK, &mask, NULL);

	/* Create signalfd and watch it in epoll */
	signal_fd = signalfd(-1, &mask, SFD_CLOEXEC | SFD_NONBLOCK);
	if (signal_fd < 0) {
		close(epoll_fd);
		epoll_fd = -1;
		return -1;
	}

	struct epoll_event ev = {
		.events  = EPOLLIN,
		.data.ptr = &signal_sentinel,
	};
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, signal_fd, &ev) < 0) {
		close(signal_fd); signal_fd = -1;
		close(epoll_fd);  epoll_fd  = -1;
		return -1;
	}

	uloop_cancelled = false;
	return 0;
}

void uloop_done(void)
{
	if (signal_fd >= 0) {
		close(signal_fd);
		signal_fd = -1;
	}

	if (epoll_fd >= 0) {
		close(epoll_fd);
		epoll_fd = -1;
	}

	/* Unblock signals */
	sigset_t mask;
	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);
	sigaddset(&mask, SIGHUP);
	sigprocmask(SIG_UNBLOCK, &mask, NULL);
}

int uloop_fd_add(struct uloop_fd *sock, unsigned int flags)
{
	struct epoll_event ev = {
		.events = 0,
		.data.ptr = sock,
	};

	if (flags & ULOOP_READ)
		ev.events |= EPOLLIN;
	if (flags & ULOOP_WRITE)
		ev.events |= EPOLLOUT;
	if (flags & ULOOP_EDGE_TRIGGER)
		ev.events |= EPOLLET;

	int op = sock->registered ? EPOLL_CTL_MOD : EPOLL_CTL_ADD;
	if (epoll_ctl(epoll_fd, op, sock->fd, &ev) < 0)
		return -1;

	sock->registered = true;
	sock->error = false;
	return 0;
}

int uloop_fd_delete(struct uloop_fd *sock)
{
	if (!sock->registered)
		return 0;

	epoll_ctl(epoll_fd, EPOLL_CTL_DEL, sock->fd, NULL);
	sock->registered = false;
	return 0;
}

static int update_timer(struct uloop_timeout *timeout)
{
	if (timeout->timerfd < 0) {
		timeout->timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
		if (timeout->timerfd < 0)
			return -1;

		/* Register the new timerfd with epoll using tagged ptr */
		struct epoll_event ev = {
			.events   = EPOLLIN,
			.data.ptr = timeout_to_ptr(timeout),
		};
		if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, timeout->timerfd, &ev) < 0) {
			close(timeout->timerfd);
			timeout->timerfd = -1;
			return -1;
		}
	}

	struct itimerspec its = {0};
	if (timeout->pending) {
		its.it_value = timeout->deadline;
		/* Convert absolute timespec to relative */
		struct timespec now;
		clock_gettime(CLOCK_MONOTONIC, &now);
		if (its.it_value.tv_sec < now.tv_sec ||
		    (its.it_value.tv_sec == now.tv_sec && its.it_value.tv_nsec < now.tv_nsec)) {
			its.it_value.tv_sec = 0;
			its.it_value.tv_nsec = 1;
		} else {
			its.it_value.tv_sec -= now.tv_sec;
			if (its.it_value.tv_nsec < now.tv_nsec) {
				its.it_value.tv_sec--;
				its.it_value.tv_nsec += 1000000000;
			}
			its.it_value.tv_nsec -= now.tv_nsec;
		}
	}

	return timerfd_settime(timeout->timerfd, 0, &its, NULL);
}

int uloop_timeout_add(struct uloop_timeout *timeout)
{
	if (!timeout->cb)
		return -1;

	timeout->pending = true;
	return update_timer(timeout);
}

int uloop_timeout_set(struct uloop_timeout *timeout, int msecs)
{
	if (!timeout->cb)
		return -1;

	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);

	timeout->deadline.tv_sec = now.tv_sec + msecs / 1000;
	timeout->deadline.tv_nsec = now.tv_nsec + (msecs % 1000) * 1000000;
	if (timeout->deadline.tv_nsec >= 1000000000) {
		timeout->deadline.tv_sec++;
		timeout->deadline.tv_nsec -= 1000000000;
	}

	timeout->pending = true;
	return update_timer(timeout);
}

int uloop_timeout_cancel(struct uloop_timeout *timeout)
{
	if (!timeout->pending)
		return -1;

	timeout->pending = false;
	return update_timer(timeout);
}

int uloop_timeout_remaining(struct uloop_timeout *timeout)
{
	if (!timeout->pending)
		return -1;

	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);

	int msecs = (timeout->deadline.tv_sec - now.tv_sec) * 1000 +
		    (timeout->deadline.tv_nsec - now.tv_nsec) / 1000000;

	return msecs > 0 ? msecs : 0;
}

int uloop_signal_add(struct uloop_signal *s)
{
	if (s->signo < 0 || s->signo >= (int)(sizeof(signal_handlers)/sizeof(signal_handlers[0])))
		return -1;

	signal_handlers[s->signo] = s;

	/* Re-create the signalfd so it covers the newly registered signal.
	 * The signal must already be blocked (uloop_init blocks the standard set).
	 * For other signals, block them now. */
	sigset_t mask;
	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);
	sigaddset(&mask, SIGHUP);
	sigaddset(&mask, s->signo);
	sigprocmask(SIG_BLOCK, &mask, NULL);

	if (signal_fd >= 0) {
		signalfd(signal_fd, &mask, SFD_NONBLOCK);
	}

	return 0;
}

int uloop_run(void)
{
	struct epoll_event events[16];

	while (!uloop_cancelled) {
		int nfds = epoll_wait(epoll_fd, events, 16, -1);
		if (nfds < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}

		for (int i = 0; i < nfds; i++) {
			void *ptr = events[i].data.ptr;

			if (ptr == &signal_sentinel) {
				/* Read all pending signals and dispatch handlers */
				struct signalfd_siginfo si;
				while (read(signal_fd, &si, sizeof(si)) == sizeof(si)) {
					unsigned signo = si.ssi_signo;
					if (signo == SIGINT || signo == SIGTERM) {
						uloop_cancelled = true;
					} else if (signo < sizeof(signal_handlers)/sizeof(signal_handlers[0]) &&
						   signal_handlers[signo]) {
						signal_handlers[signo]->cb(signal_handlers[signo]);
					}
				}
			} else if (is_timeout_ptr(ptr)) {
				/* timerfd fired */
				struct uloop_timeout *t = ptr_to_timeout(ptr);
				/* Drain the timerfd */
				uint64_t exp;
				read(t->timerfd, &exp, sizeof(exp));
				if (t->pending && t->cb) {
					t->pending = false;
					t->cb(t);
				}
			} else if (ptr) {
				/* Regular I/O fd */
				struct uloop_fd *fd = ptr;
				if (fd->cb)
					fd->cb(fd, events[i].events);
			}
		}
	}

	return 0;
}

void uloop_end(void)
{
	uloop_cancelled = true;
}