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
static volatile bool uloop_cancelled = false;

/* Signal handling */
static struct uloop_signal *signal_handlers[32] = {NULL};

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

	uloop_cancelled = false;
	return 0;
}

void uloop_done(void)
{
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

static void dispatch_signals(void)
{
	for (size_t i = 0; i < sizeof(signal_handlers)/sizeof(signal_handlers[0]); i++) {
		if (signal_handlers[i]) {
			signal_handlers[i]->cb(signal_handlers[i]);
		}
	}
}

int uloop_signal_add(struct uloop_signal *s)
{
	if (s->signo < 0 || s->signo >= (int)(sizeof(signal_handlers)/sizeof(signal_handlers[0])))
		return -1;

	signal_handlers[s->signo] = s;
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

			/* Check if this is a uloop_fd */
			if (ptr) {
				struct uloop_fd *fd = ptr;

				/* Check for timerfd */
				if (fd->cb) {
					fd->cb(fd, events[i].events);
				}
			}
		}

		/* Dispatch any pending signals */
		dispatch_signals();
	}

	return 0;
}

void uloop_end(void)
{
	uloop_cancelled = true;
}