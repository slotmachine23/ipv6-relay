# ipv6-relay Makefile

# Cross-compilation support
CROSS_COMPILE ?=
CC = $(CROSS_COMPILE)gcc

CFLAGS ?= -O2 -g
CFLAGS += -Wall -Wextra -Werror=implicit-function-declaration \
          -Wformat -Werror=format-security -Werror=format-nonliteral \
          -Wmissing-declarations -std=gnu11 -D_GNU_SOURCE

LDFLAGS +=

# Required libraries (libubox removed, libnl-3.0 for netlink)
CFLAGS += $(shell pkg-config --cflags libnl-3.0 libnl-route-3.0 json-c 2>/dev/null)
LIBS = $(shell pkg-config --libs libnl-3.0 libnl-route-3.0 json-c 2>/dev/null) -lresolv

# Source files
SRCS = src/ipv6_relay.c \
       src/compat.c \
       src/config.c \
       src/dhcpv6.c \
       src/ndp.c \
       src/netlink.c \
       src/router.c

OBJS = $(SRCS:.c=.o)
TARGET = ipv6-relay

# Installation directories
PREFIX ?= /usr
BINDIR = $(PREFIX)/sbin
SYSCONFDIR ?= /etc
UNITDIR ?= $(PREFIX)/lib/systemd/system

.PHONY: all clean install install-deb

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET)

install: $(TARGET)
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(TARGET) $(DESTDIR)$(BINDIR)/
	install -d $(DESTDIR)$(SYSCONFDIR)/ipv6-relay
	install -m 644 ipv6-relay.json.example $(DESTDIR)$(SYSCONFDIR)/ipv6-relay/
	install -d $(DESTDIR)$(UNITDIR)
	install -m 644 ipv6-relay@.service $(DESTDIR)$(UNITDIR)/

install-deb: install
	install -d $(DESTDIR)$(SYSCONFDIR)/default

.DEFAULT_GOAL := all