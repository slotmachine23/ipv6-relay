# ipv6-relay Makefile

# Cross-compilation support
CROSS_COMPILE ?=
CC = $(CROSS_COMPILE)gcc

# Build output directory
BUILD_DIR ?= build

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

# Object files inside build directory
OBJS = $(patsubst src/%.c,$(BUILD_DIR)/%.o,$(SRCS))
TARGET = $(BUILD_DIR)/ipv6-relay

# Installation directories
PREFIX ?= /usr
BINDIR = $(PREFIX)/sbin
SYSCONFDIR ?= /etc
UNITDIR ?= $(PREFIX)/lib/systemd/system

.PHONY: all clean install install-deb check-cross

# Detect broken cross-compilation environments early
ifeq ($(CROSS_COMPILE),)
  # Native build — no extra checks needed
else
  SYSROOT := $(shell $(CC) -print-sysroot 2>/dev/null)
  SYSROOT_TIME_H := $(wildcard $(SYSROOT)/usr/include/time.h)
  ifeq ($(SYSROOT_TIME_H),)
    SYSROOT_TIME_H := $(wildcard $(SYSROOT)/include/time.h)
  endif
  ifeq ($(SYSROOT_TIME_H),)
    $(error Cross-compiler sysroot is missing C library headers (e.g. time.h). \
            Sysroot path: $(SYSROOT). \
            Please install the matching aarch64 glibc/sysroot package for your distribution, \
            or point SYSROOT to a valid root filesystem with: make CROSS_COMPILE=$(CROSS_COMPILE) SYSROOT=/path/to/rootfs)
  endif
  # Pass sysroot through if the user provided one
  ifdef SYSROOT
    CFLAGS += --sysroot=$(SYSROOT)
    LDFLAGS += --sysroot=$(SYSROOT)
  endif
endif

all: $(TARGET)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

$(BUILD_DIR)/%.o: src/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -rf $(BUILD_DIR)

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