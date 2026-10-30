# SPDX-License-Identifier: GPL-2.0-only
#
# Makefile for the rswap page-hash userspace tool
#
# Targets:
#   user          - compile the userspace program
#   clean         - remove generated files
#
# Required packages:
#   - libssl-dev
#
# The eBPF prototype and kernel test module are intentionally not built while
# that design is postponed.

CC          ?= cc
RM          ?= rm -f

CFLAGS      ?= -g -O2 -Wall -Wextra
LDLIBS      := -lcrypto

# ------------------------------------------------------------------
#  Targets
# ------------------------------------------------------------------

.PHONY: all user clean

all: user

user: page_hash_user

clean:
	$(RM) page_hash_user

# ------------------------------------------------------------------
#  Userspace program
# ------------------------------------------------------------------

page_hash_user: page_hash_user.c page_hash.h
	$(CC) $(CFLAGS) -I. -o $@ $< $(LDLIBS)
