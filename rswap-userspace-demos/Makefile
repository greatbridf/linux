# SPDX-License-Identifier: GPL-2.0-only
#
# Makefile for rswap page-hash userspace demo
#
# Targets:
#   all           - build BPF program + userspace program + kernel module
#   bpf           - compile page_hash_kern.bpf.c -> page_hash_kern.bpf.o
#   user          - compile the userspace program
#   module        - build the kernel test module (requires prepared kernel tree)
#   clean         - remove generated files
#
# Required packages:
#   - clang (with BPF target support)
#   - libssl-dev (libcrypto)
#   - libelf-dev
#   - libz-dev
#   - libbpf (development headers and shared library)

CLANG       ?= clang
CC          ?= gcc
RM          ?= rm -f

BPF_TARGET  := bpf
BPF_ARCH    := $(shell uname -m | sed -e s/x86_64/x86/ -e s/aarch64/arm64/)

# Kernel source tree (assumes this Makefile lives under the kernel tree).
KERNEL_DIR  := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/..)
TOOLS_DIR   := $(KERNEL_DIR)/tools

# libbpf headers (in-kernel-tree or system-wide).
# If your distro ships libbpf-dev you can use -I/usr/include.
LIBBPF_INC  := -I$(TOOLS_DIR)/lib        \
               -I$(TOOLS_DIR)/include/uapi \
               -I$(TOOLS_DIR)/include

# BPF program include paths (minimal -- we define helpers inline)
BPF_INCLUDES := -I.

# BPF compilation flags
BPF_CFLAGS := -g -O2 -Wall -Werror                         \
              -D__TARGET_ARCH_$(BPF_ARCH)                   \
              -fno-strict-aliasing                          \
              -fno-asynchronous-unwind-tables               \
              -Wno-compare-distinct-pointer-types           \
              -Wno-initializer-overrides                    \
              -fms-extensions                               \
              $(BPF_INCLUDES)

# Userspace program flags
USER_CFLAGS := -g -O2 -Wall                                \
               -I.                                          \
               $(LIBBPF_INC)

USER_LDLIBS := -lssl -lcrypto -lelf -lz -lbpf

# Kernel module build (external module against this kernel tree).
KERNEL_BUILD := $(KERNEL_DIR)
KBUILD_EXTRA := KBUILD_MODPOST_WARN=1

# ------------------------------------------------------------------
#  Targets
# ------------------------------------------------------------------

.PHONY: all bpf user module module_clean clean dist_clean

all: bpf user module

bpf: page_hash_kern.bpf.o

user: page_hash_user

module: page_hash_test_mod.ko

clean:
	$(RM) -f page_hash_kern.bpf.o page_hash_user
	$(MAKE) -C $(KERNEL_BUILD) M=$(CURDIR) $(KBUILD_EXTRA) clean 2>/dev/null || true
	$(RM) -f *.o *.ko *.mod.c *.mod *.symvers *.order

dist_clean: clean
	$(RM) -f .*.cmd *.o.d

# ------------------------------------------------------------------
#  BPF program (compiled with clang --target=bpf)
# ------------------------------------------------------------------

page_hash_kern.bpf.o: page_hash_kern.bpf.c page_hash.h
	$(CLANG) --target=$(BPF_TARGET) $(BPF_CFLAGS)        \
		-c $< -o $@

# ------------------------------------------------------------------
#  Userspace program
# ------------------------------------------------------------------

page_hash_user: page_hash_user.c page_hash.h
	$(CC) $(USER_CFLAGS) -o $@ $< $(USER_LDLIBS)

# ------------------------------------------------------------------
#  Kernel test module (built against the kernel tree)
# ------------------------------------------------------------------

# The Kbuild file (Kbuild) specifies the module object.  The kernel
# build system handles the rest.
page_hash_test_mod.ko: page_hash_test_mod.c page_hash.h | $(KERNEL_BUILD)
	$(MAKE) -C $(KERNEL_BUILD) M=$(CURDIR) $(KBUILD_EXTRA) modules
