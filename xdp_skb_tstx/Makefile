# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

XDP_TARGETS  := sockex2_kern
USER_TARGETS := sockex2_user 

LIBBPF_DIR = ../libbpf/src/
COMMON_DIR = ../common

COPY_LOADER := xdp_loader
COPY_STATS  := xdp_stats
EXTRA_DEPS := $(COMMON_DIR)/parsing_helpers.h

include $(COMMON_DIR)/common.mk

