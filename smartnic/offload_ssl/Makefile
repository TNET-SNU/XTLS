# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2014 Intel Corporation

# binary name
APP = ssloff

# directory for third party libraries
THIRD_PARTY_DIR = ./third_party

# all source are stored in SRCS-y
SRCS-y := src/main.c src/fhash.c src/cert.c src/dpdk_io.c src/tcp.c src/ssl.c  \
		  src/ssl_crypto.c src/host.c src/ring.c \
		  $(THIRD_PARTY_DIR)/pka/pka_helper.c \

all: shared
.PHONY: shared static
shared: build/$(APP)-shared
	ln -sf $(APP)-shared build/$(APP)
static: build/$(APP)-static
	ln -sf $(APP)-static build/$(APP)

# PC_FILE := $(shell pkg-config --path libdpdk)
CFLAGS += $(shell pkg-config --cflags libdpdk)

INC = -Iinclude

PKA_DIR = /opt/pka
PKA_INC = -I$(PKA_DIR)/lib -I$(PKA_DIR)/include -I$(THIRD_PARTY_DIR)/pka
PKA_LIB = -L$(PKA_DIR)/lib

OPENSSL_DIR = /opt/openssl-1.0.2
OPENSSL_INC = -I$(OPENSSL_DIR)/include
OPENSSL_LIB = -L$(OPENSSL_DIR)/lib -Wl,-rpath=$(OPENSSL_DIR)/lib

CFLAGS += -std=gnu99 -O0 -g -Wno-deprecated-declarations -DGNU_SOURCE ${INC} ${PKA_INC} ${OPENSSL_INC}
# CFLAGS += -std=gnu99 -O3 -g -Wno-deprecated-declarations -DGNU_SOURCE ${INC} ${PKA_INC} ${OPENSSL_INC}
# CFLAGS += -std=gnu99 -O3 -Wno-deprecated-declarations -DGNU_SOURCE ${INC} ${PKA_INC} ${OPENSSL_INC}

LDFLAGS_SHARED = $(shell pkg-config --libs libdpdk) ${PKA_LIB} ${OPENSSL_LIB} -lssl -lcrypto -ldl -lPKA
LDFLAGS_STATIC = -Wl,-Bstatic $(shell pkg-config --static --libs libdpdk) ${PKA_LIB} ${OPENSSL_LIB} -lssl -lcrypto -ldl -lPKA

build/$(APP)-shared: $(SRCS-y) Makefile $(PC_FILE) | build
	$(CC) $(CFLAGS) $(SRCS-y) -o $@ $(LDFLAGS) $(LDFLAGS_SHARED)

build/$(APP)-static: $(SRCS-y) Makefile $(PC_FILE) | build
	$(CC) $(CFLAGS) $(SRCS-y) -o $@ $(LDFLAGS) $(LDFLAGS_STATIC)

build:
	@mkdir -p $@

.PHONY: clean
clean:
	rm -f build/$(APP) build/$(APP)-static build/$(APP)-shared helper/*.o
	rmdir --ignore-fail-on-non-empty build
