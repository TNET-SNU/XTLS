CC = gcc 
# CFLAGS = -O0 -g
CFLAGS = -O3 -g
# PKA_DIRECTORY = /opt/pka
PKA_DIRECTORY = /opt/pka-debug
OPENSSL_DIR = /opt/openssl-1.0.2
# OPENSSL_DIR = /opt/openssl-3.6

PKA_INC = -I$(PKA_DIRECTORY)/lib -I$(PKA_DIRECTORY)/include
OPENSSL_INC = -I$(OPENSSL_DIR)/include
LOCAL_INC = -Iinclude -Iinclude/pka
INC = $(PKA_INC) $(OPENSSL_INC) $(LOCAL_INC)

CFLAGS += $(INC) -W -Wall -D_GNU_SOURCE

LIBRARY = -L$(OPENSSL_DIR)/lib -Wl,-rpath,$(OPENSSL_DIR)/lib -lcrypto -lpthread -lPKA -lck

# with dpdk
CFLAGS += $(shell pkg-config --cflags libdpdk)
LIBRARY += $(shell pkg-config --libs libdpdk)

SRC_DIR = src
PKA_SRC_DIR = src/pka

SRCS = $(SRC_DIR)/pka_benchmark.c \
	$(SRC_DIR)/helpers.c \
	$(PKA_SRC_DIR)/pka_helper.c

OBJS = $(SRCS:.c=.o)

all: pka_benchmark

pka_benchmark: $(OBJS)
	$(CC) -o $@ $(OBJS) $(LIBRARY)
	rm -f $(OBJS)

clean:
	rm -f $(SRC_DIR)/*.o $(PKA_SRC_DIR)/*.o pka_benchmark *~
