# binary name
APP = build/ssl_server

# directory for third party libraries
THIRD_PARTY_DIR = ./third_party

# all source are stored in SRCS-y
SRCS-y = src/main.c src/helpers.c src/fhash.c src/set_sock.c src/meta_pkt.c src/mempool.c src/multiplex_io.c \



CC = gcc
# CFLAGS = -O0 -g -Wall -Werror
# CFLAGS = -O3 -g -Wall -Werror
CFLAGS = -O3 -Wall -Werror

INC = -Iinclude

CFLAGS += -std=gnu99 ${INC}
# LDFLAGS = 

all: $(APP)

$(APP): $(SRCS-y) | build
	$(CC) $(CFLAGS) -o $(APP) $(SRCS-y) $(LDFLAGS)

build:
	mkdir -p build

clean:
	rm -f $(APP)