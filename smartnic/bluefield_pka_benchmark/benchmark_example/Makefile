CC = gcc -O0 -g
PKA_DIRECTORY = /home/seongjong/pka
OPENSSL_DIR = /opt/openssl-1.0.2

PKA_INC = -I$(PKA_DIRECTORY)/lib -I$(PKA_DIRECTORY)/include
OPENSSL_INC = -I$(OPENSSL_DIR)/include
INC = $(PKA_INC) $(OPENSSL_INC)

LIBRARY = -L$(OPENSSL_DIR)/lib -Wl,-rpath,$(OPENSSL_DIR)/lib -lcrypto -lpthread -lPKA

all: pka_benchmark

pka_benchmark: pka_benchmark.c
	$(CC) -W -Wall $(INC) -o pka_benchmark pka_benchmark.c helper/pka_helper.c -D_GNU_SOURCE $(LIBRARY)

clean:
	rm -f *~ *.o helper/*~ helper/*.o pka_benchmark
