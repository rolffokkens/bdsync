ifeq ($(CRYPTO),gnutls)
CRYPTO_DEF=-DHAVE_GNUTLS
CRYPTO_LDFLAGS=-lgnutls
else
CRYPTO_DEF=
CRYPTO_LDFLAGS=-lcrypto
endif
CFLAGS=-O3

all: bdsync bdsync.1

bdsync.txt.2: bdsync.txt
ifndef OS
	sed 's/\(.*\)/"\1\\n"/g' bdsync.txt > bdsync.txt.2
else
	sed 's/\(.*\)\r/"\1\\r\\n"/g' bdsync.txt > bdsync.txt.2
endif

bdsync: bdsync.c checkzero.c bdsync.txt.2
	$(CC) -Wall $(CFLAGS) $(CRYPTO_DEF) -o bdsync bdsync.c checkzero.c $(CRYPTO_LDFLAGS)

bdsync.1: README.md
	pandoc -s -t man README.md -o bdsync.1

tar:
	./maketar.sh

test: bdsync
	./tests.sh

clean:
	rm -f bdsync bdsync.txt.2 bdsync.1
