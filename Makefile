ifeq ($(CRYPTO),gnutls)
CRYPTO_DEF=-DHAVE_GNUTLS
CRYPTO_LDFLAGS=-lgnutls
else
CRYPTO_DEF=
CRYPTO_LDFLAGS=-lcrypto
endif
CFLAGS=-O3

bdsync: bdsync.c checkzero.c
	$(CC) -Wall $(CFLAGS) $(CRYPTO_DEF) -o bdsync bdsync.c checkzero.c $(CRYPTO_LDFLAGS)

tar:
	./maketar.sh

test: bdsync
	./tests.sh

clean:
	rm -f bdsync
