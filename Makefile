ifeq ($(CRYPTO),gnutls)
CRYPTOFLAGS=-DHAVE_GNUTLS -lgnutls
else
CRYPTOFLAGS=-lcrypto
endif
CFLAGS=-O3

bdsync: bdsync.c checkzero.c
	cc -Wall $(CFLAGS) $(CRYPTOFLAGS) -o bdsync bdsync.c checkzero.c

tar:
	./maketar.sh

test: bdsync
	./tests.sh

clean:
	rm -f bdsync
