ifeq ($(CRYPTO),gnutls)
DCRYPTO=-DHAVE_GNUTLS
LCRYPTO=gnutls
else
DCRYPTO=
LCRYPTO=crypto
endif

bdsync: bdsync.c
	cc -Wall -g $(DCRYPTO) -o bdsync bdsync.c -l$(LCRYPTO)

tar:
	./maketar.sh

test: bdsync
	./tests.sh
