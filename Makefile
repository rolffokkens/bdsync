bdsync: bdsync.c
	cc -Wall -g -o bdsync bdsync.c -lcrypto

tar:
	./maketar.sh

test: bdsync
	./tests.sh
