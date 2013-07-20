bdsync: bdsync.c
	cc -g -Wall -o bdsync bdsync.c -lcrypto

tar:
	./maketar.sh
