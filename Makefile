bdsync: bdsync.c
	cc -g -o bdsync bdsync.c -lcrypto

tar:
	./maketar.sh
