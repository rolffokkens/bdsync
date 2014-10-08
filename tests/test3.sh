#!/bin/bash

echo test1a > /tmp/LOCDEV
echo test1  > /tmp/REMDEV

md5sum /tmp/LOCDEV /tmp/REMDEV

./bdsync --diffsize --remdata "./bdsync -s" /tmp/LOCDEV /tmp/REMDEV > /tmp/DEV.bdsync1
./bdsync --diffsize           "./bdsync -s" /tmp/REMDEV /tmp/LOCDEV > /tmp/DEV.bdsync2

md5sum /tmp/DEV.bdsync1 /tmp/DEV.bdsync2

./bdsync --diffsize --patch < /tmp/DEV.bdsync1

md5sum /tmp/LOCDEV /tmp/REMDEV
