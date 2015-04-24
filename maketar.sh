#!/bin/bash

TDIR=`mktemp -d /tmp/bdsync-XXXXXX`

. VERSION

mkdir $TDIR/bdsync-$VERSION

for i in maketar.sh Makefile bdsync.c bdsync-hash.h README.md VERSION COPYING bdsync.1 bdsync.spec
do
   cp $i $TDIR/bdsync-$VERSION
done

( cd $TDIR
  tar c bdsync-${VERSION} ) \
 | gzip > bdsync-${VERSION}.tgz
