#!/bin/bash

. `dirname "$0"`/testlib.sh

do_check ()
{
    local TDIR="$1"
    local TMPF="$TDIR/t1"

    local LOCDEV="$TDIR/LOCDEV"
    local REMDEV="$TDIR/REMDEV"
    local BDSYNC1="$TDIR/DEV.bdsync1"

    cre_sparse_file $LOCDEV 8k
    cre_sparse_file $REMDEV 8k

    printf "\x80" | overwrite_file $LOCDEV $((4*1024-1))

    MD5LOC1=`get_md5 $LOCDEV`
    MD5REM1=`get_md5 $REMDEV`

    check_sum "Bad checksum MD5LOC1" "$MD5LOC1" "2794e9a60991db07ed9f351e7e790587"
    check_sum "Bad checksum MD5REM1" "$MD5REM1" "0829f71740aab1ab98b33eae21dee122"

    ./bdsync --diffsize=resize --zeroblocks --flushcache "./bdsync --server" $LOCDEV $REMDEV > $BDSYNC1

    MD5BD1=`get_md5 $BDSYNC1`

    ./bdsync --diffsize=resize --patch < $BDSYNC1 2> "$TMPF" || abort_msg "bdsync (3) failed"

    MD5LOC2=`get_md5 $LOCDEV`
    MD5REM2=`get_md5 $REMDEV`

    check_sum "Bad checksum MD5LOC2" "$MD5LOC2" "$MD5LOC1"
    check_sum "Bad checksum MD5REM2" "$MD5REM2" "$MD5LOC1"
}

handle_check do_check "Make sure bug https://github.com/rolffokkens/bdsync/issues/39 doesn't rear it's head ever again."
