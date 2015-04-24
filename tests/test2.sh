#!/bin/bash

. `dirname "$0"`/testlib.sh

do_check ()
{
    local TDIR="$1"
    local TMPF="$TDIR/t1"

    local LOCDEV="$TDIR/LOCDEV"
    local REMDEV="$TDIR/REMDEV"
    local BDSYNC1="$TDIR/DEV.bdsync1"
    local BDSYNC2="$TDIR/DEV.bdsync2"

    dd if=/dev/zero of=$LOCDEV bs=1024 count=1024 2>/dev/null
    dd if=/dev/zero of=$REMDEV bs=1024 count=1024 2>/dev/null

    echo test | dd of=$LOCDEV ibs=1 seek=512 obs=1 conv=notrunc 2>/dev/null

    MD5LOC1=`get_md5 $LOCDEV`
    MD5REM1=`get_md5 $REMDEV`

    check_sum "Bad checksum MD5LOC1" "$MD5LOC1" "e2f88f4b89678325b1ad20ddbc0b9fe6"
    check_sum "Bad checksum MD5REM1" "$MD5REM1" "b6d81b360a5672d80c27430f39153e2c"

    ./bdsync --fixedsalt --checksum md5 --remdata     "./bdsync -s -v" $LOCDEV $REMDEV > $BDSYNC1 \
        || abort_msg "bdsync (1) failed"
    ./bdsync --fixedsalt --checksum md5 --hash sha256 "./bdsync -s -v" $REMDEV $LOCDEV > $BDSYNC2 \
        || abort_msg "bdsync (2) failed"

    MD5BD1=`get_md5 $BDSYNC1`
    MD5BD2=`get_md5 $BDSYNC2`

    check_sum "Inconsistent checksums MD5BD1/MD5BD2" "$MD5BD1" "$MD5BD2"

    ./bdsync --patch < $BDSYNC1 2> "$TMPF" || abort_msg "bdsync (3) failed"

    [[ "`cat $TMPF`" == checksum[md5\]:* ]] || abort_msg "ERROR: no checksum returned by --patch"
    CHECKSUM=`awk '{ print $2}' $TMPF`

    check_sum "Fifferent checksums patch/actual" "$CHECKSUM" "$MD5REM1"

    MD5LOC2=`get_md5 $LOCDEV`
    MD5REM2=`get_md5 $REMDEV`

    check_sum "Bad checksum MD5LOC2" "$MD5LOC2" "$MD5REM1"
    check_sum "Bad checksum MD5REM2" "$MD5REM2" "$MD5REM1"
}

handle_check do_check "checksums and different hashes yielding same result"
