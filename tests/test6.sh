#!/bin/bash

. `dirname "$0"`/testlib.sh

do_check ()
{
    local TDIR="$1"
    local TMPF="$TDIR/t1"

    local LOCDEV="$TDIR/LOCDEV"
    local REMDEV="$TDIR/REMDEV"
    local BDSYNC1A="$TDIR/DEV.bdsync1a"
    local BDSYNC2A="$TDIR/DEV.bdsync2a"
    local BDSYNC1B="$TDIR/DEV.bdsync1b"
    local BDSYNC2B="$TDIR/DEV.bdsync2b"

    dd if=/dev/zero of=$LOCDEV bs=1024 count=1024 2>/dev/null
    dd if=/dev/zero of=$REMDEV bs=1024 count=1024 2>/dev/null

    echo .abcd | dd of=$LOCDEV bs=1024 seek=512 conv=notrunc 2>/dev/null
    echo .abXd | dd of=$REMDEV bs=1024 seek=512 conv=notrunc 2>/dev/null

    MD5LOC1=`get_md5 $LOCDEV`
    MD5REM1=`get_md5 $REMDEV`

    check_sum "Bad checksum MD5LOC1" "$MD5LOC1" "be2f3119e1b3f8ff8dff771065488a82"
    check_sum "Bad checksum MD5REM1" "$MD5REM1" "57e7487c6ac9184d6a23cd5d2ead6bc2"

    ./bdsync --zeroblocks --remdata "./bdsync -s --zeroblocks" $LOCDEV $REMDEV > $BDSYNC1A || abort_msg "bdsync (1A) failed"
    ./bdsync --zeroblocks           "./bdsync -s --zeroblocks" $REMDEV $LOCDEV > $BDSYNC2A || abort_msg "bdsync (2A) failed"
    ./bdsync              --remdata "./bdsync -s             " $LOCDEV $REMDEV > $BDSYNC1B || abort_msg "bdsync (1B) failed"
    ./bdsync                        "./bdsync -s             " $REMDEV $LOCDEV > $BDSYNC2B || abort_msg "bdsync (2B) failed"

    MD5BD1A=`get_md5 $BDSYNC1A`
    MD5BD2A=`get_md5 $BDSYNC2A`
    MD5BD1B=`get_md5 $BDSYNC1B`
    MD5BD2B=`get_md5 $BDSYNC2B`

    check_sum "Inconsistent checksums MD5BD1A/MD5BD2A" "$MD5BD1A" "$MD5BD2A"
    check_sum "Inconsistent checksums MD5BD1B/MD5BD2B" "$MD5BD1B" "$MD5BD2B"
    check_sum "Inconsistent checksums MD5BD1A/MD5BD1B" "$MD5BD1A" "$MD5BD1B"

    ./bdsync --patch < $BDSYNC1A 2> "$TMPF" || abort_msg "bdsync (3) failed"

    MD5LOC2=`get_md5 $LOCDEV`
    MD5REM2=`get_md5 $REMDEV`

    check_sum "Bad checksum MD5LOC2" "$MD5LOC2" "$MD5REM1"
    check_sum "Bad checksum MD5REM2" "$MD5REM2" "$MD5REM1"
}

handle_check do_check "handling --zeroblocks option (1 MB files)"
