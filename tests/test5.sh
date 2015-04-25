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

    cre_sparse_file $LOCDEV 1M
    cre_sparse_file $REMDEV 1M

    echo .abcd | overwrite_file $LOCDEV 512k
    echo .abXd | overwrite_file $REMDEV 512k

    MD5LOC1=`get_md5 $LOCDEV`
    MD5REM1=`get_md5 $REMDEV`

    check_sum "Bad checksum MD5LOC1" "$MD5LOC1" "be2f3119e1b3f8ff8dff771065488a82"
    check_sum "Bad checksum MD5REM1" "$MD5REM1" "57e7487c6ac9184d6a23cd5d2ead6bc2"

    ./bdsync --zeroblocks --remdata "./bdsync -s --zeroblocks" $LOCDEV $REMDEV > $BDSYNC1 || abort_msg "bdsync (1) failed"
    check_sizemax "file BDSYNC1 too large" $BDSYNC1 5000

    ./bdsync --zeroblocks           "./bdsync -s --zeroblocks" $REMDEV $LOCDEV > $BDSYNC2 || abort_msg "bdsync (2) failed"
    check_sizemax "file BDSYNC2 too large" $BDSYNC2 5000

    MD5BD1=`get_md5 $BDSYNC1`
    MD5BD2=`get_md5 $BDSYNC2`

    check_sum "Inconsistent checksums MD5BD1/MD5BD2" "$MD5BD1" "$MD5BD2"

    ./bdsync --patch < $BDSYNC1 2> "$TMPF" || abort_msg "bdsync (3) failed"

    MD5LOC2=`get_md5 $LOCDEV`
    MD5REM2=`get_md5 $REMDEV`

    check_sum "Bad checksum MD5LOC2" "$MD5LOC2" "$MD5REM1"
    check_sum "Bad checksum MD5REM2" "$MD5REM2" "$MD5REM1"
}

handle_check do_check "handling --zeroblocks with --remdata option"
