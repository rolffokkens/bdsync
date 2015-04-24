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

    echo .abcd >$LOCDEV 
    echo .abXd >$REMDEV 

    MD5LOC1=`get_md5 $LOCDEV`
    MD5REM1=`get_md5 $REMDEV`

    check_sum "Bad checksum MD5LOC1" "$MD5LOC1" "8a47088ef3be2d289d0f2f726169e7ad"
    check_sum "Bad checksum MD5REM1" "$MD5REM1" "31a562e32a22fb5f222080abb3d907ee"

    ./bdsync --zeroblocks --remdata "./bdsync -s --zeroblocks" $LOCDEV $REMDEV > $BDSYNC1 || abort_msg "bdsync (1) failed"
    ./bdsync --zeroblocks           "./bdsync -s --zeroblocks" $REMDEV $LOCDEV > $BDSYNC2 || abort_msg "bdsync (2) failed"

    MD5BD1=`get_md5 $BDSYNC1`
    MD5BD2=`get_md5 $BDSYNC2`

    check_sum "Inconsistent checksums MD5BD1/MD5BD2" "$MD5BD1" "$MD5BD2"

    ./bdsync --patch < $BDSYNC1 2> "$TMPF" || abort_msg "bdsync (3) failed"

    MD5LOC2=`get_md5 $LOCDEV`
    MD5REM2=`get_md5 $REMDEV`

    check_sum "Bad checksum MD5LOC2" "$MD5LOC2" "$MD5REM1"
    check_sum "Bad checksum MD5REM2" "$MD5REM2" "$MD5REM1"
}

handle_check do_check "handling --zeroblocks option"
