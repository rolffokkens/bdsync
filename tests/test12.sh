#!/bin/bash

DIR=`dirname "$0"`

. $DIR/testlib.sh

do_check ()
{
    local TDIR="$1"
    local TMPF="$TDIR/t1"

    local LOCDEV="$TDIR/LOCDEV"
    local REMDEV="$TDIR/REMDEV"
    local BDSYNC1="$TDIR/DEV.bdsync1"
    local BDSYNC2="$TDIR/DEV.bdsync2"
    local BDSERR1="$TDIR/err.bdsync1"
    local BDSERR2="$TDIR/err.bdsync2"

    local SUBPROC="$DIR/subp12-1.sh"

    cre_sparse_file $LOCDEV 1234567
    cre_sparse_file $REMDEV 1234567

    echo .abcd | overwrite_file $LOCDEV 123456
    echo .abXd | overwrite_file $REMDEV 123456

    MD5LOC1=`get_md5 $LOCDEV`
    MD5REM1=`get_md5 $REMDEV`

    check_sum "Bad checksum MD5LOC1" "$MD5LOC1" "562945267ae01c091f9f3bc9b6dd7f3e"
    check_sum "Bad checksum MD5REM1" "$MD5REM1" "11578a7e90a2c275ab157f9fde66a15d"

    ./bdsync --remdata "$SUBPROC 1" $LOCDEV $REMDEV > $BDSYNC1 2> $BDSERR1 && abort_msg "bdsync (1) failed"
    MD5ER1=`get_md5 $BDSERR1`
    check_sum "Bad checksum MD5ER1" "$MD5ER1" "2780dbd9a376e11c660a8f98d53ba9e4"

    ./bdsync           "$SUBPROC 1" $REMDEV $LOCDEV > $BDSYNC2 2> $BDSERR2 && abort_msg "bdsync (2) failed"
    MD5ER2=`get_md5 $BDSERR2`
    check_sum "Bad checksum MD5ER1" "$MD5ER2" "2780dbd9a376e11c660a8f98d53ba9e4"

    #
    # bdsync file should be about 1 4k block in size
    #
    check_sizemax "file BDSYNC1 too large" $BDSYNC1 5000
    check_sizemax "file BDSYNC2 too large" $BDSYNC2 5000

    MD5BD1=`get_md5 $BDSYNC1`
    MD5BD2=`get_md5 $BDSYNC2`

    check_sum "Inconsistent checksums MD5BD1/MD5BD2" "$MD5BD1" "$MD5BD2"

    ./bdsync --patch < $BDSYNC1 2> "$TMPF" || abort_msg "bdsync (3) failed"

    [[ "`cat $TMPF`" == Warning:* ]] && abort_msg "ERROR: \"Warning: different device names\" should NOT be issued"

    MD5LOC2=`get_md5 $LOCDEV`
    MD5REM2=`get_md5 $REMDEV`

    check_sum "Bad checksum MD5LOC2" "$MD5LOC2" "$MD5REM1"
    check_sum "Bad checksum MD5REM2" "$MD5REM2" "$MD5REM1"
}

handle_check do_check "stderr forwarding and status returning of subprocess"
