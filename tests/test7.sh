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

    ./bdsync --remdata "./bdsync -s" $LOCDEV $REMDEV > $BDSYNC1 || abort_msg "bdsync (1) failed"
    ./bdsync           "./bdsync -s" $REMDEV $LOCDEV > $BDSYNC2 || abort_msg "bdsync (2) failed"

    MD5BD1=`get_md5 $BDSYNC1`
    MD5BD2=`get_md5 $BDSYNC2`

    check_sum "Inconsistent checksums MD5BD1/MD5BD2" "$MD5BD1" "$MD5BD2"

    mv $LOCDEV $LOCDEV.rename

    ./bdsync --patch=$LOCDEV.rename --warndev < $BDSYNC1 2> "$TMPF" || abort_msg "bdsync (3) failed"

    [[ "`cat $TMPF`" == Warning:* ]] || abort_msg "ERROR: \"Warning: different device names\" SHOULD be issued"

    MD5LOC2=`get_md5 $LOCDEV.rename`
    MD5REM2=`get_md5 $REMDEV`

    check_sum "Bad checksum MD5LOC2" "$MD5LOC2" "$MD5REM1"
    check_sum "Bad checksum MD5REM2" "$MD5REM2" "$MD5REM1"
}

handle_check do_check "--warndev option when a warning SHOULD be issued"
