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

    cre_sparse_file $LOCDEV 5G
    cre_sparse_file $REMDEV 5G

    echo .abcd | overwrite_file $LOCDEV 512k
    echo .abXd | overwrite_file $REMDEV 512k

    MD5LOC1=`get_md5 $LOCDEV`
    MD5REM1=`get_md5 $REMDEV`

    check_sum "Bad checksum MD5LOC1" "$MD5LOC1" "8e382bc861c96d6d811cc8a93eb83b14"
    check_sum "Bad checksum MD5REM1" "$MD5REM1" "9252f97687f1608054df9ca1b85cc624"

    ./bdsync --checksum md5 --zeroblocks --remdata "./bdsync -s --zeroblocks" $LOCDEV $REMDEV > $BDSYNC1 \
        || abort_msg "bdsync (1) failed"
    ./bdsync --checksum md5 --zeroblocks           "./bdsync -s --zeroblocks" $REMDEV $LOCDEV > $BDSYNC2 \
        || abort_msg "bdsync (2) failed"

    #
    # bdsync file should be about 1 4k block in size
    #
    check_sizemax "file BDSYNC1 too large" $BDSYNC1 5000
    check_sizemax "file BDSYNC2 too large" $BDSYNC2 5000

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

handle_check do_check "large file (> 4G) handling"
