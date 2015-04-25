#!/bin/bash

. `dirname "$0"`/testlib.sh

do_check ()
{
    #
    # Create tow files of different size, create bdsync files both ways, and apply
    # In the end the files should have swapped in contents and size
    #

    local TDIR="$1"
    local TMPF="$TDIR/t1"

    local LOCDEV="$TDIR/LOCDEV"
    local REMDEV="$TDIR/REMDEV"
    local BDSYNC1="$TDIR/DEV.bdsync1"
    local BDSYNC2="$TDIR/DEV.bdsync2"

    cre_sparse_file $LOCDEV 1234000
    cre_sparse_file $REMDEV 1234567

    echo .abcd | overwrite_file $LOCDEV 123456
    echo .abXd | overwrite_file $REMDEV 123456

    MD5LOC1=`get_md5 $LOCDEV`
    MD5REM1=`get_md5 $REMDEV`

    check_sum "Bad checksum MD5LOC1" "$MD5LOC1" "b3886c3bc2fe7b6cb910c452dd693a0c"
    check_sum "Bad checksum MD5REM1" "$MD5REM1" "11578a7e90a2c275ab157f9fde66a15d"

    ./bdsync --diffsize "./bdsync -s" $LOCDEV $REMDEV > $BDSYNC1 || abort_msg "bdsync (1) failed"
    ./bdsync --diffsize "./bdsync -s" $REMDEV $LOCDEV > $BDSYNC2 || abort_msg "bdsync (2) failed"

    MD5BD1=`get_md5 $BDSYNC1`
    MD5BD2=`get_md5 $BDSYNC2`

    ./bdsync --diffsize --patch < $BDSYNC1 2> "$TMPF" || abort_msg "bdsync (3) failed"
    ./bdsync --diffsize --patch < $BDSYNC2 2> "$TMPF" || abort_msg "bdsync (3) failed"

    MD5LOC2=`get_md5 $LOCDEV`
    MD5REM2=`get_md5 $REMDEV`

    check_sum "Bad checksum MD5LOC2" "$MD5LOC2" "$MD5REM1"
    check_sum "Bad checksum MD5REM2" "$MD5REM2" "$MD5LOC1"
}

handle_check do_check "Handling different size files with --diffsize option"
