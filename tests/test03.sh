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

    cre_sparse_file $LOCDEV $((256*4096))
    cre_sparse_file $REMDEV $((256*4096+2345))

    echo .abcd | overwrite_file $LOCDEV $((128*4096))
    echo .abXd | overwrite_file $REMDEV $((128*4096))

    MD5LOC1=`get_md5 $LOCDEV`
    MD5REM1=`get_md5 $REMDEV`

    check_sum "Bad checksum MD5LOC1" "$MD5LOC1" "be2f3119e1b3f8ff8dff771065488a82"
    check_sum "Bad checksum MD5REM1" "$MD5REM1" "231e3b8641188b6acb24d94df96751d7"

    ./bdsync --diffsize=resize "./bdsync -s" $LOCDEV $REMDEV > $BDSYNC1 || abort_msg "bdsync (1) failed"
    ./bdsync --diffsize=resize "./bdsync -s" $REMDEV $LOCDEV > $BDSYNC2 || abort_msg "bdsync (2) failed"

    #
    # bdsync file shoudl be about 1 4k block in size
    #
    check_sizemax "file BDSYNC1 too large" $BDSYNC1 5000
    check_sizemax "file BDSYNC2 too large" $BDSYNC2 5000

    MD5BD1=`get_md5 $BDSYNC1`
    MD5BD2=`get_md5 $BDSYNC2`

    ./bdsync --diffsize=resize --patch < $BDSYNC1 2> "$TMPF" || abort_msg "bdsync (3) failed"
    ./bdsync --diffsize=resize --patch < $BDSYNC2 2> "$TMPF" || abort_msg "bdsync (4) failed"

    MD5LOC2=`get_md5 $LOCDEV`
    MD5REM2=`get_md5 $REMDEV`

    check_sum "Bad checksum MD5LOC2" "$MD5LOC2" "$MD5REM1"
    check_sum "Bad checksum MD5REM2" "$MD5REM2" "$MD5LOC1"
}

handle_check do_check "Handling different size (zeroes) files with --diffsize=resize option"
