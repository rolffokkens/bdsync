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
    local BDSYNC3="$TDIR/DEV.bdsync3"
    local BDSYNC4="$TDIR/DEV.bdsync4"

    cre_sparse_file $LOCDEV $((1*1024*1024))
    cre_sparse_file $REMDEV $((2*1024*1024))

    echo test1 | overwrite_file $LOCDEV $((512*1024))
    echo test2 | overwrite_file $REMDEV $((512*1024))

    MD5LOC1=`get_md5 $LOCDEV 0 1024`
    MD5REM1=`get_md5 $REMDEV 0 1024`

    ./bdsync           --diffsize=minsize "./bdsync -s" $LOCDEV $REMDEV > $BDSYNC1 || abort_msg "bdsync (1) failed"
    ./bdsync --remdata --diffsize=minsize "./bdsync -s" $REMDEV $LOCDEV > $BDSYNC2 || abort_msg "bdsync (2) failed"
    ./bdsync           --diffsize=minsize "./bdsync -s" $REMDEV $LOCDEV > $BDSYNC3 || abort_msg "bdsync (3) failed"
    ./bdsync --remdata --diffsize=minsize "./bdsync -s" $LOCDEV $REMDEV > $BDSYNC4 || abort_msg "bdsync (4) failed"

    #
    # bdsync file shoudl be about 1 4k block in size
    #
    check_sizemax "file BDSYNC1 too large" $BDSYNC1 1100000
    check_sizemax "file BDSYNC2 too large" $BDSYNC2 1100000
    check_sizemax "file BDSYNC3 too large" $BDSYNC3 2200000
    check_sizemax "file BDSYNC4 too large" $BDSYNC4 2200000

    MD5BD1=`get_md5 $BDSYNC1`
    MD5BD2=`get_md5 $BDSYNC2`
    MD5BD3=`get_md5 $BDSYNC3`
    MD5BD4=`get_md5 $BDSYNC4`

    check_sum "Inconsistent checksums MD5BD1/MD5BD2" "$MD5BD1" "$MD5BD2"
    check_sum "Inconsistent checksums MD5BD3/MD5BD4" "$MD5BD3" "$MD5BD4"

    ./bdsync --diffsize=minsize --patch < $BDSYNC1 2> "$TMPF" || abort_msg "bdsync (5) failed"
    ./bdsync --diffsize=minsize --patch < $BDSYNC3 2> "$TMPF" || abort_msg "bdsync (6) failed"

    MD5LOC2=`get_md5 $LOCDEV 0 1024`
    MD5REM2=`get_md5 $REMDEV 0 1024`

    check_sum "Bad checksum MD5LOC2" "$MD5LOC2" "$MD5REM1"
    check_sum "Bad checksum MD5REM2" "$MD5REM2" "$MD5LOC1"
}

handle_check do_check "Handling different size (random) files with --diffsize=minsize option"
