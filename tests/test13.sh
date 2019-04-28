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

    local SUBPROC="$DIR/subp13-1.sh"

    > $LOCDEV
    > $REMDEV

    ./bdsync --remdata "$SUBPROC 1" $LOCDEV $REMDEV > $BDSYNC1 2> $BDSERR1 && abort_msg "bdsync (1) failed"
    MD5ER1=`grep RMTERR: $BDSERR1 | get_md5 -`
    ./bdsync           "$SUBPROC 1" $REMDEV $LOCDEV > $BDSYNC2 2> $BDSERR2 && abort_msg "bdsync (2) failed"
    MD5ER2=`grep RMTERR: $BDSERR2 | get_md5 -`

    check_sum "Inconsistent checksums MD5ER1/MD5ER2" "$MD5ER1" "$MD5ER2"

    check_sum "Bad checksum MD5ER1" "$MD5ER1" "28c57f9d52b8d542488703fda8afdaf5"
    check_sum "Bad checksum MD5ER2" "$MD5ER2" "28c57f9d52b8d542488703fda8afdaf5"
}

handle_check do_check "stderr forwarding and status returning of subprocess prior to bdsync execution"
