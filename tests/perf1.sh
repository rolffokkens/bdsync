#!/bin/bash
SIZE=10G
. `dirname "$0"`/testlib.sh

do_check ()
{
    local TDIR="$1"
    local TMPF="$TDIR/t1"

    local LOCDEV="$TDIR/LOCDEV"
    local REMDEV="$TDIR/REMDEV"
    local BDSYNC1="$TDIR/DEV.bdsync1"
    local BDSYNC2="$TDIR/DEV.bdsync2"

    truncate -s $SIZE $LOCDEV 
    truncate -s $SIZE $REMDEV 

    echo "no --zeroblock set"
    time ./bdsync --remdata "./bdsync -s" $LOCDEV $REMDEV > /dev/null || abort_msg "bdsync (1) failed"
    echo "--zeroblock set on remote"
    time ./bdsync --remdata "./bdsync -s --zeroblock" $LOCDEV $REMDEV > /dev/null || abort_msg "bdsync (2) failed"
    echo "--zeroblock set on local"
    time ./bdsync --remdata --zeroblock "./bdsync -s" $LOCDEV $REMDEV > /dev/null || abort_msg "bdsync (3) failed"
    echo "--zeroblock set on both"
    time ./bdsync --remdata --zeroblock "./bdsync -s --zeroblock" $LOCDEV $REMDEV > /dev/null || abort_msg "bdsync (4) failed"
}

handle_check do_check "--zeroblock speed test"
