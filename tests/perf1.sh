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

    cre_sparse_file $LOCDEV 10G
    cre_sparse_file $REMDEV 10G

    echo "no --zeroblocks set"
    time ./bdsync --remdata              "./bdsync -s             " $LOCDEV $REMDEV > /dev/null || abort_msg "bdsync (1) failed"
    echo "--zeroblocks set on remote"
    time ./bdsync --remdata              "./bdsync -s --zeroblocks" $LOCDEV $REMDEV > /dev/null || abort_msg "bdsync (2) failed"
    echo "--zeroblocks set on local"
    time ./bdsync --remdata --zeroblocks "./bdsync -s             " $LOCDEV $REMDEV > /dev/null || abort_msg "bdsync (3) failed"
    echo "--zeroblocks set on both"
    time ./bdsync --remdata --zeroblocks "./bdsync -s --zeroblocks" $LOCDEV $REMDEV > /dev/null || abort_msg "bdsync (4) failed"
}

handle_check do_check "--zeroblocks speed test"
