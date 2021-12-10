#!/bin/bash

. `dirname "$0"`/testlib.sh

do_check ()
{
    local TDIR="$1"
    local TMPF="$TDIR/t1"
    local RASIZE=$((1024*1024))

    local LOCDEV="$TDIR/LOCDEV"
    local REMDEV="$TDIR/REMDEV"
    local BDSYNC1="$TDIR/DEV.bdsync1"
    local BDSYNC2="$TDIR/DEV.bdsync2"

    cre_sparse_file $LOCDEV 10G
    cre_sparse_file $REMDEV 10G

    echo "no --readahead set"
    time ./bdsync --remdata                     "./bdsync -s                    " $LOCDEV $REMDEV > /dev/null || abort_msg "bdsync (1) failed"
    echo "--readahead set on remote"
    time ./bdsync --remdata                     "./bdsync -s --readahead $RASIZE" $LOCDEV $REMDEV > /dev/null || abort_msg "bdsync (2) failed"
    echo "--zeroblocks set on local"
    time ./bdsync --remdata --readahead $RASIZE "./bdsync -s                    " $LOCDEV $REMDEV > /dev/null || abort_msg "bdsync (3) failed"
    echo "--zeroblocks set on both"
    time ./bdsync --remdata --readahead $RASIZE "./bdsync -s --readahead $RASIZE" $LOCDEV $REMDEV > /dev/null || abort_msg "bdsync (4) failed"
}

handle_check "$1" do_check "--readahead speed test (Note: useless because using a ramdisk)"
