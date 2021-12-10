#!/bin/bash

is_md5sum_available ()
{
    which md5sum > /dev/null 2>&1 && return 0

    echo "ERROR: md5sum not found"

    exit 1
}

get_md5 ()
{
     if [ "$2" == "" ]
     then
         md5sum "$1"
     else
         dd "if=$1" skip="$2" bs=1024 count="$3" 2>/dev/null | md5sum -
     fi \
     | awk '{ print $1}'
}

abort_msg ()
{
    echo "$1" >&2

    exit 1
}

check_sum ()
{
    [ "$2" == "$3" ] && return 0
    abort_msg "$1"
}

check_sizemax ()
{
    local MSG="$1"
    local FILE="$2"
    local MAXSIZE="$3"
    local SIZE=`stat -c "%s" "$FILE"`

    [ "$SIZE" -lt "$MAXSIZE" ] && return 0

    abort_msg "$MSG"
}

handle_check ()
{
    local _tdir="$1"
    local _test="$2"
    local _desc="$3"
    local _tmp2

    if [[ ${_tdir} == "" ]]
    then
        _tdir=$(mktemp -d /tmp/handle_check-XXXXXX)
    else
        mkdir -p "${_tdir}"
    fi

    mkdir "${_tdir}/check"
    _tmp2="${_tdir}/check-output.lis"

    echo "**** Checking: ${_desc}"
    ( is_md5sum_available
      eval "${_test}" "${_tdir}/check" ) 2>&1 | tee "${_tmp2}" | sed -u 's/^/  |  /'

    _ret="${PIPESTATUS[0]}"

    if [[ ${_ret} == "0" ]]
    then
        echo "--> PASS"
    else
        echo "--> FAIL"
    fi

    rm -rf "${_tdir}"

    return "${_ret}"
}

cre_sparse_file ()
{
    local FILE="$1"
    local SIZE="$2"

    truncate -s "$SIZE" "$FILE"
}

cre_random_file_1k ()
{
    local FILE="$1"
    local SIZE="$2"

    dd if=/dev/urandom "of=$FILE" ibs=1k "count=$SIZE" 2>/dev/null
}

overwrite_file ()
{
    local FILE="$1"
    local POS="$2"

    dd "of=$FILE" ibs=1 "seek=$POS" obs=1 conv=notrunc 2>/dev/null
}
