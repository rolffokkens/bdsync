#!/bin/bash

_tmp=`mktemp -d /tmp/tests-XXXXXX`
RET=0

for i in tests/test[0-9]*.sh
do
    _base=$(basename $i)
    echo "${_base}:"
    $i "${_tmp}/${_base}" | sed 's/^/    /'
    [ "${PIPESTATUS[0]}" == 0 ] || RET=1
done

#rm -rf ${_tmp}

exit $RET
