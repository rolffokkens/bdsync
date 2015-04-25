#!/bin/bash

TMP=`mktemp /tmp/tests-XXXXXX`
RET=0

for i in tests/test[0-9]*.sh
do
    echo `basename $i`:
    $i | sed 's/^/    /'
    [ "${PIPESTATUS[0]}" == 0 ] || RET=1
done

rm -f $TMP

exit $RET
