#!/bin/bash

TMP=`mktemp /tmp/tests-XXXXXX`
RET=0

for i in tests/test[0-9]*.sh
do
    echo `basename $i`:
    $i > $TMP || RET=1
    sed 's/^/    /' < $TMP
done

rm -f $TMP

exit $RET
