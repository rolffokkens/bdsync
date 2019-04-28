#!/bin/bash

echo BEFORE >&2

./bdsync -s

echo AFTER >&2

exit 5
