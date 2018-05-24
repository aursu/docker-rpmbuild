#!/bin/bash

if [ -z "$DELAY_PERIOD" ]; then
    DELAY_PERIOD=60
fi

# check if integer greater then zero
if ! test $DELAY_PERIOD -gt 0 2>/dev/null; then
    DELAY_PERIOD=60
fi

# check if any modified packages during last half day
if find . -mtime -12 -name *.rpm | grep -q rpm; then
    /usr/bin/createrepo .
    find . -name *.rpm -exec touch -d yesterday {} \;
fi

sleep $DELAY_PERIOD
