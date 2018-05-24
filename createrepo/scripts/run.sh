#!/bin/bash

if [ -z "$DELAY_PERIOD" ]; then
    DELAY_PERIOD=60
fi

# check if integer greater then zero
if ! test $DELAY_PERIOD -gt 0 2>/dev/null; then
    DELAY_PERIOD=60
fi

/usr/bin/createrepo .
sleep $DELAY_PERIOD
