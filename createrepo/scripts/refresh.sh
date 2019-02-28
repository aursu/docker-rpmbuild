#!/bin/bash

if [ -z "$REFRESH_ACTION" ]; then
    REFRESH_ACTION=refresh
fi

[[ "$REFRESH_ACTION" == "cleanup" ]] && find . -name *.rpm -delete
[ -d repodata ] && {
    rm -rf repodata
    /usr/bin/createrepo .
}