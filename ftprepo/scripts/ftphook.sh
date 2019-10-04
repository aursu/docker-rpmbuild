#!/bin/bash

if [ -z "$BUILD_TOPDIR" ]; then
    BUILD_TOPDIR=/home/centos/rpmbuild
fi

cd $BUILD_TOPDIR/RPMS && {
    mkdir -p repodata
    /usr/local/bin/refresh.sh
}