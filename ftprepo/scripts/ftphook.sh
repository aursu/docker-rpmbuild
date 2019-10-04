#!/bin/bash

BUILD_TOPDIR="/home/$1/rpmbuild"

cd $BUILD_TOPDIR/RPMS && {
    # refresh.sh script works only for "refreshing" of existing Yum repository
    # therefore create Yum repository metadata directory if not exist
    mkdir -p repodata
    /usr/local/bin/refresh.sh
}