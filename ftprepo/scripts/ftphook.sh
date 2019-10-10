#!/bin/bash

RPM_PATH="$1"
RPM_REPO_PATH=${RPM_PATH%/*}
REPO=${RPM_REPO_PATH##*/}

cd $RPM_REPO_PATH && {
    # refresh.sh script works only for "refreshing" of existing Yum repository
    # therefore create Yum repository metadata directory if not exist
    mkdir -p repodata
    /usr/local/bin/refresh.sh
}