#!/bin/bash
# Bintray upload
# NOT COMPLETED in favor of Python version

# BINTRAY_USER
# BINTRAY_API_KEY
# BINTRAY_REPO

# mandatory for OOS
# BINTRAY_VCS_URL

[ -n "$BINTRAY_USER" -a -n "$BINTRAY_API_KEY" ] || {
    echo "Bintray authentication credentials were not provided."
    exit 1
}

[ -n "$BINTRAY_REPO" ] || {
    echo "Repository for publishing is not specified"
    exit 1
}

# check package in repo
function check_package_exists {
    local package="$1"

    [ -f "$package" ] || return 1

    local name=$(rpm -q --queryformat=%{NAME} -p $package)
    curl --user "${BINTRAY_USER}:${BINTRAY_API_KEY}" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json" \
        "https://api.bintray.com/packages/${BINTRAY_USER}/${BINTRAY_REPO}/${name}" \
        -s -Dheaders.txt -oresponse.json

    grep -q "200 OK" headers.txt
}

function create_package {
    local package="$1"

    [ -f "$package" ] || return 1

    local rpmdata=$(rpm -q --queryformat="\"name\": \"%{NAME}\", \
        \"desc\": \"%{DESCRIPTION}\", \"website_url\": \"%{URL}\"" -p $package)
    local vcs_url=$BINTRAY_VCS_URL
    local data="{${rpmdata}, \
      \"licenses\": [\"Apache-2.0\", \"GPL-3.0\"], \
      \"vcs_url\": \"$vcs_url\"}"

    # create package
    curl --user "${BINTRAY_USER}:${BINTRAY_API_KEY}" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json" \
        -X POST -d "$data" \
        "https://api.bintray.com/packages/${BINTRAY_USER}/${BINTRAY_REPO}" \
        -s -Dheaders.txt -oresponse.json

    grep -q "201 Created" headers.txt
}

function delete_package {
    local package="$1"

    [ -f "$package" ] || return 1

    local name=$(rpm -q --queryformat=%{NAME} -p $package)

    # delete package
    curl --user "${BINTRAY_USER}:${BINTRAY_API_KEY}" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json" \
        -X DELETE \
        "https://api.bintray.com/packages/${BINTRAY_USER}/${BINTRAY_REPO}/${name}" \
        -s -Dheaders.txt -oresponse.json

    grep -q success response.json
}

function upload_content {
    local package="$1"

    [ -f "$package" ] || return 1

    local name=$(rpm -q --queryformat=%{NAME} -p $package)
    local version=$(rpm -q --queryformat=%{VERSION} -p $package)
    local release=$(rpm -q --queryformat=%{RELEASE} -p $package)
    local centos=7
    if [ "${release%el7}" == "$release" ]; then
        centos=6
    fi
    local arch=$(rpm -q --queryformat=%{ARCH} -p $package)
    local filename=$(basename $package)

    curl --user "${BINTRAY_USER}:${BINTRAY_API_KEY}" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json" \
        -T $package \
        -H "X-Bintray-Package: $name" \
        -H "X-Bintray-Version: $version" \
        "https://api.bintray.com/content/${BINTRAY_USER}/${BINTRAY_REPO}/centos/${centos}/${arch}/${filename}" \
        -s -Dheaders.txt -oresponse.json

    grep -q "201 Created" headers.txt
}

function deploy_rpm {
    local package="$1"

    [ -f "$package" ] || return 1

    local publish="{\"discard\": \"false\"}"
    local name=$(rpm -q --queryformat=%{NAME} -p $package)
    local version=$(rpm -q --queryformat=%{VERSION} -p $package)

    curl --user "${BINTRAY_USER}:${BINTRAY_API_KEY}" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json" \
        -X POST -d "$publish" \
        "https://api.bintray.com/content/${BINTRAY_USER}/${BINTRAY_REPO}/${name}/${version}/publish" \
        -s -Dheaders.txt -oresponse.json

    grep -q "200 OK" headers.txt
}
