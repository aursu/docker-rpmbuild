#!/bin/bash

[[ "$1" == "cleanup" ]] && find . -name *.rpm -delete
[ -d repodata ] && rm -rf repodata