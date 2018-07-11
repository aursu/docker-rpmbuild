# Tags and respective `Dockerfile` links

- [`aursu/rpmbuild:6-base` (*6/base/Dockerfile*)](https://github.com/aursu/docker-rpmbuild/blob/8ebba4df2e62deda1c6de83c5de2d62574ad0969/6/base/Dockerfile)
- [`aursu/rpmbuild:7-base` (*7/base/Dockerfile*)](https://github.com/aursu/docker-rpmbuild/blob/8ebba4df2e62deda1c6de83c5de2d62574ad0969/7/base/Dockerfile)
- [`aursu/rpmbuild:6-build` (*6/build/Dockerfile*)](https://github.com/aursu/docker-rpmbuild/blob/8ebba4df2e62deda1c6de83c5de2d62574ad0969/6/build/Dockerfile)
- [`aursu/rpmbuild:7-build` (*7/build/Dockerfile*)](https://github.com/aursu/docker-rpmbuild/blob/8ebba4df2e62deda1c6de83c5de2d62574ad0969/7/build/Dockerfile)
- [`aursu/rpmbuild:createrepo` (*createrepo/Dockerfile*)](https://github.com/aursu/docker-rpmbuild/blob/8ebba4df2e62deda1c6de83c5de2d62574ad0969/createrepo/Dockerfile)
- [`aursu/rpmbuild:webrepo` (*webrepo/Dockerfile*)](https://github.com/aursu/docker-rpmbuild/blob/8ebba4df2e62deda1c6de83c5de2d62574ad0969/webrepo/Dockerfile)

Depends on https://github.com/aursu/docker-centos.git

### Services

1. webrepo - provides HTTP access to YUM repositories. There are 2 repositories:

  * http://webrepo/centos/6/custom - packages for CentOS 6
  * http://webrepo/centos/7/custom - packages for CentOS 7

2. centos6repo - generates Yum repository metadata on rpm6 volume. Run
periodically with period DELAY_PERIOD (default is 60 seconds). On each cycle it
checks if new packages uploaded during last 12 hours or repodata directory
missed. It regenerates repository metadata if one of any conditions are met.

3. centos7repo - same as 2. but for rpm7
