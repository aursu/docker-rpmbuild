# Tags and respective `Dockerfile` links

- [`aursu/rpmbuild:6-base` (*6/base/Dockerfile*)](https://github.com/aursu/docker-rpmbuild/blob/47053e6ab22961b3852393d73cdce1f64883747d/6/base/Dockerfile)
- [`aursu/rpmbuild:7-base` (*7/base/Dockerfile*)](https://github.com/aursu/docker-rpmbuild/blob/47053e6ab22961b3852393d73cdce1f64883747d/7/base/Dockerfile)
- [`aursu/rpmbuild:6-build` (*6/build/Dockerfile*)](https://github.com/aursu/docker-rpmbuild/blob/47053e6ab22961b3852393d73cdce1f64883747d/6/build/Dockerfile)
- [`aursu/rpmbuild:7-build` (*7/build/Dockerfile*)](https://github.com/aursu/docker-rpmbuild/blob/47053e6ab22961b3852393d73cdce1f64883747d/7/build/Dockerfile)
- [`aursu/rpmbuild:createrepo` (*createrepo/Dockerfile*)](https://github.com/aursu/docker-rpmbuild/blob/47053e6ab22961b3852393d73cdce1f64883747d/createrepo/Dockerfile)
- [`aursu/rpmbuild:webrepo` (*webrepo/Dockerfile*)](https://github.com/aursu/docker-rpmbuild/blob/47053e6ab22961b3852393d73cdce1f64883747d/webrepo/Dockerfile)

Depends on https://github.com/aursu/docker-centos.git

### Services

1. webrepo - provides HTTP access to YUM repositories. There are 2 repositories:

  * http://webrepo/centos/6/custom - packages for CentOS 6
  * http://webrepo/centos/7/custom - packages for CentOS 7

2. centos6repo - generates Yum repository metadata for rpm6 volume. Run
periodically with period DELAY_PERIOD (default is 60 seconds). On each cycle it
checks if new packages uploaded during last 12 hours or repodata directory
missed. It regenerates repository metadata if one of any conditions is true.

3. centos7repo - same as 2. but for rpm7

4. centos8repo - same as 2. but for rpm8
