# Tags and respective `Dockerfile` links

- [`aursu/rpmbuild:7-base` (*7/base/Dockerfile*)](https://github.com/aursu/docker-rpmbuild/blob/master/7/base/Dockerfile)
- [`aursu/rpmbuild:7-build` (*7/build/Dockerfile*)](https://github.com/aursu/docker-rpmbuild/blob/master/7/build/Dockerfile)
- [`aursu/rpmbuild:createrepo` (*createrepo/Dockerfile*)](https://github.com/aursu/docker-rpmbuild/blob/master/createrepo/Dockerfile)

Depends on https://github.com/aursu/docker-centos.git

### FTPrepo docker-compose example

```
version: "3.5"
services:
  ftprepo:
    volumes:
      - /diskless/bintray/custom/centos/7:/home/centos-7/rpmbuild/RPMS
      - /diskless/bintray/custom/centos/8:/home/centos-8/rpmbuild/RPMS
      - /diskless/bintray/php73custom/centos/7:/home/centos-7/rpmbuild/php73custom
      - /diskless/bintray/php73custom/centos/8:/home/centos-8/rpmbuild/php73custom
      - /diskless/bintray/php74custom/centos/7:/home/centos-7/rpmbuild/php74custom
      - /diskless/bintray/php74custom/centos/8:/home/centos-8/rpmbuild/php74custom
      - /diskless/bintray/php8custom/centos/7:/home/centos-7/rpmbuild/php8custom
      - /diskless/bintray/php8custom/centos/8:/home/centos-8/rpmbuild/php8custom
    ports:
      - "21:21"
      - "49152-49160:49152-49160"
    environment:
      - PROFTPD_OPTIONS=-DPUBLICADDR
      - PUBLICADDR=192.168.13.136
    image: aursu/rpmbuild:ftprepo
```
