# Tags and respective `Dockerfile` links

- [`aursu/rpmbuild:7-base` (*7/base/Dockerfile*)](https://github.com/aursu/docker-rpmbuild/blob/master/7/base/Dockerfile)
- [`aursu/rpmbuild:7-build` (*7/build/Dockerfile*)](https://github.com/aursu/docker-rpmbuild/blob/master/7/build/Dockerfile)
- [`aursu/rpmbuild:createrepo` (*createrepo/Dockerfile*)](https://github.com/aursu/docker-rpmbuild/blob/master/createrepo/Dockerfile)

Depends on https://github.com/aursu/docker-centos.git

### FTPrepo docker-compose example

```
version: "3"
services:
  ftprepo:
    volumes:
      - /var/lib/rpmbuild/data/custom/centos/7:/home/centos-7/rpmbuild/RPMS
      - /var/lib/rpmbuild/data/custom/centos/9-stream:/home/stream-9/rpmbuild/RPMS
      - /var/lib/rpmbuild/data/custom/rocky/8:/home/rocky-8/rpmbuild/RPMS
      - /var/lib/rpmbuild/data/php74custom/centos/7:/home/centos-7/rpmbuild/php74custom
      - /var/lib/rpmbuild/data/php74custom/centos/9-stream:/home/stream-9/rpmbuild/php74custom
      - /var/lib/rpmbuild/data/php74custom/rocky/8:/home/rocky-8/rpmbuild/php74custom
      - /var/lib/rpmbuild/data/php81custom/centos/7:/home/centos-7/rpmbuild/php81custom
      - /var/lib/rpmbuild/data/php81custom/centos/9-stream:/home/stream-9/rpmbuild/php81custom
      - /var/lib/rpmbuild/data/php81custom/rocky/8:/home/rocky-8/rpmbuild/php81custom
      - /var/lib/rpmbuild/data/php82custom/centos/7:/home/centos-7/rpmbuild/php82custom
      - /var/lib/rpmbuild/data/php82custom/centos/9-stream:/home/stream-9/rpmbuild/php82custom
      - /var/lib/rpmbuild/data/php82custom/rocky/8:/home/rocky-8/rpmbuild/php82custom
    ports:
      - "21:21"
      - "49152-49160:49152-49160"
    environment:
      - PROFTPD_OPTIONS=-DPUBLICADDR
      - PUBLICADDR=192.168.7.18
    image: aursu/rpmbuild:ftprepo
```
