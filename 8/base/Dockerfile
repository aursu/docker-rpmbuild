ARG centos=8.3.2011
FROM aursu/centos:${centos}-scm

ARG builduser=centos
ARG buildgroup=centos
ARG buildhome=/home/${builduser}

ENV BUILD_USER $builduser
ENV BUILD_HOME $buildhome
ENV BUILD_TOPDIR ${BUILD_HOME}/rpmbuild

# apache:x:48:48:Apache:/usr/share/httpd:/sbin/nologin
RUN groupadd -g 48 $buildgroup \
    && useradd -u 48 -g $buildgroup -d $BUILD_HOME -k /dev/null -m $BUILD_USER

# create rpmbuild structure for user root
RUN mkdir -p ${BUILD_TOPDIR}/{RPMS,SOURCES,SPECS,SRPMS} \
    && chown -R $BUILD_USER:$buildgroup ${BUILD_TOPDIR}
