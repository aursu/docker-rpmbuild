FROM rpmbuild:7-base

# install RPM build tools and assets
RUN yum -y install \
        rpm-build \
        yum-utils \
        epel-rpm-macros \
    && yum clean all && rm -rf /var/cache/yum

# install common build tools (autotools, compilers, parsers etc)
RUN yum -y install \
        autoconf \
        bison \
        flex \
        gcc \
        gcc-c++ \
        libtool \
        make \
    && yum clean all && rm -rf /var/cache/yum

VOLUME ${BUILD_TOPDIR}/SRPMS ${BUILD_TOPDIR}/RPMS

USER $BUILD_USER
WORKDIR ${BUILD_TOPDIR}/SPECS
