ARG centos=8.2.2004
ARG image=base
FROM aursu/rpmbuild:${centos}-${image}

ENV LANG=C

# install RPM build tools and assets
RUN dnf -y install \
        rpm-build \
        dnf-utils \
        epel-rpm-macros \
    && dnf clean all && rm -rf /var/cache/dnf /var/lib/rpm/__db*

COPY system/etc/yum.repos.d/custom.repo /etc/yum.repos.d/custom.repo
COPY system/etc/yum.repos.d/bintray-custom.repo /etc/yum.repos.d/bintray-custom.repo

# install common build tools (autotools, compilers, parsers etc)
RUN dnf config-manager --set-enabled PowerTools \
    && dnf config-manager --set-enabled epel-playground \
    && dnf -y install \
        autoconf \
        bison \
        flex \
        gcc \
        gcc-c++ \
        libtool \
        make \
        which \
    && dnf clean all && rm -rf /var/cache/dnf /var/lib/rpm/__db*

VOLUME ${BUILD_TOPDIR}/SRPMS ${BUILD_TOPDIR}/RPMS

USER $BUILD_USER
WORKDIR ${BUILD_TOPDIR}/SPECS
