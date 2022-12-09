ARG centos=stream9-20221206.0
ARG image=base
FROM aursu/rpmbuild:${centos}-${image}

ENV LANG=en_US.utf-8

# install RPM build tools and assets
RUN microdnf -y install \
        rpm-build \
        dnf-utils \
        epel-rpm-macros \
        dnf-plugins-core \
        procps-ng \
    && microdnf clean all && rm -rf /var/cache/dnf /var/lib/rpm/__db*

COPY system/etc/yum.repos.d/bintray-custom.repo /etc/yum.repos.d/bintray-custom.repo

# install common build tools (autotools, compilers, parsers etc)
# https://docs.fedoraproject.org/en-US/epel/#_el9
RUN dnf config-manager --set-enabled crb \
    && dnf -y install epel-release \
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
