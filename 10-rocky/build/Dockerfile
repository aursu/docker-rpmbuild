ARG rocky=10.0.20250606
ARG image=rpmb
FROM aursu/rpmbuild:${rocky}-${image}

# install common build tools (autotools, compilers, parsers etc)
RUN crb enable \
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
