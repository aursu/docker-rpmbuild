FROM rpmbuild:7-base

RUN yum -y install \
		createrepo \
	&& yum clean all && rm -rf /var/cache/yum

# create rpmbuild structure for user root
RUN mkdir -p ${BUILD_TOPDIR}/RPMS \
    && chown -R centos:centos ${BUILD_HOME}

VOLUME ${BUILD_TOPDIR}/RPMS

USER $BUILD_USER
WORKDIR ${BUILD_TOPDIR}/RPMS

CMD ["/usr/bin/createrepo", "."]
