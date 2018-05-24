FROM rpmbuild:7-base

# sleep for DELAY_PERIOD seconds
ENV DELAY_PERIOD 60

RUN yum -y install \
		createrepo \
	&& yum clean all && rm -rf /var/cache/yum

COPY scripts/run.sh /usr/local/bin/run.sh
RUN chmod 755 /usr/local/bin/run.sh

VOLUME ${BUILD_TOPDIR}/RPMS

USER $BUILD_USER
WORKDIR ${BUILD_TOPDIR}/RPMS

CMD /usr/local/bin/run.sh