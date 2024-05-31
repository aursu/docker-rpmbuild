ARG rocky=8.9.20231119
FROM aursu/rpmbuild:${rocky}-base

RUN microdnf -y install \
		createrepo \
	&& microdnf clean all && rm -rf /var/cache/dnf /var/lib/rpm/__db*

# sleep for DELAY_PERIOD seconds
ENV DELAY_PERIOD 60
ENV REFRESH_ACTION=refresh

COPY scripts/run.sh /usr/local/bin/run.sh
COPY scripts/refresh.sh /usr/local/bin/refresh.sh
RUN chmod 755 /usr/local/bin/run.sh /usr/local/bin/refresh.sh

VOLUME ${BUILD_TOPDIR}/RPMS

USER $BUILD_USER
WORKDIR ${BUILD_TOPDIR}/RPMS

CMD /usr/local/bin/run.sh
