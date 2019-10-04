FROM aursu/rpmbuild:createrepo

ARG buildgroup=centos
ENV LANG=C

USER root
RUN yum -y install \
		proftpd \
        proftpd-utils \
	&& yum clean all && rm -rf /var/cache/yum /var/lib/rpm/__db*

COPY system/etc/proftpd.conf /etc/proftpd.conf

RUN mkdir /etc/ftpd \
    && echo -n "" | ftpasswd --passwd --file=/etc/ftpd/passwd \
        --name=${BUILD_USER} \
        --uid=48 --gid=48 \
        --home=${BUILD_HOME} \
        --shell=/bin/false \
        --sha512 --stdin \
    && echo -n "" | ftpasswd --group --file=/etc/ftpd/group \
        --name=$buildgroup \
        --gid=48 \
        --sha512 --stdin

EXPOSE 21 49152-49160
CMD [ "/usr/sbin/proftpd", "--nodaemon"]