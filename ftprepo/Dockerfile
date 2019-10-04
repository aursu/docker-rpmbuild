FROM aursu/rpmbuild:createrepo

ENV LANG=C

ENV BUILD_USER centos
ENV BUILD_HOME /home/centos
ENV BUILD_TOPDIR /home/centos/rpmbuild

USER root
RUN yum -y install \
		proftpd \
        proftpd-utils \
	&& yum clean all && rm -rf /var/cache/yum /var/lib/rpm/__db*

COPY system/etc/proftpd.conf /etc/proftpd.conf

RUN mkdir /etc/ftpd \
    && echo -n "" | ftpasswd --passwd --file=/etc/ftpd/passwd \
        --name=centos \
        --uid=48 --gid=48 \
        --home=/home/centos \
        --shell=/bin/false \
        --sha512 --stdin \
    && echo -n "" | ftpasswd --group --file=/etc/ftpd/group \
        --name=centos \
        --gid=48 \
        --sha512 --stdin

COPY scripts/ftphook.sh /usr/local/bin/ftphook.sh
RUN chmod 755 /usr/local/bin/ftphook.sh

EXPOSE 21 49152-49160
CMD [ "/usr/sbin/proftpd", "--nodaemon"]