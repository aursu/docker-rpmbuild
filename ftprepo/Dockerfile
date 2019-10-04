FROM aursu/rpmbuild:createrepo

ENV LANG=C

USER root
RUN yum -y install \
		proftpd \
        proftpd-utils \
	&& yum clean all && rm -rf /var/cache/yum /var/lib/rpm/__db*

COPY system/etc/proftpd.conf /etc/proftpd.conf

# create rpmbuild structure for user root
RUN mkdir -p /home/centos-{6,7,8}/rpmbuild/RPMS \
    && chown -R centos:centos /home/centos-{6,7,8}

RUN mkdir /etc/ftpd \
    && for u in centos-6 centos-7 centos-8; do \
        echo -n "" | ftpasswd --passwd --file=/etc/ftpd/passwd \
        --name=$u \
        --uid=48 --gid=48 \
        --home=/home/$u \
        --shell=/bin/false \
        --sha512 --stdin; \
    done \
    && echo -n "" | ftpasswd --group --file=/etc/ftpd/group \
        --name=centos \
        --gid=48 \
        --sha512 --stdin

COPY scripts/ftphook.sh /usr/local/bin/ftphook.sh
RUN chmod 755 /usr/local/bin/ftphook.sh

EXPOSE 21 49152-49160
CMD [ "/usr/sbin/proftpd", "--nodaemon"]