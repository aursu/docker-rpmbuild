FROM aursu/rpmbuild:createrepo

ENV LANG=C
ENV PROFTPD_OPTIONS=

USER root
RUN microdnf -y install \
		proftpd \
        proftpd-utils \
	&& microdnf clean all && rm -rf /var/cache/yum /var/lib/rpm/__db*

COPY system/etc/proftpd.conf /etc/proftpd.conf

# create rpmbuild structure for user root
RUN mkdir -p /home/stream-{9,10}/rpmbuild/RPMS \
    && mkdir -p /home/rocky-{8,9,10}/rpmbuild/RPMS \
    && chown -R centos:centos /home/stream-{9,10} /home/rocky-{8,9,10}

RUN mkdir /etc/ftpd \
    && for u in stream-9 stream-10 rocky-8 rocky-9 rocky-10; do \
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
COPY scripts/proftpd-foreground /usr/local/bin/proftpd-foreground
RUN chmod 755 /usr/local/bin/ftphook.sh /usr/local/bin/proftpd-foreground

EXPOSE 20-21 49152-49160
CMD ["proftpd-foreground"]