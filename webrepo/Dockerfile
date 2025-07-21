ARG rocky=10.0.20250606
FROM aursu/rockylinux:${rocky}-httpd

# enabe alias_module to use it for /centos location alias
COPY system/etc/httpd/conf.modules.d/00-extra.conf \
	/etc/httpd/conf.modules.d/00-extra.conf

# repo aliases
COPY system/etc/httpd/conf.d/repo.conf /etc/httpd/conf.d/repo.conf

# create rpmbuild structure for user root
RUN mkdir -p /home/stream-{9,10}/rpmbuild/RPMS /home/rocky-{8,9,10}/rpmbuild/RPMS \
    && chown -R apache:apache /home/stream-{9,10} /home/rocky-{8,9,10}

RUN mkdir -p /var/www/html/centos/{9,10}-stream /var/www/html/rocky/{8,9,10} \
    && ln -s /home/stream-9/rpmbuild/RPMS /var/www/html/centos/9-stream/custom \
    && ln -s /home/stream-10/rpmbuild/RPMS /var/www/html/centos/10-stream/custom \
    && ln -s /home/rocky-8/rpmbuild/RPMS /var/www/html/rocky/8/custom \
    && ln -s /home/rocky-9/rpmbuild/RPMS /var/www/html/rocky/9/custom \
    && ln -s /home/rocky-10/rpmbuild/RPMS /var/www/html/rocky/10/custom

VOLUME /home/stream-9/rpmbuild/RPMS /home/stream-10/rpmbuild/RPMS
VOLUME /home/rocky-8/rpmbuild/RPMS /home/rocky-9/rpmbuild/RPMS /home/rocky-10/rpmbuild/RPMS
