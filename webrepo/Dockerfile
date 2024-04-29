ARG rocky=8.9.20231119
FROM aursu/rockylinux:${rocky}-httpd

# enabe alias_module to use it for /centos location alias
COPY system/etc/httpd/conf.modules.d/00-extra.conf \
	/etc/httpd/conf.modules.d/00-extra.conf

# repo aliases
COPY system/etc/httpd/conf.d/repo.conf /etc/httpd/conf.d/repo.conf

# create rpmbuild structure for user root
RUN mkdir -p /home/centos-{6,7,8}/rpmbuild/RPMS /home/stream-{8,9}/rpmbuild/RPMS /home/rocky-{8,9}/rpmbuild/RPMS \
    && chown -R apache:apache /home/centos-{6,7,8} /home/stream-{8,9} /home/rocky-{8,9}

RUN mkdir -p /var/www/html/centos/{6,7,8} /var/www/html/centos/{8,9}-stream /var/www/html/rocky/{8,9} \
    && ln -s /home/centos-6/rpmbuild/RPMS /var/www/html/centos/6/custom \
    && ln -s /home/centos-7/rpmbuild/RPMS /var/www/html/centos/7/custom \
    && ln -s /home/centos-8/rpmbuild/RPMS /var/www/html/centos/8/custom \
    && ln -s /home/stream-8/rpmbuild/RPMS /var/www/html/centos/8-stream/custom \
    && ln -s /home/stream-9/rpmbuild/RPMS /var/www/html/centos/9-stream/custom \
    && ln -s /home/rocky-8/rpmbuild/RPMS /var/www/html/rocky/8/custom \
    && ln -s /home/rocky-8/rpmbuild/RPMS /var/www/html/rocky/9/custom

VOLUME /home/centos-6/rpmbuild/RPMS /home/centos-7/rpmbuild/RPMS /home/centos-8/rpmbuild/RPMS
VOLUME /home/stream-8/rpmbuild/RPMS /home/stream-9/rpmbuild/RPMS
VOLUME /home/rocky-8/rpmbuild/RPMS /home/rocky-9/rpmbuild/RPMS
