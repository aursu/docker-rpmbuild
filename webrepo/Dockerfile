ARG centos=stream8
FROM aursu/centos:${centos}-httpd

# enabe alias_module to use it for /centos location alias
COPY system/etc/httpd/conf.modules.d/00-extra.conf \
	/etc/httpd/conf.modules.d/00-extra.conf

# repo aliases
COPY system/etc/httpd/conf.d/repo.conf /etc/httpd/conf.d/repo.conf

# create rpmbuild structure for user root
RUN mkdir -p /home/centos-{7,8}/rpmbuild/RPMS /home/stream-{8,9}/rpmbuild/RPMS \
    && chown -R apache:apache /home/centos-{7,8} /home/stream-{8,9}

RUN mkdir -p /var/www/html/centos/{7,8} /var/www/html/centos/{8,9}-stream \
    && ln -s /home/centos-7/rpmbuild/RPMS /var/www/html/centos/7/custom \
    && ln -s /home/centos-8/rpmbuild/RPMS /var/www/html/centos/8/custom \
    && ln -s /home/stream-8/rpmbuild/RPMS /var/www/html/centos/8-stream/custom \
    && ln -s /home/stream-9/rpmbuild/RPMS /var/www/html/centos/9-stream/custom

VOLUME /home/centos-7/rpmbuild/RPMS /home/centos-8/rpmbuild/RPMS /home/stream-8/rpmbuild/RPMS /home/stream-9/rpmbuild/RPMS
