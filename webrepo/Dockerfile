FROM aursu/centos:httpd

# enabe alias_module to use it for /centos location alias
COPY system/etc/httpd/conf.modules.d/00-extra.conf \
	/etc/httpd/conf.modules.d/00-extra.conf

# repo aliases
COPY system/etc/httpd/conf.d/repo.conf /etc/httpd/conf.d/repo.conf

# create rpmbuild structure for user root
RUN mkdir -p /home/centos-{6,7}/rpmbuild/RPMS \
    && chown -R apache:apache /home/centos-{6,7}

RUN mkdir -p /var/www/html/centos/{6,7} \
    && ln -s /home/centos-6/rpmbuild/RPMS /var/www/html/centos/6/custom \
    && ln -s /home/centos-7/rpmbuild/RPMS /var/www/html/centos/7/custom

VOLUME /home/centos-6/rpmbuild/RPMS /home/centos-7/rpmbuild/RPMS
