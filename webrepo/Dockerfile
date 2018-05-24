FROM centos:httpd

# enabe alias_module to use it for /centos location alias
COPY system/etc/httpd/conf.modules.d/00-extra.conf \
	/etc/httpd/conf.modules.d/00-extra.conf

# repo aliases
COPY system/etc/httpd/conf.d/repo.conf /etc/httpd/conf.d/repo.conf

# create rpmbuild structure for user root
RUN mkdir -p /home/centos-{6,7}/rpmbuild/RPMS \
    && chown -R apache /home/centos-{6,7}

VOLUME /home/centos-6/rpmbuild/RPMS /home/centos-7/rpmbuild/RPMS