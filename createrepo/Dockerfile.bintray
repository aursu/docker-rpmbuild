FROM aursu/rpmbuild:7-base

COPY scripts/bintray.py /usr/local/bin/bintray.py
RUN chmod 755 /usr/local/bin/bintray.py

VOLUME ${BUILD_TOPDIR}/RPMS

USER $BUILD_USER

CMD /usr/local/bin/bintray.py -c ${BUILD_TOPDIR}/RPMS
