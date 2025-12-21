ARG rocky=10.1.20251126
FROM aursu/rpmbuild:${rocky}-docker

ARG version=2.330.0
ARG shasum=af5c33fa94f3cc33b8e97937939136a6b04197e6dadfcfb3b6e33ae1bf41e79a

ARG DISTRO=actions-runner-linux-x64-${version}.tar.gz
ARG RELEASE_URL="https://github.com/actions/runner/releases/download/v${version}/${DISTRO}"

ARG user=runner
ARG group=runner
ARG home=/home/${user}
ARG uid=1000
ARG gid=1000

ENV RUNNER_USER $user
ENV RUNNER_HOME $home

RUN dnf -y install --enablerepo=crb \
        libicu \
        lttng-ust \
        tar \
    && dnf clean all && rm -rf /var/cache/dnf /var/lib/rpm/__db*

RUN groupadd -g $gid $group \
  && useradd -d $RUNNER_HOME -u $uid -g $gid -m -s /bin/bash $RUNNER_USER

USER $RUNNER_USER
WORKDIR $RUNNER_HOME

RUN set -ex \
    && curl -O -L $RELEASE_URL \
    && echo "${shasum} ${DISTRO}" | sha256sum -c \
    && tar zxf $DISTRO \
    && rm -f $DISTRO
