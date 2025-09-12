ARG rocky=10.0.20250606
FROM aursu/rpmbuild:${rocky}-docker

ARG version=2.328.0
ARG shasum=01066fad3a2893e63e6ca880ae3a1fad5bf9329d60e77ee15f2b97c148c3cd4e

ARG DISTRO=actions-runner-linux-x64-${version}.tar.gz
ARG RELEASE_URL="https://github.com/actions/runner/releases/download/v${version}/${DISTRO}"

ARG user=runner
ARG group=runner
ARG home=/home/${user}
ARG uid=1000
ARG gid=1000

ENV RUNNER_USER $user
ENV RUNNER_HOME $home

RUN dnf -y install \
        libicu \
        lttng-ust \
        tar \
    && dnf clean all && rm -rf /var/cache/dnf /var/lib/rpm/__db*

RUN groupadd -g $gid $group \
  && useradd -d $RUNNER_HOME -u $uid -g $gid -m -s /bin/bash $RUNNER_USER

USER $RUNNER_USER
WORKDIR $RUNNER_HOME

RUN set -ex \
    && mkdir -p $RUNNER_HOME/work \
    && curl -O -L $RELEASE_URL \
    && echo "${shasum} ${DISTRO}" | sha256sum -c \
    && tar zxf $DISTRO \
    && rm -f $DISTRO
