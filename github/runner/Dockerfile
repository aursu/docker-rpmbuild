ARG rocky=8.8.20230518
FROM aursu/rpmbuild:${rocky}-docker

ARG version=2.299.1
ARG shasum=147c14700c6cb997421b9a239c012197f11ea9854cd901ee88ead6fe73a72c74

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
