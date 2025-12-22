ARG rocky=10.1.20251126
FROM aursu/rpmbuild:${rocky}-docker

# Replace value with the latest runner release version
# source: https://github.com/actions/runner/releases
# ex: 2.330.0
ARG RUNNER_ARCH="x64"
ARG RUNNER_VERSION="2.330.0"
ARG RUNNER_CHECKSUM=af5c33fa94f3cc33b8e97937939136a6b04197e6dadfcfb3b6e33ae1bf41e79a

# Replace value with the latest runner-container-hooks release version
# source: https://github.com/actions/runner-container-hooks/releases
# ex: 0.8.0
ARG RUNNER_CONTAINER_HOOKS_VERSION="0.8.0"
ARG RUNNER_CONTAINER_HOOKS_CHECKSUM=0137e405f346ccbf4f5072e9ef94abd0940728b8f69534063879d899457edac3

ARG DISTRO="actions-runner-linux-${RUNNER_ARCH}-${RUNNER_VERSION}.tar.gz"
ARG RELEASE_URL="https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/${DISTRO}"

ARG HOOKS_DISTRO="actions-runner-hooks-k8s-${RUNNER_CONTAINER_HOOKS_VERSION}.zip"
ARG HOOKS_URL="https://github.com/actions/runner-container-hooks/releases/download/v${RUNNER_CONTAINER_HOOKS_VERSION}/${HOOKS_DISTRO}"

ARG RUNNER_ROOT=/usr/local/runner

ARG user=runner
ARG group=runner
ARG home=/home/${user}
ARG uid=1000
ARG gid=1000

ENV RUNNER_USER=$user
ENV RUNNER_HOME=$home

ENV RUNNER_MANUALLY_TRAP_SIG=1
ENV ACTIONS_RUNNER_PRINT_LOG_TO_STDOUT=1
ENV RUNNER_DISABLE_UPDATE=1

USER root

RUN mkdir -p $RUNNER_ROOT
COPY scripts/check.sh $RUNNER_ROOT/check.sh

RUN groupadd -g $gid $group \
  && useradd -d $RUNNER_HOME -u $uid -g $gid -m -s /bin/bash $RUNNER_USER \
  && usermod -aG docker $RUNNER_USER

RUN dnf -y install --enablerepo=crb \
        libicu \
        lttng-ust \
        tar \
        unzip \
        python3.12 \
    && dnf clean all && rm -rf /var/cache/dnf /var/lib/rpm/__db*

WORKDIR $RUNNER_ROOT

RUN set -ex \
    && curl -O -L $RELEASE_URL \
    && echo "${RUNNER_CHECKSUM} ${DISTRO}" | sha256sum -c \
    && tar zxf $DISTRO \
    && rm -f $DISTRO \
    && ./check.sh

RUN set -ex \
    && curl -O -L $HOOKS_URL \
    && echo "${RUNNER_CONTAINER_HOOKS_CHECKSUM} ${HOOKS_DISTRO}" | sha256sum -c \
    && mkdir -p k8s \
    && unzip $HOOKS_DISTRO -d k8s \
    && rm -f $HOOKS_DISTRO

USER $RUNNER_USER
WORKDIR $RUNNER_HOME
