ARG rocky=10.1.20251126
ARG image=docker
FROM ghcr.io/aursu/rpmbuild:${rocky}-${image}

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

ARG dest=/usr/local/runner
ARG user=runner
ARG group=runner
ARG home=/home/${user}
ARG uid=1000
ARG gid=1000

# Runtime environment variables (used by runner.py and Runner.Listener)
ENV RUNNER_HOME=$home
ENV RUNNER_ROOT=$dest

# Force python unbuffered output for real-time logging
ENV PYTHONUNBUFFERED=1
ENV ACTIONS_RUNNER_PRINT_LOG_TO_STDOUT=1
ENV RUNNER_DISABLE_UPDATE=1
ENV ACTIONS_RUNNER_CONTAINER_HOOKS=$RUNNER_ROOT/k8s
ENV GITHUB_API_RETRIES=5
ENV GITHUB_API_BACKOFF=1.5

USER root

# Install dependencies
# Note: Ensure python3.12 is available in your Rocky repo, otherwise use python3.11 or platform default
RUN dnf -y install --enablerepo=crb \
        libicu \
        lttng-ust \
        tar \
        unzip \
        python3.12 \
    && dnf clean all && rm -rf /var/cache/dnf /var/lib/rpm/__db*

# Setup User and Groups
RUN groupadd -g $gid $group \
  && useradd -d $home -u $uid -g $gid -m -s /bin/bash $user \
  && usermod -aG docker $user

# Prepare Destination
WORKDIR $dest

# Use ARG (build-time) for COPY since path is fixed at build time
COPY --chmod=755 scripts/check.sh $dest/check.sh
COPY --chmod=755 scripts/runner.py $dest/runner.py

RUN chown -R $user:$group $dest

USER $user

# Install Runner Binary
RUN set -ex \
    && curl -O -L $RELEASE_URL \
    && echo "${RUNNER_CHECKSUM} ${DISTRO}" | sha256sum -c \
    && tar zxf $DISTRO \
    && rm -f $DISTRO \
    && ./check.sh

# Install K8s Hooks
RUN set -ex \
    && curl -O -L $HOOKS_URL \
    && echo "${RUNNER_CONTAINER_HOOKS_CHECKSUM} ${HOOKS_DISTRO}" | sha256sum -c \
    && mkdir -p k8s \
    && unzip $HOOKS_DISTRO -d k8s \
    && rm -f $HOOKS_DISTRO

# Final Setup
WORKDIR $home
CMD ["/usr/local/runner/runner.py", "run"]
