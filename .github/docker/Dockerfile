# syntax=docker/dockerfile:1
# check=skip=SecretsUsedInArgOrEnv
#
# Toolchains every CI job runs inside (#3852), instead of installing them per job. Target
# `ci` serves the non-VM jobs; `ci-vm` adds qemu + Chromium for smoke and the Web-UI tiers.
# The ARG pins here are the single home of each tool version (tests/test_ci_tool_pins.py
# reads them). ci-image.yml tags the images with a hash of this directory plus the Go module's
# go.mod and go.sum (the `gomod` build context), so a change to either yields a new image.

ARG DEBIAN_IMAGE=debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2

# kcov is built from a commit id (immutable, unlike a tag). Its CMakeLists reads the version
# from `git describe` when a .git exists; a commit-only fetch has no tags, so drop .git.
# python3 is a build dependency: kcov generates sources through a Python helper.
FROM ${DEBIAN_IMAGE} AS kcov-builder
ARG KCOV_COMMIT=a39874f938ce13f7a65f253120d1ec946b349ffe
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      binutils-dev ca-certificates cmake g++ git libcurl4-openssl-dev libdw-dev \
      libelf-dev libssl-dev make python3 zlib1g-dev \
 && git init -q /tmp/kcov \
 && git -C /tmp/kcov remote add origin https://github.com/SimonKagstrom/kcov \
 && git -C /tmp/kcov fetch --depth 1 origin "${KCOV_COMMIT}" \
 && git -C /tmp/kcov checkout -q FETCH_HEAD \
 && rm -rf /tmp/kcov/.git \
 && cmake -S /tmp/kcov -B /tmp/kcov/build -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/opt/kcov \
 && cmake --build /tmp/kcov/build --parallel "$(nproc)" \
 && cmake --install /tmp/kcov/build \
 && strip /opt/kcov/bin/kcov /opt/kcov/bin/kcov-system-daemon

FROM ${DEBIAN_IMAGE} AS ci
ARG DEBIAN_FRONTEND=noninteractive

LABEL org.opencontainers.image.source=https://github.com/pfBlockerNG/pfBlockerNG
LABEL org.opencontainers.image.description="pfBlockerNG CI toolchain"

# Default stays C.UTF-8; de_DE.UTF-8 is generated for the specs that select it explicitly.
ENV LANG=C.UTF-8

# sudo: the smoke harness calls `sudo iptables` and kept workflow steps call `sudo`; as root
# it needs no password. docker-cli/-buildx drive the sibling containers the tests start.
# libcurl4t64/libdw1t64/libelf1t64 are kcov's runtime libs. netbase supplies /etc/services
# (getservbyname). patch backs build-webassets.sh. file backs the ADR-45 MIME detection.
# dash is the strict-POSIX shell the shellspec gate pins. mawk must stay the awk. iproute2 is
# the `ip` the dns_proxy tests drive; gcc + libc6-dev give Go the cgo that `go test -race` needs.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      bzip2 ca-certificates curl dash dnsutils docker-buildx docker-cli file gcc git gnupg iproute2 iprange \
      iptables jq libarchive-tools libc6-dev libcurl4t64 libdw1t64 libelf1t64 locales mawk netbase \
      openssh-client patch procps rsync sqlite3 sudo time unzip uuid-runtime xz-utils zstd \
 && rm -rf /var/lib/apt/lists/* \
 && sed -i 's/^# *de_DE.UTF-8 UTF-8/de_DE.UTF-8 UTF-8/' /etc/locale.gen \
 && locale-gen de_DE.UTF-8 \
 && ln -s /usr/bin/rsync /usr/local/bin/rsync

# PHP 8.3/8.4/8.5 side by side from sury (Debian ships one). The signing key is pinned by
# SHA-256: an unverified key would make the whole PHP toolchain trust whatever the URL serves.
# A job picks its leg with `update-alternatives --set php /usr/bin/php<ver>`; an unbaked
# version makes that fail rather than fall back. Default is the lowest supported version.
ARG SURY_ARCHIVE_SHA256=b486fd5488185c4c46467960fa69c53d5085fec492cf76b9eaf3db33561c9d7c
RUN set -eu; \
    curl -fsSLo /tmp/sury.gpg https://packages.sury.org/php/apt.gpg; \
    echo "${SURY_ARCHIVE_SHA256}  /tmp/sury.gpg" | sha256sum -c -; \
    install -D -m 0644 /tmp/sury.gpg /etc/apt/keyrings/sury-php.gpg; \
    rm -f /tmp/sury.gpg; \
    echo 'deb [signed-by=/etc/apt/keyrings/sury-php.gpg] https://packages.sury.org/php/ trixie main' \
      > /etc/apt/sources.list.d/sury-php.list; \
    apt-get update; \
    for v in 8.3 8.4 8.5; do \
      for ext in cgi cli curl intl mbstring pcov sqlite3 xml zip; do set -- "$@" "php${v}-${ext}"; done; \
    done; \
    apt-get install -y --no-install-recommends "$@"; \
    rm -rf /var/lib/apt/lists/*; \
    update-alternatives --install /usr/bin/php php /usr/bin/php8.3 83; \
    update-alternatives --install /usr/bin/php php /usr/bin/php8.4 84; \
    update-alternatives --install /usr/bin/php php /usr/bin/php8.5 85; \
    update-alternatives --set php /usr/bin/php8.3; \
    update-alternatives --set php-cgi /usr/bin/php-cgi8.3

ARG COMPOSER_VERSION=2.10.2
ARG COMPOSER_SHA256=5ee7125f8a30a34d246cefdc0bc85b8a783b28f2aec968994118512350d28027
RUN curl -fsSLo /tmp/composer.phar "https://getcomposer.org/download/${COMPOSER_VERSION}/composer.phar" \
 && echo "${COMPOSER_SHA256}  /tmp/composer.phar" | sha256sum -c - \
 && install -m 0755 /tmp/composer.phar /usr/local/bin/composer \
 && rm -f /tmp/composer.phar

# Python is the uv-managed CPython the project pins (.python-version); `--default` puts
# python/python3/python3.11 in UV_PYTHON_BIN_DIR. Downloads are switched off AFTER the
# install, so a job asking for a Python that is not baked fails instead of fetching one.
ARG UV_VERSION=0.12.6
ARG UV_SHA256=8681d8921e7d520fb368991dcf5f9c1905b80f5bf2a265a0ed085c8d8e342477
ARG PYTHON_VERSION=3.11.15
ARG CHARSET_NORMALIZER_VERSION=3.4.9
ENV UV_PYTHON_INSTALL_DIR=/opt/uv/python \
    UV_PYTHON_BIN_DIR=/usr/local/bin
RUN set -eu; \
    curl -fsSLo /tmp/uv.tar.gz "https://github.com/astral-sh/uv/releases/download/${UV_VERSION}/uv-x86_64-unknown-linux-gnu.tar.gz"; \
    echo "${UV_SHA256}  /tmp/uv.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/uv.tar.gz -C /usr/local/bin --strip-components=1; \
    rm -f /tmp/uv.tar.gz; \
    uv python install "${PYTHON_VERSION}" --default --preview-features python-install-default; \
    uv pip install --no-cache --system --break-system-packages "charset-normalizer==${CHARSET_NORMALIZER_VERSION}"
ENV UV_PYTHON_DOWNLOADS=never

ARG GO_VERSION=1.27.0
ARG GO_SHA256=675c26c449cbb18fc24b74650de1eabbae6e16f64326fd85a283fb3b58280685
ARG NODE_VERSION=24.19.0
ARG NODE_SHA256=14b342e71204f811bde6153be8e04b62aef63c236fef92b55f9c83154b409647
RUN set -eu; \
    curl -fsSLo /tmp/go.tar.gz "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz"; \
    echo "${GO_SHA256}  /tmp/go.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/go.tar.gz -C /usr/local; \
    curl -fsSLo /tmp/node.tar.xz "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz"; \
    echo "${NODE_SHA256}  /tmp/node.tar.xz" | sha256sum -c -; \
    tar -xJf /tmp/node.tar.xz -C /usr/local --strip-components=1 --no-same-owner; \
    rm -f /tmp/go.tar.gz /tmp/node.tar.xz

# Release ASSETS pinned by SHA-256: apt would re-pin a lint verdict to whatever the base
# ships (#2185), and a source archive is generated on demand from a tag, so its bytes are
# not stable (#2194).
ARG SHELLCHECK_VERSION=v0.11.0
ARG SHELLCHECK_SHA256=8c3be12b05d5c177a04c29e3c78ce89ac86f1595681cab149b65b97c4e227198
ARG SHELLSPEC_VERSION=0.28.1
ARG SHELLSPEC_SHA256=350d3de04ba61505c54eda31a3c2ee912700f1758b1a80a284bc08fd8b6c5992
ARG ACTIONLINT_VERSION=1.7.12
ARG ACTIONLINT_SHA256=8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8
ARG ORAS_VERSION=1.3.3
ARG ORAS_SHA256=9ce999f8d2de03fc03968b29d743077a58783e545e5eaa53917ca177352d0e59
ARG GH_VERSION=2.103.3
ARG GH_SHA256=4c806978ffce1cec70853302a56d70ac6da4f19bae7adca4e1a8ab00633dd91d
RUN set -eu; \
    fetch() { curl -fsSLo "/tmp/$1" "$2"; echo "$3  /tmp/$1" | sha256sum -c -; }; \
    fetch shellcheck.tar.xz "https://github.com/koalaman/shellcheck/releases/download/${SHELLCHECK_VERSION}/shellcheck-${SHELLCHECK_VERSION}.linux.x86_64.tar.xz" "${SHELLCHECK_SHA256}"; \
    tar -xJf /tmp/shellcheck.tar.xz -C /tmp "shellcheck-${SHELLCHECK_VERSION}/shellcheck"; \
    install -m 0755 "/tmp/shellcheck-${SHELLCHECK_VERSION}/shellcheck" /usr/local/bin/shellcheck; \
    fetch shellspec-dist.tar.gz "https://github.com/shellspec/shellspec/releases/download/${SHELLSPEC_VERSION}/shellspec-dist.tar.gz" "${SHELLSPEC_SHA256}"; \
    tar -xzf /tmp/shellspec-dist.tar.gz -C /opt; \
    ln -s /opt/shellspec/shellspec /usr/local/bin/shellspec; \
    fetch actionlint.tar.gz "https://github.com/rhysd/actionlint/releases/download/v${ACTIONLINT_VERSION}/actionlint_${ACTIONLINT_VERSION}_linux_amd64.tar.gz" "${ACTIONLINT_SHA256}"; \
    tar -xzf /tmp/actionlint.tar.gz -C /usr/local/bin actionlint; \
    fetch oras.tar.gz "https://github.com/oras-project/oras/releases/download/v${ORAS_VERSION}/oras_${ORAS_VERSION}_linux_amd64.tar.gz" "${ORAS_SHA256}"; \
    tar -xzf /tmp/oras.tar.gz -C /usr/local/bin oras; \
    fetch gh.tar.gz "https://github.com/cli/cli/releases/download/v${GH_VERSION}/gh_${GH_VERSION}_linux_amd64.tar.gz" "${GH_SHA256}"; \
    tar -xzf /tmp/gh.tar.gz -C /usr/local/bin --strip-components=2 "gh_${GH_VERSION}_linux_amd64/bin/gh"; \
    rm -rf /tmp/shellcheck* /tmp/shellspec-dist.tar.gz /tmp/actionlint.tar.gz /tmp/oras.tar.gz /tmp/gh.tar.gz

COPY --from=kcov-builder /opt/kcov /opt/kcov
ENV PATH=/usr/local/go/bin:/opt/kcov/bin:${PATH}

# Go's modules are baked in. Settings go in $GOROOT/go.env: sudo drops env vars, container jobs have
# another HOME and build-pfb-dns.py sets GOENV=off, but all still read it. `|direct` also falls back
# on a proxy transport error, where `,direct` only does on 404/410.
COPY --from=gomod go.mod go.sum /tmp/gomod/
RUN set -eu; \
    sed -i 's#^GOPROXY=.*#GOPROXY=https://proxy.golang.org|direct#' /usr/local/go/go.env; \
    grep -qx 'GOPROXY=https://proxy.golang.org|direct' /usr/local/go/go.env; \
    echo 'GOMODCACHE=/opt/go/pkg/mod' >> /usr/local/go/go.env; \
    cd /tmp/gomod; \
    go mod download; \
    [ "$(go env GOMODCACHE)" = /opt/go/pkg/mod ]; \
    GOPROXY=off go mod download; \
    cd /; \
    rm -rf /tmp/gomod; \
    go clean -cache

# The job workspace directory belongs to the runner's uid, not root; without this git refuses
# the "dubious ownership" repository. The ENV copy is command-scope config, which survives the
# tests that neutralise system and global config (GIT_CONFIG_SYSTEM=/dev/null).
RUN git config --system --add safe.directory '*'
ENV GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory GIT_CONFIG_VALUE_0=*

# Fail the BUILD, not the first red job, when a baked tool cannot run. Every line must be
# able to FAIL: nothing is piped into `head` (a pipeline reports its LAST status and POSIX
# sh has no pipefail), and `! cmd` is not used because errexit ignores a negated command.
RUN set -eu; \
    for tool in bsdtar bzip2 curl dash dig docker file gcc git gpg ip iprange iptables jq patch ps \
                rsync sqlite3 ssh sudo unzip uuidgen xz zstd; do \
      command -v "$tool" >/dev/null || { echo "missing: $tool" >&2; exit 1; }; \
    done; \
    [ -x /usr/bin/time ]; \
    sudo true; \
    docker --version; docker buildx version; dig -v; ssh -V; iptables --version; gpg --version; \
    echo '10.0.0.0/8' | iprange >/dev/null; \
    bsdtar --version | grep -q '^bsdtar'; \
    /usr/local/bin/rsync --version | grep -qi '^rsync'; \
    readlink -f "$(command -v awk)" | grep -q 'mawk$'; \
    LC_ALL=de_DE.UTF-8 locale charmap | grep -qx UTF-8; \
    LC_ALL=de_DE.UTF-8 awk 'BEGIN { printf "%.2f", 1.5 }' | grep -q ','; \
    for v in 8.3 8.4 8.5; do \
      for ext in curl intl mbstring pcov sqlite3; do "php${v}" -m | grep -qx "$ext"; done; \
      "php-cgi${v}" -v; \
    done; \
    [ "$(readlink -f /usr/bin/php-cgi)" = /usr/bin/php-cgi8.3 ]; \
    if update-alternatives --set php /usr/bin/php9.9; then echo "php9.9 is not baked but was selectable" >&2; exit 1; fi; \
    php -r 'getservbyname("domain", "udp") === 53 or exit(1);'; \
    php -r 'new SQLite3(":memory:");'; \
    composer --version --no-ansi | grep -q "^Composer version ${COMPOSER_VERSION} "; \
    uv --version | grep -q "^uv ${UV_VERSION} "; \
    for py in python python3 python3.11; do \
      "$py" -c 'import sys, charset_normalizer; v = ".".join(map(str, sys.version_info[:3])); assert v == sys.argv[1], v; assert charset_normalizer.__version__ == sys.argv[2]' \
        "${PYTHON_VERSION}" "${CHARSET_NORMALIZER_VERSION}"; \
    done; \
    python3 -m venv /tmp/v; rm -rf /tmp/v; \
    go version | grep -q " go${GO_VERSION} "; \
    [ "$(go env CGO_ENABLED)" = 1 ]; \
    [ "$(node --version)" = "v${NODE_VERSION}" ]; \
    shellcheck --version | grep -qx "version: ${SHELLCHECK_VERSION#v}"; \
    [ "$(shellspec --version)" = "${SHELLSPEC_VERSION}" ]; \
    [ "$(actionlint -version | sed -n 1p)" = "${ACTIONLINT_VERSION}" ]; \
    oras version | grep -Eq "^Version:[[:space:]]+${ORAS_VERSION}\$"; \
    gh --version | grep -q "^gh version ${GH_VERSION} "; \
    kcov --version; \
    mkdir /tmp/repo; git init -q /tmp/repo; chown -R 1001:1001 /tmp/repo; git -C /tmp/repo status >/dev/null; \
    GIT_CONFIG_SYSTEM=/dev/null GIT_CONFIG_GLOBAL=/dev/null git -C /tmp/repo status >/dev/null; rm -rf /tmp/repo

FROM ci AS ci-vm
ARG DEBIAN_FRONTEND=noninteractive
ARG PLAYWRIGHT_VERSION=1.61.0

# qemu boots the pfSense guest (boot_vm.sh needs /dev/kvm passed into the job container).
RUN apt-get update \
 && apt-get install -y --no-install-recommends qemu-system-x86 qemu-utils \
 && rm -rf /var/lib/apt/lists/*

# `--with-deps` runs apt itself, so the package lists must exist in THIS layer. The fixed
# browsers path lets the project's own pinned playwright (uv.lock) find the build at runtime.
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/playwright
RUN apt-get update \
 && UV_CACHE_DIR=/tmp/uv-cache UV_TOOL_DIR=/tmp/uv-tools \
    uvx --from "playwright==${PLAYWRIGHT_VERSION}" playwright install --with-deps chromium \
 && rm -rf /var/lib/apt/lists/* /tmp/uv-cache /tmp/uv-tools

# A bare executable_path read passes with no browser installed; launching and rendering cannot.
COPY check-chromium.py /tmp/check-chromium.py
RUN set -eu; \
    qemu-system-x86_64 --version; \
    qemu-img --version; \
    UV_CACHE_DIR=/tmp/uv-cache uv run --no-project --with "playwright==${PLAYWRIGHT_VERSION}" python /tmp/check-chromium.py; \
    rm -rf /tmp/check-chromium.py /tmp/uv-cache

# Unbound for the two suites that run it in Docker (acl_oracle_test.go, tests/dns_proxy/test_integration_unbound.py).
# The apt line is the one each suite's own self-build recipe uses, so a local run tests the same Unbound.
FROM ${DEBIAN_IMAGE} AS unbound
ARG DEBIAN_FRONTEND=noninteractive
LABEL org.opencontainers.image.source=https://github.com/pfBlockerNG/pfBlockerNG
LABEL org.opencontainers.image.description="pfBlockerNG CI Unbound (Go ACL oracle)"
RUN apt-get update \
 && apt-get install -y --no-install-recommends unbound \
 && rm -rf /var/lib/apt/lists/*

FROM ${DEBIAN_IMAGE} AS unbound-py
ARG DEBIAN_FRONTEND=noninteractive
LABEL org.opencontainers.image.source=https://github.com/pfBlockerNG/pfBlockerNG
LABEL org.opencontainers.image.description="pfBlockerNG CI Unbound with python3-unbound (dns_proxy integration tests)"
RUN apt-get update \
 && apt-get install -y --no-install-recommends unbound python3-unbound \
 && rm -rf /var/lib/apt/lists/*
