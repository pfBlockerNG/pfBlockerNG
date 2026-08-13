# syntax=docker/dockerfile:1
#
# pfBlockerNG CI runner image — the toolchain every workflow job that does NOT drive a
# VM runs inside (issue #2214). It replaces the per-job `setup-python` / `setup-php` /
# `setup-node` / `apt-get install` / release-tarball-download dance: the same tools, the
# same pins, installed once at image build instead of on every job on every run.
#
# Two rules hold this file together:
#
#   1. Everything is pinned and verified. Base images by digest, release assets by
#      SHA-256, kcov by commit id (a commit IS a checksum), the sury archive by its
#      signing key's SHA-256. A gate is only as trustworthy as the tool that decides it.
#   2. The PHP and Python versions are the SUPPORTED-VERSION MATRIX, not a local opinion.
#      supported-versions.json (origin/ci-metadata) is the single source of truth;
#      tests/test_ci_runner_images.py fails the moment this file and the matrix disagree.
#
# Build context is the repository root (ci-requirements.txt is read from .github/docker/).
# Bump .github/docker/VERSION with any change here — published tags are immutable.

ARG DEBIAN_IMAGE=debian:13.6-slim@sha256:3a39a0592364683e6bab97937b72cad5a8fa6dcbbee90edb3bb48c7f8e94f258
# Matrix python (py311 on every supported pfSense). Relocated to /opt/python/<ver> below,
# which CPython handles: it derives sys.prefix from the interpreter's own path.
ARG PYTHON_311_IMAGE=python:3.11-slim-trixie@sha256:94c50be2dc994b873b55bc123e95e6dbade08095b3dfd790f51c34de3f08cbb7
# Node LTS ("lts/*" is what actions/setup-node resolved for the markdownlint, widget-JS
# and webassets jobs; pinning it here also removes their dependency on GitHub's LTS
# manifest API, which has served 503s for whole hours).
ARG NODE_IMAGE=node:24.19.0-trixie-slim@sha256:0711b541c1c33a8a530ac4f0d391baa9a15b3d804695b1b24a47daa5fb60e74d

FROM ${PYTHON_311_IMAGE} AS python-3.11
FROM ${NODE_IMAGE} AS node

# ── kcov (informational shell coverage) ──────────────────────────────────────────────
# Built here so the runtime image carries only the binary, and so CI stops paying for the
# compile + the cache-restore dance that guarded it. KCOV_COMMIT is the commit tag v43
# pointed at when the pin was taken: fetched BY COMMIT, so a re-tag upstream cannot change
# what gets built. kcov's CMakeLists takes its version from `git describe` when a .git is
# present, and a commit-only shallow fetch has no tags — hence dropping .git first.
# python3 is a BUILD dependency: kcov generates several .cc sources through a Python
# helper, which the GitHub runner image happened to satisfy and a slim base does not.
FROM ${DEBIAN_IMAGE} AS kcov-builder
ARG KCOV_COMMIT=a39874f938ce13f7a65f253120d1ec946b349ffe
ENV DEBIAN_FRONTEND=noninteractive
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

# ── the runner image ─────────────────────────────────────────────────────────────────
FROM ${DEBIAN_IMAGE}

# Set by BuildKit from the target platform (amd64 / arm64), and declared here so it is in
# scope for the prebuilt-binary downloads further down — those are the only steps that
# cannot be architecture-agnostic (#2256). Everything above resolves per-arch on its own:
# the base digests are OCI indexes, apt and pip select by architecture, and kcov is
# compiled from source. Declaring it here also means a platform change invalidates the
# cache for exactly those layers.
ARG TARGETARCH

LABEL org.opencontainers.image.source=https://github.com/pfBlockerNG/pfBlockerNG
LABEL org.opencontainers.image.description="pfBlockerNG CI toolchain (non-VM workflows)"

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore

# Base tooling. jq drives the ip_pre_AWS_*.sh region filters and read-version-matrix.sh;
# dash is the strict-POSIX shell the shellspec gate pins (bash-as-sh masks ash
# divergences); iprange is the FireHOL set-subtraction tool ADR-53 P3 exercises; zstd is
# actions/cache's compressor; sudo keeps the workflow steps that call it working
# unchanged. libcurl4/libelf1/libdw1 are kcov's runtime libs, the rest are the shared
# objects the relocated CPython links against. Three are load-bearing in non-obvious ways:
# `patch` runs in scripts/build-webassets.sh, `file` backs the ADR-45 MIME detection that
# pfb_download() shells out to, and `netbase` supplies /etc/services, without which
# getservbyname() returns false and the is_port() parity tests fail. gnupg is deliberately
# absent: apt verifies the sury archive with its own gpgv against a keyring file.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      bzip2 ca-certificates curl file git iprange jq less libbz2-1.0 libcurl4 libdw1 \
      libelf1 libexpat1 libffi8 libgdbm-compat4t64 libgdbm6t64 liblzma5 libncursesw6 \
      libreadline8t64 libsqlite3-0 libssl3t64 netbase patch procps rsync sqlite3 sudo tar time unzip \
      locales uuid-runtime xz-utils zlib1g zstd \
 && rm -rf /var/lib/apt/lists/*

# Keep the process-wide default C.UTF-8, but provide the German UTF-8 locale for
# collation/decimal-separator contracts that explicitly select it.
RUN sed -i 's/^# *de_DE.UTF-8 UTF-8/de_DE.UTF-8 UTF-8/' /etc/locale.gen \
 && locale-gen de_DE.UTF-8

# ── PHP (matrix: 8.3 + 8.5) ──────────────────────────────────────────────────────────
# Debian 13 ships one PHP; the matrix needs two, side by side, so the php-syntax,
# PHPStan, PHPCS and PHPUnit legs can each select their own. sury is the standard Debian
# multi-version archive; its signing key is fetched once and pinned by SHA-256 (an
# unverified key would make the whole PHP toolchain trust whatever that URL served).
# Extensions match what shivammathur/setup-php was asked for: curl, intl, mbstring
# (ctype/filter/json live in php*-common), plus xml + zip for composer/PHPUnit and pcov
# for the informational coverage run.
ARG SURY_ARCHIVE_DIGEST=b486fd5488185c4c46467960fa69c53d5085fec492cf76b9eaf3db33561c9d7c
RUN curl -fsSLo /tmp/sury.gpg https://packages.sury.org/php/apt.gpg \
 && echo "${SURY_ARCHIVE_DIGEST}  /tmp/sury.gpg" | sha256sum -c - \
 && install -D -m 0644 /tmp/sury.gpg /etc/apt/keyrings/sury-php.gpg \
 && rm -f /tmp/sury.gpg \
 && echo 'deb [signed-by=/etc/apt/keyrings/sury-php.gpg] https://packages.sury.org/php/ trixie main' \
      > /etc/apt/sources.list.d/sury-php.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
      php8.3-cli php8.3-curl php8.3-intl php8.3-mbstring php8.3-pcov php8.3-sqlite3 php8.3-xml php8.3-zip \
      php8.5-cli php8.5-curl php8.5-intl php8.5-mbstring php8.5-pcov php8.5-sqlite3 php8.5-xml php8.5-zip \
 && rm -rf /var/lib/apt/lists/*

# Each matrix PHP is selectable through the `php` alternative; a job picks its leg's
# version with `update-alternatives --set php /usr/bin/php<ver>`. The default is the
# LOWEST supported version, so anything that forgets to select still runs on a version
# the matrix actually ships.
RUN update-alternatives --install /usr/bin/php php /usr/bin/php8.3 83 \
 && update-alternatives --install /usr/bin/php php /usr/bin/php8.5 85 \
 && update-alternatives --set php /usr/bin/php8.3

# composer, pinned and verified (setup-php's `tools: composer` fetched a floating one).
ARG COMPOSER_VERSION=2.10.2
ARG COMPOSER_SHA256=5ee7125f8a30a34d246cefdc0bc85b8a783b28f2aec968994118512350d28027
RUN curl -fsSLo /tmp/composer.phar "https://getcomposer.org/download/${COMPOSER_VERSION}/composer.phar" \
 && echo "${COMPOSER_SHA256}  /tmp/composer.phar" | sha256sum -c - \
 && install -m 0755 /tmp/composer.phar /usr/local/bin/composer \
 && rm -f /tmp/composer.phar

# ── Node (LTS) ───────────────────────────────────────────────────────────────────────
COPY --from=node /usr/local /usr/local
# markdownlint-cli2 is invoked as `npx --yes markdownlint-cli2`; a global install makes
# that resolve locally instead of hitting the npm registry on every run.
ARG MARKDOWNLINT_CLI2_VERSION=0.23.2
RUN npm install -g --no-audit --no-fund "markdownlint-cli2@${MARKDOWNLINT_CLI2_VERSION}" \
 && npm cache clean --force

# ── Python (matrix: 3.11) ────────────────────────────────────────────────────────────
# One directory per matrix version so a second python can be added without collision; a
# job selects its leg by prepending /opt/python/<ver>/bin to the PATH. The lowest
# supported version is the default `python3`, matching the appliance's py311.
COPY --from=python-3.11 /usr/local /opt/python/3.11
# The default version's bin/ goes on PATH, not just its interpreter: pip installs console
# scripts (ruff, mypy, pytest, playwright) there, and the workflows invoke those by bare
# name. A job selecting another matrix python prepends that version's bin/ the same way.
ENV PATH=/opt/python/3.11/bin:${PATH}
RUN ln -sf /opt/python/3.11/bin/python3.11 /usr/local/bin/python3.11 \
 && ln -sf /opt/python/3.11/bin/python3.11 /usr/local/bin/python3 \
 && ln -sf /opt/python/3.11/bin/python3.11 /usr/local/bin/python \
 && ln -sf /opt/python/3.11/bin/pip3.11 /usr/local/bin/pip3 \
 && ln -sf /opt/python/3.11/bin/pip3.11 /usr/local/bin/pip

# The Python test/lint toolchain the workflows install per job. Pins live in
# ci-requirements.txt next to this file (ruff and dnspython carry the repo's own pins;
# the rest were floating `pip install <name>` calls, frozen here at what CI resolved).
COPY .github/docker/ci-requirements.txt /opt/ci-requirements.txt
RUN python3 -m pip install --no-cache-dir -r /opt/ci-requirements.txt

# ── ShellCheck + shellspec ───────────────────────────────────────────────────────────
# Pinned release ASSETS verified by SHA-256, exactly as the workflow steps did: apt would
# re-pin the lint verdict to whatever the base image ships (#2185), and a source archive
# is generated on demand from the tag, so its bytes are not stable (#2194).
#
# PER-ARCHITECTURE (#2256). Upstream ships one tarball per architecture, so one hash can
# only ever verify one of them — each arch carries its own pin, and an arch this file has
# no pin for fails the build instead of silently installing an unverified or wrong-arch
# binary. ShellCheck names its arches x86_64/aarch64 while Docker's TARGETARCH says
# amd64/arm64, hence the mapping rather than a direct interpolation.
ARG SHELLCHECK_VERSION=v0.11.0
ARG SHELLCHECK_SHA256_AMD64=8c3be12b05d5c177a04c29e3c78ce89ac86f1595681cab149b65b97c4e227198
ARG SHELLCHECK_SHA256_ARM64=12b331c1d2db6b9eb13cfca64306b1b157a86eb69db83023e261eaa7e7c14588
RUN set -eu; \
    case "${TARGETARCH}" in \
      amd64) sc_arch=x86_64;  sc_sha="${SHELLCHECK_SHA256_AMD64}" ;; \
      arm64) sc_arch=aarch64; sc_sha="${SHELLCHECK_SHA256_ARM64}" ;; \
      *) echo "ShellCheck: no pinned asset for TARGETARCH=${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSLo /tmp/shellcheck.tar.xz \
      "https://github.com/koalaman/shellcheck/releases/download/${SHELLCHECK_VERSION}/shellcheck-${SHELLCHECK_VERSION}.linux.${sc_arch}.tar.xz"; \
    echo "${sc_sha}  /tmp/shellcheck.tar.xz" | sha256sum -c -; \
    tar -xJf /tmp/shellcheck.tar.xz -C /tmp "shellcheck-${SHELLCHECK_VERSION}/shellcheck"; \
    install -m 0755 "/tmp/shellcheck-${SHELLCHECK_VERSION}/shellcheck" /usr/local/bin/shellcheck; \
    rm -rf /tmp/shellcheck.tar.xz "/tmp/shellcheck-${SHELLCHECK_VERSION}"

# The GitHub CLI. Twelve workflows drive `gh api` / `gh pr` / `gh run` (the refresh jobs,
# the version tracker, the nightly alerting, the release flow); it is preinstalled on the
# GitHub-hosted runner images and would simply be MISSING inside a container, so the
# migration in #2215 depends on it being here. Pinned release asset, verified like the rest.
ARG GH_VERSION=2.97.0
ARG GH_SHA256_AMD64=a2c9b8497e1f85b1ad0dfcb78b5a622e098801b8e461e459e88e1ee12f018112
ARG GH_SHA256_ARM64=73ea440ecad9c9e284429997ee6f93577bc6f7bc6fba357ef62c53ad8fb641a5
RUN set -eu; \
    case "${TARGETARCH}" in \
      amd64) gh_sha="${GH_SHA256_AMD64}" ;; \
      arm64) gh_sha="${GH_SHA256_ARM64}" ;; \
      *) echo "gh: no pinned asset for TARGETARCH=${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSLo /tmp/gh.tar.gz \
      "https://github.com/cli/cli/releases/download/v${GH_VERSION}/gh_${GH_VERSION}_linux_${TARGETARCH}.tar.gz"; \
    echo "${gh_sha}  /tmp/gh.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/gh.tar.gz -C /tmp "gh_${GH_VERSION}_linux_${TARGETARCH}/bin/gh"; \
    install -m 0755 "/tmp/gh_${GH_VERSION}_linux_${TARGETARCH}/bin/gh" /usr/local/bin/gh; \
    rm -rf /tmp/gh.tar.gz "/tmp/gh_${GH_VERSION}_linux_${TARGETARCH}"

# actionlint validates the workflow files themselves (the `actionlint` job in
# test.yml): GitHub silently disables a workflow whose YAML its parser rejects —
# a duplicate mapping key killed five scheduled workflows before any gate saw it
# (issue #2231). Baked here (#2232) so the job stops re-downloading it per run.
ARG ACTIONLINT_VERSION=1.7.12
ARG ACTIONLINT_SHA256_AMD64=8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8
ARG ACTIONLINT_SHA256_ARM64=325e971b6ba9bfa504672e29be93c24981eeb1c07576d730e9f7c8805afff0c6
RUN set -eu; \
    case "${TARGETARCH}" in \
      amd64) al_sha="${ACTIONLINT_SHA256_AMD64}" ;; \
      arm64) al_sha="${ACTIONLINT_SHA256_ARM64}" ;; \
      *) echo "actionlint: no pinned asset for TARGETARCH=${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSLo /tmp/actionlint.tar.gz \
      "https://github.com/rhysd/actionlint/releases/download/v${ACTIONLINT_VERSION}/actionlint_${ACTIONLINT_VERSION}_linux_${TARGETARCH}.tar.gz"; \
    echo "${al_sha}  /tmp/actionlint.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/actionlint.tar.gz -C /tmp actionlint; \
    install -m 0755 /tmp/actionlint /usr/local/bin/actionlint; \
    rm -f /tmp/actionlint.tar.gz /tmp/actionlint

ARG SHELLSPEC_VERSION=0.28.1
ARG SHELLSPEC_SHA256=350d3de04ba61505c54eda31a3c2ee912700f1758b1a80a284bc08fd8b6c5992
RUN curl -fsSLo /tmp/shellspec-dist.tar.gz \
      "https://github.com/shellspec/shellspec/releases/download/${SHELLSPEC_VERSION}/shellspec-dist.tar.gz" \
 && echo "${SHELLSPEC_SHA256}  /tmp/shellspec-dist.tar.gz" | sha256sum -c - \
 && tar -xzf /tmp/shellspec-dist.tar.gz -C /opt \
 && rm -f /tmp/shellspec-dist.tar.gz \
 && ln -s /opt/shellspec/shellspec /usr/local/bin/shellspec

COPY --from=kcov-builder /opt/kcov /opt/kcov
ENV PATH=/opt/kcov/bin:${PATH}

# actions/checkout writes the workspace as root while the runner may probe it as another
# uid; without this git refuses the "dubious ownership" repository and every git-reading
# gate (version-literal tripwire, parity-guard, webassets drift) fails on checkout.
RUN git config --system --add safe.directory '*'

# Fail the BUILD, not the first red job, when a copied toolchain cannot actually run.
# LC_NUMERIC=de_DE.UTF-8 formatting is proven through awk because shell printf differs:
# the relocated CPython needs its shared libs present, and each PHP its extensions.
# Every line here must be able to FAIL. Nothing is piped into `head`: a shell reports a
# pipeline's LAST exit status and there is no `pipefail` in POSIX sh, so `tool --version |
# head -n1` succeeds even when the tool is missing entirely. iprange is checked by giving
# it real input rather than `--version`, which it exits 1 on by design.
RUN set -eu; \
    python3 -c 'import bz2, ctypes, lzma, readline, sqlite3, ssl, uuid, zlib'; \
    python3 --version; \
    ruff --version; mypy --version; pytest --version; \
    for php in php8.3 php8.5; do \
      "$php" -v >/dev/null; \
      "$php" -m | grep -qx curl; \
      "$php" -m | grep -qx intl; \
      "$php" -m | grep -qx mbstring; \
      "$php" -m | grep -qx pcov; \
    done; \
    composer --version; node --version; npm --version; gh --version; \
    shellcheck --version; shellspec --version; kcov --version; actionlint -version; \
    jq --version; dash -c 'exit 0'; \
    echo '10.0.0.0/8' | iprange >/dev/null; \
    printf 'x' | bzip2 -c | bzip2 -dc >/dev/null; \
    printf 'SELECT 1;' | sqlite3 :memory: >/dev/null; \
    /usr/bin/time -f '%e' true 2>/dev/null; \
    file --version; \
    php -r 'new SQLite3(":memory:");'; \
    php -r 'getservbyname("domain", "udp") === 53 or exit(1);'; \
    LC_ALL=de_DE.UTF-8 locale charmap | grep -qx UTF-8; \
    LC_ALL=de_DE.UTF-8 locale -k LC_NUMERIC | grep -Fq 'decimal_point=","'

CMD ["/bin/bash"]
