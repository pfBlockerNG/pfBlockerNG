# Offline audit image for Anthropic's OSS Scanner (https://github.com/anthropics/oss-scanner).
# The scanner builds this with the repository root as the context; the network is cut afterwards,
# so everything the test suites need is fetched here. It mirrors the `test.yml` CI jobs: Ubuntu
# 24.04 is the runner image, and current PHP 8.3 (Ondřej Surý's PPA, as setup-php uses) is the
# lowest supported PHP.
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive \
    UV_PYTHON_INSTALL_DIR=/opt/uv-python \
    UV_LINK_MODE=copy

RUN apt-get update && apt-get install -y --no-install-recommends software-properties-common gpg-agent \
    && add-apt-repository -y ppa:ondrej/php \
    && apt-get install -y --no-install-recommends \
      ca-certificates curl git jq dash mawk locales iprange rsync libarchive-tools netbase python3 \
      file bzip2 xz-utils zstd openssh-client \
      php8.3-cli php8.3-curl php8.3-intl php8.3-mbstring php8.3-xml php8.3-sqlite3 php8.3-zip composer \
    && rm -rf /var/lib/apt/lists/* \
    && update-alternatives --set awk /usr/bin/mawk \
    && sed -i -E 's/^# *((de_DE|en_US).UTF-8)/\1/' /etc/locale.gen && locale-gen \
    # The appliance runs FreeBSD sh (pipefail) and libarchive's unzip at /usr/bin/unzip; CI does the same.
    && ln -sf bash /bin/sh \
    && ln -sf bsdunzip /usr/bin/unzip \
    && ln -sf /usr/bin/rsync /usr/local/bin/rsync

COPY --from=ghcr.io/astral-sh/uv:0.12 /uv /usr/local/bin/uv

ARG SHELLSPEC_VERSION=0.28.1
ARG SHELLSPEC_SHA256=350d3de04ba61505c54eda31a3c2ee912700f1758b1a80a284bc08fd8b6c5992
RUN curl -fsSLo /tmp/shellspec.tar.gz \
      "https://github.com/shellspec/shellspec/releases/download/${SHELLSPEC_VERSION}/shellspec-dist.tar.gz" \
    && echo "${SHELLSPEC_SHA256}  /tmp/shellspec.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/shellspec.tar.gz -C /opt && rm /tmp/shellspec.tar.gz \
    && ln -s /opt/shellspec/shellspec /usr/local/bin/shellspec

# scanner contract: the checkout lives inside the image, at /src
COPY . /src
WORKDIR /src

# Python 3.11 (the appliance minor) plus the locked dev group, and the locked PHP dependencies.
RUN uv sync --locked --group dev && composer install --no-interaction --prefer-dist --no-progress
ENV PATH=/src/.venv/bin:$PATH

# Smoke the image without failing the build. Full suites, offline:
#   pytest  |  vendor/bin/phpunit  |  shellspec --shell /usr/bin/dash
RUN (vendor/bin/phpunit --no-progress >/tmp/phpunit.log 2>&1 && echo "phpunit: ok" \
      || { tail -n 30 /tmp/phpunit.log; echo "WARNING: phpunit reported failures"; }) \
    && (shellspec --shell /usr/bin/dash >/tmp/shellspec.log 2>&1 && echo "shellspec: ok" \
      || { tail -n 30 /tmp/shellspec.log; echo "WARNING: shellspec reported failures"; })
