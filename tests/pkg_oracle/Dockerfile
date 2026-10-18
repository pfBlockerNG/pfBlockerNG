FROM debian:trixie-slim
# Real Unbound with its python bindings (the proxy forwards to it), PHP for the package's own code and the pinned pfSense core
# functions, and the shared libraries the FreeBSD pkg built by build.sh links against.
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
    unbound python3-unbound python3 php-cli php-curl php-intl php-mbstring php-sqlite3 php-xml php-zip \
    libarchive-tools procps bsdutils libarchive13t64 libssl3t64 libbsd0 libelf1t64 libzstd1 liblzma5 zlib1g libmd0 \
    && rm -rf /var/lib/apt/lists/*
COPY prefix /work/prefix
COPY shims/daemon /usr/sbin/daemon
COPY shims/lockf /usr/bin/lockf
COPY shims/read_xml_tag.sh /usr/local/sbin/read_xml_tag.sh
RUN chmod +x /usr/sbin/daemon /usr/bin/lockf /usr/local/sbin/read_xml_tag.sh \
    && mkdir -p /opt/pybin /var/log/pfblockerng /var/unbound /usr/local/etc/rc.d \
    && ln -sf /usr/bin/python3 /opt/pybin/python3.13 \
    && (id unbound >/dev/null 2>&1 || useradd -r unbound)
