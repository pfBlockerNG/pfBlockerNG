#!/bin/sh
# build.sh OUT_DIR -- fetch the pinned pfSense core files, build FreeBSD pkg from source, build the oracle image.
# Needs docker and network. Everything lands in OUT_DIR (core/, prefix/, ctx/); nothing on the host is installed or changed.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
[ $# -eq 1 ] || { echo "usage: build.sh OUT_DIR" >&2; exit 2; }
out=$1
mkdir -p "$out/core"
out=$(cd "$out" && pwd)
. "$here/PINS"

fetch_verified() { # url dest sha256
	[ -f "$2" ] && [ "$(sha256sum "$2" | cut -d' ' -f1)" = "$3" ] && return 0
	curl -fsSL "$1" -o "$2"
	[ "$(sha256sum "$2" | cut -d' ' -f1)" = "$3" ] || { echo "build.sh: $2 does not match its pinned sha256" >&2; exit 1; }
}

for file in $CORE_FILES; do
	key=$(printf '%s' "$file" | tr '.-' '__')
	for label in master:$PFSENSE_MASTER r272:$PFSENSE_RELENG_2_7_2; do
		name=${label%%:*}; sha=${label#*:}
		want=$(eval "printf '%s' \"\$SHA256_${name}_${key}\"")
		fetch_verified "https://raw.githubusercontent.com/pfsense/pfsense/$sha/src/etc/inc/$file" "$out/core/$name.$file" "$want"
	done
done

if [ ! -x "$out/prefix/sbin/pkg" ]; then
	fetch_verified "https://github.com/freebsd/pkg/archive/refs/tags/$PKG_VERSION.tar.gz" "$out/pkg-$PKG_VERSION.tar.gz" "$PKG_SHA256"
	docker run --rm -v "$out:/work" -w /work debian:trixie-slim sh -ec '
		export DEBIAN_FRONTEND=noninteractive
		apt-get update -qq
		apt-get install -y -qq build-essential autoconf automake libtool pkg-config libarchive-dev libssl-dev libbsd-dev libelf-dev libzstd-dev liblzma-dev zlib1g-dev libmd-dev m4 file xz-utils bmake >/dev/null
		rm -rf pkg-src prefix && mkdir pkg-src && tar xzf pkg-'"$PKG_VERSION"'.tar.gz -C pkg-src --strip-components=1
		cd pkg-src && ./autogen.sh && ./configure --prefix=/work/prefix --sysconfdir=/work/prefix/etc --localstatedir=/work/prefix/var --with-ldns=no
		make -j4 && make install'
fi
"$out/prefix/sbin/pkg" --version 2>/dev/null || docker run --rm -v "$out:/work" debian:trixie-slim sh -c 'apt-get update -qq >/dev/null; apt-get install -y -qq libarchive13t64 libssl3t64 libbsd0 libelf1t64 libzstd1 liblzma5 zlib1g libmd0 >/dev/null; /work/prefix/sbin/pkg --version'

rm -rf "$out/ctx" && mkdir -p "$out/ctx"
cp -R "$out/prefix" "$out/ctx/prefix"
cp -R "$here/shims" "$out/ctx/shims"
cp "$here/Dockerfile" "$out/ctx/Dockerfile"
image=${PFB_ORACLE_IMAGE:-pfb-pkg-oracle:2}
docker build -t "$image" "$out/ctx"
echo "built $image; core files and pkg $PKG_VERSION pinned by tests/pkg_oracle/PINS"
