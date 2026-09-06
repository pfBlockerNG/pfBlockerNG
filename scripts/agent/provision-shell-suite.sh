#!/bin/sh
# provision-shell-suite.sh -- give a dev host the shellspec suite's CI-only inputs
# (issue #3189): the real FireHOL iprange and the comma-decimal de_DE.UTF-8 locale.
# Mirrors the install and verification steps in .github/workflows/test.yml -- change
# them together. Debian/Ubuntu hosts; needs root or passwordless sudo.
set -eu

if [ "$(id -u)" -eq 0 ]; then
	as_root() { "$@"; }
else
	as_root() { sudo "$@"; }
fi

need_iprange=0
command -v iprange >/dev/null 2>&1 || need_iprange=1
need_locale=0
LC_ALL=de_DE.UTF-8 awk 'BEGIN { printf "%.2f", 1.5 }' 2>/dev/null | grep -q ',' || need_locale=1

if [ "$need_iprange" -eq 1 ] || [ "$need_locale" -eq 1 ]; then
	as_root apt-get update
	if [ "$need_iprange" -eq 1 ]; then
		as_root apt-get install -y iprange
	fi
	if [ "$need_locale" -eq 1 ]; then
		as_root apt-get install -y --no-install-recommends mawk locales
		# test.yml pins mawk: gawk honours LC_NUMERIC only in POSIX mode.
		if command -v update-alternatives >/dev/null 2>&1; then
			as_root update-alternatives --set awk /usr/bin/mawk
		fi
		as_root locale-gen de_DE.UTF-8
	fi
fi

# The same verification test.yml runs: a locale that generated while awk stayed
# dotted, or a locale-gen that silently no-oped, must fail here with the check named.
if ! command -v iprange >/dev/null 2>&1; then
	echo 'provision failed: no iprange binary after install' >&2
	exit 1
fi
if ! locale -a | grep -Eqi '^de_DE\.utf-?8$'; then
	echo 'provision failed: de_DE.UTF-8 absent from the locale -a output after locale-gen' >&2
	exit 1
fi
if ! LC_ALL=de_DE.UTF-8 locale -k LC_NUMERIC | grep -Fq 'decimal_point=","'; then
	echo 'provision failed: de_DE.UTF-8 LC_NUMERIC is not comma-decimal' >&2
	exit 1
fi
if ! LC_ALL=de_DE.UTF-8 awk 'BEGIN { printf "%.2f", 1.5 }' | grep -q ','; then
	echo 'provision failed: awk under de_DE.UTF-8 still prints a dot decimal (is mawk the selected awk alternative?)' >&2
	exit 1
fi
echo 'shell suite provisioned: real iprange + comma-decimal de_DE.UTF-8'
