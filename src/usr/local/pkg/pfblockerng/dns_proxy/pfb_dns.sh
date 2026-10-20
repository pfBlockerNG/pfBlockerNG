#!/bin/sh
# Run the pfb-dns binary that matches this machine (issue #3513).
#
# usage: /bin/sh /usr/local/pkg/pfblockerng/dns_proxy/pfb_dns.sh [pfb-dns arguments...]
#
# The package stays architecture-independent and ships one binary per FreeBSD architecture,
# bin/freebsd-amd64/pfb-dns and bin/freebsd-arm64/pfb-dns. `uname -p` names the machine:
# amd64 selects freebsd-amd64, aarch64 (or arm64) selects freebsd-arm64. The binary replaces
# this shell (exec), so its exit status and signals are the caller's.
#
# Exit status when no binary runs (there is nothing to fall back to: pfB-DNS has no other front end, and the
# supervisor that starts this script starts it again every 5 s, so the caller never publishes its ready marker):
#   3  no pfb-dns payload is installed at all.
#   1  a payload is installed but unusable here (unknown machine, or this machine's binary is
#      missing or not executable); the caller must NOT fall back to another binary or to anything else.

diag() {
	printf '%s\n' "pfb_dns.sh: $*" >&2
}

here=$(CDPATH='' cd "$(dirname "$0")" && pwd) || {
	diag 'cannot resolve its own directory'
	exit 1
}

payload=0
for candidate in "${here}"/bin/*/pfb-dns; do
	if [ -e "${candidate}" ] || [ -L "${candidate}" ]; then
		payload=1
		break
	fi
done
if [ "${payload}" -eq 0 ]; then
	diag "no pfb-dns binary is installed under ${here}/bin"
	exit 3
fi

machine=$(uname -p)
case "${machine}" in
	amd64) target=freebsd-amd64 ;;
	aarch64|arm64) target=freebsd-arm64 ;;
	*)
		diag "no pfb-dns binary for machine '${machine}' (uname -p)"
		exit 1
		;;
esac

binary="${here}/bin/${target}/pfb-dns"
if [ ! -f "${binary}" ] || [ ! -x "${binary}" ]; then
	diag "this machine needs ${binary} (${target}), which is missing or not executable"
	exit 1
fi

exec "${binary}" "$@"
