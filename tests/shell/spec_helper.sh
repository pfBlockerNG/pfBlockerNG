#!/bin/sh
# shellcheck shell=sh
# shellspec spec_helper — shared setup for the POSIX-sh test suite.
#
# Loaded via `--require spec_helper` (see .shellspec). SHELLSPEC_PROJECT_ROOT is
# the directory holding .shellspec, i.e. the repo root.

PFB_ROOT="${SHELLSPEC_PROJECT_ROOT}"
PFB_PKGDIR="${PFB_ROOT}/src/usr/local/pkg/pfblockerng"
PFB_FIXTURES="${PFB_ROOT}/tests/shell/fixtures"
PFB_SHIMS="${PFB_ROOT}/tests/shell/bin"

# ── GIT_* scrub (ADR-47 P5) — sourced once, aliased as scrub_git_env ─────────
# All git-touching specs call scrub_git_env in their setup() / subshells.
# The alias keeps spec code readable; the underlying function is in the shared lib.
# shellcheck source=scripts/lib/git-env-scrub.sh
. "${PFB_ROOT}/scripts/lib/git-env-scrub.sh"
scrub_git_env() { pfb_scrub_git_env; }

# Put the iprange shim ahead of the real PATH so the AWS pre-scripts (which call
# `iprange` by bare name) pick up the deterministic stand-in. jq stays the real
# system binary.
PATH="${PFB_SHIMS}:${PATH}"
export PATH PFB_ROOT PFB_PKGDIR PFB_FIXTURES PFB_SHIMS

# Run one ip_pre_AWS_*.sh over a private copy of the fixture (the script
# overwrites its input file in place) and echo the resulting prefixes, sorted and
# space-joined on a single line for easy equality assertions.
aws_filter() {
	_aws_script="$1"
	_aws_proto="$2"
	_aws_work="$(mktemp "${SHELLSPEC_TMPBASE:-/tmp}/awsfix.XXXXXX")"
	cp "${PFB_FIXTURES}/aws-ip-ranges.json" "${_aws_work}"
	# The AWS region scripts live under list_scripts/; each is a thin wrapper that
	# resolves the shared aws_region_prefixes.sh relative to its own $0.
	( cd "${PFB_PKGDIR}/list_scripts" && sh "${_aws_script}" "${_aws_work}" "${_aws_proto}" ) >/dev/null 2>&1
	sort "${_aws_work}" | tr '\n' ' ' | sed 's/ *$//'
	rm -f "${_aws_work}"
}

# Source pfblockerng.sh as a library: PFB_SOURCED=1 makes it define its functions
# and return before running any top-level init or the argument dispatch.
pfb_source() {
	# shellcheck disable=SC2034  # read by pfblockerng.sh's source guard
	PFB_SOURCED=1
	# shellcheck disable=SC1091
	. "${PFB_PKGDIR}/pfblockerng.sh"
}

# Write an executable mmdblookup stand-in at $1 that prints $2 verbatim (no
# trailing newline) and ignores its arguments. Used by the reputation_max /
# iptoasn specs to avoid the real GeoIP binary + databases.
make_geoip_stub() {
	cat > "$1" <<EOF
#!/bin/sh
printf '%s' '$2'
EOF
	chmod +x "$1"
}

# Call exitnow() against a caller-supplied tmpdir. Always run via \`When run\` so
# the exit() lands in a subshell; afterwards the directory should be gone.
run_exitnow_on() {
	# shellcheck disable=SC2034  # read by the sourced exitnow()
	tmpdir="$1"
	exitnow
}
