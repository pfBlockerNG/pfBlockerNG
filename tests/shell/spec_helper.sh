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

unset CODEX_THREAD_ID OMP_CLI PI_CLI

# ── GIT_* scrub (ADR-47 P5) — sourced once, aliased as scrub_git_env ─────────
# All git-touching specs call scrub_git_env in their setup() / subshells.
# The alias keeps spec code readable; the underlying function is in the shared lib.
# shellcheck source=scripts/lib/git-env-scrub.sh
. "${PFB_ROOT}/scripts/lib/git-env-scrub.sh"
scrub_git_env() { pfb_scrub_git_env; }

# Run fixture/setup Git calls without developer global or system config.
git_fixture() {
	GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null git "$@"
}

# Put the iprange shim ahead of the real PATH -- pfb_real_iprange() (see
# pfblockerng_suppress_spec.sh) strips PFB_SHIMS back off to find a genuine
# system iprange when one is present.
PATH="${PFB_SHIMS}:${PATH}"

# issue #714: aws_region_prefixes.sh resolves jq/iprange via pathjq/pathaggregate
# (absolute path, no bare-name PATH lookup) instead of calling them by bare name.
# Point those at the real system jq and at the deterministic iprange shim.
pathjq="$(command -v jq)"
pathaggregate="${PFB_SHIMS}/iprange"

export PATH PFB_ROOT PFB_PKGDIR PFB_FIXTURES PFB_SHIMS pathjq pathaggregate

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

# Hermetic `wt` in $1/wt for specs that exercise work-branch.sh's worktree cut. The
# specs must not depend on whether the host has Worktrunk installed, and must not let
# git's raw progress output stand in for wt's — real wt swallows it and prints its own
# line, so an assertion keyed to git's text would pass on a string wt never emits.
make_wt_stub() {
	cat > "$1/wt" <<'WTSTUB'
#!/bin/sh
wt_path=''
wt_branch=''
while [ "$#" -gt 0 ]; do
  case $1 in
    --config-set)
      wt_path=${2#worktree-path=\"}
      wt_path=${wt_path%\"}
      shift 2
      ;;
    switch)
      shift
      wt_branch=${1:-}
      [ "$#" -eq 0 ] || shift
      ;;
    *) shift ;;
  esac
done
git worktree add "$wt_path" "$wt_branch" >/dev/null 2>&1 || exit $?
printf '%s\n' "✓ Created worktree for $wt_branch @ $wt_path" >&2
WTSTUB
	chmod +x "$1/wt"
}

# Call exitnow() against a caller-supplied tmpdir. Always run via \`When run\` so
# the exit() lands in a subshell; afterwards the directory should be gone.
run_exitnow_on() {
	# shellcheck disable=SC2034  # read by the sourced exitnow()
	tmpdir="$1"
	exitnow
}

# Run a sourced function with its stdout/stderr discarded while preserving its
# exit status. Lets a spec assert a function's FILE side-effects + status without
# tripping shellspec's "unexpected output" warning on the function's own progress
# / stat printing (or an injected shim's diagnostic) -- output that is incidental,
# not the behaviour under test. Use for examples that assert files/status only;
# examples that assert stdout keep a plain `When call`.
silently() {
	"$@" >/dev/null 2>&1
}
