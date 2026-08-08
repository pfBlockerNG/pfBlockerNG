#!/bin/sh
# migrate-channel.sh — move an ALREADY-INSTALLED pfBlockerNG onto one of the four
# pkg channels (issue #2148, the client side of ADR-17). Run it ON the pfSense box,
# AFTER `add-repo.sh --channel <ch>` has subscribed the box to that channel.
#
# WHY THIS EXISTS SEPARATELY FROM add-repo.sh: adding a repository is not a
# migration. `pkg` never moves an installed package to a different repository on
# its own while the repository it was installed from is enabled and still offers
# that package — measured on pfSense CE 2.8.1 / pkg 1.21.3, and neither
# CONSERVATIVE_UPGRADE=false nor a higher `priority:` changes it. So a box that
# merely gains a channel conf keeps running its old build forever, silently. And
# the four channel catalogues publish only the ONE canonical identity
# `pfSense-pkg-pfBlockerNG`, so a box carrying a legacy suffixed identity
# (`-devel`, `-nightly`/`-NIGHTLY`, `-testing`, `-edge`) has no upgrade path at all
# until that identity is replaced. This script performs that replacement with a
# repository-qualified operation and then PROVES the result.
#
# DIVISION OF LABOUR
#   add-repo.sh          configures repositories only — writes this channel's conf,
#                        retires every other project conf (single-repository
#                        subscription), installs the boot-time regenerator hook.
#   migrate-channel.sh   moves the installed package onto the subscribed channel.
#
#   Run add-repo.sh FIRST. This script refuses to touch the installed package
#   while the box's repository configuration does not match --channel, because a
#   second enabled project repository makes `pkg`'s later choices undetermined
#   (all project repos share priority 100 and `pkg` does not order across
#   equal-priority repositories).
#
# WHAT IT DOES
#   1. Requires an explicit --channel; there is no default target.
#   2. Fails BEFORE any mutation on: a repository configuration that is not exactly
#      the requested channel, no pfBlockerNG installed, more than one installed,
#      an unrecognised identity, or a target catalogue that does not offer the
#      canonical package.
#   3. Canonical already on the target repo  -> reported no-op, nothing mutated.
#      Canonical on some other repo          -> `pkg install -f -r <target>`.
#      Legacy suffixed identity              -> `pkg delete` + `pkg install -r <target>`.
#   4. Verifies afterwards: exactly the canonical identity installed, `%R` equal to
#      the target repo, the version the target catalogue offered, every path in
#      `pkg info -l` present on disk, and the `installedpackages/pfblockerng`
#      config section preserved across the mutation.
#
# CONFIGURATION PRESERVATION is the package's own lifecycle hooks (the existing
# capture/restore around install), not something this script re-implements. It only
# checks that the section survived, so a silent loss cannot be reported as success.
#
# EXIT CODES (each failure class is distinguishable by a script wrapping this one)
#   0  success, including a reported no-op
#   1  environment: `pkg` binary missing
#   2  usage: missing/unknown/wrong-case --channel, unknown flag
#   3  installed state: none, more than one, or an unrecognised pfBlockerNG identity
#   4  target unavailable: repo not subscribed, stale multi-repo config, or the
#      canonical package absent from the target catalogue
#   5  the package operation itself failed
#   6  post-migration verification failed (the box is NOT in the requested state)
#
# POSIX sh; quoted expansions; absolute path for the privileged `pkg` binary.
# Env:
#   PFBLOCKERNG_ROOT  filesystem root prefix (default: /); override in tests to
#                     redirect the conf/config.xml reads to a temp dir.
#   PKG_BIN           pkg binary path (default: /usr/local/sbin/pkg); override
#                     in tests to stub out pkg.

set -eu

PKG_BIN="${PKG_BIN:-/usr/local/sbin/pkg}"

PFBLOCKERNG_ROOT="${PFBLOCKERNG_ROOT:-/}"
ROOT="${PFBLOCKERNG_ROOT%/}"
REPOS_DIR="${ROOT}/usr/local/etc/pkg/repos"
CONFIG_XML="${ROOT}/cf/conf/config.xml"

# The one identity every channel catalogue publishes. Channel is catalogue
# placement, never a package-name suffix (issue #2142/#2164).
CANONICAL_PKG="pfSense-pkg-pfBlockerNG"

# Every project conf add-repo.sh may ever have written. Exactly one may be present.
PROJECT_CONFS="pfblockerng.conf
pfblockerng-stable.conf
pfblockerng-testing.conf
pfblockerng-edge.conf
pfblockerng-nightly.conf"

CHANNEL=""

die() {
	_die_code="$1"
	shift
	printf 'migrate-channel.sh: %s\n' "$*" >&2
	exit "${_die_code}"
}

usage() {
	cat <<'EOF'
Usage: migrate-channel.sh --channel <stable|testing|edge|nightly>

Move an already-installed pfBlockerNG onto a pkg channel. Run
`add-repo.sh --channel <ch>` FIRST — that subscribes the box to the channel;
this script moves the installed package onto it.

  --channel <ch>   REQUIRED target channel: stable, testing, edge or nightly.
                   `release` is the legacy shared repo, not a channel, and is
                   rejected. Channel names are lower-case.
  -h, --help       this text.

Before running: back up your configuration (Diagnostics > Backup & Restore).
To go back afterwards: re-run `add-repo.sh --channel <previous>` and then this
script with that channel — moving to an OLDER version is a repository-qualified
downgrade, which is exactly what this script performs.

Exit codes: 0 ok/no-op, 1 no pkg, 2 usage, 3 installed state, 4 target
unavailable, 5 pkg operation failed, 6 verification failed.
EOF
}

# ── Arg parsing ────────────────────────────────────────────────────────────────
while [ $# -gt 0 ]; do
	case "$1" in
	--channel)
		[ $# -ge 2 ] || die 2 "--channel requires a value"
		CHANNEL="$2"
		shift 2
		;;
	--channel=*)
		CHANNEL="${1#--channel=}"
		shift
		;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		usage >&2
		die 2 "unknown argument: $1"
		;;
	esac
done

[ -n "${CHANNEL}" ] || {
	usage >&2
	die 2 "--channel is required; there is no default target channel"
}

# Exact, lower-case match only. `release` is the legacy shared repo (it carries
# both the canonical and the -devel identity) and is deliberately not a target:
# migrating INTO it would reintroduce the ambiguity this ticket removes.
case "${CHANNEL}" in
stable | testing | edge | nightly) ;;
release)
	die 2 "'release' is the legacy shared repo, not a channel — pick stable, testing, edge or nightly"
	;;
*)
	die 2 "unknown channel '${CHANNEL}' — expected one of: stable testing edge nightly (lower-case)"
	;;
esac

TARGET_REPO="pfblockerng-${CHANNEL}"
TARGET_CONF="pfblockerng-${CHANNEL}.conf"

# ── 1. The box must already be subscribed to EXACTLY this channel ──────────────
# Checked before anything else because it is free and because a mismatch is the
# one failure a user hits by running this script out of order. A second enabled
# project repo is not a tidiness problem: `pkg` does not order across
# equal-priority repositories, so whatever this script installs could be replaced
# by the other repo's build on the next upgrade.
[ -f "${REPOS_DIR}/${TARGET_CONF}" ] ||
	die 4 "not subscribed to the ${CHANNEL} channel (${REPOS_DIR}/${TARGET_CONF} is absent) — run: add-repo.sh --channel ${CHANNEL}"

_stray=""
for _conf in ${PROJECT_CONFS}; do
	[ "${_conf}" = "${TARGET_CONF}" ] && continue
	[ -f "${REPOS_DIR}/${_conf}" ] || continue
	_stray="${_stray}${_stray:+ }${_conf}"
done
[ -z "${_stray}" ] ||
	die 4 "another pfBlockerNG repository is still configured (${_stray}) — a box subscribes to exactly one channel; run: add-repo.sh --channel ${CHANNEL}"

command -v "${PKG_BIN}" >/dev/null 2>&1 ||
	die 1 "pkg binary not found at ${PKG_BIN} (run this on the pfSense box, or set PKG_BIN)"

# ── 2. Classify the installed identity ─────────────────────────────────────────
# `-g` makes the trailing '*' a glob; without it `pkg query` treats the pattern as
# an exact name and matches nothing (the same trap pfb_pkg_installed_name() names).
# A query miss is "not installed", not an error, so its non-zero status is absorbed.
INSTALLED_NAMES="$("${PKG_BIN}" query -g '%n' "${CANONICAL_PKG}*" 2>/dev/null || true)"
INSTALLED_NAMES="$(printf '%s\n' "${INSTALLED_NAMES}" | grep -v '^[[:space:]]*$' || true)"

_count="$(printf '%s\n' "${INSTALLED_NAMES}" | grep -c '[^[:space:]]' || true)"

[ "${_count}" -ne 0 ] ||
	die 3 "no pfBlockerNG package is installed — nothing to migrate; install from the ${CHANNEL} channel with: pkg install ${CANONICAL_PKG}"
[ "${_count}" -eq 1 ] ||
	die 3 "$(printf 'more than one pfBlockerNG package is installed:\n%s\nRemove all but one before migrating.' "${INSTALLED_NAMES}")"

INSTALLED_NAME="${INSTALLED_NAMES}"

# Suffix classification against the shipped set — the same enumeration
# pfb_channel_from_pkgname() carries in pfblockerng.inc, lower-cased so the
# historical `-NIGHTLY` spelling (ADR-18) is recognised. An identity outside the
# set is NOT assumed migratable: it may be a fork or a hand-built package whose
# configuration this script cannot reason about.
_suffix="$(printf '%s' "${INSTALLED_NAME}" | tr '[:upper:]' '[:lower:]')"
_suffix="${_suffix#pfsense-pkg-pfblockerng}"
case "${_suffix}" in
"")
	INSTALLED_KIND="canonical"
	;;
-devel | -testing | -edge | -nightly)
	INSTALLED_KIND="legacy"
	;;
*)
	die 3 "unrecognised pfBlockerNG identity '${INSTALLED_NAME}' — refusing to migrate a package this script does not ship"
	;;
esac

INSTALLED_REPO="$("${PKG_BIN}" query '%R' "${INSTALLED_NAME}" 2>/dev/null || true)"
INSTALLED_VERSION="$("${PKG_BIN}" query '%v' "${INSTALLED_NAME}" 2>/dev/null || true)"

printf '==> Installed: %s-%s (from repo %s)\n' \
	"${INSTALLED_NAME}" "${INSTALLED_VERSION:-unknown}" "${INSTALLED_REPO:-unknown}"

# ── 3. The target catalogue must actually offer the canonical package ──────────
# `pkg rquery -r <repo>` reads that ONE repo's catalogue. Checked before any
# mutation so a typo'd/unpublished channel can never leave the box with the old
# package deleted and nothing to install.
#
# A catalogue holds MORE than one version of the canonical package — retention keeps
# several, and containment back-fills a faster channel with its slower channels'
# builds — so rquery prints one line per offered version in catalogue order. Taking
# the first would name a build `pkg install` is not going to choose, and the
# post-migration version check would then fail a perfectly good migration. Pick the
# highest with `pkg version -t`, which is the comparator `pkg` itself resolves by.
TARGET_VERSION=""
for _offered in $("${PKG_BIN}" rquery -r "${TARGET_REPO}" '%v' "${CANONICAL_PKG}" 2>/dev/null || true); do
	if [ -z "${TARGET_VERSION}" ]; then
		TARGET_VERSION="${_offered}"
		continue
	fi
	# A comparator that answers nothing would silently degrade this loop back to "keep
	# the first line", and the step-6 version check would then fail a migration that
	# actually succeeded. Name the real cause instead of dying on the symptom.
	_order="$("${PKG_BIN}" version -t "${_offered}" "${TARGET_VERSION}" 2>/dev/null || true)"
	case "${_order}" in
	'>') TARGET_VERSION="${_offered}" ;;
	'<' | '=') ;;
	*)
		die 4 "\`${PKG_BIN} version -t\` gave no usable answer comparing '${_offered}' and '${TARGET_VERSION}' — cannot tell which build ${TARGET_REPO} would install"
		;;
	esac
done
[ -n "${TARGET_VERSION}" ] ||
	die 4 "repo '${TARGET_REPO}' does not offer ${CANONICAL_PKG} — run \`pkg update -f\`, and check the ${CHANNEL} catalogue has a build for this pfSense edition/version"

printf '==> Target:    %s-%s (repo %s)\n' "${CANONICAL_PKG}" "${TARGET_VERSION}" "${TARGET_REPO}"

# ── 4. No-op: already canonical, already on the target repo ────────────────────
# Reported, never silent. Reached by re-running the script after a migration that
# already completed, or by naming the channel the box is on. A switch BETWEEN two
# channels serving the identical tagged artifact does NOT land here — its installed
# repo differs, so it takes the repository-qualified reinstall below and ends with
# the same version served from the new catalogue.
if [ "${INSTALLED_KIND}" = "canonical" ] && [ "${INSTALLED_REPO}" = "${TARGET_REPO}" ]; then
	printf '==> Already on the %s channel as %s-%s — nothing to do.\n' \
		"${CHANNEL}" "${INSTALLED_NAME}" "${INSTALLED_VERSION}"
	exit 0
fi

# ── 5. Record the config section, then mutate ──────────────────────────────────
# The package's own lifecycle hooks preserve `installedpackages/pfblockerng`
# across the replacement. Recording presence here turns a silent loss into a
# verification failure instead of a reported success.
CONFIG_SECTION_BEFORE=0
if [ -f "${CONFIG_XML}" ] && grep -q '<pfblockerng>' "${CONFIG_XML}" 2>/dev/null; then
	CONFIG_SECTION_BEFORE=1
fi

printf '==> Back up your configuration first if you have not (Diagnostics > Backup & Restore).\n'

if [ "${INSTALLED_KIND}" = "legacy" ]; then
	# A legacy suffixed identity is a DIFFERENT package name, so `pkg install` can
	# never replace it — the two would simply coexist (or conflict). Delete first,
	# then install the canonical one from the target repo. The delete runs the
	# outgoing package's PRE-UNINSTALL, which is where its configuration capture
	# lives; the install runs the incoming package's restore.
	printf '==> Removing the legacy identity %s\n' "${INSTALLED_NAME}"
	env ASSUME_ALWAYS_YES=yes "${PKG_BIN}" delete -y "${INSTALLED_NAME}" ||
		die 5 "\`pkg delete ${INSTALLED_NAME}\` failed — the box is unchanged apart from that failed operation; re-run after fixing the cause"
	printf '==> Installing %s from %s\n' "${CANONICAL_PKG}" "${TARGET_REPO}"
	env ASSUME_ALWAYS_YES=yes "${PKG_BIN}" install -y -r "${TARGET_REPO}" "${CANONICAL_PKG}" ||
		die 5 "\`pkg install -r ${TARGET_REPO} ${CANONICAL_PKG}\` failed AFTER ${INSTALLED_NAME} was removed — the box currently has NO pfBlockerNG installed; fix the cause, then finish with: ${PKG_BIN} install -y -r ${TARGET_REPO} ${CANONICAL_PKG}"
else
	# Canonical identity, wrong repo. `-f` forces the reinstall even when the
	# target version equals or is OLDER than the installed one: crossing
	# repositories is exactly the case ordinary `pkg upgrade` refuses, and moving
	# to a slower channel is a downgrade by design (each channel catalogue
	# strictly contains its slower channels' files, so the older build is there).
	printf '==> Reinstalling %s from %s (repository-qualified)\n' "${CANONICAL_PKG}" "${TARGET_REPO}"
	env ASSUME_ALWAYS_YES=yes "${PKG_BIN}" install -f -y -r "${TARGET_REPO}" "${CANONICAL_PKG}" ||
		die 5 "\`pkg install -f -r ${TARGET_REPO} ${CANONICAL_PKG}\` failed — the previous build is still installed"
fi

# ── 6. Prove the result ────────────────────────────────────────────────────────
# Every claim this script makes is re-read from pkg after the fact. A migration
# that "ran" but left the box on the old repo, the old identity, or with missing
# payload files is a FAILURE, not a success with a warning.
FINAL_NAMES="$("${PKG_BIN}" query -g '%n' "${CANONICAL_PKG}*" 2>/dev/null || true)"
FINAL_NAMES="$(printf '%s\n' "${FINAL_NAMES}" | grep -v '^[[:space:]]*$' || true)"
[ "${FINAL_NAMES}" = "${CANONICAL_PKG}" ] ||
	die 6 "$(printf 'expected exactly %s installed after migration, found:\n%s' "${CANONICAL_PKG}" "${FINAL_NAMES:-(none)}")"

FINAL_REPO="$("${PKG_BIN}" query '%R' "${CANONICAL_PKG}" 2>/dev/null || true)"
[ "${FINAL_REPO}" = "${TARGET_REPO}" ] ||
	die 6 "${CANONICAL_PKG} reports repo '${FINAL_REPO:-unknown}', expected '${TARGET_REPO}' — the box is not on the ${CHANNEL} channel"

FINAL_VERSION="$("${PKG_BIN}" query '%v' "${CANONICAL_PKG}" 2>/dev/null || true)"
[ "${FINAL_VERSION}" = "${TARGET_VERSION}" ] ||
	die 6 "${CANONICAL_PKG} reports version '${FINAL_VERSION:-unknown}', expected '${TARGET_VERSION}' from ${TARGET_REPO}"

# Payload inventory: `pkg info -l` lists the installed file manifest, one
# tab-indented absolute path per line after a header. A missing path means the
# install did not land completely, which `pkg install`'s exit status alone does
# not always reveal. The header line has no leading slash, so grep drops it.
_missing="$(
	"${PKG_BIN}" info -l "${CANONICAL_PKG}" 2>/dev/null |
		sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' |
		grep '^/' |
		while IFS= read -r _path; do
			[ -e "${ROOT}${_path}" ] || printf '%s\n' "${_path}"
		done
)"
[ -z "${_missing}" ] ||
	die 6 "$(printf 'the installed payload is incomplete — these files listed by pkg info -l are missing:\n%s' "${_missing}")"

if [ "${CONFIG_SECTION_BEFORE}" -eq 1 ]; then
	grep -q '<pfblockerng>' "${CONFIG_XML}" 2>/dev/null ||
		die 6 "the installedpackages/pfblockerng section is gone from ${CONFIG_XML} — restore your configuration backup"
fi

printf '==> Done — %s-%s installed from %s (%s channel).\n' \
	"${CANONICAL_PKG}" "${FINAL_VERSION}" "${FINAL_REPO}" "${CHANNEL}"
