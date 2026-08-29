#!/bin/sh
# shellcheck shell=sh
# install.sh — put this pfSense box on a pfBlockerNG channel (issue #2416 follow-up:
# one script, --channel parameterizes it, replacing the earlier per-channel
# install-<ch>.sh + install-common.sh split).
#
# WHY ONE SCRIPT: repo bootstrap (conf + boot hook) and an installed package's
# channel move fold into ONE idempotent state machine, parameterized by --channel —
# a fresh box and an already-installed box converge through the same steps instead
# of separate scripts run in sequence, and re-running on a converged box mutates
# nothing (check-then-act throughout). Four near-identical per-channel wrapper
# scripts added nothing but drift risk over a single --channel argument.
#
# WHY EVERY pkg(8) CALL REDIRECTS STDIN FROM /dev/null: a leftover pipe user
# (`fetch | sh`) still exists in the wild, and under that form the script's own
# stdin IS the script text — any child that reads stdin without redirection would
# consume trailing script bytes and corrupt the run. The documented form is
# mktemp + fetch-to-file (issue #2754): a POSIX pipeline's status is the last
# command, so `fetch | sh` exits 0 when fetch delivers zero bytes (`sh` on empty
# stdin succeeds). `[ -s "$t" ]` also refuses a successful empty write.
#
# Usage:
#   install.sh --channel <stable|testing|edge|nightly>   subscribe + install/converge
#   install.sh -h|--help                                  this text
#
# Published at https://${PFB_REPO_HOST}/install.sh; run ON the box:
#   t=$(mktemp "${TMPDIR:-/tmp}/pfb-install.XXXXXX") && fetch -T 60 -o "$t" https://${PFB_REPO_HOST}/install.sh && [ -s "$t" ] && /bin/sh "$t" --channel stable; e=$?; [ -n "$t" ] && rm -f "$t"; (exit $e)
#
# Env (all overridable; forks/staging/tests set these):
#   PKG_BIN           pkg(8) binary path (default: /usr/local/sbin/pkg)
#   PFBLOCKERNG_ROOT  filesystem root prefix (default: /)
#   PFB_BASE_URL      catalog base (default: http://<PFB_REPO_HOST>)
#   PFB_SSL_CA_CERT_PATH  CA hash dir exported to pkg (default: <root>/etc/ssl/certs)
#   PFB_SSL_CA_CERT_FILE  CA bundle exported to pkg (default: <root>/etc/ssl/cert.pem)
#                         Each half is guarded independently and exported on its own: the
#                         path when it is a directory, the bundle when it is a non-empty
#                         regular file. A box failing one guard still gets the other. Set
#                         either to "" to opt that half out.
#
# Exit codes: see usage() below (kept in sync — the header is the interface doc).

set -eu

# The hook source lives at the shipped path, under a checkout's src/usr/local/etc/rc.d/
# sibling of this file's own scripts/ directory (issue #2675).
# Resolved once at source time — CDPATH='' guard used throughout scripts/, see
# tests/shell/cdpath_spec.sh.
SCRIPT_DIR="$(CDPATH='' cd "$(dirname "$0")" && pwd)"
HOOK_SRC="${SCRIPT_DIR}/../src/usr/local/etc/rc.d/pfblockerng_repo_generate.sh"

PKG_BIN="${PKG_BIN:-/usr/local/sbin/pkg}"
PFBLOCKERNG_ROOT="${PFBLOCKERNG_ROOT:-/}"
ROOT="${PFBLOCKERNG_ROOT%/}"
# The pkg repository domain, once. The scheme is chosen per use: the CATALOGUE is fetched
# over plain HTTP, because pkg on pfSense Plus runs against a Netgate-pinned CA bundle
# nothing we ship can widen — authenticity rides the catalogue signature instead (issue
# #2675). Fetching THIS script has no signature to fall back on, so that stays HTTPS.
PFB_REPO_HOST="${PFB_REPO_HOST:-pkg.pfblockerng.com}"
PFB_BASE_URL="${PFB_BASE_URL:-http://${PFB_REPO_HOST}}"
# Normalised once, here at the input boundary, so nothing downstream rewrites a scheme:
# an operator (or an older doc) handing us https for OUR host would otherwise produce a
# conf pairing TLS with signature_type: fingerprints — the one combination pkg cannot
# fetch on Plus. Any other host is left exactly as given.
case "${PFB_BASE_URL}" in
    "https://${PFB_REPO_HOST}" | "https://${PFB_REPO_HOST}/"*)
        PFB_BASE_URL="http://${PFB_BASE_URL#https://}"
        ;;
esac

CANONICAL_PKG="pfSense-pkg-pfBlockerNG"
REPOS_DIR="${ROOT}/usr/local/etc/pkg/repos"
# Staged like every other on-box path: a ROOT-staged run (the test harnesses, a
# chroot install) must never write the host's real fingerprint store.
FINGERPRINT_DIR="${ROOT}/usr/local/etc/pkg/fingerprints/pfblockerng"
ON_BOX_HOOK="${ROOT}/usr/local/etc/rc.d/pfblockerng_repo_generate.sh"
CONFIG_XML="${ROOT}/cf/conf/config.xml"
CONF_MARKER="Generated at boot by pfblockerng_repo_generate"

# Every project conf this script (or a pre-#2148 legacy bootstrap) may have written.
# Exactly one may be enabled at a time — single-repository subscription, issue #2148.
PROJECT_CONFS="pfblockerng.conf
pfblockerng-stable.conf
pfblockerng-testing.conf
pfblockerng-edge.conf
pfblockerng-nightly.conf"

# die CODE MSG... — every non-zero exit goes through this.
die() {
    _die_code="$1"
    shift
    printf 'install.sh: %s\n' "$*" >&2
    exit "${_die_code}"
}

# pfb_pkg_die CODE MSG... — die(), then the pfSense repository-repair sequence, for the
# failures a broken pkg(8) setup on the box itself can cause: the catalogue refresh, and
# the delete/install (issue #2789). Stale or half-written Netgate repo files, or an
# interrupted upgrade, leave pkg unable to refresh ANY catalogue, and no conf this script
# writes can repair that. Guidance only, never run for the user.
#
# `pfSense-upgrade -u` is the whole cheap repair in one command whenever it reaches its
# work (issue #2808): upstream runs pfSense-repo-setup before dispatching any action,
# that script runs pfSense-repoc-static itself, and `-u` then forces `pkg update -f`,
# upgrading pkg and bootstrapping it when the repository moved to metadata version 2. Two
# early exits precede all of that: the pid lock, which refuses while a boot-time metadata
# refresh runs, and the block_external_services flag, which exits 0 without doing
# anything. A BARE
# `pfSense-upgrade` is NOT a second item beside it: upstream sets
# `: ${action:="upgrade"}` when no action flag is given, so it applies whatever release
# the box's branch offers and reboots afterwards. It is the escalation for a mismatch the
# repository rebuild did not fix, and it is stated as such, with the reboot named where
# it is proposed (issue #2803).
#
# The diagnosis prints FIRST: the remedy is conditional on it, and a reader who has not
# yet been told what failed cannot judge whether this sequence is their answer.
# die() exits, hence a wrapper rather than a call beside it.
#
# Deliberately NOT used for the conf-resolution failures that also exit 4, nor for a
# package-script failure, where pkg fetched and extracted fine and the box's repository
# setup is not implicated — a hint pointing at the wrong cause costs more than none.
pfb_pkg_die() {
    _pkg_die_code="$1"
    shift
    printf 'install.sh: %s\n' "$*" >&2
    cat >&2 <<'HINT'
install.sh: if this box's own pkg setup is at fault, rebuild it and re-run this script:
install.sh:   pfSense-upgrade -u
install.sh: only if the re-run still fails, escalate to a bare pfSense-upgrade — it applies
install.sh: any pfSense release upgrade the box's branch offers, and reboots when it does.
HINT
    exit "${_pkg_die_code}"
}

# _pkg ARGS... — every pkg(8) invocation: /dev/null stdin (piped-script safety, see
# header) + ASSUME_ALWAYS_YES so a stray prompt cannot wedge a non-interactive run.
# Callers add -y themselves on verbs that take it (delete/install); read-only verbs
# (query/rquery/version/info) ignore ASSUME_ALWAYS_YES harmlessly.
#
# CA locations (issue #2514): on pfSense Plus, pfSense-repo-setup writes a PKG_ENV block
# into pkg.conf pinning SSL_CA_CERT_FILE to Netgate's private CA bundle, which carries
# only Netgate CAs. libpkg applies that block with setenv(..., overwrite=1), so a
# libfetch-based pkg (1.x) verifies against Netgate's CAs and nothing else, and every
# fetch from a third-party catalog fails with "certificate verify failed". PKG_ENV never
# sets SSL_CA_CERT_PATH, and libfetch loads file and path into one store
# (SSL_CTX_load_verify_locations(ctx, ca_cert_file, ca_cert_path)), so exporting the path
# survives the pin. That mirrors what a libcurl-based pkg (2.x) already does by default:
# peer verification stays fully enabled, the trust store is not modified, and no vendor
# configuration is touched.
#
# The bundle goes with it, because libfetch takes load_verify_locations() as soon as
# EITHER variable is set and then never calls SSL_CTX_set_default_verify_paths(). On a box
# with no pin (CE), exporting the path alone would therefore drop the default bundle from
# the store, and FreeBSD ships /etc/ssl/certs EMPTY until certctl rehash populates it — so
# path-only would turn a working stock box into this very failure. On Plus, PKG_ENV
# overwrites this value with Netgate's bundle, which is what should happen there.
#
# The bundle is checked with -f AND -s. load_verify_locations() reads the file eagerly and
# abandons the path when that read fails, so an empty or truncated bundle would take the
# whole store down with it, a state set_default_verify_paths() would have tolerated. -s
# alone is not enough because it is TRUE for a directory, whose size is nonzero.
#
# Setting either variable to the empty string opts that half out (hence `-`, not `:-`).
# Opting the BUNDLE out on a box with no PKG_ENV pin leaves the path-only store this code
# exists to avoid, so that half is for boxes whose bundle is known bad.
PFB_SSL_CA_CERT_PATH="${PFB_SSL_CA_CERT_PATH-${ROOT}/etc/ssl/certs}"
PFB_SSL_CA_CERT_FILE="${PFB_SSL_CA_CERT_FILE-${ROOT}/etc/ssl/cert.pem}"

# Spelled out per combination so every path stays quoted: a single accumulated string
# would have to be word-split to become separate env(1) operands, which breaks the moment
# a location contains a space.
# TRUE when the hash directory holds at least one entry. FreeBSD ships /etc/ssl/certs
# EMPTY until `certctl rehash` populates it, and libfetch abandons
# SSL_CTX_set_default_verify_paths() as soon as EITHER variable is set -- so exporting an
# empty hash dir with no bundle beside it leaves an EMPTY store, strictly worse than
# exporting nothing (issue #2524). Mirrors the boot hook's populated-directory glob loop
# and pfb_pkg_exec()'s glob() guard: any non-dot entry counts, including a dangling
# symlink, which is what a hash dir is made of.
_ca_path_populated() {
    [ -d "$1" ] || return 1
    _cap_has_entry=0
    for _cap_entry in "$1"/*; do
        if [ -e "${_cap_entry}" ] || [ -L "${_cap_entry}" ]; then
            _cap_has_entry=1
            break
        fi
    done
    unset _cap_entry
    [ "${_cap_has_entry}" -eq 1 ] || { unset _cap_has_entry; return 1; }
    unset _cap_has_entry
    return 0
}

_pkg() {
    if [ -d "${PFB_SSL_CA_CERT_PATH}" ] &&
        [ -f "${PFB_SSL_CA_CERT_FILE}" ] && [ -s "${PFB_SSL_CA_CERT_FILE}" ]; then
        env ASSUME_ALWAYS_YES=yes \
            SSL_CA_CERT_PATH="${PFB_SSL_CA_CERT_PATH}" \
            SSL_CA_CERT_FILE="${PFB_SSL_CA_CERT_FILE}" \
            "${PKG_BIN}" "$@" </dev/null
    elif _ca_path_populated "${PFB_SSL_CA_CERT_PATH}"; then
        env ASSUME_ALWAYS_YES=yes \
            SSL_CA_CERT_PATH="${PFB_SSL_CA_CERT_PATH}" \
            "${PKG_BIN}" "$@" </dev/null
    elif [ -f "${PFB_SSL_CA_CERT_FILE}" ] && [ -s "${PFB_SSL_CA_CERT_FILE}" ]; then
        env ASSUME_ALWAYS_YES=yes \
            SSL_CA_CERT_FILE="${PFB_SSL_CA_CERT_FILE}" \
            "${PKG_BIN}" "$@" </dev/null
    else
        env ASSUME_ALWAYS_YES=yes "${PKG_BIN}" "$@" </dev/null
    fi
}

# Hard cap on the reader's polling below: 6 hours at one tick a second. An install that
# has not finished by then is not one this script can still narrate.
_PFB_DRAIN_MAX_TICKS=21600

# _pkg_mutate_cleanup — reap the background reader and drop both capture files. Runs from
# the EXIT trap and from every signal trap _pkg_mutate installs; safe to run twice, and
# safe before either name is set.
_pkg_mutate_cleanup() {
    if [ -n "${_mut_reader:-}" ]; then
        kill "${_mut_reader}" 2>/dev/null || true
        wait "${_mut_reader}" 2>/dev/null || true
    fi
    rm -f "${_mut_log:-}" "${_mut_done:-}"
}

# _pfb_parent_gone PID — TRUE once PID can no longer be the running parent of this
# reader: either it is gone, or it is a zombie. The zombie half matters because a killed
# parent stays in the table until whatever started it reaps it, and `kill -0` succeeds
# against a zombie the whole time — so `kill -0` alone would keep a reader polling long
# after the run it belongs to died.
_pfb_parent_gone() {
    kill -0 "$1" 2>/dev/null || return 0
    case "$(ps -o state= -p "$1" 2>/dev/null | tr -d ' ')" in
        Z*) return 0 ;;
    esac
    return 1
}

# _pkg_mutate_drain FILE — print what FILE has grown by since this shell last drained
# it, carrying the position in _drain_seen. Addressed by LINE, so a half-written line is
# never split across two prints; a final line with no newline is left for the
# read-to-end-of-file drain that runs once pkg has exited.
_pkg_mutate_drain() {
    _drain_lines=$(wc -l <"$1" 2>/dev/null || printf '0')
    _drain_lines=$((_drain_lines + 0))
    if [ "${_drain_lines}" -gt "${_drain_seen}" ]; then
        sed -n "$((_drain_seen + 1)),${_drain_lines}p" "$1"
        _drain_seen=${_drain_lines}
    fi
}

# _pkg_mutate DIE_CODE DIE_MSG ARGS... — mutating pkg verbs (install/delete).
# Stream output while pkg runs, then die if pkg rc != 0 OR a line is
# `pkg: * script failed` (pkg(8) can exit 0 after POST-INSTALL/DEINSTALL
# still failed — the files are already in place; issue #2575).
#
# pkg writes to a capture FILE and a reader prints what that file grows by, rather than
# pkg writing down a pipe. A pipe outlives pkg: every process a package script leaves
# running inherits the write end, and a reader sees no EOF until the last holder closes
# it — the hazard pfblockerng.inc states as "LOG FILE, never a pipe" for its own capture
# (issue #662), and solves the same way its own hook mirror does (issue #693). Our
# POST-INSTALL starts unbound, so that risk is not theoretical, and a hang after a
# completed install is worse than the burst it would replace. A regular file cannot stall
# the run, and the foreground pkg hands back its own status with no side channel to read
# it out of (issue #2644).
#
# What a reader can show is bounded by what pkg flushes and when; the package scripts
# (PHP CLI writes unbuffered) appear as they print.
_pkg_mutate() {
    _mut_code="$1"
    shift
    _mut_msg="$1"
    shift
    if [ -n "${ROOT}" ]; then
        mkdir -p "${ROOT}/tmp" || die "${_mut_code}" "could not create ${ROOT}/tmp"
        _mut_dir="${ROOT}/tmp"
    else
        _mut_dir="${TMPDIR:-/tmp}"
    fi
    # mktemp for BOTH files: a derived name is a name an attacker can predict from the
    # first one and pre-create as a symlink, and this runs as root.
    _mut_log=$(mktemp "${_mut_dir}/pfb-install-pkg.XXXXXX") ||
        die "${_mut_code}" "mktemp failed while capturing pkg output"
    # Armed before the SECOND mktemp, so its failure cannot leak the first file. Every
    # path is read as `:-` because `set -u` makes an unset name in a trap fatal AND
    # replaces the exit status the trap fired on; `rm -f ""` is a no-op. die() exits the
    # script, so the EXIT trap runs on that path too. /tmp on pfSense is a small RAM disk.
    #
    # The signal traps exist because the reader below is a background job: a bare EXIT
    # trap never runs on an untrapped INT/TERM/HUP, which would leave the reader
    # reparented to PID 1 polling forever and both files behind. Each re-raises the
    # conventional 128+signal status rather than swallowing the interrupt.
    trap '_pkg_mutate_cleanup' EXIT
    trap '_pkg_mutate_cleanup; exit 130' INT
    trap '_pkg_mutate_cleanup; exit 143' TERM
    trap '_pkg_mutate_cleanup; exit 129' HUP
    _mut_done=$(mktemp "${_mut_dir}/pfb-install-pkg.XXXXXX") ||
        die "${_mut_code}" "mktemp failed while capturing pkg output"
    # The reader runs in the background and stops when pkg is done: mktemp already
    # created the done-file, so the flag is CONTENT, not existence.
    #
    # It also dies with its task rather than only on being told to. `$$` stays the
    # parent's pid inside a subshell, so the liveness test ends the loop even when the
    # parent is killed outright and no trap can fire; the counter is the backstop for the
    # case where the pid outlives the run some other way, i.e. a hard cap and a deadline
    # on a wait nothing else is tracking (AGENTS.md "No orphaned waits").
    _mut_parent=$$
    (
        _drain_seen=0
        _drain_ticks=0
        while [ ! -s "${_mut_done}" ] &&
            ! _pfb_parent_gone "${_mut_parent}" &&
            [ "${_drain_ticks}" -lt "${_PFB_DRAIN_MAX_TICKS}" ]; do
            _pkg_mutate_drain "${_mut_log}"
            _drain_ticks=$((_drain_ticks + 1))
            sleep 1
        done
        sed -n "$((_drain_seen + 1)),\$p" "${_mut_log}"
    ) &
    _mut_reader=$!
    _mut_rc=0
    _pkg "$@" >"${_mut_log}" 2>&1 || _mut_rc=$?
    printf 'done\n' >"${_mut_done}"
    wait "${_mut_reader}" 2>/dev/null || true
    if [ "${_mut_rc}" -ne 0 ]; then
        pfb_pkg_die "${_mut_code}" "${_mut_msg}"
    fi
    while IFS= read -r _mut_line || [ -n "${_mut_line}" ]; do
        # Hook stdout often ends without a newline, so pkg's message is glued
        # mid-line: ``thrown</pre>pkg: POST-INSTALL script failed``.
        case "${_mut_line}" in
            *'pkg: '*' script failed'*)
                die "${_mut_code}" "pkg reported a package-script failure — ${_mut_msg}"
                ;;
        esac
    done < "${_mut_log}"
    trap - EXIT INT TERM HUP
    rm -f "${_mut_log}" "${_mut_done}"
    unset _mut_code _mut_msg _mut_dir _mut_log _mut_done _mut_parent _mut_reader _mut_rc _mut_line
}

usage() {
    cat <<USAGE
install.sh — put this pfSense box on a pfBlockerNG channel.

Usage:
  install.sh --channel <stable|testing|edge|nightly>   subscribe + install/converge (idempotent)
  install.sh -h|--help                                  this text

Published at https://${PFB_REPO_HOST}/install.sh; run ON the box:
USAGE
    # Single-quoted format: dash/set -u must not expand $t or $(mktemp) while
    # printing help. ${PFB_REPO_HOST} is the %s argument (issue #2756).
    # shellcheck disable=SC2016
    printf '  t=$(mktemp "${TMPDIR:-/tmp}/pfb-install.XXXXXX") && fetch -T 60 -o "$t" https://%s/install.sh && [ -s "$t" ] && /bin/sh "$t" --channel <stable|testing|edge|nightly>; e=$?; [ -n "$t" ] && rm -f "$t"; (exit $e)\n' "${PFB_REPO_HOST}"
    cat <<'USAGE_TAIL'

Installs the boot-time repo-conf generator hook (ADR-39), subscribes this box to the
named channel ALONE (retiring any other pfBlockerNG channel conf), then installs or
moves the running package onto pfSense-pkg-pfBlockerNG from that channel. Safe to
re-run: a converged box performs no package changes.

Exit codes:
  0  ok, including a reported no-op (already up to date)
  1  environment: pkg binary or hook source not found
  2  usage: unknown argument, unknown/missing --channel
  4  target unavailable: the hook could not resolve the conf, pkg update failed, the
     catalogue offers nothing, or pkg version -t gave no usable answer
  5  a pkg operation (delete/install) failed, including a package-script failure while pkg exited 0
  6  post-install verification failed

A failed pkg step is often this box's own repository setup rather than the pfBlockerNG
conf: rebuild it, then re-run this script.

  pfSense-upgrade -u

That one command re-fetches the repository settings (it runs pfSense-repo-setup, which
runs pfSense-repoc-static) and then forces a catalogue refresh, upgrading or
re-bootstrapping pkg itself if the repository requires it. "Another instance is already
running" means a boot-time metadata refresh holds the lock; wait for it and retry.

Only if the re-run still fails, escalate to a bare pfSense-upgrade. With no arguments it
applies any pfSense release upgrade the box's branch offers, and reboots when it does, so
it is a deliberate last step rather than part of the repair above.
USAGE_TAIL
}

# pfb_emit_embedded_hook — print the rc.d generator hook to stdout. In the repository
# copy this is a STUB that fails loud: the standalone
# src/usr/local/etc/rc.d/pfblockerng_repo_generate.sh is the source of truth, used
# directly from a checkout via HOOK_SRC. The pkg-owned website renderer replaces
# the body between the PFB_EMBED markers with the hook in a single-quoted
# heredoc, producing the self-contained install.sh served at <base>/install.sh
# for leftover `fetch | sh` users and the published fetch-to-file form.
pfb_emit_embedded_hook() {
    # PFB_EMBED_HOOK_BEGIN — do not edit; replaced by the pkg-owned website renderer.
    printf 'install.sh: no embedded hook in this copy — run from a checkout, or use the published %s/install.sh\n' "https://${PFB_REPO_HOST}" >&2
    return 1
    # PFB_EMBED_HOOK_END
}

# pfb_channel_install ARGS... — the state machine. Every step is check-then-act
# against live state, so a second run on a converged box performs zero package
# mutations and leaves the conf + hook bytes unchanged (idempotent).
pfb_channel_install() {
    PFB_CHANNEL=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --channel)
                [ $# -ge 2 ] || {
                    usage >&2
                    die 2 "--channel requires a value"
                }
                PFB_CHANNEL="$2"
                shift 2
                ;;
            --channel=*)
                PFB_CHANNEL="${1#--channel=}"
                shift
                ;;
            -h | --help)
                usage
                return 0
                ;;
            *)
                usage >&2
                die 2 "unknown argument: $1"
                ;;
        esac
    done

    case "${PFB_CHANNEL}" in
        stable | testing | edge | nightly) ;;
        "")
            usage >&2
            die 2 "--channel is required — there is no default"
            ;;
        release)
            usage >&2
            die 2 "'release' is not a channel — choose stable, testing, edge, or nightly"
            ;;
        *)
            usage >&2
            die 2 "unknown channel '${PFB_CHANNEL}' — choose stable, testing, edge, or nightly"
            ;;
    esac

    REPO_NAME="pfblockerng-${PFB_CHANNEL}"
    CONF_NAME="pfblockerng-${PFB_CHANNEL}.conf"
    CONF_PATH="${REPOS_DIR}/${CONF_NAME}"

    # 1. Environment.
    command -v "${PKG_BIN}" >/dev/null 2>&1 ||
        die 1 "'${PKG_BIN}' not found — run this ON a pfSense box, or set PKG_BIN"

    # 2. Boot-time generator hook: install/refresh only if missing or different.
    #    Try the EMBEDDED hook first; HOOK_SRC (the checkout copy under src/) is
    #    consulted only when the embedded hook is the repository stub
    #    (pfb_emit_embedded_hook fails). Die if neither source is available.
    _hook_tmp="$(mktemp "${TMPDIR:-/tmp}/pfb-hook.XXXXXX")" || die 1 "mktemp failed while staging the boot hook"
    if pfb_emit_embedded_hook >"${_hook_tmp}" 2>/dev/null; then
        :
    elif [ -f "${HOOK_SRC}" ]; then
        cp "${HOOK_SRC}" "${_hook_tmp}"
    else
        rm -f "${_hook_tmp}"
        die 1 "no embedded hook in this copy and no checkout sibling at ${HOOK_SRC} — run the published install.sh, or run from a checkout"
    fi
    if [ -f "${ON_BOX_HOOK}" ] && cmp -s "${_hook_tmp}" "${ON_BOX_HOOK}"; then
        # "Up to date" means the BYTES match — never that the mode is already
        # correct (a restored config backup / tar extraction can drop the exec
        # bit on an otherwise byte-identical file), so chmod runs unconditionally.
        chmod 755 "${ON_BOX_HOOK}"
        printf '==> Hook up to date\n'
    else
        mkdir -p "$(dirname "${ON_BOX_HOOK}")"
        cp "${_hook_tmp}" "${ON_BOX_HOOK}"
        chmod 755 "${ON_BOX_HOOK}"
        printf '==> Installed boot-time generator hook to %s\n' "${ON_BOX_HOOK}"
    fi
    rm -f "${_hook_tmp}"

    # 3. Conf: stage a stub ONLY if absent — an existing conf is never truncated, the
    #    hook rewrites it in place (or leaves it untouched if detection fails), so no
    #    backup/restore dance is needed here (the predecessor two-script flow used to
    #    stage over a possibly-working conf before proving the new one).
    CONF_CREATED=0
    if [ ! -f "${CONF_PATH}" ]; then
        mkdir -p "${REPOS_DIR}"
        printf '# pfBlockerNG %s repo conf — pending boot-time generation (ADR-39).\n' "${PFB_CHANNEL}" >"${CONF_PATH}"
        CONF_CREATED=1
    fi

    # Drive the hook for THIS channel's conf only. Its orphan guard skips an absent
    # path, so every peer conf is aimed at a path that cannot exist: a run against
    # another base (fork, staged prefix) that fails before verify must not have
    # re-pointed a working peer subscription — peers are only ever retired, after.
    printf '==> Running the generator hook to resolve the conf now\n'
    _no_conf="${REPOS_DIR}/.pfb-no-such-conf"
    _own_conf_var="PFB_$(printf '%s' "${PFB_CHANNEL}" | tr '[:lower:]' '[:upper:]')_CONF"
    env PFB_STABLE_CONF="${_no_conf}" \
        PFB_TESTING_CONF="${_no_conf}" \
        PFB_EDGE_CONF="${_no_conf}" \
        PFB_NIGHTLY_CONF="${_no_conf}" \
        "${_own_conf_var}=${CONF_PATH}" \
        PFB_BASE_URL="${PFB_BASE_URL}" \
        PFB_FINGERPRINT_DIR="${FINGERPRINT_DIR}" \
        PFB_PRODUCT_LABEL="${ROOT}/etc/product_label" \
        PFB_VERSION_FILE="${ROOT}/etc/version" \
        sh "${ON_BOX_HOOK}" onestart </dev/null || true

    if ! grep -q "${CONF_MARKER}" "${CONF_PATH}" 2>/dev/null; then
        [ "${CONF_CREATED}" -eq 1 ] && rm -f "${CONF_PATH}"
        die 4 "the generator hook did not resolve ${CONF_PATH} (no marker line) — variant detection may have failed; inspect: sh ${ON_BOX_HOOK} onestart"
    fi
    # The marker alone is not enough: the hook leaves an EXISTING conf UNCHANGED
    # when detection fails, so a pre-existing conf carrying the marker but
    # resolving to ANOTHER base/channel (a stale conf from a fork, a staged
    # prefix, or a restored config backup) must be rejected too.
    _expect_url_prefix="url: \"${PFB_BASE_URL%/}/${PFB_CHANNEL}/"
    if ! grep -qF "${_expect_url_prefix}" "${CONF_PATH}" 2>/dev/null; then
        [ "${CONF_CREATED}" -eq 1 ] && rm -f "${CONF_PATH}"
        die 4 "${CONF_PATH} does not resolve to ${PFB_BASE_URL%/}/${PFB_CHANNEL}/ — a stale or foreign conf; inspect: sh ${ON_BOX_HOOK} onestart"
    fi
    printf '==> Conf resolved:\n'
    sed -n 's/^[[:space:]]*url:[[:space:]]*/    url: /p' "${CONF_PATH}"

    # 4. Refresh THIS repo's catalog only (a stale/unpublished peer must not veto the
    #    switch — issue #2384).
    printf '==> pkg update -f -r %s (refreshing the pfBlockerNG catalog)\n' "${REPO_NAME}"
    _pkg update -f -r "${REPO_NAME}" || {
        [ "${CONF_CREATED}" -eq 1 ] && rm -f "${CONF_PATH}"
        pfb_pkg_die 4 "$(printf '%s update -f -r %s failed — the catalog was not refreshed. Repo '\''%s'\'' is unreachable or serving an unreadable catalog. Inspect with: %s -d update -r %s' \
            "${PKG_BIN}" "${REPO_NAME}" "${REPO_NAME}" "${PKG_BIN}" "${REPO_NAME}")"
    }

    # 5. Pick the newest offered version with the SAME comparator pkg install itself
    #    resolves by (issue #2393) — rquery order is catalogue order, not version order.
    OFFERED=""
    for _offered in $(_pkg rquery -r "${REPO_NAME}" '%v' "${CANONICAL_PKG}" 2>/dev/null || true); do
        if [ -z "${OFFERED}" ]; then
            OFFERED="${_offered}"
            continue
        fi
        _order="$(_pkg version -t "${_offered}" "${OFFERED}" 2>/dev/null || true)"
        case "${_order}" in
            '>') OFFERED="${_offered}" ;;
            '<' | '=') ;;
            *)
                [ "${CONF_CREATED}" -eq 1 ] && rm -f "${CONF_PATH}"
                die 4 "\`${PKG_BIN} version -t\` gave no usable answer comparing '${_offered}' and '${OFFERED}' — cannot tell which build ${REPO_NAME} would install"
                ;;
        esac
    done
    [ -n "${OFFERED}" ] || {
        [ "${CONF_CREATED}" -eq 1 ] && rm -f "${CONF_PATH}"
        pfb_pkg_die 4 "repo '${REPO_NAME}' does not offer ${CANONICAL_PKG} — run \`pkg update -f\`, and check the ${PFB_CHANNEL} catalogue has a build for this pfSense edition/version"
    }
    printf '==> Target: %s-%s (repo %s)\n' "${CANONICAL_PKG}" "${OFFERED}" "${REPO_NAME}"

    # 6. Only now retire every OTHER project conf — the target is proven usable, so
    #    this cannot strand the box (issue #2148).
    for _other in ${PROJECT_CONFS}; do
        [ "${_other}" = "${CONF_NAME}" ] && continue
        [ -f "${REPOS_DIR}/${_other}" ] || continue
        printf '==> Retiring %s — a box subscribes to ONE pfBlockerNG channel\n' "${REPOS_DIR}/${_other}"
        rm -f "${REPOS_DIR}/${_other}"
    done

    # 7. Report installed state.
    _installed_names="$(_pkg query -g '%n' 'pfSense-pkg-pfBlockerNG*' 2>/dev/null || true)"
    _installed_names="$(printf '%s\n' "${_installed_names}" | grep -v '^[[:space:]]*$' || true)"
    if [ -n "${_installed_names}" ]; then
        for _iname in ${_installed_names}; do
            _iver="$(_pkg query '%v' "${_iname}" 2>/dev/null || true)"
            _irepo="$(_pkg query '%R' "${_iname}" 2>/dev/null || true)"
            printf '==> Installed: %s-%s (from repo %s)\n' "${_iname}" "${_iver:-unknown}" "${_irepo:-unknown}"
        done
    else
        printf '==> Installed: none\n'
    fi

    # 8. Snapshot the config section so a silent loss during 9 becomes a step-10 failure.
    CONFIG_SECTION_BEFORE=0
    if [ -f "${CONFIG_XML}" ] && grep -q '<pfblockerng>' "${CONFIG_XML}" 2>/dev/null; then
        CONFIG_SECTION_BEFORE=1
    fi

    # 9. Converge.
    # 9a. Every OTHER identity (legacy suffix, fork) is a different pkg NAME, so a
    #     plain install could never replace it — delete first.
    for _iname in ${_installed_names}; do
        [ "${_iname}" = "${CANONICAL_PKG}" ] && continue
        printf '==> Removing %s\n' "${_iname}"
        _pkg_mutate 5 "\`pkg delete ${_iname}\` failed — re-run after fixing the cause, or finish manually: ${PKG_BIN} delete -y ${_iname}" \
            delete -y "${_iname}"
    done

    _canon_ver="$(_pkg query '%v' "${CANONICAL_PKG}" 2>/dev/null || true)"
    _canon_repo="$(_pkg query '%R' "${CANONICAL_PKG}" 2>/dev/null || true)"

    if [ -n "${_canon_ver}" ] && [ "${_canon_repo}" = "${REPO_NAME}" ] && [ "${_canon_ver}" = "${OFFERED}" ]; then
        # 9b. Already converged — no pkg mutation.
        printf '==> Already up to date: %s-%s (repo %s) — nothing to do.\n' "${CANONICAL_PKG}" "${_canon_ver}" "${REPO_NAME}"
    elif [ -n "${_canon_ver}" ]; then
        # 9c. Canonical installed from another repo, or another version of this repo —
        #     a repository-qualified force reinstall (ordinary `pkg upgrade` refuses a
        #     same-or-older version; crossing repos or channels needs -f by design).
        _order="$(_pkg version -t "${OFFERED}" "${_canon_ver}" 2>/dev/null || true)"
        if [ "${_order}" = "<" ]; then
            _fam_offered="$(printf '%s' "${OFFERED}" | cut -d. -f1,2)"
            _fam_installed="$(printf '%s' "${_canon_ver}" | cut -d. -f1,2)"
            if [ "${_fam_offered}" != "${_fam_installed}" ]; then
                {
                    printf 'install.sh: WARNING — moving back from %s to %s crosses release families:\n' "${_canon_ver}" "${OFFERED}"
                    printf '  settings written by the newer build may be rolled back or dropped by the\n'
                    printf '  older build'\''s migrations, features present in the newer build disappear,\n'
                    printf '  and a re-save may be needed.\n'
                } >&2
            fi
        fi
        printf '==> Reinstalling %s from %s (repository-qualified)\n' "${CANONICAL_PKG}" "${REPO_NAME}"
        _pkg_mutate 5 "\`pkg install -f -r ${REPO_NAME} ${CANONICAL_PKG}-${OFFERED}\` failed — the previous build is still installed" \
            install -y -f -r "${REPO_NAME}" "${CANONICAL_PKG}-${OFFERED}"
    else
        # 9d. Nothing canonical installed (fresh box, or right after 9a's deletes).
        printf '==> Installing %s from %s\n' "${CANONICAL_PKG}" "${REPO_NAME}"
        _pkg_mutate 5 "\`pkg install -r ${REPO_NAME} ${CANONICAL_PKG}\` failed — no pfBlockerNG is currently installed; fix the cause, then finish with: ${PKG_BIN} install -y -r ${REPO_NAME} ${CANONICAL_PKG}" \
            install -y -r "${REPO_NAME}" "${CANONICAL_PKG}"
    fi

    # 10. Prove the result — every claim is re-read from pkg after the fact.
    _final_names="$(_pkg query -g '%n' "${CANONICAL_PKG}*" 2>/dev/null || true)"
    _final_names="$(printf '%s\n' "${_final_names}" | grep -v '^[[:space:]]*$' || true)"
    [ "${_final_names}" = "${CANONICAL_PKG}" ] ||
        die 6 "$(printf 'expected exactly %s installed, found:\n%s' "${CANONICAL_PKG}" "${_final_names:-(none)}")"

    _final_repo="$(_pkg query '%R' "${CANONICAL_PKG}" 2>/dev/null || true)"
    [ "${_final_repo}" = "${REPO_NAME}" ] ||
        die 6 "${CANONICAL_PKG} reports repo '${_final_repo:-unknown}', expected '${REPO_NAME}'"

    _final_ver="$(_pkg query '%v' "${CANONICAL_PKG}" 2>/dev/null || true)"
    [ "${_final_ver}" = "${OFFERED}" ] ||
        die 6 "${CANONICAL_PKG} reports version '${_final_ver:-unknown}', expected '${OFFERED}' from ${REPO_NAME}"

    _missing="$(
        _pkg info -l "${CANONICAL_PKG}" 2>/dev/null |
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

    # 11. Done.
    printf '==> Done — %s-%s installed from %s (%s channel).\n' "${CANONICAL_PKG}" "${OFFERED}" "${REPO_NAME}" "${PFB_CHANNEL}"
}

pfb_channel_install "$@"
