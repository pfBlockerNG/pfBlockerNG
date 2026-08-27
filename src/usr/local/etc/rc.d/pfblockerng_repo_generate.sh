#!/bin/sh
# /usr/local/etc/rc.d/pfblockerng_repo_generate.sh — boot-time repo-conf
# regenerator (ADR-39). Installed by install.sh.
#
# JOB 1 — WHAT IT DOES (and nothing more): for each pfBlockerNG pkg-repo conf
# file that EXISTS, it detects this box's pfSense edition/version and
# overwrites the conf with the canonical body — a fully-resolved catalog URL
# for the box's variant (ADR-17 / ADR-20) plus a marker comment. No pkg call,
# no network fetch, no snapshot, no reconcile. It is a conf REGENERATOR:
# re-deriving the conf from scratch is strictly simpler — and never wrong —
# than diffing and patching one in place.
#
# The one thing it does NOT re-derive is the catalog BASE. With no environment
# (which is every boot) the base is read back out of the conf's own url, so only
# the <varver> moves; a fork site, a staging prefix and a `file://` guest
# catalogue survive a reboot instead of being redirected to the primary Pages
# site, and a url this hook could not have written is left alone (issue #2459).
#
# WHY AT BOOT: a pfSense OS upgrade can change the box's edition/version, which
# requires a reboot and moves the catalog subtree; regenerating here keeps the
# conf's url aligned with no extra upgrade hook to register.
#
# rc.d ordering: REQUIRE FILESYSTEMS (so /usr/local is mounted) and
# BEFORE NETWORKING (so the conf is correct before anything that could invoke
# pkg over the network runs). Safe to run this early precisely because it is
# local-file-only — it touches no network and no daemon.
#
# HARD RULE: every path ends in `exit 0`. This hook MUST NEVER wedge boot.
#
# Detection (KISS): edition = "/etc/product_label contains 'Plus'" -> plus, else
# ce; version = major.minor of /etc/version, with any dash suffix (e.g.
# "-BETA"/"-RC") stripped FIRST. This MIRRORS catalog_name_from_version() in
# scripts/build-repo-portable.py exactly, including that strip: a live box's
# /etc/version can carry a pre-release suffix the matrix's version never does
# (issue #1786), and the producers strip it identically so a pre-release box and
# the publisher agree on one catalog dir (issue #1965). Arch-less since issue #1806 (NO_ARCH) — the catalog
# no longer has a per-arch leaf, so this hook no longer calls `pkg` at all (it
# used to read `pkg config abi` only to derive that leaf).
#
# The emitted conf body is BYTE-IDENTICAL to `build-repo.sh --print-conf` and
# `build-repo-portable.py --print-conf` (pinned by tests/test_repo_conf_generators.py).
#
# POSIX sh only; quote all expansions.

# shellcheck shell=sh
#
# FreeBSD rc.d script: rc.subr's run_rc_command dispatches the *_start handler
# via indirect variables, so shellcheck cannot see those call sites — SC2317
# (unreachable command) and SC2034 ($rcvar assigned-but-unused) are false
# positives here.
# shellcheck disable=SC2317,SC2034

# PROVIDE: pfblockerng_repo_generate
# REQUIRE: FILESYSTEMS
# BEFORE: NETWORKING

name="pfblockerng_repo_generate"

# On-box paths (installed by install.sh). Override
# via env for tests.
#
# One path per channel repository (issue #2148). The four channel repos each own
# a <channel>/<varver>/ catalogue serving the ONE canonical package. A box
# subscribes to exactly ONE of these — the orphan guard in _regen_one() is what
# keeps regeneration from re-enabling a channel the user switched away from. The
# legacy shared release repo (pfblockerng.conf, pre-#2148) is retired by the
# installers and never regenerated — a leftover is left byte-unchanged
# (issue #2416).
: "${PFB_STABLE_CONF:=/usr/local/etc/pkg/repos/pfblockerng-stable.conf}"
: "${PFB_TESTING_CONF:=/usr/local/etc/pkg/repos/pfblockerng-testing.conf}"
: "${PFB_EDGE_CONF:=/usr/local/etc/pkg/repos/pfblockerng-edge.conf}"
: "${PFB_NIGHTLY_CONF:=/usr/local/etc/pkg/repos/pfblockerng-nightly.conf}"
: "${PFB_FINGERPRINT_DIR:=/usr/local/etc/pkg/fingerprints/pfblockerng}"
: "${PFB_PRODUCT_LABEL:=/etc/product_label}"
: "${PFB_VERSION_FILE:=/etc/version}"

# The catalog base. NOT defaulted into PFB_BASE_URL: an explicitly exported
# PFB_BASE_URL (install.sh, the smoke guests, a fork bootstrap) must stay
# distinguishable from "nothing in the environment", because at boot the base
# comes from the conf itself — see _base_from_conf() and issue #2459.
#
# The fallback below is reached only by a conf that carries no url line at all —
# today only the off-box test harnesses, since install.sh always supplies a base
# of its own. Deliberately NOT named PFB_DEFAULT_BASE_URL: gen_landing.py injects
# a variable of that name into install.sh, and the published installer carries
# this hook embedded in it.
# The pkg repository domain. Scheme per use site: the catalogue is plain HTTP (pkg's
# CA store is Netgate-pinned on pfSense Plus, so TLS is not a trust anchor we can rely
# on there -- the catalogue signature is, issue #2675).
REPO_HOST='pkg.pfblockerng.com'
PFB_FALLBACK_BASE_URL="http://${REPO_HOST}"

CONF_PRIORITY=100

# Detect this box's catalog subtree "<varver>" (e.g. "ce-2.8") — arch-less
# since issue #1806 (NO_ARCH). Returns 1 (no output) if the version can't be
# resolved — the caller then leaves the existing conf untouched rather than
# writing a malformed URL.
_detect_catalog() {
    # Edition: lowercase prefix matching build-repo-portable.py (ce | plus).
    if grep -q 'Plus' "${PFB_PRODUCT_LABEL}" 2>/dev/null; then
        _dc_edition='plus'
    else
        _dc_edition='ce'
    fi
    # Version: major.minor of /etc/version, pre-release suffix stripped first
    # (e.g. "2.8.1" -> "2.8"; "26.07-BETA" -> "26.07"; issue #1786: a dash
    # suffix sitting inside the minor field, e.g. "-BETA"/"-RC"/"-RELEASE",
    # must not leak into the catalog varver — cut on '-' before cut on '.').
    _dc_ver=''
    [ -r "${PFB_VERSION_FILE}" ] && IFS= read -r _dc_ver < "${PFB_VERSION_FILE}"
    _dc_mm="$(printf '%s' "${_dc_ver}" | cut -d- -f1 | cut -d. -f1,2)"
    [ -n "${_dc_mm}" ] || return 1
    printf '%s-%s' "${_dc_edition}" "${_dc_mm}"
}

# Recover the catalog base a conf was last generated from. $1 = conf path,
# $2 = channel word. The canonical url is "<base>/<channel>/<varver>", so the
# base is what is left after stripping the two trailing segments — and the
# channel segment MUST equal this conf's own channel, which is what makes the
# url recognisably one this hook wrote.
#
# WHY (issue #2459): at boot there is no environment, so composing the url from
# a hardcoded default rewrote every conf to the primary Pages site — a fork
# site, a staging prefix and a `file://` guest catalogue all silently became
# https://pkg.pfblockerng.com, redirecting where the box fetches packages
# from. Reading the base back out of the conf keeps the OS-upgrade job the hook
# exists for (move the <varver>) without moving anything else.
#
# Prints the base on success. Returns 1 ONLY when the conf carries no url line at
# all (an install.sh stub pending first generation — the caller falls back to the
# built-in default); 2 whenever a url IS present but is not one this hook could
# have written (the caller leaves the conf alone). The discriminator is the
# presence of the url line, never whether the pattern below matched it:
# unquoted and single-quoted strings are valid UCL an operator can hand-write,
# and an unterminated quote is what a botched hand edit leaves behind — treating
# any of those as a pending stub would rewrite them from the built-in default,
# which is the redirect this whole guard exists to prevent.
_base_from_conf() {
    _bc_conf="$1"
    _bc_channel="$2"
    _bc_url="$(sed -n 's/^[[:space:]]*url:[[:space:]]*"\([^"]*\)".*/\1/p' "${_bc_conf}" 2>/dev/null | head -n 1)"
    if [ -z "${_bc_url}" ]; then
        # -i: a conf spelling the key `URL:` matches neither the extractor above
        # nor a case-sensitive presence check, and taking it for a conf with no
        # url at all would clobber it from the fallback base.
        grep -qi '^[[:space:]]*url[[:space:]]*:' "${_bc_conf}" 2>/dev/null && return 2
        return 1
    fi
    # One trailing slash is still our shape — a conf frozen as foreign over it
    # would sit on a stale varver forever after an OS upgrade.
    _bc_url="${_bc_url%/}"
    _bc_head="${_bc_url%/*}"
    [ "${_bc_head}" != "${_bc_url}" ] || return 2
    # The trailing segment must be shaped like the varver _detect_catalog()
    # above emits: a `ce-` or `plus-` prefix followed by major.minor. Anything
    # looser accepts a directory the operator chose (and would then replace it),
    # or a url carrying a query string or fragment (and would drop credentials
    # they put there while rewriting the path). Deliberately a shape check and
    # not an equality one — the point is to recognise OUR url, including the
    # pre-upgrade varver we are about to move off.
    _bc_varver="${_bc_url##*/}"
    case "${_bc_varver}" in
        ce-[0-9]* | plus-[0-9]*) ;;
        *) return 2 ;;
    esac
    case "${_bc_varver#*-}" in
        *[!0-9.]*) return 2 ;;
    esac
    [ "${_bc_head##*/}" = "${_bc_channel}" ] || return 2
    _bc_base="${_bc_head%/*}"
    [ "${_bc_base}" != "${_bc_head}" ] || return 2
    # The base must carry a whole scheme separator. Without one it is either a
    # bare scheme — what is left when the channel segment was in fact the host,
    # e.g. "https://nightly/ce-2.7" — or a one-slash scheme, neither of which
    # this hook emits and both of which rebuild into a malformed url.
    case "${_bc_base}" in
        *://*) ;;
        *) return 2 ;;
    esac
    # ONE-WAY MIGRATION, and the only scheme rewrite anywhere: a box bootstrapped
    # before issue #2675 carries an https base in its own conf, and re-emitting that
    # verbatim would pair TLS with `signature_type: fingerprints` -- precisely the
    # combination pkg cannot fetch on pfSense Plus, where its CA store is
    # Netgate-pinned. Only OUR host is moved, and only downward: a fork base, a
    # staging host, a file:// tree all keep exactly what they had. Generators emit
    # the base they are handed; nothing else rewrites a scheme.
    case "${_bc_base}" in
        "https://${REPO_HOST}" | "https://${REPO_HOST}/"*)
            printf 'http://%s' "${_bc_base#https://}"
            return 0
            ;;
    esac
    printf '%s' "${_bc_base}"
}

# The catalogue signing key's public half, as the fingerprint pkg checks: the SHA256 of
# the DER public key exactly as the catalogue embeds it (issue #2675). Shipped as the
# hex rather than the key itself because that is all `signature_type: fingerprints`
# needs on the box -- the key travels inside each signed catalogue.
# What the conf TELLS pkg, and where this hook WRITES, are two different paths and
# must stay so: PFB_FINGERPRINT_DIR is staged by every off-box caller (install.sh
# under ROOT, the specs under their own tmp box), while the emitted conf has to
# name the path that will exist on the running box -- a chroot install whose conf
# pointed at the staging directory would find no trusted key once it booted as /.
CONF_FINGERPRINT_DIR='/usr/local/etc/pkg/fingerprints/pfblockerng'
CONF_FINGERPRINT_NAME="${REPO_HOST}"
CONF_FINGERPRINT_SHA256='081df5476f84d8d20417c400f576c355069a4a9979d170bcaae1c9da32778915'

# Install the trusted fingerprint. Runs BEFORE any conf is rewritten: a box that reached
# a signature-requiring conf without the key that validates it could no longer reach the
# repository that would fix it. Every failure is non-fatal -- this hook must never wedge
# boot -- and a conf rewrite that follows a failed write is still safe, because pkg
# treats an unreadable fingerprint dir as "no trusted key" and refuses the catalogue
# rather than trusting it.
_write_fingerprint() {
    _wf_trusted="${PFB_FINGERPRINT_DIR}/trusted"
    _wf_file="${_wf_trusted}/${CONF_FINGERPRINT_NAME}"
    # $$-suffixed and OUTSIDE trusted/: two hooks racing at boot would otherwise
    # collide on one temp name, and pkg reads every file in trusted/ as a key.
    _wf_tmp="${PFB_FINGERPRINT_DIR}/.${CONF_FINGERPRINT_NAME}.$$"
    mkdir -p "${_wf_trusted}" "${PFB_FINGERPRINT_DIR}/revoked" 2>/dev/null || {
        printf '[%s] WARNING: could not create %s\n' "${name}" "${PFB_FINGERPRINT_DIR}" >&2
        return 1
    }
    if printf 'function: "sha256"\nfingerprint: "%s"\n' "${CONF_FINGERPRINT_SHA256}" >"${_wf_tmp}" 2>/dev/null; then
        if mv "${_wf_tmp}" "${_wf_file}" 2>/dev/null; then
            return 0
        fi
    fi
    rm -f "${_wf_tmp}" 2>/dev/null
    printf '[%s] WARNING: could not write %s\n' "${name}" "${_wf_file}" >&2
    return 1
}

# The URL a conf points at, for a resolved catalogue base. HTTPS is downgraded to plain
# HTTP deliberately: pkg on pfSense Plus runs against a Netgate-pinned CA bundle that
# nothing we ship can widen, so TLS to our host is not a trust anchor we can rely on --
# authenticity comes from the catalogue signature instead, and package payloads are
# checksummed by that signed catalogue. Any other scheme is left alone; a file://
# catalogue has no network in its path at all.
# The one host whose catalogues our signing key signs. The signed shape keys on the
# HOST, never the scheme alone: a fork base serves a catalogue our key never touched,
# so pinning our fingerprint to it would leave that fork unusable -- and downgrading
# someone else's host to plaintext is not ours to do.
_conf_signed_host() {
    case "$1" in
        "https://${REPO_HOST}" | "https://${REPO_HOST}/"* | \
            "http://${REPO_HOST}" | "http://${REPO_HOST}/"*) return 0 ;;
    esac
    return 1
}

# Trust comment + signature fields, keyed on the URL: a file:// catalogue is built
# locally and carries no signature, so requiring one would fail a catalogue that is fine.
_conf_trust_comment() {
    if _conf_signed_host "$1"; then
        printf '%s\n%s\n%s\n' \
            '# Signed catalogue (issue #2675): the trust anchor is our own ECDSA key, whose' \
            "# fingerprint the boot rc.d hook installs; the fetch is plain HTTP because pkg's" \
            '# CA store is Netgate-pinned on pfSense Plus and unreachable from the GUI.'
    else
        printf '%s\n' '# Unsigned catalogue: this base is not the signed project host.'
    fi
}

_conf_signature_lines() {
    if _conf_signed_host "$1"; then
        printf '  signature_type: fingerprints,\n  fingerprints: "%s",' "${CONF_FINGERPRINT_DIR}"
    else
        printf '  signature_type: none,'
    fi
}

# Emit the canonical conf body. $1 = channel word, $2 = repo name, $3 = url.
# Kept byte-identical to the *_print_conf generators (drift-pinned by tests).
_emit_conf() {
    _ec_channel="$1"
    _ec_repo="$2"
    _ec_url="$3"
    cat <<EOF
# Generated at boot by pfblockerng_repo_generate (ADR-39) — do not edit; re-run install.sh --channel ${_ec_channel} to change.
# pfBlockerNG (${_ec_channel} channel) — self-hosted pkg repository (ADR-17).
$(_conf_trust_comment "${_ec_url}")
# The URL is fully resolved for this box's edition/version (ADR-39; arch-less/NO_ARCH,
# issue #1806); the boot rc.d hook updates it on a pfSense OS upgrade.
# priority ${CONF_PRIORITY} sits above the base Netgate \`pfSense\` repo so cross-repo
# resolution (pkg install/upgrade, GUI Install) selects the pfBlockerNG build.
${_ec_repo}: {
  url: "${_ec_url}",
  mirror_type: none,
$(_conf_signature_lines "${_ec_url}")
  priority: ${CONF_PRIORITY},
  enabled: yes
}
EOF
}

# Regenerate one conf IF it exists (orphan guard: an absent conf stays absent —
# we never create a channel the user didn't bootstrap).
# $1 = conf path, $2 = channel word (stable|testing|edge|nightly), $3 = repo name.
_regen_one() {
    _ro_conf="$1"
    _ro_channel="$2"
    _ro_repo="$3"
    [ -f "${_ro_conf}" ] || return 0
    # Base: an explicit PFB_BASE_URL wins (install.sh drives the hook with one
    # precisely to MOVE a box onto another base); otherwise it is read back out
    # of the conf, so a boot with no environment preserves it (issue #2459).
    if [ -n "${PFB_BASE_URL:-}" ]; then
        _ro_base="${PFB_BASE_URL%/}"
    else
        _ro_base="$(_base_from_conf "${_ro_conf}" "${_ro_channel}")"
        _ro_rc=$?
        if [ "${_ro_rc}" -eq 1 ]; then
            _ro_base="${PFB_FALLBACK_BASE_URL}"
        elif [ "${_ro_rc}" -ne 0 ]; then
            printf '[%s] WARNING: %s carries a url this hook did not write (expected <base>/%s/<varver>) — leaving it unchanged; re-run install.sh --channel %s to re-point it\n' \
                "${name}" "${_ro_conf}" "${_ro_channel}" "${_ro_channel}" >&2
            return 0
        fi
    fi
    _ro_catalog="$(_detect_catalog)" || {
        printf '[%s] WARNING: variant detection failed — leaving %s unchanged\n' \
            "${name}" "${_ro_conf}" >&2
        return 0
    }
    # No %/ here: a base derived from the conf is already bare, except for the
    # degenerate "file://" (a catalogue rooted at /), whose slash is load-bearing.
    _ro_url="${_ro_base}/${_ro_channel}/${_ro_catalog}"
    if _emit_conf "${_ro_channel}" "${_ro_repo}" "${_ro_url}" > "${_ro_conf}.tmp" 2>/dev/null \
        && mv "${_ro_conf}.tmp" "${_ro_conf}" 2>/dev/null; then
        printf '[%s] INFO: regenerated %s -> %s\n' "${name}" "${_ro_conf}" "${_ro_url}" >&2
    else
        rm -f "${_ro_conf}.tmp" 2>/dev/null
        printf '[%s] WARNING: could not rewrite %s\n' "${name}" "${_ro_conf}" >&2
    fi
}

# Regenerate each channel's conf independently (channel keyed by conf path). Only
# the channel(s) the box actually subscribed to are touched — _regen_one()'s
# orphan guard skips every absent conf, so a box on one channel stays on that one
# channel across a reboot (single-repository subscription, issue #2148).
pfblockerng_repo_generate_start() {
    # FIRST, and a hard gate: a conf that requires a signature is useless without the
    # key that validates it, and a box that got one could no longer reach the repository
    # that would fix it. If the store cannot be written, every conf is left exactly as
    # it is -- whatever the box had kept working until now.
    if ! _write_fingerprint; then
        printf '[%s] WARNING: no trusted fingerprint installed — leaving every conf unchanged\n' \
            "${name}" >&2
        return 0
    fi
    _regen_one "${PFB_STABLE_CONF}"  'stable'  'pfblockerng-stable'
    _regen_one "${PFB_TESTING_CONF}" 'testing' 'pfblockerng-testing'
    _regen_one "${PFB_EDGE_CONF}"    'edge'    'pfblockerng-edge'
    _regen_one "${PFB_NIGHTLY_CONF}" 'nightly' 'pfblockerng-nightly'
    return 0
}

# Run as an rc.d service when rc.subr is present (the pfSense box); otherwise run
# the regeneration directly (off-box: install.sh's bootstrap + the shellspec
# suite, where /etc/rc.subr does not exist).
if [ -r /etc/rc.subr ]; then
    . /etc/rc.subr
    rcvar="${name}_enable"
    start_cmd="pfblockerng_repo_generate_start"
    stop_cmd=":"
    load_rc_config "${name}"
    : "${pfblockerng_repo_generate_enable:=YES}"
    run_rc_command "${1:-onestart}"
else
    pfblockerng_repo_generate_start
fi
# Always exit 0 regardless of the above — never wedge boot.
exit 0
