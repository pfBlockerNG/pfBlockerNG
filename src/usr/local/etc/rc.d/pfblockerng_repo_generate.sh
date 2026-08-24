#!/bin/sh
# /usr/local/etc/rc.d/pfblockerng_repo_generate.sh — boot-time repo-conf
# regenerator (ADR-39) AND consent-gated login.conf CA carrier (issue #2617).
# Installed by install.sh.
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
# JOB 2 — consent-gated login.conf CA carry (issue #2617, DEFAULT-ON — owner
# ruling): carries SSL_CA_CERT_PATH into the `default` login class's setenv
# (_logincap_setenv_add()) unless the admin has explicitly opted out (config
# field pfb_pkg_ca_consent, read live every call — never cached; see
# _login_ca_consent() below), in which case it is removed
# (_logincap_setenv_remove()). This supersedes the pkg.conf PKG_ENV patcher
# from issue #2518: that approach was retired because pfSense-repo-setup
# rewrites pkg.conf at arbitrary times (OS upgrades, branch switches) this hook
# cannot serialise against, whereas nothing on the box rewrites login.conf.
#
# WHY AT BOOT: a pfSense OS upgrade can change the box's edition/version (which
# requires a reboot and moves the catalog subtree), and can also revert
# login.conf to its stock shape. Boot follows either, and /etc/pfSense-rc
# recompiles login.conf.db on every boot regardless, so reconciling here keeps
# the carried variable aligned with no extra upgrade hook to register.
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

# JOB 2 paths (issue #2617) — see _login_ca_consent().
: "${PFB_CONFIG_XML:=/cf/conf/config.xml}"
: "${PFB_SSL_CA_CERT_PATH:=/etc/ssl/certs}"

# login.conf editor paths (issue #2617) — see _logincap_setenv_add() below.
: "${PFB_LOGIN_CONF:=/etc/login.conf}"
: "${PFB_CAP_MKDB:=/usr/bin/cap_mkdb}"

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
PFB_FALLBACK_BASE_URL='https://pkg.pfblockerng.com'

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
    printf '%s' "${_bc_base}"
}

# The catalogue signing key's public half, as the fingerprint pkg checks: the SHA256 of
# the DER public key exactly as the catalogue embeds it (issue #2675). Shipped as the
# hex rather than the key itself because that is all `signature_type: fingerprints`
# needs on the box -- the key travels inside each signed catalogue.
CONF_FINGERPRINT_DIR="${PFB_FINGERPRINT_DIR}"
CONF_FINGERPRINT_NAME='pkg.pfblockerng.com'
CONF_FINGERPRINT_SHA256='081df5476f84d8d20417c400f576c355069a4a9979d170bcaae1c9da32778915'

# Install the trusted fingerprint. Runs BEFORE any conf is rewritten: a box that reached
# a signature-requiring conf without the key that validates it could no longer reach the
# repository that would fix it. Every failure is non-fatal -- this hook must never wedge
# boot -- and a conf rewrite that follows a failed write is still safe, because pkg
# treats an unreadable fingerprint dir as "no trusted key" and refuses the catalogue
# rather than trusting it.
_write_fingerprint() {
    _wf_trusted="${CONF_FINGERPRINT_DIR}/trusted"
    _wf_file="${_wf_trusted}/${CONF_FINGERPRINT_NAME}"
    mkdir -p "${_wf_trusted}" "${CONF_FINGERPRINT_DIR}/revoked" 2>/dev/null || {
        printf '[%s] WARNING: could not create %s\n' "${name}" "${CONF_FINGERPRINT_DIR}" >&2
        return 1
    }
    if printf 'function: "sha256"\nfingerprint: "%s"\n' "${CONF_FINGERPRINT_SHA256}" >"${_wf_file}.tmp" 2>/dev/null; then
        if mv "${_wf_file}.tmp" "${_wf_file}" 2>/dev/null; then
            return 0
        fi
    fi
    rm -f "${_wf_file}.tmp" 2>/dev/null
    printf '[%s] WARNING: could not write %s\n' "${name}" "${_wf_file}" >&2
    return 1
}

# The URL a conf points at, for a resolved catalogue base. HTTPS is downgraded to plain
# HTTP deliberately: pkg on pfSense Plus runs against a Netgate-pinned CA bundle that
# nothing we ship can widen, so TLS to our host is not a trust anchor we can rely on --
# authenticity comes from the catalogue signature instead, and package payloads are
# checksummed by that signed catalogue. Any other scheme is left alone; a file://
# catalogue has no network in its path at all.
_conf_url() {
    case "$1" in
        https://*) printf 'http://%s' "${1#https://}" ;;
        *) printf '%s' "$1" ;;
    esac
}

# Trust comment + signature fields, keyed on the URL: a file:// catalogue is built
# locally and carries no signature, so requiring one would fail a catalogue that is fine.
_conf_trust_comment() {
    case "$1" in
        file://*)
            printf '%s\n%s\n' \
                '# Local catalogue: served from this filesystem, unsigned — no network and no' \
                '# CA store in the path.'
            ;;
        *)
            printf '%s\n%s\n%s\n' \
                '# Signed catalogue (issue #2675): the trust anchor is our own ECDSA key, whose' \
                "# fingerprint the boot rc.d hook installs; the fetch is plain HTTP because pkg's CA" \
                '# store is Netgate-pinned on pfSense Plus and cannot be widened from the GUI.'
            ;;
    esac
}

_conf_signature_lines() {
    case "$1" in
        file://*) printf '  signature_type: none,' ;;
        *) printf '  signature_type: fingerprints,\n  fingerprints: "%s",' "${CONF_FINGERPRINT_DIR}" ;;
    esac
}

# Emit the canonical conf body. $1 = channel word, $2 = repo name, $3 = url.
# Kept byte-identical to the *_print_conf generators (drift-pinned by tests).
_emit_conf() {
    _ec_channel="$1"
    _ec_repo="$2"
    _ec_url="$(_conf_url "$3")"
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

# JOB 2 (issue #2617): read the admin's consent for carrying SSL_CA_CERT_PATH
# into login.conf. Prints `on`, `off`, or `skip`; DEFAULT-ON (owner ruling) --
# an absent ELEMENT means the registered default, which is now On. PHP writes
# an empty token for an explicit Off and the literal token "on" for an
# explicit On, so "present but empty" is an explicit opt-out, never "absent".
# A missing/unreadable config.xml is `skip`, not On: consent is unknowable
# there, and a pfSense box cannot boot without /cf/conf/config.xml, so the
# only runs that hit this are off-box (a ROOT-staged install.sh, a dev host)
# -- exactly the runs that must never edit the host's real login.conf.
#
# pfb_pkg_ca_consent is a registered config field read on the PHP side at
# installedpackages/pfblockerng/config/0 -- PfbConfig::read('gen/pfb_pkg_ca_consent')
# -- meaning the element must be a DIRECT CHILD of the FIRST <config> block
# under the single <pfblockerng> section (config/0): never nested under a
# <row> or any other wrapper, and never a later <config> row. <config> is NOT
# unique tree-wide (every installed package gets one under
# <installedpackages>), so a whole-file grep for the element can key on the
# WRONG <config> block and disagree with the PHP side. Scoped instead: the
# FIRST <pfblockerng>...</pfblockerng> range, then within it the FIRST
# <config>...</config> block (config/0), then the element AT DEPTH 0 of that
# block on a line BY ITSELF (case-insensitive value; PfbToggle::fromLegacy()
# also accepts On/ON); every opening line also checks for its own closing tag
# before advancing scope, so a self-closed or one-line element closes on the
# line it opens rather than latching the scope open to EOF.
#
# Hardening (issue #2617, decoy-vs-default-on): under the OLD fail-closed
# default a scoping miss was a bounded FALSE NEGATIVE; under default-on the
# same miss reads as "absent" = On -- a FALSE POSITIVE against an explicit
# opt-out. The opening match is therefore line-anchored (only a "<pfblockerng>"
# or "<pfblockerng ...attrs...>" starting its own line opens the scope, so a
# decoy embedded in another element's text never does), and an attribute on
# the open tag is accepted. Remaining accepted bounded misses, all shapes
# pfSense's own config writer never emits: an attribute on the consent element
# itself, and a CDATA value containing a literal "</config>" ahead of the
# element -- each would read as "absent" = On against an explicit opt-out.
_login_ca_consent() {
    [ -r "${PFB_CONFIG_XML}" ] || { printf 'skip'; return 0; }
    _lcc_consent="$(awk '
            !seen_pb && /^[[:space:]]*<pfblockerng([[:space:]][^>]*)?>/ {
                in_pb = 1; seen_pb = 1
                if ($0 ~ /<\/pfblockerng>/) { in_pb = 0 }
                next
            }
            in_pb && /<\/pfblockerng>/ { in_pb = 0; next }
            in_pb && !seen_cfg && /<config>/ {
                in_cfg = 1; seen_cfg = 1; cfg_depth = 0
                if ($0 ~ /<\/config>/) { in_cfg = 0 }
                next
            }
            in_cfg && /<\/config>/ { in_cfg = 0; next }
            in_cfg {
                if (cfg_depth == 0 && /^[[:space:]]*<pfb_pkg_ca_consent>[Oo][Nn]<\/pfb_pkg_ca_consent>[[:space:]]*$/) {
                    print "on"; exit
                }
                if (cfg_depth == 0 && /^[[:space:]]*<pfb_pkg_ca_consent>[^<]*<\/pfb_pkg_ca_consent>[[:space:]]*$/) {
                    print "off"; exit
                }
                if (cfg_depth == 0 && /^[[:space:]]*<pfb_pkg_ca_consent\/>[[:space:]]*$/) {
                    print "off"; exit
                }
                _line = $0
                _self_closing = gsub(/<[A-Za-z_][A-Za-z0-9_.:-]*[[:space:]][^<>]*\/>/, "&", _line)
                _line = $0
                _opens = gsub(/<[A-Za-z_][A-Za-z0-9_.:-]*([[:space:]][^<>]*)?>/, "&", _line)
                _line = $0
                _closes = gsub(/<\/[A-Za-z_][A-Za-z0-9_.:-]*[[:space:]]*>/, "&", _line)
                cfg_depth += (_opens - _closes - _self_closing)
                if (cfg_depth < 0) { cfg_depth = 0 }
            }
        ' "${PFB_CONFIG_XML}" 2>/dev/null)"
    case "${_lcc_consent}" in
        off) printf 'off' ;;
        *) printf 'on' ;;
    esac
    unset _lcc_consent
}

# Reconcile login.conf with the live consent read: on -> carry the CA path
# (_logincap_setenv_add()); explicitly off -> strip it
# (_logincap_setenv_remove()); skip (no readable config.xml) -> touch nothing.
# Propagates the editor's rc.
_login_ca_reconcile() {
    case "$(_login_ca_consent)" in
        on) _logincap_setenv_add ;;
        off) _logincap_setenv_remove ;;
        *) return 0 ;;
    esac
}

# login.conf `default`-class setenv editor (issue #2617): the actual write side
# of JOB 2 above -- _login_ca_reconcile() calls _logincap_setenv_add() or
# _logincap_setenv_remove() depending on the live consent read. Ground truth
# from a live box:
#   1. getcap keeps only the FIRST `setenv` per class record; duplicates
#      compile but are dead.
#   2. a non-default class with its OWN setenv shadows `default` for its
#      users; reported, never edited.
#   3. login.conf.db (compiled by cap_mkdb), not login.conf, is what libc
#      reads.
#   4. cap_mkdb validates nothing — the byte-exact write result is the oracle.
# Wired into onestart via consent (_login_ca_reconcile()); the login-ca-sync
# and login-ca-revoke verbs below stay direct and consent-independent -- the
# PHP caller flushes config before invoking either, so it trusts its own
# read, and a boot reconcile self-heals any mismatch.

# One awk pass over PFB_LOGIN_CONF: a label starts at column 0, a record
# continues while lines end in `\`. Only the FIRST `default` record counts
# (rule 1). Prints KEY=value lines read back via _logincap_field().
_logincap_scan() {
    _lc_scan_raw="$(awk '
        {
            line = $0
            has_cont = (line ~ /\\$/)
            if (!prev_cont) {
                in_def = 0
                if (line ~ /^[^ \t#]/) {
                    cur = line
                    sub(/[:|].*/, "", cur)
                    if (cur == "default" && !done_def) {
                        in_def = 1
                        done_def = 1
                        label = NR
                        last = NR
                        wellformed = (line == "default:\\") ? 1 : 0
                    }
                } else {
                    cur = ""
                }
            } else if (in_def) {
                last = NR
                if (se_line == 0 && index(line, ":setenv=") > 0) {
                    se_line = NR
                    se_text = line
                    tmp = line
                    n = 0
                    while ((p = index(tmp, ":setenv=")) > 0) { n++; tmp = substr(tmp, p + 8) }
                    p = index(line, ":setenv=")
                    vs = p + 8
                    rest = substr(line, vs)
                    c = index(rest, ":")
                    if (n == 1 && c > 0) {
                        v = substr(rest, 1, c - 1)
                        if (index(v, "\\") == 0) {
                            se_ok = 1
                            vstart = vs
                            vend = vs + c - 1
                            value = v
                        }
                    }
                }
            } else if (cur != "" && cur != "default" && index(line, ":setenv=") > 0) {
                if (index(" " other " ", " " cur " ") == 0) {
                    other = (other == "" ? cur : other " " cur)
                }
            }
            prev_cont = has_cont
        }
        END {
            printf "WELLFORMED=%d\n", wellformed ? 1 : 0
            printf "LABEL=%d\n", label + 0
            printf "LAST=%d\n", last + 0
            printf "SETENV_LINE=%d\n", se_line + 0
            printf "SETENV_OK=%d\n", se_ok ? 1 : 0
            printf "VSTART=%d\n", vstart + 0
            printf "VEND=%d\n", vend + 0
            printf "VALUE=%s\n", value
            printf "LINE=%s\n", se_text
            printf "OTHER=%s\n", other
        }
    ' "${PFB_LOGIN_CONF}" 2>/dev/null)"
}

# Pull one KEY out of the last _logincap_scan() result.
_logincap_field() {
    printf '%s\n' "${_lc_scan_raw}" | sed -n "s/^$1=//p"
}

# Shared writer: $@ is an awk program (with any -v args) applied over
# PFB_LOGIN_CONF. A raw value handed in MUST travel via ENVIRON, never -v
# (which decodes backslash escapes and would corrupt it).
# One shared value-splice program: replace the chars [vs, ve) on line tgt with
# $PFB_LC_NEWVAL (via ENVIRON -- `awk -v` would decode escapes in the value).
# Line tgt must still read exactly as the scan saw it ($PFB_LC_EXPECT): the
# scan and this transform are separate reads of the file, so a concurrent
# editor invocation (boot reconcile vs a Software-page save) could land its
# mv in between -- splicing scan-time offsets into changed content would
# corrupt the class, while aborting here degrades the race to a clean
# refusal/lost update that the next boot reconcile repairs.
# shellcheck disable=SC2016  # awk's own $0/vs/ve, not shell expansion
_LC_SPLICE='NR==tgt { if ($0 != ENVIRON["PFB_LC_EXPECT"]) exit 9; $0 = substr($0,1,vs-1) ENVIRON["PFB_LC_NEWVAL"] substr($0,ve) } { print }'

_logincap_write() {
    _lc_tmp="${PFB_LOGIN_CONF}.tmp.$$"
    if cp -p "${PFB_LOGIN_CONF}" "${_lc_tmp}" 2>/dev/null \
        && awk "$@" "${PFB_LOGIN_CONF}" > "${_lc_tmp}" 2>/dev/null \
        && mv "${_lc_tmp}" "${PFB_LOGIN_CONF}" 2>/dev/null; then
        unset _lc_tmp
        return 0
    fi
    rm -f "${_lc_tmp}" 2>/dev/null
    unset _lc_tmp
    return 1
}

# Unconditional after every successful write (rule 3) -- /etc/pfSense-rc
# recompiles at boot anyway, so there's no stale-.db state worth tracking.
_logincap_compile() {
    if [ -x "${PFB_CAP_MKDB}" ] && ! "${PFB_CAP_MKDB}" "${PFB_LOGIN_CONF}" >/dev/null 2>&1; then
        printf '[%s] WARNING: could not recompile %s.db -- the change will not take effect until something else compiles it\n' \
            "${name}" "${PFB_LOGIN_CONF}" >&2
    fi
}

# Ensure SSL_CA_CERT_PATH is carried in the FIRST setenv of the `default`
# login class.
_logincap_setenv_add() {
    # -h before -f: a symlink also passes -f, and _logincap_write()'s tmp+mv
    # would replace the LINK's identity instead of editing through it.
    [ -h "${PFB_LOGIN_CONF}" ] && return 1
    [ -f "${PFB_LOGIN_CONF}" ] || return 1

    case "${PFB_SSL_CA_CERT_PATH}" in
        /?*) ;;
        *) return 1 ;;
    esac
    case "${PFB_SSL_CA_CERT_PATH}" in
        *[!A-Za-z0-9._/+-]*) return 1 ;;
    esac

    # Load-bearing (issue #2524): once set, libfetch skips its own default
    # verify paths, so an empty/missing hash dir would leave no trust store.
    [ -d "${PFB_SSL_CA_CERT_PATH}" ] || return 1
    _lc_has_entry=0
    for _lc_entry in "${PFB_SSL_CA_CERT_PATH}"/*; do
        if [ -e "${_lc_entry}" ] || [ -L "${_lc_entry}" ]; then
            _lc_has_entry=1
            break
        fi
    done
    unset _lc_entry
    if [ "${_lc_has_entry}" -ne 1 ]; then
        unset _lc_has_entry
        return 1
    fi
    unset _lc_has_entry

    _logincap_scan
    _lc_wellformed="$(_logincap_field WELLFORMED)"
    _lc_se_line="$(_logincap_field SETENV_LINE)"
    _lc_se_ok="$(_logincap_field SETENV_OK)"
    if [ "${_lc_wellformed}" != 1 ] || { [ "${_lc_se_line}" != 0 ] && [ "${_lc_se_ok}" != 1 ]; }; then
        printf '[%s] WARNING: login.conf default class has a shape this editor does not recognise -- not touching it\n' "${name}" >&2
        unset _lc_scan_raw _lc_wellformed _lc_se_line _lc_se_ok
        return 1
    fi

    # Rule 2: report a shadowing sibling class by name; not a refusal.
    _lc_other="$(_logincap_field OTHER)"
    if [ -n "${_lc_other}" ]; then
        for _lc_cls in ${_lc_other}; do
            printf '[%s] WARNING: login.conf class "%s" defines its own setenv, shadowing default for its users -- SSL_CA_CERT_PATH will not reach them; not touching that class\n' \
                "${name}" "${_lc_cls}" >&2
        done
        unset _lc_cls
    fi
    unset _lc_other

    _lc_want="SSL_CA_CERT_PATH=${PFB_SSL_CA_CERT_PATH}"

    if [ "${_lc_se_line}" = 0 ]; then
        _lc_label="$(_logincap_field LABEL)"
        PFB_LC_NEWVAL="${_lc_want}"
        export PFB_LC_NEWVAL
        # shellcheck disable=SC2016  # awk's own $0/lbl, not shell expansion
        if _logincap_write -v lbl="${_lc_label}" \
            'NR==lbl && $0 != "default:\\" { exit 9 } { print } NR==lbl { print "\t:setenv=" ENVIRON["PFB_LC_NEWVAL"] ":\\" }'; then
            printf '[%s] INFO: added SSL_CA_CERT_PATH to the default class setenv in %s\n' "${name}" "${PFB_LOGIN_CONF}" >&2
            _logincap_compile
            unset PFB_LC_NEWVAL PFB_LC_EXPECT _lc_label _lc_want _lc_scan_raw _lc_wellformed _lc_se_line _lc_se_ok
            return 0
        fi
        printf '[%s] WARNING: could not patch %s\n' "${name}" "${PFB_LOGIN_CONF}" >&2
        unset PFB_LC_NEWVAL PFB_LC_EXPECT _lc_label _lc_want _lc_scan_raw _lc_wellformed _lc_se_line _lc_se_ok
        return 1
    fi

    _lc_value="$(_logincap_field VALUE)"
    _lc_found_ours=0
    _lc_found_foreign=0
    IFS=,
    set -f
    for _lc_entry_v in ${_lc_value}; do
        case "${_lc_entry_v}" in
            "${_lc_want}") _lc_found_ours=1 ;;
            SSL_CA_CERT_PATH=*) _lc_found_foreign=1 ;;
        esac
    done
    set +f
    unset IFS _lc_entry_v

    # Foreign first: getcap applies the list in order with overwrite
    # semantics, so when ours and a foreign entry coexist the LATER one wins
    # at login -- a mixed list must warn, never read as a clean no-op.
    if [ "${_lc_found_foreign}" -eq 1 ]; then
        printf '[%s] WARNING: login.conf already sets SSL_CA_CERT_PATH to a different value in the default class -- leaving it unchanged, something else owns that variable\n' "${name}" >&2
        unset _lc_scan_raw _lc_wellformed _lc_se_line _lc_se_ok _lc_value _lc_want _lc_found_ours _lc_found_foreign
        return 0
    fi
    if [ "${_lc_found_ours}" -eq 1 ]; then
        unset _lc_scan_raw _lc_wellformed _lc_se_line _lc_se_ok _lc_value _lc_want _lc_found_ours _lc_found_foreign
        return 0
    fi

    _lc_vstart="$(_logincap_field VSTART)"
    _lc_vend="$(_logincap_field VEND)"
    if [ -z "${_lc_value}" ]; then
        PFB_LC_NEWVAL="${_lc_want}"
    else
        PFB_LC_NEWVAL="${_lc_value},${_lc_want}"
    fi
    PFB_LC_EXPECT="$(_logincap_field LINE)"
    export PFB_LC_NEWVAL PFB_LC_EXPECT
    if _logincap_write -v tgt="${_lc_se_line}" -v vs="${_lc_vstart}" -v ve="${_lc_vend}" \
        "${_LC_SPLICE}"; then
        printf '[%s] INFO: added SSL_CA_CERT_PATH to the default class setenv in %s\n' "${name}" "${PFB_LOGIN_CONF}" >&2
        _logincap_compile
        unset PFB_LC_NEWVAL PFB_LC_EXPECT _lc_scan_raw _lc_wellformed _lc_se_line _lc_se_ok _lc_value _lc_want _lc_found_ours _lc_found_foreign _lc_vstart _lc_vend
        return 0
    fi
    printf '[%s] WARNING: could not patch %s\n' "${name}" "${PFB_LOGIN_CONF}" >&2
    unset PFB_LC_NEWVAL PFB_LC_EXPECT _lc_scan_raw _lc_wellformed _lc_se_line _lc_se_ok _lc_value _lc_want _lc_found_ours _lc_found_foreign _lc_vstart _lc_vend
    return 1
}

# Inverse of _logincap_setenv_add(). No CA whitelist/populated-dir check here:
# an opt-out must succeed even with the CA dir now empty or gone.
_logincap_setenv_remove() {
    [ -h "${PFB_LOGIN_CONF}" ] && return 1
    [ -f "${PFB_LOGIN_CONF}" ] || return 0

    # Fast no-op: never nag about a file that never carried our value.
    grep -F -q "SSL_CA_CERT_PATH" "${PFB_LOGIN_CONF}" 2>/dev/null || return 0

    _logincap_scan
    _lc_wellformed="$(_logincap_field WELLFORMED)"
    _lc_se_line="$(_logincap_field SETENV_LINE)"
    _lc_se_ok="$(_logincap_field SETENV_OK)"
    if [ "${_lc_wellformed}" != 1 ] || { [ "${_lc_se_line}" != 0 ] && [ "${_lc_se_ok}" != 1 ]; }; then
        printf '[%s] WARNING: login.conf default class has a shape this editor does not recognise -- not touching it\n' "${name}" >&2
        unset _lc_scan_raw _lc_wellformed _lc_se_line _lc_se_ok
        return 1
    fi
    if [ "${_lc_se_line}" = 0 ]; then
        unset _lc_scan_raw _lc_wellformed _lc_se_line _lc_se_ok
        return 0
    fi

    _lc_value="$(_logincap_field VALUE)"
    _lc_want="SSL_CA_CERT_PATH=${PFB_SSL_CA_CERT_PATH}"
    _lc_newval=""
    IFS=,
    set -f
    for _lc_entry_v in ${_lc_value}; do
        [ "${_lc_entry_v}" = "${_lc_want}" ] && continue
        if [ -z "${_lc_newval}" ]; then
            _lc_newval="${_lc_entry_v}"
        else
            _lc_newval="${_lc_newval},${_lc_entry_v}"
        fi
    done
    set +f
    unset IFS _lc_entry_v

    if [ "${_lc_newval}" = "${_lc_value}" ]; then
        # Not ours -- a foreign value is never stripped, but an opt-out that
        # leaves the variable exported must say so instead of reporting a
        # clean success. A list with no SSL_CA_CERT_PATH at all stays silent.
        case ",${_lc_value}," in
            *,SSL_CA_CERT_PATH=*)
                printf '[%s] WARNING: login.conf sets SSL_CA_CERT_PATH to a value this hook did not write -- leaving it in place, the opt-out did not remove it\n' "${name}" >&2
                ;;
        esac
        unset _lc_scan_raw _lc_wellformed _lc_se_line _lc_se_ok _lc_value _lc_want _lc_newval
        return 0
    fi

    _lc_vstart="$(_logincap_field VSTART)"
    _lc_vend="$(_logincap_field VEND)"

    if [ -n "${_lc_newval}" ]; then
        PFB_LC_NEWVAL="${_lc_newval}"
        PFB_LC_EXPECT="$(_logincap_field LINE)"
        export PFB_LC_NEWVAL PFB_LC_EXPECT
        if _logincap_write -v tgt="${_lc_se_line}" -v vs="${_lc_vstart}" -v ve="${_lc_vend}" \
            "${_LC_SPLICE}"; then
            printf '[%s] INFO: removed SSL_CA_CERT_PATH from the default class setenv in %s\n' "${name}" "${PFB_LOGIN_CONF}" >&2
            _logincap_compile
            unset PFB_LC_NEWVAL PFB_LC_EXPECT _lc_scan_raw _lc_wellformed _lc_se_line _lc_se_ok _lc_value _lc_want _lc_newval _lc_vstart _lc_vend
            return 0
        fi
        printf '[%s] WARNING: could not patch %s\n' "${name}" "${PFB_LOGIN_CONF}" >&2
        unset PFB_LC_NEWVAL PFB_LC_EXPECT _lc_scan_raw _lc_wellformed _lc_se_line _lc_se_ok _lc_value _lc_want _lc_newval _lc_vstart _lc_vend
        return 1
    fi

    # newval empty: ours was the only entry, so the field (fs = start of its
    # ":setenv=" tag) or whole line goes. "whole" is precomputed here, not in
    # the writeback awk below, because that awk must strip a dangling `\`
    # from the PRECEDING line in the same pass -- before it has read this
    # line's own content to know whether the removal empties it.
    _lc_fs=$((_lc_vstart - 8))
    _lc_line="$(sed -n "${_lc_se_line}p" "${PFB_LOGIN_CONF}")"
    _lc_last="$(_logincap_field LAST)"
    _lc_whole="$(PFB_LC_LINE="${_lc_line}" awk -v fs="${_lc_fs}" -v ve="${_lc_vend}" '
        BEGIN {
            line = ENVIRON["PFB_LC_LINE"]
            pre = substr(line, 1, fs - 1)
            trail = substr(line, ve + 1)
            print (pre ~ /^[ \t]*$/ && (trail == "\\" || trail == "")) ? 1 : 0
        }
    ' 2>/dev/null)"

    # shellcheck disable=SC2016  # awk's own $0/tgt/whole/fs/ve, not shell expansion
    PFB_LC_EXPECT="$(_logincap_field LINE)"
    export PFB_LC_EXPECT
    # shellcheck disable=SC2016  # awk's own $0/tgt/whole/fs/ve, not shell expansion
    if _logincap_write -v tgt="${_lc_se_line}" -v last="${_lc_last}" -v whole="${_lc_whole}" -v fs="${_lc_fs}" -v ve="${_lc_vend}" \
        'NR == tgt && $0 != ENVIRON["PFB_LC_EXPECT"] { exit 9 }
         NR == tgt - 1 && whole == 1 && tgt == last { sub(/\\$/, "") }
         NR == tgt && whole == 1 { next }
         NR == tgt && whole == 0 { $0 = substr($0, 1, fs - 1) substr($0, ve) }
         { print }'; then
        printf '[%s] INFO: removed SSL_CA_CERT_PATH from the default class setenv in %s\n' "${name}" "${PFB_LOGIN_CONF}" >&2
        _logincap_compile
        unset PFB_LC_NEWVAL PFB_LC_EXPECT _lc_scan_raw _lc_wellformed _lc_se_line _lc_se_ok _lc_value _lc_want _lc_newval _lc_vstart _lc_vend _lc_fs _lc_line _lc_last _lc_whole
        return 0
    fi
    printf '[%s] WARNING: could not patch %s\n' "${name}" "${PFB_LOGIN_CONF}" >&2
    unset PFB_LC_NEWVAL PFB_LC_EXPECT _lc_scan_raw _lc_wellformed _lc_se_line _lc_se_ok _lc_value _lc_want _lc_newval _lc_vstart _lc_vend _lc_fs _lc_line _lc_last _lc_whole
    return 1
}

# Regenerate each channel's conf independently (channel keyed by conf path). Only
# the channel(s) the box actually subscribed to are touched — _regen_one()'s
# orphan guard skips every absent conf, so a box on one channel stays on that one
# channel across a reboot (single-repository subscription, issue #2148).
pfblockerng_repo_generate_start() {
    # FIRST, before any conf: the fingerprint must exist before a conf can require one.
    _write_fingerprint || :
    _regen_one "${PFB_STABLE_CONF}"  'stable'  'pfblockerng-stable'
    _regen_one "${PFB_TESTING_CONF}" 'testing' 'pfblockerng-testing'
    _regen_one "${PFB_EDGE_CONF}"    'edge'    'pfblockerng-edge'
    _regen_one "${PFB_NIGHTLY_CONF}" 'nightly' 'pfblockerng-nightly'
    _login_ca_reconcile
    return 0
}

# login.conf editing verbs (issue #2617): no upgrade lock to take -- login.conf
# has no supported concurrent rewriter to serialise against, unlike pkg.conf
# under the retired JOB 2 approach (issue #2518).
case "${1:-}" in
    login-ca-sync) _logincap_setenv_add; exit $? ;;
    login-ca-revoke) _logincap_setenv_remove; exit $? ;;
esac

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
