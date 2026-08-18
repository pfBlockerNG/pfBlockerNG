#!/bin/sh
# /usr/local/etc/rc.d/pfblockerng_repo_generate.sh — boot-time repo-conf
# regenerator (ADR-39) AND consented pkg.conf CA re-applier (issue #2518).
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
# JOB 2 — consented pkg.conf CA re-apply (issue #2518): on Plus,
# pfSense-repo-setup deletes and regenerates /usr/local/etc/pkg.conf on
# upgrades and branch switches, appending a PKG_ENV block that pins
# SSL_CA_CERT_FILE to a Netgate-only bundle. libpkg applies that block with
# setenv(key, value, 1), so only an added SSL_CA_CERT_PATH line — which
# PKG_ENV never sets — survives it and restores the public roots third-party
# repos need. Because the wipe can happen at any OS upgrade or branch switch,
# and boot follows both, this hook re-applies that one line every boot when
# the admin has consented (config field, checked live — never cached). See
# _pkgconf_ca_reapply() below; this job is UNLIKE job 1 in every other way —
# patch-in-place, not regenerate, and consent-gated rather than unconditional.
#
# WHY AT BOOT: a pfSense OS upgrade can change the box's edition/version (which
# requires a reboot), which moves the catalog subtree, and can also wipe
# pkg.conf via pfSense-repo-setup. Regenerating/re-applying every boot keeps
# both aligned with no upgrade hook to register.
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
: "${PFB_PRODUCT_LABEL:=/etc/product_label}"
: "${PFB_VERSION_FILE:=/etc/version}"

# JOB 2 paths (issue #2518) — see _pkgconf_ca_reapply().
: "${PFB_PKG_CONF:=/usr/local/etc/pkg.conf}"
: "${PFB_CONFIG_XML:=/cf/conf/config.xml}"
: "${PFB_SSL_CA_CERT_PATH:=/etc/ssl/certs}"
: "${PFB_PKG_DIRTY:=/var/run/pkg.dirty}"

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
PFB_FALLBACK_BASE_URL='https://pfblockerng.github.io/pkg'

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
# https://pfblockerng.github.io/pkg, redirecting where the box fetches packages
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

# Emit the canonical conf body. $1 = channel word, $2 = repo name, $3 = url.
# Kept byte-identical to the *_print_conf generators (drift-pinned by tests).
_emit_conf() {
    _ec_channel="$1"
    _ec_repo="$2"
    _ec_url="$3"
    cat <<EOF
# Generated at boot by pfblockerng_repo_generate (ADR-39) — do not edit; re-run install.sh --channel ${_ec_channel} to change.
# pfBlockerNG (${_ec_channel} channel) — self-hosted pkg repository (ADR-17).
# NONE-signed: trust anchor is HTTPS to the host (no signing key). The URL is
# fully resolved for this box's edition/version (ADR-39; arch-less/NO_ARCH,
# issue #1806); the boot rc.d hook updates it on a pfSense OS upgrade.
# priority ${CONF_PRIORITY} sits above the base Netgate \`pfSense\` repo so cross-repo
# resolution (pkg install/upgrade, GUI Install) selects the pfBlockerNG build.
${_ec_repo}: {
  url: "${_ec_url}",
  mirror_type: none,
  signature_type: none,
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

# JOB 2 (issue #2518): re-apply the consented SSL_CA_CERT_PATH line to pkg.conf
# after pfSense-repo-setup wipes it. Every guard below fails CLOSED and quiet —
# this runs at boot for the overwhelmingly common CE case, where none of it
# applies, so a miss must never print or wedge boot. Never reverts: consent-off
# simply skips the patch, and pfSense-repo-setup's own rewrite drops a
# previously-applied line anyway — revocation is handled synchronously by the
# PHP side, not by this hook running backwards.
_pkgconf_ca_reapply() {
    grep -q 'Plus' "${PFB_PRODUCT_LABEL}" 2>/dev/null || return 0
    [ -e "${PFB_PKG_DIRTY}" ] && return 0
    # Consent gate, fail-closed. pfb_pkg_ca_consent is a registered config field
    # read on the PHP side at installedpackages/pfblockerng/config/0 --
    # PfbConfig::read('gen/pfb_pkg_ca_consent') -- meaning the element must be a
    # DIRECT CHILD of the FIRST <config> block under the single <pfblockerng>
    # section (config/0): never nested under a <row> or any other wrapper, and
    # never a later <config> row. <config> is NOT unique tree-wide (every
    # installed package gets one under <installedpackages>), so a whole-file
    # grep for the element can key on the WRONG <config> block and disagree
    # with the PHP side about whether the admin consented.
    #
    # Scoped instead: take the FIRST <pfblockerng>...</pfblockerng> range, then
    # within it the FIRST <config>...</config> block -- that is exactly
    # config/0 -- then require the element AT DEPTH 1 of that block (a running
    # open/close-tag count, not just "present somewhere inside"), on a line BY
    # ITSELF (full-line match; the value compares case-insensitively --
    # PfbToggle::fromLegacy() also accepts On/ON). Every opening line ALSO
    # checks for its OWN closing tag before advancing the scope -- a self-closed
    # `<pfblockerng></pfblockerng>` / `<config></config>`, or a whole element on
    # one line, closes on the SAME line it opens. Earlier revisions of this awk
    # used `next` before that same-line check and LATCHED the scope open to
    # EOF, which is what let a same-named sibling field, a second <config> row,
    # or a nested <row> wrapper read as consent when PfbConfig disagreed
    # (issue #2518 B2).
    #
    # What this guarantees: config/0's own direct-child element, and only that
    # element, ever supplies "on" -- a sibling package's field, a later
    # <config> row, and a <row>-nested (or any deeper-nested) copy are all
    # refused. What it does NOT guarantee: a literal "<pfblockerng>" (or
    # "<config>") substring belonging to a DIFFERENT, EARLIER package in the
    # document exhausts the "first occurrence" search this hook does
    # (seen_pb/seen_cfg never re-arm), so a decoy ahead of the real block can
    # cause a FALSE NEGATIVE -- never a false positive -- and the cron tick
    # still re-applies on that box; pfSense's own config writer never emits
    # such a decoy or reorders sections, so this is a defensive bound, not an
    # expected case. Nor is it sound against an XML attribute on the
    # <pfblockerng> open tag, a CDATA-wrapped value, or the whole element
    # collapsed onto one line (PfbConfig reads all three as consent, this hook
    # matches none of them) -- tracking any of those in POSIX sh is
    # disproportionate to the risk, and pfSense's own config writer emits none
    # of them (verified against a live config.xml); each is a bounded,
    # documented miss (boot skip only -- the cron tick still re-applies),
    # pinned by its own spec row. Also NOT sound against a MULTI-LINE XML
    # comment that happens to wrap the element inside config/0 -- tracking
    # multi-line comment state in POSIX sh is disproportionate to that risk
    # too, and pfSense's own config writer emits no XML comments at all.
    _pcr_consent="$(awk '
            !seen_pb && /<pfblockerng>/ {
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
                _line = $0
                _self_closing = gsub(/<[A-Za-z_][A-Za-z0-9_.:-]*([[:space:]][^<>]*)?\/>/, "&", _line)
                _line = $0
                _opens = gsub(/<[A-Za-z_][A-Za-z0-9_.:-]*([[:space:]][^<>]*)?>/, "&", _line)
                _line = $0
                _closes = gsub(/<\/[A-Za-z_][A-Za-z0-9_.:-]*[[:space:]]*>/, "&", _line)
                cfg_depth += (_opens - _closes - _self_closing)
                if (cfg_depth < 0) { cfg_depth = 0 }
            }
        ' "${PFB_CONFIG_XML}" 2>/dev/null)"
    [ "${_pcr_consent}" = 'on' ] || { unset _pcr_consent; return 0; }
    unset _pcr_consent

    # -h before -f: a symlink also passes -f, and the tmp+mv patch below would
    # replace the LINK's identity rather than editing through it to its target.
    [ -h "${PFB_PKG_CONF}" ] && return 0
    [ -f "${PFB_PKG_CONF}" ] || return 0

    # FreeBSD ships /etc/ssl/certs empty until `certctl rehash` populates it;
    # exporting an empty hash dir to pkg LOOKS fixed but verifies nothing, so
    # refuse rather than patch a file that only appears to work. Glob-based
    # (no `ls | wc -l`): with no match dash leaves the pattern word literal, so
    # -e/-L on it is false and the loop body never sets the flag. A bare `*`
    # glob under POSIX never matches a dotfile, which matches the PHP side
    # exactly: pfb_pkgconf_dir_populated() counts only non-dot scandir()
    # entries (issue #2518 nitpick N-dotfile-guard), so a directory holding
    # e.g. only ".DS_Store" is NOT populated on either side -- no patch,
    # matching the PHP read.
    [ -d "${PFB_SSL_CA_CERT_PATH}" ] || return 0
    _pcr_has_entry=0
    for _pcr_entry in "${PFB_SSL_CA_CERT_PATH}"/*; do
        if [ -e "${_pcr_entry}" ] || [ -L "${_pcr_entry}" ]; then
            _pcr_has_entry=1
            break
        fi
    done
    unset _pcr_entry
    [ "${_pcr_has_entry}" -eq 1 ] || { unset _pcr_has_entry; return 0; }
    unset _pcr_has_entry

    # CA-path character whitelist, mirroring PHP's pfb_pkgconf_ca_add() guard
    # `^/[A-Za-z0-9._/+-]+$` exactly (including that a bare "/" is refused: it
    # has nothing after the leading slash). A '#' landing inside the PKG_ENV
    # block would make libucl treat the rest of the line as a comment and
    # silently truncate the CA path; a space or quote corrupts the block --
    # refuse rather than write either. `/?*` requires the leading slash plus
    # at least one more character (rejects the bare-slash case); the second
    # case matches any string containing a character outside the whitelist
    # (the idiom this file already uses at the varver check above).
    case "${PFB_SSL_CA_CERT_PATH}" in
        /?*) ;;
        *) return 0 ;;
    esac
    case "${PFB_SSL_CA_CERT_PATH}" in
        *[!A-Za-z0-9._/+-]*) return 0 ;;
    esac

    # Shape guard: refuse anything but exactly what pfSense-repo-setup writes.
    # Never touch a file already patched (SSL_CA_CERT_PATH present anywhere) or
    # hand-edited into an unrecognised shape — each check below is one clause
    # of that shape, checked independently so a near-miss is still refused.
    grep -q 'SSL_CA_CERT_PATH' "${PFB_PKG_CONF}" 2>/dev/null && return 0
    # grep -c on an unreadable file prints nothing to stdout and exits nonzero;
    # an unguarded `[ "$_pcr_open_count" -eq 1 ]` then errors with a literal
    # "Illegal number:" on stderr, contradicting this file's own "never print"
    # intent (issue #2518 nitpick N-illegal-number) -- `|| _pcr_open_count=0`
    # defaults it on ANY grep failure (unreadable file or a genuine zero
    # matches; either way the -eq 1 check below correctly refuses).
    _pcr_open_count="$(grep -c '^PKG_ENV {$' "${PFB_PKG_CONF}" 2>/dev/null)" || _pcr_open_count=0
    [ "${_pcr_open_count:-0}" -eq 1 ] || { unset _pcr_open_count; return 0; }
    unset _pcr_open_count
    # The block: from the (unique) opener to the first column-0 `}` after it.
    # If no such `}` exists this range runs to EOF and its last line is not
    # `}` — the "later line equal to `}`" check that catches an unclosed block.
    _pcr_block="$(sed -n '/^PKG_ENV {$/,/^}$/p' "${PFB_PKG_CONF}" 2>/dev/null)"
    [ "$(printf '%s\n' "${_pcr_block}" | tail -n 1)" = '}' ] || { unset _pcr_block; return 0; }
    _pcr_ca_file="$(printf '%s\n' "${_pcr_block}" | sed -n 's/^	SSL_CA_CERT_FILE=//p')"
    [ "$(printf '%s\n' "${_pcr_ca_file}" | wc -l | tr -d ' ')" -eq 1 ] \
        || { unset _pcr_block _pcr_ca_file; return 0; }
    case "${_pcr_ca_file}" in
        /?*) ;;
        *) unset _pcr_block _pcr_ca_file; return 0 ;;
    esac
    case "${_pcr_ca_file}" in
        *[!A-Za-z0-9._/+-]*) unset _pcr_block _pcr_ca_file; return 0 ;;
    esac
    [ -f "${_pcr_ca_file}" ] && [ -r "${_pcr_ca_file}" ] && [ -s "${_pcr_ca_file}" ] \
        || { unset _pcr_block _pcr_ca_file; return 0; }
    unset _pcr_ca_file
    # Refuse a block whose "close" is really a NESTED sub-object's own `}`
    # (issue #2518 nitpick N-nested-brace): the sed range above stops at the
    # FIRST column-0 `}` after the opener, same as the insertion awk below --
    # so a `SOMETHING {` sub-block occurring before the true close makes that
    # `}` look like PKG_ENV's own, and the line below would be inserted INSIDE
    # the sub-object instead (looks patched, verifies nothing: libpkg would set
    # the key on the sub-object, not PKG_ENV). Rule: strip the block's own
    # opening and closing lines; the remaining lines must be brace-BALANCED (as
    # many "...{"-opening lines as bare "}" lines) -- a nested open with no
    # matching nested close inside that middle means the "close" found above is
    # not PKG_ENV's own.
    _pcr_mid="$(printf '%s\n' "${_pcr_block}" | sed '1d;$d')"
    _pcr_mid_opens="$(printf '%s\n' "${_pcr_mid}" | grep -c '{$' 2>/dev/null)" || _pcr_mid_opens=0
    _pcr_mid_closes="$(printf '%s\n' "${_pcr_mid}" | grep -cx '}' 2>/dev/null)" || _pcr_mid_closes=0
    if [ "${_pcr_mid_opens:-0}" -ne "${_pcr_mid_closes:-0}" ]; then
        unset _pcr_block _pcr_mid _pcr_mid_opens _pcr_mid_closes
        return 0
    fi
    unset _pcr_block _pcr_mid _pcr_mid_opens _pcr_mid_closes

    # Patch: insert the one line immediately before the block's closing `}`,
    # nothing else touched. tmp+mv mirrors _regen_one()'s idiom, with two extra
    # steps the PHP appender already gets for free (issue #2518 nitpicks
    # N-mode / N-trailing-newline):
    #   - `cp -p` seeds the temp with the ORIGINAL file's permission bits
    #     before the `>` redirect below truncates it -- truncation keeps the
    #     inode (and its mode); a fresh `>` on a name that did not exist would
    #     not, which is why the patched file used to land at the process
    #     umask instead of pkg.conf's own mode (PHP's fileperms()+chmod()
    #     already preserves this).
    #   - awk's `print` always terminates its last output line, which would
    #     otherwise turn a pkg.conf whose last byte is `}` (no trailing
    #     newline) into one that has one; the tail-c1 check + reprint below
    #     restores that exact newline-less state when the original had it
    #     (PHP round-trips the input bytes exactly; see
    #     testAddPatchesWhenFinalBraceHasNoTrailingNewline).
    _pcr_original_sum="$(cksum < "${PFB_PKG_CONF}" 2>/dev/null)" \
        || { unset _pcr_original_sum; return 0; }
    _pcr_tmp="${PFB_PKG_CONF}.tmp"
    _pcr_had_no_trailing_nl=0
    [ -n "$(tail -c1 "${PFB_PKG_CONF}" 2>/dev/null)" ] && _pcr_had_no_trailing_nl=1
    if cp -p "${PFB_PKG_CONF}" "${_pcr_tmp}" 2>/dev/null \
        && awk -v ins="	SSL_CA_CERT_PATH=${PFB_SSL_CA_CERT_PATH}" '
            $0 == "PKG_ENV {" { seen_open = 1 }
            seen_open && !done && $0 == "}" { print ins; done = 1 }
            { print }
        ' "${PFB_PKG_CONF}" > "${_pcr_tmp}" 2>/dev/null; then
        if [ "${_pcr_had_no_trailing_nl}" -eq 1 ]; then
            printf '%s' "$(cat "${_pcr_tmp}" 2>/dev/null)" > "${_pcr_tmp}" 2>/dev/null
        fi
        if [ -e "${PFB_PKG_DIRTY}" ]; then
            _pcr_live_sum=''
        else
            _pcr_live_sum="$(cksum < "${PFB_PKG_CONF}" 2>/dev/null)" || _pcr_live_sum=''
        fi
        if [ -z "${_pcr_live_sum}" ] || [ "${_pcr_live_sum}" != "${_pcr_original_sum}" ]; then
            rm -f "${_pcr_tmp}" 2>/dev/null
            unset _pcr_tmp _pcr_had_no_trailing_nl _pcr_original_sum _pcr_live_sum
            return 0
        fi
        if mv "${_pcr_tmp}" "${PFB_PKG_CONF}" 2>/dev/null; then
            printf '[%s] INFO: patched %s with the consented SSL_CA_CERT_PATH\n' "${name}" "${PFB_PKG_CONF}" >&2
        else
            rm -f "${_pcr_tmp}" 2>/dev/null
            printf '[%s] WARNING: could not patch %s\n' "${name}" "${PFB_PKG_CONF}" >&2
        fi
    else
        rm -f "${_pcr_tmp}" 2>/dev/null
        printf '[%s] WARNING: could not patch %s\n' "${name}" "${PFB_PKG_CONF}" >&2
    fi
    unset _pcr_tmp _pcr_had_no_trailing_nl _pcr_original_sum _pcr_live_sum
    return 0
}

# Regenerate each channel's conf independently (channel keyed by conf path). Only
# the channel(s) the box actually subscribed to are touched — _regen_one()'s
# orphan guard skips every absent conf, so a box on one channel stays on that one
# channel across a reboot (single-repository subscription, issue #2148).
pfblockerng_repo_generate_start() {
    _regen_one "${PFB_STABLE_CONF}"  'stable'  'pfblockerng-stable'
    _regen_one "${PFB_TESTING_CONF}" 'testing' 'pfblockerng-testing'
    _regen_one "${PFB_EDGE_CONF}"    'edge'    'pfblockerng-edge'
    _regen_one "${PFB_NIGHTLY_CONF}" 'nightly' 'pfblockerng-nightly'
    _pkgconf_ca_reapply
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
