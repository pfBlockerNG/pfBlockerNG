#shellcheck shell=sh
# pfblockerng_repo_generate.sh — boot-time repo-conf regenerator (ADR-39;
# arch-less/NO_ARCH since issue #1806).
#
# The hook is a REGENERATOR: for each of our conf files that EXISTS, it detects
# the box's <varver> and overwrites the conf with the canonical body. No pkg
# call at all (issue #1806 retired the `pkg config abi` read — arch-less
# catalogs have no per-arch leaf left to detect), no network, no snapshot, no
# reconcile. The one thing it does NOT re-derive is the catalog BASE — see the
# DEST BASE contract below (issue #2459).
#
# Behavioural contracts pinned here:
#   orphan      — neither conf present → nothing written, pkg never invoked, exit 0.
#   regenerate  — a present conf is overwritten with the resolved canonical body
#                 (stable → ce-..; nightly → plus-..) keyed by the conf filename.
#                 The legacy release conf (pfblockerng.conf) is retired by the
#                 installers and never regenerated — a leftover survives byte-
#                 unchanged (issue #2416).
#   unconditional — a STALE-varver conf is rewritten to the box's current varver
#                 (before: stale present; after: stale gone, current present).
#   dest base   — the base the conf was generated from survives a boot with no
#                 environment (fork site, staging prefix, file:// catalogue); an
#                 explicit PFB_BASE_URL still wins; a url this hook could not
#                 have written leaves the conf byte-unchanged (issue #2459).
#   detection   — edition = "/etc/product_label contains 'Plus'": Plus vs CE; the
#                 varver prefix and the catalog path follow. Version-only —
#                 arch-less (issue #1806): the hook never calls `pkg` at all.
#   no-pkg      — the hook NEVER invokes `pkg` at all (it has no configurable
#                 pkg-binary override, unlike e.g. build-repo.sh's PKG_BIN) —
#                 no arch detection to read, no reconcile, no fetch. The stub
#                 below only intercepts a BARE PATH `pkg` lookup, which is the
#                 only mechanism there is to catch.
#   fail-proof  — detection failure (empty version) leaves the conf UNCHANGED,
#                 warns on stderr, and still exits 0 (never wedge boot).
#
# Before-and-after mandate (CLAUDE.md): the regenerate/unconditional/fail-proof
# examples assert the before-state before the after-state, so green proves the
# regeneration CAUSED the change.
#
# The hook runs standalone off-box (CI Linux has no /etc/rc.subr → the hook's
# else-branch runs its *_start directly), so these examples execute it with
# `When run` and assert on the conf files + stderr + exit status — no sourcing
# trickery, no rc.subr stub.
#
# Tip: run with `shellspec tests/shell/generate_hook_spec.sh` from the repo root.

HOOK="${PFB_ROOT}/src/usr/local/etc/rc.d/pfblockerng_repo_generate.sh"

# ── helpers ───────────────────────────────────────────────────────────────────

# Write a pkg stub at $1 that LOGS every invocation to PKG_STUB_LOG — a pure
# regression guard (issue #1806: the hook never calls `pkg` for anything; a
# stub that would log a call, combined with asserting the log never appears,
# catches a regression that reintroduces one).
_make_pkg_stub() {
    _mps_path="$1"
    cat > "${_mps_path}" <<EOF
#!/bin/sh
printf 'pkg %s\n' "\$*" >> "\${PKG_STUB_LOG:-/dev/null}"
exit 0
EOF
    chmod +x "${_mps_path}"
    unset _mps_path
}

# Stand up a stubbed box in dir $1: product_label=$2, version=$3.
# Exports every PFB_* override the hook reads — ALL FIVE conf paths, because an
# override the spec omits falls back to its /usr/local/etc/pkg/repos/ default and
# the hook would then regenerate the REAL box's conf mid-suite. A logging `pkg`
# stub is placed on PATH so a BARE `pkg` invocation is caught — the hook has no
# PFB_PKG_BIN-style override to intercept separately, and calls it under no
# mechanism at all (issue #1806) — pure regression guard. Conf files are NOT
# created here — each example stages the conf(s) it wants the hook to (not)
# regenerate.
_make_box() {
    _mb_dir="$1"
    mkdir -p "${_mb_dir}/repos" "${_mb_dir}/bin"
    printf '%s\n' "$2" > "${_mb_dir}/product_label"
    printf '%s\n' "$3" > "${_mb_dir}/version"
    _make_pkg_stub "${_mb_dir}/bin/pkg"

    PFB_RELEASE_CONF="${_mb_dir}/repos/pfblockerng.conf"
    PFB_STABLE_CONF="${_mb_dir}/repos/pfblockerng-stable.conf"
    PFB_TESTING_CONF="${_mb_dir}/repos/pfblockerng-testing.conf"
    PFB_EDGE_CONF="${_mb_dir}/repos/pfblockerng-edge.conf"
    PFB_NIGHTLY_CONF="${_mb_dir}/repos/pfblockerng-nightly.conf"
    PFB_PRODUCT_LABEL="${_mb_dir}/product_label"
    PFB_VERSION_FILE="${_mb_dir}/version"
    PKG_STUB_LOG="${_mb_dir}/pkg_calls.log"
    # Staged like every other on-box path: an unstaged run would write the HOST's
    # real fingerprint store (issue #2675).
    PFB_FINGERPRINT_DIR="${_mb_dir}/fingerprints/pfblockerng"
    PATH="${_mb_dir}/bin:${PATH}"
    export PFB_RELEASE_CONF PFB_STABLE_CONF PFB_TESTING_CONF PFB_EDGE_CONF \
           PFB_NIGHTLY_CONF PFB_PRODUCT_LABEL PFB_VERSION_FILE PFB_FINGERPRINT_DIR \
           PKG_STUB_LOG PATH
}

_unset_box() {
    unset PFB_RELEASE_CONF PFB_STABLE_CONF PFB_TESTING_CONF PFB_EDGE_CONF \
          PFB_NIGHTLY_CONF PFB_PRODUCT_LABEL PFB_VERSION_FILE PFB_FINGERPRINT_DIR \
          PKG_STUB_LOG
}

# How many conf files the box currently carries — the single-subscription oracle.
_conf_count() { ls -1 "$1"/repos | wc -l | tr -d ' '; }

# ── ORPHAN: no conf present → nothing written, pkg never invoked ───────────────

Describe 'generate hook — orphan: no conf present'
    setup() {
        _o_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/gen_orphan.XXXXXX")"
        _make_box "${_o_dir}" "pfSense" "2.8.1"
    }
    cleanup() { rm -rf "${_o_dir}"; _unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: no channel conf exists'
      The value "$(_conf_count "${_o_dir}")" should equal 0
    End

    It 'writes nothing, never invokes pkg, and exits 0'
      When run sh "${HOOK}" onestart
      The status should be success
      The value "$(_conf_count "${_o_dir}")" should equal 0
      # The orphan guard returns before detection, and detection itself never
      # touches pkg (arch-less; issue #1806).
      The path "${PKG_STUB_LOG}" should not be exist
    End
End

# ── PER-CHANNEL REGENERATION (issue #2148) ────────────────────────────────────
#
# Before #2148 the hook knew only the legacy release conf and nightly, so a box
# subscribed to stable/testing/edge kept a stale <varver> forever after a pfSense
# OS upgrade. Each channel now regenerates from the same canonical body, and the
# orphan guard still holds per channel so regeneration can never re-enable a
# channel the user switched away from (single-repository subscription).

Describe 'generate hook — regenerate the stable conf (CE)'
    setup() {
        _st_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/gen_stable.XXXXXX")"
        _make_box "${_st_dir}" "pfSense" "2.8.1"
        printf '# stub pending\n' > "${PFB_STABLE_CONF}"
    }
    cleanup() { rm -rf "${_st_dir}"; _unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: only the stable conf exists, and it is the unresolved stub'
      The contents of file "${PFB_STABLE_CONF}" should include "pending"
      The value "$(_conf_count "${_st_dir}")" should equal 1
    End

    It 'resolves the stable catalogue and keeps every other channel unsubscribed'
      When run sh "${HOOK}" onestart
      The status should be success
      The stderr should include "regenerated"
      The contents of file "${PFB_STABLE_CONF}" should include 'url: "http://pkg.pfblockerng.com/stable/ce-2.8"'
      The contents of file "${PFB_STABLE_CONF}" should include "pfblockerng-stable: {"
      The contents of file "${PFB_STABLE_CONF}" should include "stable channel"
      The contents of file "${PFB_STABLE_CONF}" should not include "pending"
      The value "$(_conf_count "${_st_dir}")" should equal 1
    End
End

Describe 'generate hook — regenerate the testing conf (Plus)'
    setup() {
        _te_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/gen_testing.XXXXXX")"
        _make_box "${_te_dir}" "pfSense Plus" "26.03.1"
        printf '# stub pending\n' > "${PFB_TESTING_CONF}"
    }
    cleanup() { rm -rf "${_te_dir}"; _unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: only the testing conf exists, and it is the unresolved stub'
      The contents of file "${PFB_TESTING_CONF}" should include "pending"
      The value "$(_conf_count "${_te_dir}")" should equal 1
    End

    It 'resolves the Plus testing catalogue and keeps every other channel unsubscribed'
      When run sh "${HOOK}" onestart
      The status should be success
      The stderr should include "regenerated"
      The contents of file "${PFB_TESTING_CONF}" should include 'url: "http://pkg.pfblockerng.com/testing/plus-26.03"'
      The contents of file "${PFB_TESTING_CONF}" should include "pfblockerng-testing: {"
      The value "$(_conf_count "${_te_dir}")" should equal 1
    End
End

Describe 'generate hook — regenerate the edge conf across a pfSense OS upgrade'
    # The upgrade case is the whole reason the hook runs at boot: the box moved
    # from CE 2.7 to CE 2.8, so the edge subscription must follow to the new
    # varver instead of pointing at a catalogue that no longer receives builds.
    setup() {
        _ed_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/gen_edge.XXXXXX")"
        _make_box "${_ed_dir}" "pfSense" "2.8.1"
        cat > "${PFB_EDGE_CONF}" <<'STALE'
# Generated at boot by pfblockerng_repo_generate (ADR-39)
pfblockerng-edge: {
  url: "https://pkg.pfblockerng.com/edge/ce-2.7",
  enabled: yes
}
STALE
    }
    cleanup() { rm -rf "${_ed_dir}"; _unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: the edge conf still points at the pre-upgrade ce-2.7 catalogue'
      The contents of file "${PFB_EDGE_CONF}" should include "edge/ce-2.7"
      The contents of file "${PFB_EDGE_CONF}" should not include "edge/ce-2.8"
    End

    It 'rewrites the edge conf to the box current varver, exit 0'
      When run sh "${HOOK}" onestart
      The status should be success
      The stderr should include "regenerated"
      The contents of file "${PFB_EDGE_CONF}" should include 'url: "http://pkg.pfblockerng.com/edge/ce-2.8"'
      The contents of file "${PFB_EDGE_CONF}" should not include "ce-2.7"
      The path "${PKG_STUB_LOG}" should not be exist
    End
End

Describe 'generate hook — a subscribed channel never re-enables the one it replaced'
    # Single-repository subscription (issue #2148): the user switched from the
    # legacy release repo to edge. Boot regeneration must not resurrect release.
    setup() {
        _sw_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/gen_switch.XXXXXX")"
        _make_box "${_sw_dir}" "pfSense" "2.8.1"
        printf '# stub pending\n' > "${PFB_EDGE_CONF}"
    }
    cleanup() { rm -rf "${_sw_dir}"; _unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: edge is the only subscription; the legacy release conf is gone'
      The path "${PFB_EDGE_CONF}" should be exist
      The path "${PFB_RELEASE_CONF}" should not be exist
    End

    It 'regenerates edge alone and leaves release, stable, testing and nightly absent'
      When run sh "${HOOK}" onestart
      The status should be success
      The stderr should include "regenerated"
      The contents of file "${PFB_EDGE_CONF}" should include "pfblockerng-edge: {"
      The path "${PFB_RELEASE_CONF}" should not be exist
      The path "${PFB_STABLE_CONF}" should not be exist
      The path "${PFB_TESTING_CONF}" should not be exist
      The path "${PFB_NIGHTLY_CONF}" should not be exist
      The value "$(_conf_count "${_sw_dir}")" should equal 1
    End
End

# ── LEGACY RELEASE CONF: retired, never regenerated (issue #2416) ────────────

Describe 'generate hook — leaves a leftover legacy release conf untouched'
    # Before #2416 the hook regenerated pfblockerng.conf (the pre-#2148 shared
    # release repo). install.sh retired it — a box that still carries a leftover
    # from before the migration must not have it silently resurrected/rewritten
    # at every boot; it is simply never touched.
    setup() {
        _r_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/gen_rel.XXXXXX")"
        _make_box "${_r_dir}" "pfSense" "2.8.1"
        printf '# stub pending\n' > "${PFB_RELEASE_CONF}"
    }
    cleanup() { rm -rf "${_r_dir}"; _unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: a leftover release conf stub exists; nightly is absent'
      The contents of file "${PFB_RELEASE_CONF}" should include "pending"
      The path "${PFB_NIGHTLY_CONF}" should not be exist
    End

    It 'leaves the leftover release conf byte-unchanged, exit 0'
      When run sh "${HOOK}" onestart
      The status should be success
      The contents of file "${PFB_RELEASE_CONF}" should include "pending"
      # Orphan guard: the nightly conf the user never bootstrapped stays absent.
      The path "${PFB_NIGHTLY_CONF}" should not be exist
    End

    It 'never invokes pkg at all (arch-less; issue #1806)'
      When run sh "${HOOK}" onestart
      The status should be success
      The path "${PKG_STUB_LOG}" should not be exist
    End
End

# ── REGENERATE nightly (Plus 26.03.1) — detection: Plus + channel keying ──────

Describe 'generate hook — regenerate nightly conf (Plus)'
    setup() {
        _n_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/gen_nightly.XXXXXX")"
        _make_box "${_n_dir}" "pfSense Plus" "26.03.1"
        printf '# stub pending\n' > "${PFB_NIGHTLY_CONF}"
    }
    cleanup() { rm -rf "${_n_dir}"; _unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: nightly conf is the unresolved stub; release is absent'
      The contents of file "${PFB_NIGHTLY_CONF}" should include "pending"
      The path "${PFB_RELEASE_CONF}" should not be exist
    End

    It 'resolves the Plus nightly catalog and keys the channel by filename, exit 0'
      When run sh "${HOOK}" onestart
      The status should be success
      The stderr should include "regenerated"
      The contents of file "${PFB_NIGHTLY_CONF}" should include 'url: "http://pkg.pfblockerng.com/nightly/plus-26.03"'
      The contents of file "${PFB_NIGHTLY_CONF}" should include "pfblockerng-nightly: {"
      The contents of file "${PFB_NIGHTLY_CONF}" should include "nightly channel"
      The path "${PFB_RELEASE_CONF}" should not be exist
    End
End

# ── PRE-RELEASE SUFFIX STRIP: a dash-suffixed /etc/version must not leak into
#    the varver (issue #1786) ────────────────────────────────────────────────

Describe 'generate hook — pre-release suffix strip (Plus BETA)'
    setup() {
        _pb_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/gen_plusbeta.XXXXXX")"
        _make_box "${_pb_dir}" "pfSense Plus" "26.07-BETA"
        printf '# stub pending\n' > "${PFB_STABLE_CONF}"
    }
    cleanup() { rm -rf "${_pb_dir}"; _unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: stable conf is the unresolved stub'
      The contents of file "${PFB_STABLE_CONF}" should include "pending"
    End

    It 'strips the -BETA suffix before major.minor, exit 0'
      When run sh "${HOOK}" onestart
      The status should be success
      The stderr should include "regenerated"
      The contents of file "${PFB_STABLE_CONF}" should include 'url: "http://pkg.pfblockerng.com/stable/plus-26.07"'
      The contents of file "${PFB_STABLE_CONF}" should not include "plus-26.07-BETA"
    End
End

Describe 'generate hook — pre-release suffix strip (CE RC)'
    setup() {
        _cr_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/gen_cerc.XXXXXX")"
        _make_box "${_cr_dir}" "pfSense" "2.9-RC"
        printf '# stub pending\n' > "${PFB_EDGE_CONF}"
    }
    cleanup() { rm -rf "${_cr_dir}"; _unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: edge conf is the unresolved stub'
      The contents of file "${PFB_EDGE_CONF}" should include "pending"
    End

    It 'strips the -RC suffix before major.minor, exit 0'
      When run sh "${HOOK}" onestart
      The status should be success
      The stderr should include "regenerated"
      The contents of file "${PFB_EDGE_CONF}" should include 'url: "http://pkg.pfblockerng.com/edge/ce-2.9"'
      The contents of file "${PFB_EDGE_CONF}" should not include "ce-2.9-RC"
    End
End

# ── UNCONDITIONAL: a STALE-varver conf is rewritten to the current varver ──────

Describe 'generate hook — unconditional rewrite of a stale-varver conf'
    setup() {
        _s_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/gen_stale.XXXXXX")"
        _make_box "${_s_dir}" "pfSense" "2.8.1"
        # Seed a conf carrying a STALE varver (as if from before an OS upgrade).
        cat > "${PFB_TESTING_CONF}" <<'EOF'
# old generated body
pfblockerng-testing: {
  url: "https://pkg.pfblockerng.com/testing/ce-2.7",
  enabled: yes
}
EOF
    }
    cleanup() { rm -rf "${_s_dir}"; _unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: conf carries the stale ce-2.7 varver, not the current ce-2.8'
      The contents of file "${PFB_TESTING_CONF}" should include "ce-2.7"
      The contents of file "${PFB_TESTING_CONF}" should not include "ce-2.8"
    End

    It 'rewrites the conf to the current ce-2.8 varver (stale gone), exit 0'
      When run sh "${HOOK}" onestart
      The status should be success
      The stderr should include "regenerated"
      The contents of file "${PFB_TESTING_CONF}" should include "ce-2.8"
      The contents of file "${PFB_TESTING_CONF}" should not include "ce-2.7"
      # No pkg reconcile on an upgrade-driven varver change.
      The path "${PKG_STUB_LOG}" should not be exist
    End
End

# ── FAIL-PROOF: detection failure leaves the conf unchanged, still exit 0 ──────

Describe 'generate hook — fail-proof: detection failure leaves conf unchanged'
    # Empty /etc/version → varver unresolvable. Arch-less (issue #1806) means
    # there is no second, pkg-dependent detection failure mode any more (the
    # old "broken pkg config abi" case was retired along with the arch read).
    setup_ev() {
        _ev_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/gen_emptyver.XXXXXX")"
        _make_box "${_ev_dir}" "pfSense" ""
        printf '# UNCHANGED-STUB\n' > "${PFB_NIGHTLY_CONF}"
    }
    cleanup_ev() { rm -rf "${_ev_dir}"; _unset_box; }

    Describe 'empty version'
        Before 'setup_ev'
        After  'cleanup_ev'

        It 'before-state: conf is the unchanged stub'
          The contents of file "${PFB_NIGHTLY_CONF}" should include "UNCHANGED-STUB"
        End

        It 'leaves the conf byte-unchanged, warns, and exits 0'
          When run sh "${HOOK}" onestart
          The status should be success
          The stderr should include "WARNING"
          The contents of file "${PFB_NIGHTLY_CONF}" should include "UNCHANGED-STUB"
        End
    End
End

# ── DEST BASE: the hook preserves the base its conf was generated from ────────
#
# Issue #2459. `_regen_one` used to compose the url from PFB_BASE_URL alone,
# defaulting to the primary Pages site. At boot there is no env, so a fork site,
# a staging prefix and a `file://` guest catalogue were all silently rewritten to
# `https://pkg.pfblockerng.com` — a redirect of where the box fetches
# packages from. The base now comes from the conf the hook is about to rewrite
# (its url's `<base>/<channel>/<varver>` shape), so only the varver moves; an
# explicit PFB_BASE_URL still wins, and a url the hook cannot parse as its own
# is left alone instead of being clobbered.

Describe 'generate hook — a file:// catalogue base survives a boot with no env'
    setup() {
        _fb_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/gen_fileurl.XXXXXX")"
        _make_box "${_fb_dir}" "pfSense" "2.8.1"
        cat > "${PFB_STABLE_CONF}" <<'FILEURL'
# Generated at boot by pfblockerng_repo_generate (ADR-39)
pfblockerng-stable: {
  url: "file:///root/pfb_repo/stable/ce-2.7",
  enabled: yes
}
FILEURL
    }
    cleanup() { rm -rf "${_fb_dir}"; _unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: the conf points at the file:// catalogue with a stale varver'
      The contents of file "${PFB_STABLE_CONF}" should include 'url: "file:///root/pfb_repo/stable/ce-2.7"'
    End

    It 'keeps the file:// base and only moves the varver, exit 0'
      When run sh "${HOOK}" onestart
      The status should be success
      The stderr should include "regenerated"
      The contents of file "${PFB_STABLE_CONF}" should include 'url: "file:///root/pfb_repo/stable/ce-2.8"'
      The contents of file "${PFB_STABLE_CONF}" should not include "pkg.pfblockerng.com"
    End
End

Describe 'generate hook — a staging-prefixed fork base survives a boot with no env'
    setup() {
        _sp_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/gen_stageurl.XXXXXX")"
        _make_box "${_sp_dir}" "pfSense" "2.8.1"
        cat > "${PFB_EDGE_CONF}" <<'STAGEURL'
# Generated at boot by pfblockerng_repo_generate (ADR-39)
pfblockerng-edge: {
  url: "https://fork.example.org/pkg/staging/pr-7/edge/ce-2.7",
  enabled: yes
}
STAGEURL
    }
    cleanup() { rm -rf "${_sp_dir}"; _unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: the conf carries the fork site and its staging prefix'
      The contents of file "${PFB_EDGE_CONF}" should include 'url: "https://fork.example.org/pkg/staging/pr-7/edge/ce-2.7"'
    End

    It 'keeps host and staging prefix and only moves the varver, exit 0'
      When run sh "${HOOK}" onestart
      The status should be success
      The stderr should include "regenerated"
      The contents of file "${PFB_EDGE_CONF}" should include 'url: "https://fork.example.org/pkg/staging/pr-7/edge/ce-2.8"'
      The contents of file "${PFB_EDGE_CONF}" should not include "pkg.pfblockerng.com"
    End
End

Describe 'generate hook — a url the hook did not write is left alone'
    # The channel segment does not match the conf's channel, so this url is not
    # one this hook generated: rewriting it would silently move the box to
    # another catalogue. Leave it, warn, exit 0.
    setup() {
        _fo_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/gen_foreign.XXXXXX")"
        _make_box "${_fo_dir}" "pfSense" "2.8.1"
        cat > "${PFB_NIGHTLY_CONF}" <<'FOREIGN'
# hand-written by the operator — FOREIGN-CONF
pfblockerng-nightly: {
  url: "https://mirror.example.net/custom-layout",
  enabled: yes
}
FOREIGN
        _fo_sum="$(cksum < "${PFB_NIGHTLY_CONF}")"
    }
    cleanup() { rm -rf "${_fo_dir}"; _unset_box; unset _fo_sum; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: the conf carries a url of a shape the hook never emits'
      The contents of file "${PFB_NIGHTLY_CONF}" should include "FOREIGN-CONF"
      The contents of file "${PFB_NIGHTLY_CONF}" should include 'url: "https://mirror.example.net/custom-layout"'
    End

    It 'leaves the conf byte-unchanged, warns, and exits 0'
      When run sh "${HOOK}" onestart
      The status should be success
      The stderr should include "WARNING"
      The stderr should include "did not write"
      The value "$(cksum < "${PFB_NIGHTLY_CONF}")" should equal "${_fo_sum}"
      The contents of file "${PFB_NIGHTLY_CONF}" should not include "pkg.pfblockerng.com"
    End
End

Describe 'generate hook — an explicit PFB_BASE_URL still overrides the conf base'
    # install.sh drives the hook with PFB_BASE_URL set, precisely to MOVE a box
    # onto another base; the conf-derived base must not defeat that.
    setup() {
        _ov_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/gen_override.XXXXXX")"
        _make_box "${_ov_dir}" "pfSense" "2.8.1"
        cat > "${PFB_TESTING_CONF}" <<'OLDBASE'
# Generated at boot by pfblockerng_repo_generate (ADR-39)
pfblockerng-testing: {
  url: "file:///root/pfb_repo/testing/ce-2.8",
  enabled: yes
}
OLDBASE
        PFB_BASE_URL="https://override.example/pkg"
        export PFB_BASE_URL
    }
    cleanup() { rm -rf "${_ov_dir}"; _unset_box; unset PFB_BASE_URL; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: the conf still carries the old file:// base'
      The contents of file "${PFB_TESTING_CONF}" should include "file:///root/pfb_repo/testing"
    End

    It 'rewrites to the base given in the environment, exit 0'
      When run sh "${HOOK}" onestart
      The status should be success
      The stderr should include "regenerated"
      The contents of file "${PFB_TESTING_CONF}" should include 'url: "https://override.example/pkg/testing/ce-2.8"'
      The contents of file "${PFB_TESTING_CONF}" should not include "file:///root/pfb_repo"
    End
End

# ── The "no url at all" branch must not swallow an UNPARSEABLE url ────────────
#
# The stub-vs-foreign discriminator is "does the conf carry a url line", NOT
# "did our double-quoted pattern match one". Unquoted and single-quoted strings
# are valid UCL that libpkg reads fine, so an operator can hand-write one; an
# unterminated quote is what a botched hand edit leaves behind. None of those
# are a pending install.sh stub, and rewriting them from the built-in default
# would silently redirect the box — the very defect of issue #2459.

Describe 'generate hook — a url line it cannot parse is foreign, not a stub'
    setup() {
        _up_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/gen_unparsed.XXXXXX")"
        _make_box "${_up_dir}" "pfSense" "2.8.1"
        cat > "${PFB_STABLE_CONF}" <<'UNQUOTED'
pfblockerng-stable: {
  url: file:///root/pfb_repo/stable/ce-2.7,
  enabled: yes
}
UNQUOTED
        cat > "${PFB_EDGE_CONF}" <<'SINGLEQ'
pfblockerng-edge: {
  url: 'https://fork.example.org/pkg/edge/ce-2.7',
  enabled: yes
}
SINGLEQ
        cat > "${PFB_NIGHTLY_CONF}" <<'UNTERM'
pfblockerng-nightly: {
  url: "https://fork.example.org/pkg/nightly/ce-2.7,
  enabled: yes
}
UNTERM
        _up_sums="$(cat "${PFB_STABLE_CONF}" "${PFB_EDGE_CONF}" "${PFB_NIGHTLY_CONF}" | cksum)"
    }
    cleanup() { rm -rf "${_up_dir}"; _unset_box; unset _up_sums; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: three confs carry a url line our pattern cannot parse'
      The contents of file "${PFB_STABLE_CONF}" should include "url: file:///root/pfb_repo/stable/ce-2.7"
      The contents of file "${PFB_EDGE_CONF}" should include "url: 'https://fork.example.org/pkg/edge/ce-2.7'"
      The contents of file "${PFB_NIGHTLY_CONF}" should include 'url: "https://fork.example.org/pkg/nightly/ce-2.7,'
    End

    It 'leaves all three byte-unchanged, warns, and exits 0'
      When run sh "${HOOK}" onestart
      The status should be success
      The stderr should include "did not write"
      The value "$(cat "${PFB_STABLE_CONF}" "${PFB_EDGE_CONF}" "${PFB_NIGHTLY_CONF}" | cksum)" should equal "${_up_sums}"
      The contents of file "${PFB_STABLE_CONF}" should not include "pkg.pfblockerng.com"
      The contents of file "${PFB_EDGE_CONF}" should not include "pkg.pfblockerng.com"
      The contents of file "${PFB_NIGHTLY_CONF}" should not include "pkg.pfblockerng.com"
    End
End

Describe 'generate hook — a varver segment it never emits is foreign too'
    # The channel segment matching is not enough: the last segment must also look
    # like a varver this hook wrote. A query string carries credentials an
    # operator put there, and dropping it while rewriting the path would break
    # the subscription silently; a host literally named after the channel would
    # collapse the base to a bare scheme.
    setup() {
        _vv_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/gen_varver.XXXXXX")"
        _make_box "${_vv_dir}" "pfSense" "2.8.1"
        cat > "${PFB_TESTING_CONF}" <<'QUERY'
pfblockerng-testing: {
  url: "https://mirror.example.net/pkg/testing/ce-2.7?token=abc",
  enabled: yes
}
QUERY
        cat > "${PFB_NIGHTLY_CONF}" <<'BARESCHEME'
pfblockerng-nightly: {
  url: "https://nightly/ce-2.7",
  enabled: yes
}
BARESCHEME
        _vv_sums="$(cat "${PFB_TESTING_CONF}" "${PFB_NIGHTLY_CONF}" | cksum)"
    }
    cleanup() { rm -rf "${_vv_dir}"; _unset_box; unset _vv_sums; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: one url carries a query string, one has the channel as its host'
      The contents of file "${PFB_TESTING_CONF}" should include "ce-2.7?token=abc"
      The contents of file "${PFB_NIGHTLY_CONF}" should include 'url: "https://nightly/ce-2.7"'
    End

    It 'leaves both byte-unchanged, warns, and exits 0'
      When run sh "${HOOK}" onestart
      The status should be success
      The stderr should include "did not write"
      The value "$(cat "${PFB_TESTING_CONF}" "${PFB_NIGHTLY_CONF}" | cksum)" should equal "${_vv_sums}"
      The contents of file "${PFB_TESTING_CONF}" should include "token=abc"
      The contents of file "${PFB_NIGHTLY_CONF}" should not include "https:/nightly"
    End
End

# ── Base composition edge cases ───────────────────────────────────────────────

Describe 'generate hook — a catalogue rooted at / keeps its third slash'
    # `file:///stable/ce-2.7` derives the base `file://`. Stripping a trailing
    # slash off THAT (which the env branch must do, and only the env branch)
    # would emit `file://stable/...` — a host-form url pointing somewhere else
    # entirely, written with an INFO line rather than a warning.
    setup() {
        _fr_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/gen_fsroot.XXXXXX")"
        _make_box "${_fr_dir}" "pfSense" "2.8.1"
        cat > "${PFB_STABLE_CONF}" <<'FSROOT'
# Generated at boot by pfblockerng_repo_generate (ADR-39)
pfblockerng-stable: {
  url: "file:///stable/ce-2.7",
  enabled: yes
}
FSROOT
    }
    cleanup() { rm -rf "${_fr_dir}"; _unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: the catalogue root is the filesystem root'
      The contents of file "${PFB_STABLE_CONF}" should include 'url: "file:///stable/ce-2.7"'
    End

    It 'regenerates to a path url, not a host url, exit 0'
      When run sh "${HOOK}" onestart
      The status should be success
      The stderr should include "regenerated"
      The contents of file "${PFB_STABLE_CONF}" should include 'url: "file:///stable/ce-2.8"'
      The contents of file "${PFB_STABLE_CONF}" should not include "file://stable"
    End
End

Describe 'generate hook — an env base with a trailing slash does not double it'
    setup() {
        _ts_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/gen_envslash.XXXXXX")"
        _make_box "${_ts_dir}" "pfSense" "2.8.1"
        printf '# stub pending\n' > "${PFB_EDGE_CONF}"
        PFB_BASE_URL="https://fork.example.org/pkg/"
        export PFB_BASE_URL
    }
    cleanup() { rm -rf "${_ts_dir}"; _unset_box; unset PFB_BASE_URL; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: the conf is the unresolved stub'
      The contents of file "${PFB_EDGE_CONF}" should include "pending"
    End

    It 'emits exactly one slash between base and channel, exit 0'
      When run sh "${HOOK}" onestart
      The status should be success
      The stderr should include "regenerated"
      The contents of file "${PFB_EDGE_CONF}" should include 'url: "https://fork.example.org/pkg/edge/ce-2.8"'
      The contents of file "${PFB_EDGE_CONF}" should not include "pkg//edge"
    End
End

Describe 'generate hook — one trailing slash on a conf url is tolerated'
    # A conf whose url is otherwise exactly our shape but carries a trailing
    # slash is still one we wrote (or a harmless hand edit of one); freezing it
    # as foreign would strand the box on a stale varver after an OS upgrade.
    setup() {
        _cs_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/gen_confslash.XXXXXX")"
        _make_box "${_cs_dir}" "pfSense" "2.8.1"
        cat > "${PFB_TESTING_CONF}" <<'CONFSLASH'
# Generated at boot by pfblockerng_repo_generate (ADR-39)
pfblockerng-testing: {
  url: "https://fork.example.org/pkg/testing/ce-2.7/",
  enabled: yes
}
CONFSLASH
    }
    cleanup() { rm -rf "${_cs_dir}"; _unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: the conf url carries a trailing slash and a stale varver'
      The contents of file "${PFB_TESTING_CONF}" should include 'url: "https://fork.example.org/pkg/testing/ce-2.7/"'
    End

    It 'keeps the fork base and moves the varver, exit 0'
      When run sh "${HOOK}" onestart
      The status should be success
      The stderr should include "regenerated"
      The contents of file "${PFB_TESTING_CONF}" should include 'url: "https://fork.example.org/pkg/testing/ce-2.8"'
      The contents of file "${PFB_TESTING_CONF}" should not include "pkg.pfblockerng.com"
    End
End

Describe 'generate hook — the url-line discriminator ignores case'
    # A hand-edited conf spelling the key `URL:` matches neither the extractor
    # nor a case-sensitive presence check, so it would be taken for a conf with
    # no url at all and rewritten from the fallback base — the same defect class
    # as an unparseable url, reached through a different variant.
    setup() {
        _uc_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/gen_upcase.XXXXXX")"
        _make_box "${_uc_dir}" "pfSense" "2.8.1"
        cat > "${PFB_EDGE_CONF}" <<'UPCASE'
pfblockerng-edge: {
  URL: "https://decoy.example.org/pkg/edge/ce-2.7",
  enabled: yes
}
UPCASE
        _uc_sum="$(cksum < "${PFB_EDGE_CONF}")"
    }
    cleanup() { rm -rf "${_uc_dir}"; _unset_box; unset _uc_sum; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: the conf spells the key in upper case'
      The contents of file "${PFB_EDGE_CONF}" should include 'URL: "https://decoy.example.org/pkg/edge/ce-2.7"'
    End

    It 'leaves the conf byte-unchanged, warns, and exits 0'
      When run sh "${HOOK}" onestart
      The status should be success
      The stderr should include "did not write"
      The value "$(cksum < "${PFB_EDGE_CONF}")" should equal "${_uc_sum}"
      The contents of file "${PFB_EDGE_CONF}" should not include "pkg.pfblockerng.com"
    End
End

Describe 'generate hook — a pre-#1806 arch-leaf conf is frozen, not healed'
    # Before issue #1806 the url carried a per-arch leaf: <base>/<channel>/
    # <varver>/<arch>. The old hook healed one on the next boot; the dest-base
    # guard now freezes it, because a url of that shape is indistinguishable
    # from any other four-segment tail. The warning names the install.sh re-run
    # that re-points it — this row pins that deliberate trade.
    setup() {
        _al_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/gen_archleaf.XXXXXX")"
        _make_box "${_al_dir}" "pfSense" "2.8.1"
        cat > "${PFB_NIGHTLY_CONF}" <<'ARCHLEAF'
# Generated at boot by pfblockerng_repo_generate (ADR-39)
pfblockerng-nightly: {
  url: "https://pkg.pfblockerng.com/nightly/ce-2.7/FreeBSD:15:amd64",
  enabled: yes
}
ARCHLEAF
        _al_sum="$(cksum < "${PFB_NIGHTLY_CONF}")"
    }
    cleanup() { rm -rf "${_al_dir}"; _unset_box; unset _al_sum; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: the conf carries the retired per-arch leaf'
      The contents of file "${PFB_NIGHTLY_CONF}" should include "ce-2.7/FreeBSD:15:amd64"
    End

    It 'leaves it byte-unchanged and points at the install.sh re-run, exit 0'
      When run sh "${HOOK}" onestart
      The status should be success
      The stderr should include "did not write"
      The stderr should include "install.sh --channel nightly"
      The value "$(cksum < "${PFB_NIGHTLY_CONF}")" should equal "${_al_sum}"
    End
End

Describe 'generate hook — the varver segment must be one this hook emits'
    # `<channel>/<anything>` is not our shape: only `<edition>-<major.minor>` is,
    # and `_detect_catalog` emits exactly `ce-` or `plus-` prefixes. Accepting a
    # foreign leaf preserved the operator's base but still replaced their
    # directory. A scheme with one slash is malformed and equally not ours.
    setup() {
        _ns_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/gen_notshape.XXXXXX")"
        _make_box "${_ns_dir}" "pfSense" "2.8.1"
        cat > "${PFB_STABLE_CONF}" <<'NOTVARVER'
pfblockerng-stable: {
  url: "https://mirror.example.net/pkg/stable/mycustomdir",
  enabled: yes
}
NOTVARVER
        cat > "${PFB_EDGE_CONF}" <<'ONESLASH'
pfblockerng-edge: {
  url: "https:/mirror.example.net/pkg/edge/ce-2.7",
  enabled: yes
}
ONESLASH
        _ns_sums="$(cat "${PFB_STABLE_CONF}" "${PFB_EDGE_CONF}" | cksum)"
    }
    cleanup() { rm -rf "${_ns_dir}"; _unset_box; unset _ns_sums; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: one url has a non-catalog leaf, one a one-slash scheme'
      The contents of file "${PFB_STABLE_CONF}" should include "stable/mycustomdir"
      The contents of file "${PFB_EDGE_CONF}" should include 'url: "https:/mirror.example.net/pkg/edge/ce-2.7"'
    End

    It 'leaves both byte-unchanged, warns, and exits 0'
      When run sh "${HOOK}" onestart
      The status should be success
      The stderr should include "did not write"
      The value "$(cat "${PFB_STABLE_CONF}" "${PFB_EDGE_CONF}" | cksum)" should equal "${_ns_sums}"
      The contents of file "${PFB_STABLE_CONF}" should include "mycustomdir"
      The contents of file "${PFB_EDGE_CONF}" should include "ce-2.7"
      The contents of file "${PFB_EDGE_CONF}" should not include "ce-2.8"
    End
End

# ── TRUSTED FINGERPRINT (issue #2675) ─────────────────────────────────────────
#
# The conf the hook emits for a network catalogue says `signature_type:
# fingerprints`, so pkg refuses the catalogue unless the signing key's fingerprint
# is installed. The hook writes it, before any conf, at every run.

Describe 'generate hook — installs the trusted fingerprint'
    setup() {
        _fp_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/gen_fp.XXXXXX")"
        _make_box "${_fp_dir}" "pfSense" "2.8.1"
        printf '# stub pending\n' > "${PFB_STABLE_CONF}"
    }
    cleanup() { rm -rf "${_fp_dir}"; _unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: no fingerprint is installed'
      The path "${PFB_FINGERPRINT_DIR}/trusted/pkg.pfblockerng.com" should not be exist
    End

    It 'writes the trusted fingerprint and the revoked dir beside it'
      When run sh "${HOOK}" onestart
      The status should be success
      The stderr should include 'regenerated'
      The path "${PFB_FINGERPRINT_DIR}/trusted/pkg.pfblockerng.com" should be file
      The path "${PFB_FINGERPRINT_DIR}/revoked" should be directory
      fingerprint="$(cat "${PFB_FINGERPRINT_DIR}/trusted/pkg.pfblockerng.com")"
      # The exact two-line UCL pkg_repo_check_fingerprint() parses, carrying the
      # SHA256 of the DER public key the catalogues embed.
      The variable fingerprint should equal 'function: "sha256"
fingerprint: "081df5476f84d8d20417c400f576c355069a4a9979d170bcaae1c9da32778915"'
    End

    It 'is idempotent — a second run leaves the same bytes'
      sh "${HOOK}" onestart >/dev/null 2>&1
      before="$(cat "${PFB_FINGERPRINT_DIR}/trusted/pkg.pfblockerng.com")"
      When run sh "${HOOK}" onestart
      The status should be success
      The stderr should include 'regenerated'
      after="$(cat "${PFB_FINGERPRINT_DIR}/trusted/pkg.pfblockerng.com")"
      The variable after should equal "${before}"
    End
End

Describe 'generate hook — a fingerprint store it cannot write gates the rewrite'
    setup() {
        _fpf_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/gen_fpfail.XXXXXX")"
        _make_box "${_fpf_dir}" "pfSense" "2.8.1"
        printf '# stub pending\n' > "${PFB_STABLE_CONF}"
        # A FILE where the store's parent directory must be: mkdir -p cannot
        # proceed, which is the shape a hostile or corrupted /usr/local/etc/pkg
        # would present.
        printf 'not a directory\n' > "${_fpf_dir}/blocked"
        PFB_FINGERPRINT_DIR="${_fpf_dir}/blocked/pfblockerng"
        export PFB_FINGERPRINT_DIR
    }
    cleanup() { rm -rf "${_fpf_dir}"; _unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'warns, leaves every conf untouched, and exits 0'
      When run sh "${HOOK}" onestart
      The status should be success
      The stderr should include 'WARNING'
      The stderr should not include 'regenerated'
      The path "${PFB_FINGERPRINT_DIR}/trusted/pkg.pfblockerng.com" should not be exist
      # The ordering oracle: the conf is untouched because the fingerprint write runs
      # FIRST and gates it. Move that call after the regeneration and this example goes
      # red -- a box would be holding a signature-requiring conf and no key.
      The contents of file "${PFB_STABLE_CONF}" should equal '# stub pending'
    End
End
