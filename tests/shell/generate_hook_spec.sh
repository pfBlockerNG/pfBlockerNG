#shellcheck shell=sh
# pfblockerng_repo_generate.sh — boot-time repo-conf regenerator (ADR-39;
# arch-less/NO_ARCH since issue #1806).
#
# The hook is a pure REGENERATOR: for each of our conf files that EXISTS, it
# detects the box's <varver> and unconditionally overwrites the conf with the
# canonical body. No pkg call at all (issue #1806 retired the `pkg config abi`
# read — arch-less catalogs have no per-arch leaf left to detect), no network,
# no snapshot, no reconcile.
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

HOOK="${PFB_ROOT}/scripts/rc.d/pfblockerng_repo_generate.sh"

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
    PATH="${_mb_dir}/bin:${PATH}"
    export PFB_RELEASE_CONF PFB_STABLE_CONF PFB_TESTING_CONF PFB_EDGE_CONF \
           PFB_NIGHTLY_CONF PFB_PRODUCT_LABEL PFB_VERSION_FILE PKG_STUB_LOG PATH
}

_unset_box() {
    unset PFB_RELEASE_CONF PFB_STABLE_CONF PFB_TESTING_CONF PFB_EDGE_CONF \
          PFB_NIGHTLY_CONF PFB_PRODUCT_LABEL PFB_VERSION_FILE PKG_STUB_LOG
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
      The contents of file "${PFB_STABLE_CONF}" should include 'url: "https://pfblockerng.github.io/pkg/stable/ce-2.8"'
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
      The contents of file "${PFB_TESTING_CONF}" should include 'url: "https://pfblockerng.github.io/pkg/testing/plus-26.03"'
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
  url: "https://pfblockerng.github.io/pkg/edge/ce-2.7",
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
      The contents of file "${PFB_EDGE_CONF}" should include 'url: "https://pfblockerng.github.io/pkg/edge/ce-2.8"'
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
      The contents of file "${PFB_NIGHTLY_CONF}" should include 'url: "https://pfblockerng.github.io/pkg/nightly/plus-26.03"'
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
      The contents of file "${PFB_STABLE_CONF}" should include 'url: "https://pfblockerng.github.io/pkg/stable/plus-26.07"'
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
      The contents of file "${PFB_EDGE_CONF}" should include 'url: "https://pfblockerng.github.io/pkg/edge/ce-2.9"'
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
  url: "https://pfblockerng.github.io/pkg/testing/ce-2.7",
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
