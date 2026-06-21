#shellcheck shell=sh
# pfblockerng_repo_generate.sh — boot-time repo-conf regenerator (ADR-39).
#
# The hook is a pure REGENERATOR: for each of our conf files that EXISTS, it
# detects the box's <varver>/<arch> and unconditionally overwrites the conf with
# the canonical body. No pkg call, no network, no snapshot, no reconcile.
#
# Behavioural contracts pinned here:
#   orphan      — neither conf present → nothing written, pkg never invoked, exit 0.
#   regenerate  — a present conf is overwritten with the resolved canonical body
#                 (release → ce-..; nightly → plus-..) keyed by the conf filename.
#   unconditional — a STALE-varver conf is rewritten to the box's current varver
#                 (before: stale present; after: stale gone, current present).
#   detection   — edition = "/etc/product_label contains 'Plus'": Plus vs CE; the
#                 varver prefix and the catalog path follow.
#   no-network  — the hook calls `pkg config abi` for arch ONLY; it NEVER runs
#                 pkg update/install/upgrade (no reconcile, no fetch).
#   fail-proof  — detection failure (empty version / broken pkg) leaves the conf
#                 UNCHANGED, warns on stderr, and still exits 0 (never wedge boot).
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

# Write a pkg stub at $1 whose `config abi` prints $2 (e.g. "FreeBSD:15:amd64").
# Every invocation is logged to PKG_STUB_LOG so a test can assert which
# subcommands ran (the hook must touch ONLY `config abi`).
# Pass abi="" to simulate a broken pkg (config abi prints nothing → arch empty).
_make_pkg_stub() {
    _mps_path="$1"
    _mps_abi="$2"
    cat > "${_mps_path}" <<EOF
#!/bin/sh
printf 'pkg %s\n' "\$*" >> "\${PKG_STUB_LOG:-/dev/null}"
case "\$*" in
    'config abi') printf '%s' '${_mps_abi}' ;;
esac
exit 0
EOF
    chmod +x "${_mps_path}"
    unset _mps_path _mps_abi
}

# Stand up a stubbed box in dir $1: product_label=$2, version=$3, abi=$4.
# Exports every PFB_* override the hook reads. Conf files are NOT created here —
# each example stages the conf(s) it wants the hook to (not) regenerate.
_make_box() {
    _mb_dir="$1"
    mkdir -p "${_mb_dir}/repos"
    printf '%s\n' "$2" > "${_mb_dir}/product_label"
    printf '%s\n' "$3" > "${_mb_dir}/version"
    _make_pkg_stub "${_mb_dir}/pkg" "$4"

    PFB_RELEASE_CONF="${_mb_dir}/repos/pfblockerng.conf"
    PFB_NIGHTLY_CONF="${_mb_dir}/repos/pfblockerng-nightly.conf"
    PFB_PRODUCT_LABEL="${_mb_dir}/product_label"
    PFB_VERSION_FILE="${_mb_dir}/version"
    PFB_PKG_BIN="${_mb_dir}/pkg"
    PKG_STUB_LOG="${_mb_dir}/pkg_calls.log"
    export PFB_RELEASE_CONF PFB_NIGHTLY_CONF PFB_PRODUCT_LABEL PFB_VERSION_FILE \
           PFB_PKG_BIN PKG_STUB_LOG
}

_unset_box() {
    unset PFB_RELEASE_CONF PFB_NIGHTLY_CONF PFB_PRODUCT_LABEL PFB_VERSION_FILE \
          PFB_PKG_BIN PKG_STUB_LOG
}

# ── ORPHAN: neither conf present → nothing written, pkg never invoked ──────────

Describe 'generate hook — orphan: no conf present'
    setup() {
        _o_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/gen_orphan.XXXXXX")"
        _make_box "${_o_dir}" "pfSense" "2.8.1" "FreeBSD:15:amd64"
    }
    cleanup() { rm -rf "${_o_dir}"; _unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: neither conf exists'
      The path "${PFB_RELEASE_CONF}" should not be exist
      The path "${PFB_NIGHTLY_CONF}" should not be exist
    End

    It 'writes nothing, never invokes pkg, and exits 0'
      When run sh "${HOOK}" onestart
      The status should be success
      The path "${PFB_RELEASE_CONF}" should not be exist
      The path "${PFB_NIGHTLY_CONF}" should not be exist
      # The orphan guard returns before detection, so pkg is never even called.
      The path "${PKG_STUB_LOG}" should not be exist
    End
End

# ── REGENERATE release (CE 2.8.1/amd64) ───────────────────────────────────────

Describe 'generate hook — regenerate release conf (CE)'
    setup() {
        _r_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/gen_rel.XXXXXX")"
        _make_box "${_r_dir}" "pfSense" "2.8.1" "FreeBSD:15:amd64"
        printf '# stub pending\n' > "${PFB_RELEASE_CONF}"
    }
    cleanup() { rm -rf "${_r_dir}"; _unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: release conf is the unresolved stub; nightly is absent'
      The contents of file "${PFB_RELEASE_CONF}" should include "pending"
      The path "${PFB_NIGHTLY_CONF}" should not be exist
    End

    It 'overwrites the release conf with the resolved CE catalog body, exit 0'
      When run sh "${HOOK}" onestart
      The status should be success
      The stderr should include "regenerated"
      The contents of file "${PFB_RELEASE_CONF}" should include 'url: "https://pfblockerng.github.io/pkg/release/ce-2.8/amd64"'
      The contents of file "${PFB_RELEASE_CONF}" should include "Generated at boot by pfblockerng_repo_generate"
      The contents of file "${PFB_RELEASE_CONF}" should include "pfblockerng: {"
      # The stub line is gone (full overwrite, not a patch).
      The contents of file "${PFB_RELEASE_CONF}" should not include "pending"
      # Orphan guard: the nightly conf the user never bootstrapped stays absent.
      The path "${PFB_NIGHTLY_CONF}" should not be exist
    End

    It 'calls pkg config abi for arch but NEVER pkg update/install/upgrade'
      When run sh "${HOOK}" onestart
      The status should be success
      The stderr should include "regenerated"
      The contents of file "${PKG_STUB_LOG}" should include "pkg config abi"
      The contents of file "${PKG_STUB_LOG}" should not include "pkg update"
      The contents of file "${PKG_STUB_LOG}" should not include "pkg install"
      The contents of file "${PKG_STUB_LOG}" should not include "pkg upgrade"
    End
End

# ── REGENERATE nightly (Plus 26.03.1/aarch64) — detection: Plus + channel keying ─

Describe 'generate hook — regenerate nightly conf (Plus)'
    setup() {
        _n_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/gen_nightly.XXXXXX")"
        _make_box "${_n_dir}" "pfSense Plus" "26.03.1" "FreeBSD:15:aarch64"
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
      The contents of file "${PFB_NIGHTLY_CONF}" should include 'url: "https://pfblockerng.github.io/pkg/nightly/plus-26.03/aarch64"'
      The contents of file "${PFB_NIGHTLY_CONF}" should include "pfblockerng-nightly: {"
      The contents of file "${PFB_NIGHTLY_CONF}" should include "nightly channel"
      The path "${PFB_RELEASE_CONF}" should not be exist
    End
End

# ── UNCONDITIONAL: a STALE-varver conf is rewritten to the current varver ──────

Describe 'generate hook — unconditional rewrite of a stale-varver conf'
    setup() {
        _s_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/gen_stale.XXXXXX")"
        _make_box "${_s_dir}" "pfSense" "2.8.1" "FreeBSD:15:amd64"
        # Seed a conf carrying a STALE varver (as if from before an OS upgrade).
        cat > "${PFB_RELEASE_CONF}" <<'EOF'
# old generated body
pfblockerng: {
  url: "https://pfblockerng.github.io/pkg/release/ce-2.7/amd64",
  enabled: yes
}
EOF
    }
    cleanup() { rm -rf "${_s_dir}"; _unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: conf carries the stale ce-2.7 varver, not the current ce-2.8'
      The contents of file "${PFB_RELEASE_CONF}" should include "ce-2.7/amd64"
      The contents of file "${PFB_RELEASE_CONF}" should not include "ce-2.8/amd64"
    End

    It 'rewrites the conf to the current ce-2.8 varver (stale gone), exit 0'
      When run sh "${HOOK}" onestart
      The status should be success
      The stderr should include "regenerated"
      The contents of file "${PFB_RELEASE_CONF}" should include "ce-2.8/amd64"
      The contents of file "${PFB_RELEASE_CONF}" should not include "ce-2.7/amd64"
      # No pkg reconcile on an upgrade-driven varver change.
      The contents of file "${PKG_STUB_LOG}" should not include "pkg update"
    End
End

# ── FAIL-PROOF: detection failure leaves the conf unchanged, still exit 0 ──────

Describe 'generate hook — fail-proof: detection failure leaves conf unchanged'
    # Case A: empty /etc/version → varver unresolvable.
    setup_ev() {
        _ev_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/gen_emptyver.XXXXXX")"
        _make_box "${_ev_dir}" "pfSense" "" "FreeBSD:15:amd64"
        printf '# UNCHANGED-STUB\n' > "${PFB_RELEASE_CONF}"
    }
    cleanup_ev() { rm -rf "${_ev_dir}"; _unset_box; }

    Describe 'empty version'
        Before 'setup_ev'
        After  'cleanup_ev'

        It 'before-state: conf is the unchanged stub'
          The contents of file "${PFB_RELEASE_CONF}" should include "UNCHANGED-STUB"
        End

        It 'leaves the conf byte-unchanged, warns, and exits 0'
          When run sh "${HOOK}" onestart
          The status should be success
          The stderr should include "WARNING"
          The contents of file "${PFB_RELEASE_CONF}" should include "UNCHANGED-STUB"
        End
    End

    # Case B: broken pkg (config abi prints nothing) → arch unresolvable.
    setup_ba() {
        _ba_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/gen_badabi.XXXXXX")"
        _make_box "${_ba_dir}" "pfSense" "2.8.1" ""
        printf '# UNCHANGED-STUB\n' > "${PFB_RELEASE_CONF}"
    }
    cleanup_ba() { rm -rf "${_ba_dir}"; _unset_box; }

    Describe 'broken pkg config abi'
        Before 'setup_ba'
        After  'cleanup_ba'

        It 'leaves the conf byte-unchanged, warns, and exits 0'
          When run sh "${HOOK}" onestart
          The status should be success
          The stderr should include "WARNING"
          The contents of file "${PFB_RELEASE_CONF}" should include "UNCHANGED-STUB"
        End
    End
End
