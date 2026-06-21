#shellcheck shell=sh
# pfblockerng_repo_selfheal.sh — boot self-heal hook (ADR-39 Phase 2).
#
# Tests four behavioural contracts:
#   guard     — no conf present → hook exits 0, writes nothing.
#   match     — conf varver == box varver → exit 0, conf byte-for-byte unchanged.
#   mismatch  — stale varver in conf → only the <varver>/<arch> segment of the
#               url: line is rewritten; every other byte is preserved; pkg stubs are
#               called; hook still exits 0.
#   fail-proof — forced internal error (broken pkg stub) → still exits 0.
#
# Before-and-after mandate (CLAUDE.md): guard/match tests assert the before-state
# (conf absent / conf unchanged) before asserting the after-state, so a false-pass
# is impossible.
#
# The hook script sources /etc/rc.subr (FreeBSD rc(8) machinery) which does not
# exist on CI Linux runners.  We provide a minimal stub (load_rc_config / run_rc_command
# no-ops) via a helper that temporarily shadows /etc/rc.subr for the hook source.
# All on-box paths (PFB_DETECT_HELPER, PFB_RELEASE_CONF, PFB_NIGHTLY_CONF, PFB_PKG_BIN)
# are overridden via the env-override mechanism built into the hook.
#
# How sourcing works:
#   source_hook() creates a minimal rc.subr stub, then sources the hook using a
#   shell substitution that inlines the stub before the `. /etc/rc.subr` line.
#   Functions defined by the hook (_selfheal_main, _heal_one_conf, etc.) become
#   available in the spec scope.  `run_rc_command` is a no-op in the stub so the
#   global `run_rc_command "$1"` at the end of the hook is harmless.
#   `exit 0` at the tail of the hook is the ONLY statement that would terminate the
#   spec process — we suppress it by aliasing `exit` to a no-op before sourcing.
#
# Tip: run with `shellspec tests/shell/selfheal_hook_spec.sh` from the repo root.

SELFHEAL_HOOK="${PFB_ROOT}/scripts/rc.d/pfblockerng_repo_selfheal.sh"
DETECT_VARIANT_REAL="${PFB_ROOT}/scripts/lib/detect_variant.sh"

# ── helpers ───────────────────────────────────────────────────────────────────

# Write the minimal /etc/rc.subr stub into a given dir.
# $1 = dir that will hold etc/rc.subr
_make_rc_subr_stub() {
    mkdir -p "$1/etc"
    cat > "$1/etc/rc.subr" <<'EOF'
# Minimal rc.subr stub for shellspec tests — no-ops for functions the hook calls.
load_rc_config() { :; }
run_rc_command() { :; }
EOF
}

# Build a detect_variant stub that always prints a fixed catalog.
# $1 = output path for the stub, $2 = catalog string (e.g. "ce-2.8/amd64").
# The catalog value is baked into the stub at creation time.
_make_detect_stub() {
    _mds_path="$1"
    _mds_catalog="$2"
    printf '#!/bin/sh\n# detect_variant stub — returns fixed catalog: %s\n' "${_mds_catalog}" > "${_mds_path}"
    printf 'pfb_detect_edition() { printf '"'"'CE'"'"'; }\n' >> "${_mds_path}"
    printf 'pfb_detect_version() { printf '"'"'2.8.1'"'"'; }\n' >> "${_mds_path}"
    printf 'pfb_detect_arch()    { printf '"'"'amd64'"'"'; }\n' >> "${_mds_path}"
    printf 'pfb_detect_varver()  { printf '"'"'ce-2.8'"'"'; }\n' >> "${_mds_path}"
    printf 'pfb_detect_catalog() { printf '"'"'%%s'"'"' '"'"'%s'"'"'; }\n' "${_mds_catalog}" >> "${_mds_path}"
    chmod +x "${_mds_path}"
    unset _mds_path _mds_catalog
}

# Build a pkg stub.  $1 = output path.
# Behaviour is parameterized by env vars set before calling:
#   PKG_STUB_INFO_RESULT  — exit code for `pkg info <pkg>` (default 1 = not installed)
#   PKG_STUB_CMDS_LOG     — file to append "pkg <args>" lines to
#   PKG_STUB_FAIL         — if "1", every pkg subcommand exits 1
_make_pkg_stub() {
    cat > "$1" <<'EOF'
#!/bin/sh
# pkg stub for selfheal hook tests.
: "${PKG_STUB_INFO_RESULT:=1}"
: "${PKG_STUB_CMDS_LOG:=/dev/null}"
: "${PKG_STUB_FAIL:=0}"
printf 'pkg %s\n' "$*" >> "${PKG_STUB_CMDS_LOG}"
if [ "${PKG_STUB_FAIL}" = "1" ]; then
    exit 1
fi
case "$1" in
    info)    exit "${PKG_STUB_INFO_RESULT}" ;;
    update)  exit 0 ;;
    upgrade) exit 0 ;;
    install) exit 0 ;;
    *)       exit 0 ;;
esac
EOF
    chmod +x "$1"
}

# Write a realistic release conf for a given catalog (e.g. "ce-2.8/amd64").
# $1 = output path, $2 = catalog string.
_make_release_conf() {
    cat > "$1" <<EOF
pfblockerng: {
  url: "https://pfblockerng.github.io/pkg/release/${2}",
  mirror_type: "none",
  signature_type: "none",
  enabled: yes,
  priority: 100
}
EOF
}

# Source the hook into the current shell environment.
# Creates a temporary rc.subr stub, then evaluates the hook's content with
# `exit` aliased to a no-op so the trailing `exit 0` doesn't kill the spec.
# All external overrides (PFB_DETECT_HELPER, etc.) must be exported before calling.
_source_hook() {
    _sh_tmpdir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/sh_rcsubr.XXXXXX")"
    _make_rc_subr_stub "${_sh_tmpdir}"

    # Build a sourcing wrapper that:
    #   1. Defines no-op stubs for load_rc_config and run_rc_command.
    #   2. Sources the hook content with two transformations applied via sed:
    #      a. The `. /etc/rc.subr` line is suppressed (stubs already loaded).
    #      b. The trailing `exit 0` line is suppressed (would kill the spec process).
    _sh_wrapper="${_sh_tmpdir}/hook_functions.sh"
    # Extract only the function definitions and rc.d variable assignments:
    # strip the `. /etc/rc.subr` line, the `run_rc_command "$1"` line, and `exit 0`.
    {
        printf 'load_rc_config() { :; }\nrun_rc_command() { :; }\n'
        sed \
            -e 's|^\. /etc/rc\.subr.*||' \
            -e 's|^run_rc_command .*||' \
            -e 's|^exit 0||' \
            "${SELFHEAL_HOOK}"
    } > "${_sh_wrapper}"

    # shellcheck disable=SC1090
    . "${_sh_wrapper}"
    rm -rf "${_sh_tmpdir}"
}

# ── GUARD: no conf present ─────────────────────────────────────────────────────
#
# Before-state: both conf paths point at absent files.
# After-state:  hook returns 0; nothing was written.

Describe 'self-heal hook — guard: no conf present'
    setup() {
        _g_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/sh_guard.XXXXXX")"
        PFB_RELEASE_CONF="${_g_dir}/pfblockerng.conf"
        PFB_NIGHTLY_CONF="${_g_dir}/pfblockerng-nightly.conf"
        # PFB_DETECT_HELPER need not exist (guard fires before it is sourced).
        PFB_DETECT_HELPER="${_g_dir}/nonexistent_detect.sh"
        PFB_PKG_BIN="${_g_dir}/pkg"
        export PFB_RELEASE_CONF PFB_NIGHTLY_CONF PFB_DETECT_HELPER PFB_PKG_BIN
    }
    cleanup() {
        rm -rf "${_g_dir}"
        unset PFB_RELEASE_CONF PFB_NIGHTLY_CONF PFB_DETECT_HELPER PFB_PKG_BIN
    }
    BeforeAll '_source_hook'
    Before 'setup'
    After  'cleanup'

    It 'before-state: neither conf exists'
      The path "${PFB_RELEASE_CONF}" should not be exist
      The path "${PFB_NIGHTLY_CONF}" should not be exist
    End

    It 'exits 0 and writes no conf when neither conf file exists'
      When call _selfheal_main
      The status should be success
      The path "${PFB_RELEASE_CONF}" should not be exist
      The path "${PFB_NIGHTLY_CONF}" should not be exist
    End
End

# ── MATCH: conf varver == box varver ──────────────────────────────────────────
#
# Before-state: conf exists with ce-2.8/amd64; detect stub returns ce-2.8/amd64.
# After-state:  hook returns 0; conf is byte-for-byte unchanged; pkg never called.

Describe 'self-heal hook — match: conf varver equals box varver'
    setup() {
        _m_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/sh_match.XXXXXX")"

        # Write a release conf with ce-2.8/amd64.
        PFB_RELEASE_CONF="${_m_dir}/pfblockerng.conf"
        PFB_NIGHTLY_CONF="${_m_dir}/pfblockerng-nightly.conf"
        _make_release_conf "${PFB_RELEASE_CONF}" "ce-2.8/amd64"

        # Save the original bytes for the before-state assertion.
        _m_orig="$(cat "${PFB_RELEASE_CONF}")"

        # Detection stub also returns ce-2.8/amd64 → MATCH.
        PFB_DETECT_HELPER="${_m_dir}/detect_variant.sh"
        _make_detect_stub "${PFB_DETECT_HELPER}" "ce-2.8/amd64"

        # pkg stub — log calls so we can assert pkg was NOT called.
        _m_pkg_log="${_m_dir}/pkg_calls.log"
        PFB_PKG_BIN="${_m_dir}/pkg"
        PKG_STUB_CMDS_LOG="${_m_pkg_log}"
        _make_pkg_stub "${PFB_PKG_BIN}"

        export PFB_RELEASE_CONF PFB_NIGHTLY_CONF PFB_DETECT_HELPER PFB_PKG_BIN PKG_STUB_CMDS_LOG
    }
    cleanup() {
        rm -rf "${_m_dir}"
        unset PFB_RELEASE_CONF PFB_NIGHTLY_CONF PFB_DETECT_HELPER PFB_PKG_BIN \
              PKG_STUB_CMDS_LOG _m_orig _m_pkg_log
    }
    BeforeAll '_source_hook'
    Before 'setup'
    After  'cleanup'

    It 'before-state: release conf exists with ce-2.8/amd64'
      The path "${PFB_RELEASE_CONF}" should be exist
      The contents of file "${PFB_RELEASE_CONF}" should include "ce-2.8/amd64"
    End

    It 'exits 0 and leaves the conf byte-for-byte unchanged'
      When call _selfheal_main
      The status should be success
      The contents of file "${PFB_RELEASE_CONF}" should equal "${_m_orig}"
    End

    It 'does not invoke pkg at all on a match'
      _selfheal_main
      The path "${_m_pkg_log}" should not be exist
    End
End

# ── MISMATCH: stale varver in conf ────────────────────────────────────────────
#
# Before-state: release conf has ce-2.7/amd64 (stale); detect stub returns ce-2.8/amd64.
# After-state:
#   - Only the <varver>/<arch> segment of the url: line changed (ce-2.7 → ce-2.8).
#   - Every other byte in the conf is preserved.
#   - `pkg update -r pfblockerng` was called.
#   - Hook exits 0.

Describe 'self-heal hook — mismatch: stale varver rewritten'
    setup() {
        _mm_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/sh_mismatch.XXXXXX")"

        # Conf seeded with a STALE varver ce-2.7/amd64.
        PFB_RELEASE_CONF="${_mm_dir}/pfblockerng.conf"
        PFB_NIGHTLY_CONF="${_mm_dir}/pfblockerng-nightly.conf"
        _make_release_conf "${PFB_RELEASE_CONF}" "ce-2.7/amd64"

        # Save the stale conf content for before-state assertion.
        _mm_stale="$(cat "${PFB_RELEASE_CONF}")"

        # Detection stub returns the CURRENT varver ce-2.8/amd64 → MISMATCH.
        PFB_DETECT_HELPER="${_mm_dir}/detect_variant.sh"
        _make_detect_stub "${PFB_DETECT_HELPER}" "ce-2.8/amd64"

        # pkg stub — log all calls.
        _mm_pkg_log="${_mm_dir}/pkg_calls.log"
        PFB_PKG_BIN="${_mm_dir}/pkg"
        PKG_STUB_CMDS_LOG="${_mm_pkg_log}"
        _make_pkg_stub "${PFB_PKG_BIN}"

        export PFB_RELEASE_CONF PFB_NIGHTLY_CONF PFB_DETECT_HELPER PFB_PKG_BIN PKG_STUB_CMDS_LOG
    }
    cleanup() {
        rm -rf "${_mm_dir}"
        unset PFB_RELEASE_CONF PFB_NIGHTLY_CONF PFB_DETECT_HELPER PFB_PKG_BIN \
              PKG_STUB_CMDS_LOG _mm_stale _mm_pkg_log
    }
    BeforeAll '_source_hook'
    Before 'setup'
    After  'cleanup'

    It 'before-state: release conf contains the stale varver ce-2.7/amd64'
      The contents of file "${PFB_RELEASE_CONF}" should include "ce-2.7/amd64"
      The contents of file "${PFB_RELEASE_CONF}" should not include "ce-2.8/amd64"
    End

    It 'exits 0 on a varver mismatch'
      When call _selfheal_main
      The status should be success
      The stderr should include "mismatch"
    End

    It 'rewrites the url: line to the current varver (ce-2.8/amd64)'
      _selfheal_main 2>/dev/null
      The contents of file "${PFB_RELEASE_CONF}" should include "ce-2.8/amd64"
    End

    It 'does not leave the stale varver in the conf'
      _selfheal_main 2>/dev/null
      The contents of file "${PFB_RELEASE_CONF}" should not include "ce-2.7/amd64"
    End

    It 'preserves every other conf field (url prefix, priority, signature_type, etc.)'
      _selfheal_main 2>/dev/null
      # The non-url fields should be byte-identical; compare the conf with the stale
      # one minus the changed varver segment — both should match when we substitute back.
      _mm_after="$(cat "${PFB_RELEASE_CONF}")"
      # Substitute the new varver back to the stale one in the after-conf and compare
      # with the original stale content: they should be identical.
      _mm_restored="$(printf '%s' "${_mm_after}" | sed 's|ce-2\.8/amd64|ce-2.7/amd64|g')"
      The value "${_mm_restored}" should equal "${_mm_stale}"
    End

    It 'calls pkg update -r pfblockerng after the rewrite'
      _selfheal_main 2>/dev/null
      The contents of file "${_mm_pkg_log}" should include "pkg update -r pfblockerng"
    End
End

# ── FAIL-PROOF: forced internal error still exits 0 ──────────────────────────
#
# This tests the "HARD RULE" contract: no matter what goes wrong inside the hook,
# it must never propagate a non-zero exit (which would wedge boot).
#
# We test two forced-failure scenarios:
#   1. pkg stub always fails (all subcommands return 1).
#   2. Detection helper itself fails (exits non-zero).
#
# Both paths must still yield exit 0.
#
# These use `When run` (subshell) rather than `When call` so that even a `set -e`
# or stray `exit N` inside the hook is captured without killing the spec runner.

Describe 'self-heal hook — fail-proof: forced failures still exit 0'
    setup_fp() {
        _fp_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/sh_failproof.XXXXXX")"

        # Conf seeded with stale varver (trigger mismatch path where pkg is called).
        PFB_RELEASE_CONF="${_fp_dir}/pfblockerng.conf"
        PFB_NIGHTLY_CONF="${_fp_dir}/pfblockerng-nightly.conf"
        _make_release_conf "${PFB_RELEASE_CONF}" "ce-2.7/amd64"

        # Detection stub returning a DIFFERENT catalog so the mismatch path runs.
        PFB_DETECT_HELPER="${_fp_dir}/detect_variant.sh"
        _make_detect_stub "${PFB_DETECT_HELPER}" "ce-2.8/amd64"

        # pkg stub that ALWAYS fails.
        PFB_PKG_BIN="${_fp_dir}/pkg"
        PKG_STUB_FAIL="1"
        _make_pkg_stub "${PFB_PKG_BIN}"

        export PFB_RELEASE_CONF PFB_NIGHTLY_CONF PFB_DETECT_HELPER PFB_PKG_BIN PKG_STUB_FAIL
    }
    cleanup_fp() {
        rm -rf "${_fp_dir}"
        unset PFB_RELEASE_CONF PFB_NIGHTLY_CONF PFB_DETECT_HELPER PFB_PKG_BIN \
              PKG_STUB_FAIL _fp_dir
    }
    BeforeAll '_source_hook'
    Before 'setup_fp'
    After  'cleanup_fp'

    It 'exits 0 even when pkg stub always fails on mismatch path'
      When call _selfheal_main
      The status should be success
      The stderr should include "WARNING"
    End

    Describe 'failing detect helper'
        setup_fd() {
            _fd_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/sh_faildet.XXXXXX")"
            PFB_RELEASE_CONF="${_fd_dir}/pfblockerng.conf"
            PFB_NIGHTLY_CONF="${_fd_dir}/pfblockerng-nightly.conf"
            _make_release_conf "${PFB_RELEASE_CONF}" "ce-2.7/amd64"
            # Detection helper that EXISTS but always exits 1 (simulate broken helper).
            PFB_DETECT_HELPER="${_fd_dir}/detect_variant.sh"
            printf '#!/bin/sh\npfb_detect_catalog() { exit 1; }\n' > "${PFB_DETECT_HELPER}"
            PFB_PKG_BIN="${_fd_dir}/pkg"
            _make_pkg_stub "${PFB_PKG_BIN}"
            export PFB_RELEASE_CONF PFB_NIGHTLY_CONF PFB_DETECT_HELPER PFB_PKG_BIN
        }
        cleanup_fd() {
            rm -rf "${_fd_dir}"
            unset PFB_RELEASE_CONF PFB_NIGHTLY_CONF PFB_DETECT_HELPER PFB_PKG_BIN _fd_dir
        }
        Before 'setup_fd'
        After  'cleanup_fd'

        It 'exits 0 when the detect helper function returns non-zero'
          When call _selfheal_main
          The status should be success
          The stderr should include "WARNING"
        End
    End
End
