#shellcheck shell=sh
# detect_variant.sh — on-box variant detection helper (ADR-39 Phase 1).
#
# Pins both edition branches (CE = absent globals.plus.inc, Plus = present) and
# the version→varver mapping against the SAME cases as test_catalog_name_from_version()
# in tests/test_build_repo_portable.py.  Also asserts the arch-leaf parse from a
# stubbed `pkg config abi` output.
#
# The helper exposes overridable paths (PFB_GLOBALS_PLUS_INC, PFB_VERSION_FILE,
# PFB_PKG_CMD) so every syscall is mockable without a real box.

DETECT_VARIANT="${PFB_ROOT}/scripts/lib/detect_variant.sh"

# Source the helper into the current shell; all functions become available.
source_helper() {
    # shellcheck disable=SC1090
    . "${DETECT_VARIANT}"
}

# ── pfb_detect_edition — both edition branches ───────────────────────────────
#
# The before-and-after mandate (CLAUDE.md test-coverage): we assert the CE outcome
# (absent file) first, then the Plus outcome (present file), proving it is a real branch
# and not an always-one-edition path.

Describe 'pfb_detect_edition'
  BeforeAll 'source_helper'

  Describe 'CE branch — globals.plus.inc ABSENT'
    setup() {
        _ce_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/dvce.XXXXXX")"
        # Point the helper at a path that does NOT exist yet.
        PFB_GLOBALS_PLUS_INC="${_ce_dir}/globals.plus.inc"
        export PFB_GLOBALS_PLUS_INC
    }
    cleanup() {
        rm -rf "${_ce_dir}"
        unset PFB_GLOBALS_PLUS_INC
    }
    Before 'setup'
    After  'cleanup'

    It 'prints CE when globals.plus.inc is absent'
      When call pfb_detect_edition
      The status should be success
      The output should equal "CE"
    End
  End

  Describe 'Plus branch — globals.plus.inc PRESENT'
    setup() {
        _plus_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/dvplus.XXXXXX")"
        PFB_GLOBALS_PLUS_INC="${_plus_dir}/globals.plus.inc"
        # Create the file so the helper sees it.
        touch "${PFB_GLOBALS_PLUS_INC}"
        export PFB_GLOBALS_PLUS_INC
    }
    cleanup() {
        rm -rf "${_plus_dir}"
        unset PFB_GLOBALS_PLUS_INC
    }
    Before 'setup'
    After  'cleanup'

    It 'prints Plus when globals.plus.inc is present'
      When call pfb_detect_edition
      The status should be success
      The output should equal "Plus"
    End
  End

  # Before-and-after test: runs two It blocks sharing the same dir; the first
  # removes the file (CE), the second creates it (Plus) — proving a real branch.
  Describe 'edition flip — absent (CE) then present (Plus)'
    setup() {
        _flip_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/dvflip.XXXXXX")"
        PFB_GLOBALS_PLUS_INC="${_flip_dir}/globals.plus.inc"
        export PFB_GLOBALS_PLUS_INC _flip_dir
        # Ensure the file is absent at start.
        rm -f "${PFB_GLOBALS_PLUS_INC}"
    }
    cleanup() {
        rm -rf "${_flip_dir}"
        unset PFB_GLOBALS_PLUS_INC _flip_dir
    }
    Before 'setup'
    After  'cleanup'

    It 'returns CE when file is absent (before-state)'
      When call pfb_detect_edition
      The status should be success
      The output should equal "CE"
    End

    It 'returns Plus once the file is created (after-state — proves the real branch)'
      touch "${PFB_GLOBALS_PLUS_INC}"
      When call pfb_detect_edition
      The status should be success
      The output should equal "Plus"
    End
  End
End

# ── pfb_detect_version ───────────────────────────────────────────────────────

Describe 'pfb_detect_version'
  BeforeAll 'source_helper'

  setup() {
      _ver_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/dvver.XXXXXX")"
      PFB_VERSION_FILE="${_ver_dir}/version"
      export PFB_VERSION_FILE
  }
  cleanup() {
      rm -rf "${_ver_dir}"
      unset PFB_VERSION_FILE
  }
  Before 'setup'
  After  'cleanup'

  It 'reads the CE version string (2.8.1)'
    printf '2.8.1\n' > "${PFB_VERSION_FILE}"
    When call pfb_detect_version
    The status should be success
    The output should equal "2.8.1"
  End

  It 'reads a Plus version string (26.03.1)'
    printf '26.03.1\n' > "${PFB_VERSION_FILE}"
    When call pfb_detect_version
    The status should be success
    The output should equal "26.03.1"
  End
End

# ── pfb_detect_arch ──────────────────────────────────────────────────────────

Describe 'pfb_detect_arch'
  BeforeAll 'source_helper'

  make_pkg_stub() {
      # $1 = the ABI string to print (e.g. "FreeBSD:15:amd64").
      # Returns the stub path in _arch_stub.
      _arch_stub_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/dvarch.XXXXXX")"
      _arch_stub="${_arch_stub_dir}/pkg"
      _abi_val="$1"
      # Write a script that prints the ABI string verbatim (no newline suffix matters;
      # pfb_detect_arch reads it via a command substitution which strips trailing newlines).
      printf '#!/bin/sh\nprintf '\''%s'\'' "%s"\n' "${_abi_val}" > "${_arch_stub}"
      chmod +x "${_arch_stub}"
  }
  cleanup_arch() {
      rm -rf "${_arch_stub_dir}"
      unset PFB_PKG_CMD _arch_stub_dir _arch_stub
  }

  Describe 'amd64 arch from FreeBSD:15:amd64'
    setup() {
        make_pkg_stub "FreeBSD:15:amd64"
        PFB_PKG_CMD="${_arch_stub}"
        export PFB_PKG_CMD
    }
    Before 'setup'
    After  'cleanup_arch'

    It 'parses amd64 as the arch leaf'
      When call pfb_detect_arch
      The status should be success
      The output should equal "amd64"
    End
  End

  Describe 'aarch64 arch from FreeBSD:16:aarch64'
    setup() {
        make_pkg_stub "FreeBSD:16:aarch64"
        PFB_PKG_CMD="${_arch_stub}"
        export PFB_PKG_CMD
    }
    Before 'setup'
    After  'cleanup_arch'

    It 'parses aarch64 as the arch leaf'
      When call pfb_detect_arch
      The status should be success
      The output should equal "aarch64"
    End
  End
End

# ── pfb_detect_varver — version→varver table ─────────────────────────────────
#
# Case table mirrors test_catalog_name_from_version() in
# tests/test_build_repo_portable.py exactly (same four cases).

Describe 'pfb_detect_varver'
  BeforeAll 'source_helper'

  # Helper: write the version file and set the edition discriminator.
  # Callers must set _vv_ver and _vv_edition before calling this.
  setup_vv() {
      _vv_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/dvvv.XXXXXX")"
      PFB_VERSION_FILE="${_vv_dir}/version"
      printf '%s\n' "${_vv_ver}" > "${PFB_VERSION_FILE}"
      export PFB_VERSION_FILE

      _vv_plus_path="${_vv_dir}/globals.plus.inc"
      case "${_vv_edition}" in
          Plus) touch "${_vv_plus_path}" ;;
      esac
      PFB_GLOBALS_PLUS_INC="${_vv_plus_path}"
      export PFB_GLOBALS_PLUS_INC
  }
  cleanup_vv() {
      rm -rf "${_vv_dir}"
      unset PFB_VERSION_FILE PFB_GLOBALS_PLUS_INC _vv_dir
  }

  Describe '"2.8.1" + CE -> "ce-2.8" (patch stripped)'
    setup() { _vv_ver="2.8.1"; _vv_edition="CE"; setup_vv; }
    Before 'setup'
    After  'cleanup_vv'
    It 'produces ce-2.8'
      When call pfb_detect_varver
      The status should be success
      The output should equal "ce-2.8"
    End
  End

  Describe '"2.8.x" + CE -> "ce-2.8" (non-numeric patch stripped)'
    setup() { _vv_ver="2.8.x"; _vv_edition="CE"; setup_vv; }
    Before 'setup'
    After  'cleanup_vv'
    It 'produces ce-2.8'
      When call pfb_detect_varver
      The status should be success
      The output should equal "ce-2.8"
    End
  End

  Describe '"26.03" + Plus -> "plus-26.03" (no patch component)'
    setup() { _vv_ver="26.03"; _vv_edition="Plus"; setup_vv; }
    Before 'setup'
    After  'cleanup_vv'
    It 'produces plus-26.03'
      When call pfb_detect_varver
      The status should be success
      The output should equal "plus-26.03"
    End
  End

  Describe '"26.03.1" + Plus -> "plus-26.03" (patch stripped)'
    setup() { _vv_ver="26.03.1"; _vv_edition="Plus"; setup_vv; }
    Before 'setup'
    After  'cleanup_vv'
    It 'produces plus-26.03'
      When call pfb_detect_varver
      The status should be success
      The output should equal "plus-26.03"
    End
  End
End

# ── pfb_detect_catalog — full integration ────────────────────────────────────

Describe 'pfb_detect_catalog'
  BeforeAll 'source_helper'

  setup_catalog() {
      _cat_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/dvcat.XXXXXX")"

      # Version file.
      PFB_VERSION_FILE="${_cat_dir}/version"
      printf '%s\n' "${_cat_ver}" > "${PFB_VERSION_FILE}"
      export PFB_VERSION_FILE

      # Edition discriminator.
      _cat_plus_path="${_cat_dir}/globals.plus.inc"
      case "${_cat_edition}" in
          Plus) touch "${_cat_plus_path}" ;;
      esac
      PFB_GLOBALS_PLUS_INC="${_cat_plus_path}"
      export PFB_GLOBALS_PLUS_INC

      # pkg stub: prints "FreeBSD:15:<arch>" with the requested arch leaf.
      _cat_pkg="${_cat_dir}/pkg"
      _abi_str="FreeBSD:15:${_cat_arch}"
      printf '#!/bin/sh\nprintf '\''%s'\'' "%s"\n' "${_abi_str}" > "${_cat_pkg}"
      chmod +x "${_cat_pkg}"
      PFB_PKG_CMD="${_cat_pkg}"
      export PFB_PKG_CMD
  }
  cleanup_catalog() {
      rm -rf "${_cat_dir}"
      unset PFB_VERSION_FILE PFB_GLOBALS_PLUS_INC PFB_PKG_CMD _cat_dir
  }

  Describe 'CE 2.8.1 / amd64 -> "ce-2.8/amd64"'
    setup() { _cat_ver="2.8.1"; _cat_edition="CE"; _cat_arch="amd64"; setup_catalog; }
    Before 'setup'
    After  'cleanup_catalog'
    It 'produces ce-2.8/amd64'
      When call pfb_detect_catalog
      The status should be success
      The output should equal "ce-2.8/amd64"
    End
  End

  Describe 'Plus 26.03.1 / aarch64 -> "plus-26.03/aarch64"'
    setup() { _cat_ver="26.03.1"; _cat_edition="Plus"; _cat_arch="aarch64"; setup_catalog; }
    Before 'setup'
    After  'cleanup_catalog'
    It 'produces plus-26.03/aarch64'
      When call pfb_detect_catalog
      The status should be success
      The output should equal "plus-26.03/aarch64"
    End
  End
End
