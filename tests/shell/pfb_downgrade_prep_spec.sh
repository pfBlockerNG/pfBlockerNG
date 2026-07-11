#shellcheck shell=sh
# pfb-downgrade-prep.sh spec — the devops downgrade-preparation tool.
#
# Covers the file-move logic (restore user list scripts to the package root) and the
# shipped-name gate, plus the tick-cron removal's OUTPUT PARSING via a fake pfSsh.php.
# The fake ignores the piped PHP body (just echoes a fixed marker), so it exercises the
# marker contract only -- not the real cron-tick + legacy-tick two-needle removal
# (issue #1204), which install_cron_job() effect is exercised on a live VM by
# tests/smoke/test_downgrade_prepare.py (this suite runs off-appliance, no pfSsh.php).
#
# The tool is sourced as a library: PFB_DOWNGRADE_PREP_SOURCED=1 makes its source guard
# define the functions and skip main(). PFB_PKGDIR / PFB_LISTDIR / PFB_PFSSH are
# env-overridable, so every example points them at a private temp sandbox.

Describe 'pfb-downgrade-prep.sh'
  # shellcheck disable=SC2034  # PFB_DOWNGRADE_PREP_SOURCED is read by the tool's source guard
  BeforeAll 'PFB_DOWNGRADE_PREP_SOURCED=1; . "${PFB_ROOT}/scripts/pfb-downgrade-prep.sh"'

  setup() {
    PFBDG_WORK="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pfbdg.XXXXXX")"
    PFB_PKGDIR="${PFBDG_WORK}/pkg"
    PFB_LISTDIR="${PFB_PKGDIR}/list_scripts"
    mkdir -p "${PFB_LISTDIR}"
  }
  cleanup() { rm -rf "${PFBDG_WORK}"; }
  BeforeEach 'setup'
  AfterEach 'cleanup'

  # A fake pfSsh.php: consumes stdin (the PHP snippet) and prints a fixed marker.
  # Exercises the tick-cron parse/aggregation branches without a live box.
  fake_pfssh() {
    _fp="${PFBDG_WORK}/pfssh_$1"
    cat > "${_fp}" <<EOF
#!/bin/sh
cat >/dev/null
echo "$2"
EOF
    chmod +x "${_fp}"
    echo "${_fp}"
  }

  # Prepend a fake \`id\` on PATH that prints $1 as the uid, so the tool's root guard
  # can be driven deterministically on a non-root CI host.
  shim_id() {
    _bin="${PFBDG_WORK}/bin"
    mkdir -p "${_bin}"
    printf '#!/bin/sh\necho %s\n' "$1" > "${_bin}/id"
    chmod +x "${_bin}/id"
    PATH="${_bin}:${PATH}"
  }

  Describe 'pfb_is_shipped_list_script (shipped-name gate)'
    It 'treats an AWS region wrapper as shipped'
      When call pfb_is_shipped_list_script "${PFB_LISTDIR}/ip_pre_AWS_US.sh"
      The status should be success
    End

    It 'treats aws_region_prefixes.sh as shipped'
      When call pfb_is_shipped_list_script "${PFB_LISTDIR}/aws_region_prefixes.sh"
      The status should be success
    End

    It 'treats a user-authored script as not shipped'
      When call pfb_is_shipped_list_script "${PFB_LISTDIR}/ip_pre_custom.sh"
      The status should be failure
    End
  End

  Describe 'pfb_restore_list_scripts'
    It 'moves a user script from list_scripts/ back to the package root'
      touch "${PFB_LISTDIR}/ip_pre_custom.sh"
      When call pfb_restore_list_scripts
      The output should equal 1
      The path "${PFB_PKGDIR}/ip_pre_custom.sh" should be file
      The path "${PFB_LISTDIR}/ip_pre_custom.sh" should not be exist
    End

    It 'restores .sh and .py user scripts across every stage'
      touch "${PFB_LISTDIR}/ip_pre_a.sh" "${PFB_LISTDIR}/dnsbl_post_b.py"
      When call pfb_restore_list_scripts
      The output should equal 2
      The path "${PFB_PKGDIR}/ip_pre_a.sh" should be file
      The path "${PFB_PKGDIR}/dnsbl_post_b.py" should be file
    End

    It 'leaves shipped AWS wrappers in list_scripts/ (never orphaned to the root)'
      touch "${PFB_LISTDIR}/ip_pre_AWS_US.sh" "${PFB_LISTDIR}/aws_region_prefixes.sh"
      When call pfb_restore_list_scripts
      The output should equal 0
      The path "${PFB_LISTDIR}/ip_pre_AWS_US.sh" should be file
      The path "${PFB_PKGDIR}/ip_pre_AWS_US.sh" should not be exist
      The path "${PFB_LISTDIR}/aws_region_prefixes.sh" should be file
    End

    It 'ignores files that are not list scripts'
      touch "${PFB_LISTDIR}/readme.txt"
      When call pfb_restore_list_scripts
      The output should equal 0
      The path "${PFB_LISTDIR}/readme.txt" should be file
    End

    It 'never clobbers a same-named file already at the root'
      printf ROOT > "${PFB_PKGDIR}/ip_post_dup.sh"
      printf LIST > "${PFB_LISTDIR}/ip_post_dup.sh"
      When call pfb_restore_list_scripts
      The output should equal 0
      The contents of file "${PFB_PKGDIR}/ip_post_dup.sh" should equal ROOT
      The path "${PFB_LISTDIR}/ip_post_dup.sh" should be file
      The stderr should include 'not overwriting'
    End

    It 'is idempotent — a second run restores nothing'
      touch "${PFB_LISTDIR}/ip_pre_custom.sh"
      pfb_restore_list_scripts >/dev/null   # first run relocates it
      When call pfb_restore_list_scripts    # second run
      The output should equal 0
      The path "${PFB_PKGDIR}/ip_pre_custom.sh" should be file
    End

    It 'is a no-op when list_scripts/ is absent'
      rm -rf "${PFB_LISTDIR}"
      When call pfb_restore_list_scripts
      The output should equal 0
    End
  End

  Describe 'pfb_remove_tick_cron (output parsing)'
    It 'reports "removed" when pfSsh.php signals removal'
      PFB_PFSSH="$(fake_pfssh removed PFB_TICK_REMOVED)"
      When call pfb_remove_tick_cron
      The output should equal removed
      The status should be success
    End

    It 'reports "absent" when there is no tick cron'
      PFB_PFSSH="$(fake_pfssh absent PFB_TICK_ABSENT)"
      When call pfb_remove_tick_cron
      The output should equal absent
      The status should be success
    End

    It 'fails when the pfSsh.php output is unrecognised'
      PFB_PFSSH="$(fake_pfssh junk SOMETHING_ELSE)"
      When call pfb_remove_tick_cron
      The status should be failure
      The stderr should include 'unexpected pfSsh.php output'
    End

    It 'fails cleanly when pfSsh.php is missing'
      PFB_PFSSH="${PFBDG_WORK}/nonexistent-pfSsh.php"
      When call pfb_remove_tick_cron
      The status should be failure
      The stderr should include 'pfSsh.php not found'
    End
  End

  Describe 'pfb_downgrade_prep_main (orchestration + exit status)'
    It 'refuses to run as non-root'
      shim_id 1000
      When call pfb_downgrade_prep_main
      The status should be failure
      The stderr should include 'must run as root'
    End

    It 'succeeds (exit 0) when both reversals succeed and reports them'
      shim_id 0
      touch "${PFB_LISTDIR}/ip_pre_custom.sh"
      PFB_PFSSH="$(fake_pfssh ok PFB_TICK_REMOVED)"
      When call pfb_downgrade_prep_main
      The status should be success
      The output should include 'restored to package root: 1'
      The output should include 'tick cron entry: removed'
      The path "${PFB_PKGDIR}/ip_pre_custom.sh" should be file
    End

    It 'fails (non-zero exit) when the tick-cron removal fails — so a chained downgrade stops'
      shim_id 0
      touch "${PFB_LISTDIR}/ip_pre_custom.sh"
      PFB_PFSSH="${PFBDG_WORK}/nonexistent-pfSsh.php"   # pfSsh.php missing -> tick removal fails
      When call pfb_downgrade_prep_main
      The status should be failure
      The output should include 'tick cron entry: ERROR'
      The stderr should include 'pfSsh.php not found'
      # The script restore still happened; only the exit status signals the partial failure.
      The path "${PFB_PKGDIR}/ip_pre_custom.sh" should be file
    End
  End
End
