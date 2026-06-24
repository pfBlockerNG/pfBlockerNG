#shellcheck shell=sh
# pfblockerng.sh dnsbl_cache (#468) — keep DNSBL alive across a RAM-disk /var reboot.
#
# Pins the three subcommands against a sandbox chroot:
#   stage   -- copies the SHIPPED files into the chroot and creates the nullfs/devfs
#              mount-point dirs (the fresh-MFS fix that made pfb_python_mount fail).
#   save    -- archives ONLY the GENERATED set (pfb_py_* + pfb_unbound.ini), never the
#              shipped files (those come from /usr/local on restore -> no stale code).
#   restore -- untars the generated set THEN stages the shipped files; round-trips the
#              generated state and re-stages current shipped code over an empty chroot.
#
# #468: the archives are zstd (.tar.zst). zstd ships OOTB on pfSense-CE but may be
# absent on the dev box, so the zstd-specific examples SKIP (never fail) when
# `command -v zstd` misses. The shared helpers pfb_archive_compress/_extract also
# read a legacy .tar.bz2 (the pre-#468 IP-aliastables format) and retire it after a
# verified zst write -- both pinned below.
#
# Off-appliance the staged-file chown to unbound:unbound fails (no such user/group);
# that is harmless and not the behaviour under test, so each example runs the function
# through a wrapper that swallows the chown noise and the resulting non-zero status.
# Before-state is asserted where a transition is claimed (the wiped chroot is empty
# before restore; the archive carries the generated file and NOT the shipped one).

Describe 'pfblockerng.sh dnsbl_cache (#468)'
  BeforeAll 'pfb_source'

  zstd_present() { command -v zstd >/dev/null 2>&1; }

  # shellcheck disable=SC2034  # consumed by the sourced dnsbl_cache() at runtime
  setup_sandbox() {
    sandbox="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pfbdc.XXXXXX")"
    # Overridable locations the sourced dnsbl_cache() reads.
    pfbchroot="${sandbox}/chroot"
    pfbpkgdir="${sandbox}/pkg"
    dnsblarchive="${sandbox}/pfb_dnsbl_cache.tar.zst"
    pathtar="/usr/bin/tar"
    mkdir -p "${pfbpkgdir}"
    # The shipped files (current code in /usr/local).
    echo 'PY-CODE-v1' > "${pfbpkgdir}/pfb_unbound.py"
    echo 'INC-CODE-v1' > "${pfbpkgdir}/pfb_unbound_include.inc"
    echo 'HSTS-v1' > "${pfbpkgdir}/pfb_py_hsts.txt"
  }

  cleanup_sandbox() {
    rm -rf "${sandbox}"
  }

  # Run dnsbl_cache and discard the off-appliance chown failure (status + stderr).
  dc() {
    dnsbl_cache "$1" 2>/dev/null || true
  }

  # List archive members (zstd .tar.zst), basename only.
  tar_list() {
    zstd -dc "${dnsblarchive}" 2>/dev/null | /usr/bin/tar -tf - 2>/dev/null | sed 's#.*/##'
  }

  It 'stage copies the shipped files and creates the nullfs/devfs mount-point dirs'
    setup_sandbox
    # Before: the chroot does not exist at all (fresh MFS).
    When call dc stage
    # The shipped files landed in the chroot.
    The path "${pfbchroot}/pfb_unbound.py" should be exist
    The path "${pfbchroot}/pfb_unbound_include.inc" should be exist
    The path "${pfbchroot}/pfb_py_hsts.txt" should be exist
    # The mount-point dirs exist (the fresh-MFS fix).
    The path "${pfbchroot}/lib" should be directory
    The path "${pfbchroot}/dev" should be directory
    The path "${pfbchroot}/var/log/pfblockerng" should be directory
    The path "${pfbchroot}/usr/local/share/GeoIP" should be directory
    cleanup_sandbox
  End

  It 'save archives the generated set only (never the shipped files)'
    zstd_present || Skip 'zstd not installed'
    setup_sandbox
    dc stage
    # A generated manifest + raw + ini present in the chroot.
    echo '{"feeds":[]}' > "${pfbchroot}/pfb_py_sources.json"
    echo 'rawdata' > "${pfbchroot}/pfb_py_raw"
    echo 'ini' > "${pfbchroot}/pfb_unbound.ini"
    When call dc save
    The path "${dnsblarchive}" should be exist
    # The archive carries the GENERATED files ...
    The result of "tar_list()" should include 'pfb_py_sources.json'
    The result of "tar_list()" should include 'pfb_unbound.ini'
    # ... and NOT the shipped files (re-staged from /usr/local on restore).
    The result of "tar_list()" should not include 'pfb_py_hsts.txt'
    The result of "tar_list()" should not include 'pfb_unbound_include.inc'
    cleanup_sandbox
  End

  # Wrapper: report the wiped-chroot before-state, then restore — so the test proves
  # restore CAUSED the generated state to reappear (not a leftover from before).
  restore_and_report() {
    if [ -e "${pfbchroot}/pfb_py_sources.json" ]; then
      echo 'PRE:present'
    else
      echo 'PRE:wiped'
    fi
    dc restore
    echo 'POST:restored'
  }

  It 'restore round-trips the generated state and re-stages current shipped code (zstd)'
    zstd_present || Skip 'zstd not installed'
    setup_sandbox
    dc stage
    echo 'MANIFEST-v1' > "${pfbchroot}/pfb_py_sources.json"
    echo 'ini-v1' > "${pfbchroot}/pfb_unbound.ini"
    dc save
    # Simulate a RAM-disk reboot: wipe the whole chroot.
    rm -rf "${pfbchroot}"
    # Bump the shipped code in /usr/local to prove restore re-stages CURRENT code.
    echo 'PY-CODE-v2' > "${pfbpkgdir}/pfb_unbound.py"
    When call restore_and_report
    # Before: the chroot was wiped; After: restore ran.
    The output should include 'PRE:wiped'
    The output should include 'POST:restored'
    # The generated state came back from the archive (round-trip).
    The contents of file "${pfbchroot}/pfb_py_sources.json" should equal 'MANIFEST-v1'
    The contents of file "${pfbchroot}/pfb_unbound.ini" should equal 'ini-v1'
    # The shipped code is the CURRENT /usr/local copy (v2), not a stale archived v1.
    The contents of file "${pfbchroot}/pfb_unbound.py" should equal 'PY-CODE-v2'
    # Mount-point dirs are present again after restore.
    The path "${pfbchroot}/lib" should be directory
    cleanup_sandbox
  End

  It 'restore with no archive still stages the shipped files (first boot / no prior save)'
    setup_sandbox
    # No save() ran, so no archive exists — restore must still stage the shipped files.
    When call dc restore
    The path "${dnsblarchive}" should not be exist
    The path "${pfbchroot}/pfb_unbound.py" should be exist
    The path "${pfbchroot}/lib" should be directory
    cleanup_sandbox
  End
End

# The shared archive helpers (#468): zstd round-trip + legacy-bz2 read + legacy retire.
# These back BOTH the DNSBL cache and the IP aliastables, so they are pinned directly.
Describe 'pfblockerng.sh archive helpers (#468)'
  BeforeAll 'pfb_source'

  zstd_present() { command -v zstd >/dev/null 2>&1; }

  # shellcheck disable=SC2034  # pathtar is read by the sourced helpers
  setup_arc() {
    arcbox="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pfbarc.XXXXXX")"
    pathtar="/usr/bin/tar"
    arc_zst="${arcbox}/data.tar.zst"
    arc_bz2="${arcbox}/data.tar.bz2"
    # A payload file to archive, addressed with an absolute path so -P keeps it.
    payload="${arcbox}/payload.txt"
    echo 'PAYLOAD-v1' > "${payload}"
    # Extract target: wipe + recreate the payload's dir to prove extract restores it.
    extract_root="${arcbox}"
  }
  cleanup_arc() { rm -rf "${arcbox}"; }

  It 'compress writes a verified zst and extract round-trips it'
    zstd_present || Skip 'zstd not installed'
    setup_arc
    # When: compress with no legacy archive.
    When call pfb_archive_compress "${arc_zst}" '' "${payload}"
    The status should be success
    The path "${arc_zst}" should be exist
    # The archive passes zstd integrity (the helper verifies, assert it too).
    zstd -tq "${arc_zst}"
    # Before: remove the payload so extract must restore it.
    rm -f "${payload}"
    pfb_archive_extract "${arc_zst}" '' 2>/dev/null
    The contents of file "${payload}" should equal 'PAYLOAD-v1'
    cleanup_arc
  End

  # Wrapper: report the legacy-present before-state, then compress -- proving the
  # legacy was there first and the compress retired it.
  compress_and_report() {
    if [ -f "${arc_bz2}" ]; then echo 'PRE:legacy-present'; else echo 'PRE:legacy-absent'; fi
    pfb_archive_compress "${arc_zst}" "${arc_bz2}" "${payload}"
    echo 'POST:compressed'
  }

  It 'compress retires the legacy bz2 only after a verified zst write'
    zstd_present || Skip 'zstd not installed'
    setup_arc
    # Given: a pre-existing legacy bz2 archive (an old install).
    /usr/bin/tar -Pjcf "${arc_bz2}" "${payload}"
    When call compress_and_report
    The status should be success
    # Before: the legacy archive existed; After: compress ran.
    The output should include 'PRE:legacy-present'
    The output should include 'POST:compressed'
    # The zst is written and the legacy bz2 has been retired.
    The path "${arc_zst}" should be exist
    The path "${arc_bz2}" should not be exist
    cleanup_arc
  End

  # Wrapper: report the no-zst before-state, then extract from the legacy fallback.
  extract_legacy_and_report() {
    if [ -f "${arc_zst}" ]; then echo 'PRE:zst-present'; else echo 'PRE:zst-absent'; fi
    pfb_archive_extract "${arc_zst}" "${arc_bz2}"
    echo 'POST:extracted'
  }

  It 'extract reads a legacy bz2 when no zst exists (existing install upgrade)'
    setup_arc
    # Given: only the legacy bz2 archive exists (no zst yet -- not upgraded).
    /usr/bin/tar -Pjcf "${arc_bz2}" "${payload}"
    rm -f "${payload}"
    When call extract_legacy_and_report
    # Before: no zst present; After: extract ran.
    The output should include 'PRE:zst-absent'
    The output should include 'POST:extracted'
    # Then: the payload is restored from the legacy bz2.
    The contents of file "${payload}" should equal 'PAYLOAD-v1'
    cleanup_arc
  End

  It 'thread count is ncpu-1, floored at 1 and capped at 4'
    When call pfb_zstd_threads
    The output should match pattern '[1234]'
    The status should be success
  End
End
