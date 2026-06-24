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
# Off-appliance the staged-file chown to unbound:unbound fails (no such user/group);
# that is harmless and not the behaviour under test, so each example runs the function
# through a wrapper that swallows the chown noise and the resulting non-zero status.
# Before-state is asserted where a transition is claimed (the wiped chroot is empty
# before restore; the archive carries the generated file and NOT the shipped one).

Describe 'pfblockerng.sh dnsbl_cache (#468)'
  BeforeAll 'pfb_source'

  # shellcheck disable=SC2034  # consumed by the sourced dnsbl_cache() at runtime
  setup_sandbox() {
    sandbox="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pfbdc.XXXXXX")"
    # Overridable locations the sourced dnsbl_cache() reads.
    pfbchroot="${sandbox}/chroot"
    pfbpkgdir="${sandbox}/pkg"
    dnsblarchive="${sandbox}/pfb_dnsbl_cache.tar.bz2"
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

  # List archive members, basename only.
  tar_list() {
    /usr/bin/tar -tjf "${dnsblarchive}" 2>/dev/null | sed 's#.*/##'
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

  It 'restore round-trips the generated state and re-stages current shipped code'
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
