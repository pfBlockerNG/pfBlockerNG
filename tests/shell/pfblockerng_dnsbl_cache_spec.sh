#shellcheck shell=sh
# pfblockerng.sh dnsbl_cache (#468) — keep DNSBL alive across a RAM-disk /var reboot.
#
# Pins the three subcommands against a sandbox chroot:
#   stage   -- copies the SHIPPED files into the chroot and creates the nullfs/devfs
#              mount-point dirs (the fresh-MFS fix that made pfb_python_mount fail).
#   teardown -- removes the SHIPPED files from the chroot.
#   save    -- archives ONLY the GENERATED set (pfb_py_* + pfb_unbound.ini), never the
#              shipped files (those come from /usr/local on restore -> no stale code).
#   restore -- untars the generated set THEN stages the shipped files; round-trips the
#              generated state and re-stages current shipped code over an empty chroot.
#
# FORMAT-AGNOSTIC: pfb_archive_compress writes "<base>.zst" (zstd) or, if zstd is
# missing/errors, "<base>.bz2" (bzip2); pfb_archive_extract / tar auto-detect either.
# So the tests resolve the archive via archive_path() and never assume a codec --
# they pass with zstd OR bzip2, exactly like the production helpers.
#
# Off-appliance the staged-file chown to unbound:unbound fails (no such user/group);
# that is harmless and not the behaviour under test, so each example runs the function
# through a wrapper that swallows the chown noise and the resulting non-zero status.
# Before-state is asserted where a transition is claimed (the wiped chroot is empty
# before restore; the archive carries the generated file and NOT the shipped one).

# Echo the archive that exists for a base (<base>.zst or <base>.bz2), else nothing.
pfb_spec_archive_path() {
  for _e in zst bz2; do
    if [ -f "${1}.${_e}" ]; then echo "${1}.${_e}"; return 0; fi
  done
  return 0
}

Describe 'pfblockerng.sh dnsbl_cache (#468)'
  BeforeAll 'pfb_source'

  # shellcheck disable=SC2034  # consumed by the sourced dnsbl_cache() at runtime
  setup_sandbox() {
    sandbox="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pfbdc.XXXXXX")"
    # Overridable locations the sourced dnsbl_cache() reads.
    pfbchroot="${sandbox}/chroot"
    pfbpkgdir="${sandbox}/pkg"
    pfbdb="${sandbox}/db"
    dnsblarchive="${sandbox}/pfb_dnsbl_cache.tar"   # extension-less BASE
    pathtar="/usr/bin/tar"
    mkdir -p "${pfbpkgdir}" "${pfbdb}"
    # The shipped files (current code in /usr/local).
    echo 'PY-CODE-v1' > "${pfbpkgdir}/pfb_unbound.py"
    echo 'RULES-CODE-v1' > "${pfbpkgdir}/pfb_dnsbl_regex_rules.py"
    echo 'INC-CODE-v1' > "${pfbpkgdir}/pfb_unbound_include.inc"
    echo 'HSTS-v1' > "${pfbpkgdir}/pfb_py_hsts.txt"
    echo 'WRAPPER-CODE-v1' > "${pfbpkgdir}/pfb_python.sh"
    chmod +x "${pfbpkgdir}/pfb_python.sh"
    echo 'PSL-AUTHORITY-v1' > "${pfbpkgdir}/dnsbl_psl"
  }

  cleanup_sandbox() {
    rm -rf "${sandbox}"
  }

  # Run dnsbl_cache and discard the off-appliance chown failure (status + stderr).
  dc() {
    dnsbl_cache "$1" 2>/dev/null || true
  }

  # List archive members (codec-agnostic: tar auto-detects), basename only.
  tar_list() {
    /usr/bin/tar -tf "$(pfb_spec_archive_path "${dnsblarchive}")" 2>/dev/null | sed 's#.*/##'
  }

  tar_list_full() {
    /usr/bin/tar -tf "$(pfb_spec_archive_path "${dnsblarchive}")" 2>/dev/null
  }

  top1m_cksum() {
    cksum "${1}" 2>/dev/null || echo 'MISSING'
  }

  save_restore_top1m() {
    dc save
    echo "ARCHIVE:$(pfb_spec_archive_path "${dnsblarchive}")"
    tar_list_full
    rm -rf "${pfbchroot}" "${pfbdb}"
    dc restore
  }

  It 'stage copies all shipped files and the PSL authority, then creates mount-point dirs'
    setup_sandbox
    # Before: the chroot does not exist at all (fresh MFS).
    When call dc stage
    # The shipped files landed in the chroot.
    The path "${pfbchroot}/pfb_unbound.py" should be exist
    The path "${pfbchroot}/pfb_dnsbl_regex_rules.py" should be exist
    The path "${pfbchroot}/pfb_unbound_include.inc" should be exist
    The path "${pfbchroot}/pfb_py_hsts.txt" should be exist
    The path "${pfbchroot}/pfb_python.sh" should be executable
    The path "${pfbchroot}/dnsbl_psl" should be exist
    # The mount-point dirs exist (the fresh-MFS fix).
    The path "${pfbchroot}/lib" should be directory
    The path "${pfbchroot}/dev" should be directory
    The path "${pfbchroot}/var/log/pfblockerng" should be directory
    The path "${pfbchroot}/usr/local/share/GeoIP" should be directory
    cleanup_sandbox
  End

  It 'teardown removes all shipped files from a chroot path with spaces'
    setup_sandbox
    pfbchroot="${sandbox}/chroot path"
    dc stage
    When call dc teardown
    The status should be success
    The path "${pfbchroot}/pfb_dnsbl_regex_rules.py" should not be exist
    The path "${pfbchroot}/pfb_unbound.py" should not be exist
    The path "${pfbchroot}/pfb_unbound_include.inc" should not be exist
    The path "${pfbchroot}/pfb_py_hsts.txt" should not be exist
    The path "${pfbchroot}/pfb_python.sh" should not be exist
    The path "${pfbchroot}/dnsbl_psl" should not be exist
    cleanup_sandbox
  End

  teardown_twice() {
    dnsbl_cache teardown 2>/dev/null
    first=$?
    dnsbl_cache teardown 2>/dev/null
    second=$?
    printf '%s:%s\n' "${first}" "${second}"
  }

  It 'teardown is idempotent when all files are already absent'
    setup_sandbox
    pfbchroot="${sandbox}/chroot path"
    dc stage
    dc teardown
    When call teardown_twice
    The output should equal '0:0'
    The path "${pfbchroot}/dnsbl_psl" should not be exist
    cleanup_sandbox
  End

  stage_root_chown() (
    setup_sandbox
    # shellcheck disable=SC2329  # invoked indirectly by dnsbl_cache
    chown() {
      if [ "$3" = "${pfbchroot}" ]; then
        printf '%s %s CHROOT\n' "$1" "$2"
      fi
    }
    dnsbl_cache stage
    cleanup_sandbox
  )

  It 'stage gives unbound the chroot directory without recursive ownership changes'
    When call stage_root_chown
    The output should equal '-f unbound:unbound CHROOT'
  End

  It 'stage copies the PSL authority by basename'
    setup_sandbox
    When call dc stage
    The contents of file "${pfbchroot}/dnsbl_psl" should equal 'PSL-AUTHORITY-v1'
    The contents of file "${pfbpkgdir}/dnsbl_psl" should equal 'PSL-AUTHORITY-v1'
    cleanup_sandbox
  End

  It 'stage is a no-op for the PSL authority when the shipped file is absent'
    setup_sandbox
    rm -f "${pfbpkgdir}/dnsbl_psl"
    When call dc stage
    The status should be success
    The path "${pfbchroot}/dnsbl_psl" should not be exist
    cleanup_sandbox
  End

  It 'save archives the generated set only (never the shipped files)'
    setup_sandbox
    dc stage
    # A generation-consistent manifest + versioned raw dir + stale stage.
    generation='pfb_py_raw.0123456789abcdef0123456789abcdef'
    stage='pfb_py_raw.stage.abcdef0123456789abcdef0123456789'
    mkdir "${pfbchroot}/${generation}" "${pfbchroot}/${stage}"
    echo 'rawdata' > "${pfbchroot}/${generation}/feed.raw"
    echo 'partial' > "${pfbchroot}/${stage}/feed.raw"
    echo "{\"feeds\":[{\"raw\":\"${generation}/feed.raw\"}]}" > "${pfbchroot}/pfb_py_sources.json"
    true > "${pfbchroot}/pfb_py_sources.lock"
    echo 'ini' > "${pfbchroot}/pfb_unbound.ini"
    When call dc save
    # An archive was written (codec-agnostic).
    arc="$(pfb_spec_archive_path "${dnsblarchive}")"
    The path "$arc" should be exist
    # The archive carries the GENERATED files ...
    The result of "tar_list()" should include 'pfb_py_sources.json'
    The result of "tar_list_full()" should include "${generation}/feed.raw"
    The result of "tar_list()" should not include "${stage}"
    The result of "tar_list()" should not include 'pfb_py_sources.lock'
    The result of "tar_list()" should include 'pfb_unbound.ini'
    # ... and NOT the shipped files (re-staged from /usr/local on restore).
    The result of "tar_list()" should not include 'pfb_py_hsts.txt'
    The result of "tar_list()" should not include 'pfb_unbound_include.inc'
    # ... nor pfb_dnsbl_regex_rules.py (issue #1765): its basename matches
    # neither the pfb_unbound*/pfb_py_* archive glob, so it is shipped, not
    # generated -- re-staged from /usr/local on restore, same as the others.
    The result of "tar_list()" should not include 'pfb_dnsbl_regex_rules.py'
    # ... nor the shipped PSL authority (issue #1541): staged into the chroot by
    # `dc stage` above, but SHIPPED -- outside the pfb_unbound*/pfb_py_* archive
    # globs and re-staged from /usr/local on restore. Archiving it would
    # reinstate a stale authority on restore; this row pins that the staged
    # copy stays out of the archive.
    The result of "tar_list()" should not include 'dnsbl_psl'
    cleanup_sandbox
  End

  It 'save and restore preserves TOP1M detector sidecars and excludes transient DB files'
    setup_sandbox
    pfbdb="${sandbox}/db path [top1m]"
    mkdir -p "${pfbdb}" "${pfbchroot}"
    for _suffix in orig xxhash128 md5 source orig.etag orig.lastmod; do
      printf 'TOP1M-%s\n' "${_suffix}" > "${pfbdb}/top-1m.csv.zip.${_suffix}"
    done
    printf 'transient\n' > "${pfbdb}/.pfbtop1m_stage"
    printf 'unrelated\n' > "${pfbdb}/other.db"
    printf 'TOP1M-GENERATED\n' > "${pfbchroot}/pfb_py_top1m.txt"
    top1m_orig_cksum="$(cksum "${pfbdb}/top-1m.csv.zip.orig")"
    top1m_xxh_cksum="$(cksum "${pfbdb}/top-1m.csv.zip.xxhash128")"
    top1m_md5_cksum="$(cksum "${pfbdb}/top-1m.csv.zip.md5")"
    top1m_source_cksum="$(cksum "${pfbdb}/top-1m.csv.zip.source")"
    top1m_etag_cksum="$(cksum "${pfbdb}/top-1m.csv.zip.orig.etag")"
    top1m_lastmod_cksum="$(cksum "${pfbdb}/top-1m.csv.zip.orig.lastmod")"
    When call save_restore_top1m
    The output should include 'ARCHIVE:'
    The output should include "${pfbdb}/top-1m.csv.zip.orig"
    The output should include "${pfbdb}/top-1m.csv.zip.xxhash128"
    The output should include "${pfbdb}/top-1m.csv.zip.md5"
    The output should include "${pfbdb}/top-1m.csv.zip.source"
    The output should include "${pfbdb}/top-1m.csv.zip.orig.etag"
    The output should include "${pfbdb}/top-1m.csv.zip.orig.lastmod"
    The output should include "${pfbchroot}/pfb_py_top1m.txt"
    The output should not include "${pfbdb}/.pfbtop1m_stage"
    The output should not include "${pfbdb}/other.db"
    The contents of file "${pfbchroot}/pfb_py_top1m.txt" should equal 'TOP1M-GENERATED'
    The value "$(top1m_cksum "${pfbdb}/top-1m.csv.zip.orig")" should equal "${top1m_orig_cksum}"
    The value "$(top1m_cksum "${pfbdb}/top-1m.csv.zip.xxhash128")" should equal "${top1m_xxh_cksum}"
    The value "$(top1m_cksum "${pfbdb}/top-1m.csv.zip.md5")" should equal "${top1m_md5_cksum}"
    The value "$(top1m_cksum "${pfbdb}/top-1m.csv.zip.source")" should equal "${top1m_source_cksum}"
    The value "$(top1m_cksum "${pfbdb}/top-1m.csv.zip.orig.etag")" should equal "${top1m_etag_cksum}"
    The value "$(top1m_cksum "${pfbdb}/top-1m.csv.zip.orig.lastmod")" should equal "${top1m_lastmod_cksum}"
    The path "${pfbdb}/.pfbtop1m_stage" should not be exist
    The path "${pfbdb}/other.db" should not be exist
    cleanup_sandbox
  End

  It 'save archives only existing TOP1M detector sidecars'
    setup_sandbox
    printf 'TOP1M-ORIG\n' > "${pfbdb}/top-1m.csv.zip.orig"
    When call dc save
    The result of "tar_list_full()" should include "${pfbdb}/top-1m.csv.zip.orig"
    The result of "tar_list_full()" should not include "${pfbdb}/top-1m.csv.zip.xxhash128"
    The result of "tar_list_full()" should not include "${pfbdb}/top-1m.csv.zip.md5"
    The result of "tar_list_full()" should not include "${pfbdb}/top-1m.csv.zip.source"
    The result of "tar_list_full()" should not include "${pfbdb}/top-1m.csv.zip.orig.etag"
    The result of "tar_list_full()" should not include "${pfbdb}/top-1m.csv.zip.orig.lastmod"
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

  It 'restore round-trips a manifest with its referenced versioned raw generation'
    setup_sandbox
    dc stage
    generation='pfb_py_raw.0123456789abcdef0123456789abcdef'
    mkdir "${pfbchroot}/${generation}"
    echo 'RAW-v1' > "${pfbchroot}/${generation}/feed.raw"
    echo "{\"feeds\":[{\"raw\":\"${generation}/feed.raw\"}]}" > "${pfbchroot}/pfb_py_sources.json"
    dc save
    rm -rf "${pfbchroot}"
    When call dc restore
    The path "${pfbchroot}/${generation}" should be directory
    The contents of file "${pfbchroot}/${generation}/feed.raw" should equal 'RAW-v1'
    The contents of file "${pfbchroot}/pfb_py_sources.json" should include "${generation}/feed.raw"
    cleanup_sandbox
  End

  It 're-stages the CURRENT TLD oracle on restore, not a stale archived copy (issue #1255)'
    setup_sandbox
    dc stage
    dc save
    rm -rf "${pfbchroot}"
    # Bump the shipped oracle to prove restore re-stages CURRENT code, like pfb_unbound.py.
    echo 'PSL-AUTHORITY-v2' > "${pfbpkgdir}/dnsbl_psl"
    When call dc restore
    The contents of file "${pfbchroot}/dnsbl_psl" should equal 'PSL-AUTHORITY-v2'
    cleanup_sandbox
  End

  It 'restore with no archive still stages the shipped files (first boot / no prior save)'
    setup_sandbox
    # No save() ran, so no archive exists — restore must still stage the shipped files.
    When call dc restore
    arc="$(pfb_spec_archive_path "${dnsblarchive}")"
    The value "$arc" should equal ''
    The path "${pfbchroot}/pfb_unbound.py" should be exist
    The path "${pfbchroot}/lib" should be directory
    cleanup_sandbox
  End
End

# The shared archive helpers (#468) back BOTH the DNSBL cache and the IP aliastables.
# Codec-agnostic: round-trip + the legacy/fallback .bz2 read + the retire-on-write.
Describe 'pfblockerng.sh archive helpers (#468)'
  BeforeAll 'pfb_source'

  # shellcheck disable=SC2034  # pathtar is read by the sourced helpers
  setup_arc() {
    arcbox="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pfbarc.XXXXXX")"
    pathtar="/usr/bin/tar"
    arc_base="${arcbox}/data.tar"   # extension-less BASE; helper appends .zst/.bz2
    arc_bz2="${arc_base}.bz2"
    # A payload file to archive, addressed with an absolute path so -P keeps it.
    payload="${arcbox}/payload.txt"
    echo 'PAYLOAD-v1' > "${payload}"
  }
  cleanup_arc() { rm -rf "${arcbox}"; }

  It 'compress writes an archive and extract round-trips it'
    setup_arc
    When call pfb_archive_compress "${arc_base}" "${payload}"
    The status should be success
    # An archive exists (whichever codec was used).
    arc="$(pfb_spec_archive_path "${arc_base}")"
    The path "$arc" should be exist
    # Before: remove the payload so extract must restore it.
    rm -f "${payload}"
    pfb_archive_extract "${arc_base}" 2>/dev/null
    The contents of file "${payload}" should equal 'PAYLOAD-v1'
    cleanup_arc
  End

  # Wrapper: report the legacy-present before-state, then compress -- proving the legacy
  # bz2 was there first and a verified write retired it (only meaningful when zstd is in
  # play; with the bzip2 fallback the single .bz2 is simply overwritten, also fine).
  compress_and_report() {
    if [ -f "${arc_bz2}" ]; then echo 'PRE:legacy-present'; else echo 'PRE:legacy-absent'; fi
    pfb_archive_compress "${arc_base}" "${payload}"
    if pfb_spec_archive_path "${arc_base}" >/dev/null && [ -n "$(pfb_spec_archive_path "${arc_base}")" ]; then
      echo 'POST:archive-present'
    fi
  }

  It 'compress leaves exactly one current archive (retiring a pre-existing bz2)'
    setup_arc
    # Given: a pre-existing legacy bz2 archive (an old install).
    /usr/bin/tar -Pjcf "${arc_bz2}" "${payload}"
    When call compress_and_report
    The status should be success
    The output should include 'PRE:legacy-present'
    The output should include 'POST:archive-present'
    cleanup_arc
  End

  # issue #713 bug 7: POSIX sh has no pipefail, so the OLD `tar -Pcf - ... | zstd
  # ...` pipe silently discarded a failed/truncated tar's exit status (only
  # zstd's mattered), and "zstd -tq" verifies only the zstd FRAMING, not tar
  # completeness -- so a truncated tar stream still compressed into a small but
  # VALID .zst, publishing a corrupt archive AND deleting the still-good .bz2.
  # A tar stand-in that dies mid-write (simulates a killed process / disk-full /
  # a genuinely truncated source) reproduces the exact shape: it writes SOME
  # bytes then exits non-zero, same as a real truncated tar stream would.
  write_faketar() {
    cat > "${arcbox}/faketar" <<'EOF'
#!/bin/sh
printf 'PARTIAL-NOT-A-COMPLETE-TAR-STREAM'
exit 2
EOF
    chmod +x "${arcbox}/faketar"
  }

  # Wrapper: report the pre-existing .bz2's validity, run compress with a tar
  # that dies mid-stream, then report compress's own exit status plus the
  # POST-run .bz2 validity -- so the example proves the failed attempt neither
  # published a corrupt .zst nor damaged the pre-existing backup (not just that
  # a .bz2 happens to exist afterwards).
  faketar_compress_and_report() {
    # Given: a pre-existing, verified-good .bz2 backup (as if from a prior run).
    /usr/bin/tar -Pjcf "${arc_bz2}" "${payload}"
    if /usr/bin/tar -Ptjf "${arc_bz2}" >/dev/null 2>&1; then echo 'PRE:bz2-valid'; else echo 'PRE:bz2-invalid'; fi
    write_faketar
    pathtar="${arcbox}/faketar"
    pfb_archive_compress "${arc_base}" "${payload}"
    echo "COMPRESS_RC:$?"
    pathtar='/usr/bin/tar'
    if /usr/bin/tar -Ptjf "${arc_bz2}" >/dev/null 2>&1; then echo 'POST:bz2-valid'; else echo 'POST:bz2-invalid'; fi
  }

  It 'compress never publishes a corrupt .zst and never deletes the pre-existing .bz2 when tar fails (issue #713 bug 7)'
    setup_arc
    When call faketar_compress_and_report
    The output should include 'PRE:bz2-valid'
    # compress fails end-to-end (tar failed, so the bzip2 fallback -- itself run
    # through the same broken ${pathtar} stand-in in this scenario -- fails too).
    The output should include 'COMPRESS_RC:2'
    # The pre-existing .bz2 is untouched: still a valid, complete archive.
    The output should include 'POST:bz2-valid'
    # No .zst was ever published -- a truncated tar must never reach the
    # "zstd -tq passed, publish it" branch.
    The path "${arc_base}.zst" should not be exist
    The path "${arc_bz2}" should be exist
    payload_content="$(/usr/bin/tar -Pxjf "${arc_bz2}" -O)"
    The value "$payload_content" should equal 'PAYLOAD-v1'
    # No leftover mktemp temp files from the failed attempt.
    leftover="$(find "${arcbox}" -maxdepth 1 -name "$(basename "${arc_base}").??????" 2>/dev/null)"
    The value "$leftover" should equal ''
    cleanup_arc
  End

  # Wrapper: report the no-archive before-state, then extract from the bz2 fallback.
  extract_legacy_and_report() {
    if [ -f "${arc_base}.zst" ]; then echo 'PRE:zst-present'; else echo 'PRE:zst-absent'; fi
    pfb_archive_extract "${arc_base}"
    echo 'POST:extracted'
  }

  It 'extract reads a bz2 archive when no zst exists (legacy install upgrade)'
    setup_arc
    # Given: only a bz2 archive exists (no zst yet -- pre-upgrade, or zstd-less fallback).
    /usr/bin/tar -Pjcf "${arc_bz2}" "${payload}"
    rm -f "${payload}"
    When call extract_legacy_and_report
    The output should include 'PRE:zst-absent'
    The output should include 'POST:extracted'
    # Then: the payload is restored from the bz2 archive.
    The contents of file "${payload}" should equal 'PAYLOAD-v1'
    cleanup_arc
  End

  It 'thread count is ncpu-1, floored at 1 and capped at 4'
    When call pfb_zstd_threads
    The output should match pattern '[1234]'
    The status should be success
  End
End
