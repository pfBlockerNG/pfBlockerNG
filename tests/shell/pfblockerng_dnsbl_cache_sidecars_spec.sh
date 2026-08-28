#shellcheck shell=sh
# pfblockerng_dnsbl_cache_spec.sh's generated-only header predates issue #1542.
# Current save set: generated chroot files plus exact TOP1M detector sidecars; never prefix
# decoys, transient DB files, or outside paths.

pfb_sidecar_archive_path() {
  for _e in zst bz2; do
    if [ -f "${1}.${_e}" ]; then echo "${1}.${_e}"; return 0; fi
  done
  return 0
}

Describe 'pfblockerng.sh dnsbl_cache TOP1M sidecar boundaries'
  BeforeAll 'pfb_source'

  # shellcheck disable=SC2034  # consumed by the sourced dnsbl_cache() at runtime
  setup_sidecar_sandbox() {
    sandbox="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pfbdcside.XXXXXX")"
    pfbchroot="${sandbox}/chroot path [cache]"
    pfbpkgdir="${sandbox}/pkg"
    pfbdb="${sandbox}/db path [top1m]"
    dnsblarchive="${sandbox}/pfb_dnsbl_cache.tar"
    pathtar='/usr/bin/tar'
    outside="${sandbox}/outside absolute"
    mkdir -p "${pfbpkgdir}"
  }

  cleanup_sidecar_sandbox() {
    rm -rf "${sandbox}"
  }

  dc_sidecar() {
    dnsbl_cache "$1" 2>/dev/null || true
  }

  sidecar_archive_list() {
    /usr/bin/tar -tf "$(pfb_sidecar_archive_path "${dnsblarchive}")" 2>/dev/null
  }

  save_list_restore_sidecars() {
    dc_sidecar save
    sidecar_archive_list
    rm -rf "${pfbchroot}" "${pfbdb}" "${outside}"
    dc_sidecar restore
  }

  save_list_restore_missing_db() {
    [ ! -e "${pfbdb}" ] && echo 'PRE:db-missing'
    dc_sidecar save
    [ ! -e "${pfbdb}" ] && echo 'POST-SAVE:db-missing'
    sidecar_archive_list
    rm -rf "${pfbchroot}"
    dc_sidecar restore
    [ ! -e "${pfbdb}" ] && echo 'POST-RESTORE:db-missing'
  }

  It 'excludes TOP1M prefix decoys and an absolute outside sentinel'
    setup_sidecar_sandbox
    mkdir -p "${pfbchroot}" "${pfbdb}" "${outside}"
    printf 'GENERATED\n' > "${pfbchroot}/pfb_py_top1m.txt"
    printf 'EXACT\n' > "${pfbdb}/top-1m.csv.zip.orig"
    printf 'UPDATE-DECOY\n' > "${pfbdb}/top-1m.csv.zip.update"
    printf 'RAW-DECOY\n' > "${pfbdb}/top-1m.csv.zip.raw"
    printf 'NEIGHBOR-DECOY\n' > "${pfbdb}/top-1m.csv.zip.orig.neighbor"
    outside_sentinel="${outside}/top-1m.csv.zip.orig"
    printf 'OUTSIDE\n' > "${outside_sentinel}"
    When call save_list_restore_sidecars
    The output should include "${pfbchroot}/pfb_py_top1m.txt"
    The output should include "${pfbdb}/top-1m.csv.zip.orig"
    The output should not include "${pfbdb}/top-1m.csv.zip.update"
    The output should not include "${pfbdb}/top-1m.csv.zip.raw"
    The output should not include "${pfbdb}/top-1m.csv.zip.orig.neighbor"
    The output should not include "${outside_sentinel}"
    The contents of file "${pfbchroot}/pfb_py_top1m.txt" should equal 'GENERATED'
    The contents of file "${pfbdb}/top-1m.csv.zip.orig" should equal 'EXACT'
    The path "${pfbdb}/top-1m.csv.zip.update" should not be exist
    The path "${pfbdb}/top-1m.csv.zip.raw" should not be exist
    The path "${pfbdb}/top-1m.csv.zip.orig.neighbor" should not be exist
    The path "${outside_sentinel}" should not be exist
    cleanup_sidecar_sandbox
  End

  It 'keeps generated-only save and restore behavior when the DB directory is missing'
    setup_sidecar_sandbox
    mkdir -p "${pfbchroot}"
    printf 'GENERATED\n' > "${pfbchroot}/pfb_py_top1m.txt"
    When call save_list_restore_missing_db
    The output should include 'PRE:db-missing'
    The output should include 'POST-SAVE:db-missing'
    The output should include 'POST-RESTORE:db-missing'
    The output should include "${pfbchroot}/pfb_py_top1m.txt"
    The contents of file "${pfbchroot}/pfb_py_top1m.txt" should equal 'GENERATED'
    The path "${pfbdb}" should not be exist
    cleanup_sidecar_sandbox
  End
End
