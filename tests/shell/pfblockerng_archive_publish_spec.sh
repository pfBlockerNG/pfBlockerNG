#shellcheck shell=sh

Describe 'RAM-disk fallback archives publish only after tar succeeds'
  BeforeAll 'pfb_source'

  setup_publish() {
    publishbox="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pfb-publish.XXXXXX")"
    publishbase="${publishbox}/archive.tar"
    printf 'PAYLOAD' > "${publishbox}/payload"
    cat > "${publishbox}/tar" <<'SH'
#!/bin/sh
printf 'PARTIAL' > "$2"
exit 2
SH
    chmod +x "${publishbox}/tar"
  }
  Before 'setup_publish'
  After 'cleanup_publish'
  cleanup_publish() { rm -rf "${publishbox}"; }

  failed_publish() {
    pathtar="${publishbox}/tar"
    pfb_archive_compress "${publishbase}" "${publishbox}/payload" 2>/dev/null
    printf 'rc=%s\n' "$?"
    if [ -f "${publishbase}.bz2" ]; then cat "${publishbase}.bz2"; else printf 'ABSENT'; fi
    printf '\n'
    find "${publishbox}" -name 'archive.tar.??????' -print
  }

  It 'leaves a missing archive missing after a partial fallback write, so the next pass retries'
    When call failed_publish
    The output should equal "rc=2
ABSENT"
  End

  It 'preserves the last good fallback archive when a replacement tar fails'
    printf 'LAST-GOOD' > "${publishbase}.bz2"
    When call failed_publish
    The output should equal "rc=2
LAST-GOOD"
  End

  retry_publish() {
    failed_publish
    pathtar='/usr/bin/tar'
    zstd() { return 1; }
    pfb_archive_compress "${publishbase}" "${publishbox}/payload" 2>/dev/null
    printf 'retry=%s\n' "$?"
    /usr/bin/tar -xOf "${publishbase}.bz2" "${publishbox}/payload" 2>/dev/null
  }

  It 'publishes a complete fallback on a successful retry'
    When call retry_publish
    The output should equal "rc=2
ABSENT
retry=0
PAYLOAD"
  End
End
