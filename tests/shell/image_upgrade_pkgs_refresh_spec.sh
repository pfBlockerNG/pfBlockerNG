#shellcheck shell=sh
# image_upgrade_pkgs_refresh_spec.sh — pins pfb_refresh_pkgs, the --upgrade-pkgs
# body image-refresh.yml runs unattended (from==to, no human watching the
# plan). It must fail closed on any FreeBSD ABI/kernel major movement across
# the refresh, and on a pkg-reported major crossing, instead of publishing
# foreign-major packages onto the running tag (issue #2299 residual — a repo
# flip rewriting ABI mid-refresh is issue #2242's mechanism).
#
# Hermetic: drives the shipped helper with a stub ssh_guest — no VM.

Describe 'image-upgrade.sh package refresh (--upgrade-pkgs)'
  SCRIPT="${PFB_ROOT}/scripts/image-upgrade.sh"

  setup() {
    WORK="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/upgpkgs.XXXXXX")"
    CALLS="${WORK}/calls"
    ABI_N="${WORK}/abi-n"
    KERN_N="${WORK}/kern-n"
    UPD_N="${WORK}/upd-n"
    export WORK CALLS ABI_N KERN_N UPD_N
  }
  teardown() { rm -rf "$WORK"; }
  BeforeEach 'setup'
  AfterEach 'teardown'

  # run_refresh ABI0 KERN0 DRY DRY_RC UPGRADE_RC UPDMODE ABI1 ABI2 KERN2
  #   [UPGRADE_Y_OUT] [PKG_QUERY_OUT] [NOISE] — drive pfb_refresh_pkgs (plus
  # the helpers it calls) with a stub ssh_guest that answers `pkg config
  # ABI`/`uname -r` from ABI0/KERN0 on the 1st call, ABI1 on the 2nd (post
  # `pkg update -f`), ABI2/KERN2 on the 3rd+ (post-reboot) — defaulting each
  # unset ABI1/ABI2/KERN2 to its snapshot, so a scenario only names the values
  # it moves. UPDMODE shapes `pkg update -f` (transient-lock / permanent-lock
  # / other-error / unset=succeeds). UPGRADE_Y_OUT overrides `pkg upgrade -y`'s
  # stdout (default: a plain "applying upgrades" line) so a scenario can plant
  # the FreeBSD-major phrase in the POST-`-y` log (issue #2299, F3a).
  # PKG_QUERY_RC (arg 13, default 0) is `pkg query`'s exit status.
  # PKG_QUERY_OUT overrides `pkg query "%n %q"`'s stdout (default: one package
  # reporting ABI0, so unrelated scenarios that reach the post-reboot sweep
  # stay green). NOISE is 'ssh-banner' (every ssh_guest call also writes the
  # real known_hosts stderr line) or 'abi-warn' (`pkg config ABI` also writes
  # pkg's own foreign-major stderr warning) — neither may leak into a captured
  # value (issue #2299, F2).
  run_refresh() {
    _abi0="$1" _kern0="$2" _dry="$3" _dryrc="$4" _upgraderc="$5" _updmode="$6" _abi1="$7" _abi2="$8" _kern2="$9" \
    _upgy_out="${10}" _pkgquery_out="${11}" _noise="${12}" _pkgquery_rc="${13:-0}" \
      sh -c '
        set -e
        log()  { printf "==> %s\n" "$*"; }
        warn() { printf "WARNING: %s\n" "$*" >&2; }
        die()  { printf "ERROR: %s\n" "$*" >&2; exit 1; }
        sleep() { :; }
        wait_guest_ssh() { :; }
        : "${_abi1:=$_abi0}"
        : "${_abi2:=$_abi0}"
        : "${_kern2:=$_kern0}"
        : "${_dryrc:=0}"
        : "${_upgraderc:=0}"
        : "${_upgy_out:=applying upgrades}"
        : "${_pkgquery_out:=baseline-pkg $_abi0}"
        ssh_guest() {
          [ "$_noise" = ssh-banner ] && printf "Warning: Permanently added '"'"'[127.0.0.1]:2222'"'"' (ED25519) to the list of known hosts.\n" >&2
          printf "%s\n" "$*" >> "$CALLS"
          case "$*" in
            "/usr/local/sbin/pkg config ABI")
              [ "$_noise" = abi-warn ] && printf "pkg: Warning: Major OS version upgrade detected -- consider setting IGNORE_OSVERSION\n" >&2
              _n=$(( $(cat "$ABI_N" 2>/dev/null || echo 0) + 1 )); printf "%s" "$_n" > "$ABI_N"
              case "$_n" in
                1) printf "%s\n" "$_abi0" ;;
                2) printf "%s\n" "$_abi1" ;;
                *) printf "%s\n" "$_abi2" ;;
              esac
              ;;
            "uname -r")
              _n=$(( $(cat "$KERN_N" 2>/dev/null || echo 0) + 1 )); printf "%s" "$_n" > "$KERN_N"
              if [ "$_n" -eq 1 ]; then printf "%s\n" "$_kern0"; else printf "%s\n" "$_kern2"; fi
              ;;
            "pkg update -f")
              _n=$(( $(cat "$UPD_N" 2>/dev/null || echo 0) + 1 )); printf "%s" "$_n" > "$UPD_N"
              case "$_updmode" in
                transient-lock)
                  if [ "$_n" -eq 1 ]; then
                    printf "%s\n" "pkg: Cannot get an exclusive lock on a database, it is locked by another process"
                    return 1
                  fi
                  ;;
                permanent-lock)
                  printf "%s\n" "pkg: Package database is busy while closing!"
                  return 1
                  ;;
                other-error)
                  printf "%s\n" "pkg: repository FreeBSD has a wrong packagesite"
                  return 9
                  ;;
              esac
              printf "%s\n" "catalogue refreshed"
              ;;
            "pkg upgrade -n")
              printf "%s\n" "$_dry"
              return "$_dryrc"
              ;;
            "env ASSUME_ALWAYS_YES=yes pkg upgrade -y")
              printf "%s\n" "$_upgy_out"
              return "$_upgraderc"
              ;;
            "/sbin/reboot") return 0 ;;
            '"'"'/usr/local/sbin/pkg query "%n %q"'"'"')
              printf "%s\n" "$_pkgquery_out"
              return "$_pkgquery_rc"
              ;;
          esac
        }
        eval "$(sed -n "/^# pfb_abi_major BEGIN/,/^# pfb_abi_major END/p" "$1")"
        eval "$(sed -n "/^# pfb_kern_major BEGIN/,/^# pfb_kern_major END/p" "$1")"
        eval "$(sed -n "/^# pfb_pkg_refresh_verdict BEGIN/,/^# pfb_pkg_refresh_verdict END/p" "$1")"
        eval "$(sed -n "/^# pfb_pkg_update_retry BEGIN/,/^# pfb_pkg_update_retry END/p" "$1")"
        eval "$(sed -n "/^# pfb_refresh_pkgs BEGIN/,/^# pfb_refresh_pkgs END/p" "$1")"
        PKG_LOCK_RETRIES=2
        PKG_LOCK_INTERVAL=0
        pfb_refresh_pkgs "$2"
        printf "PKG_WAS_UPGRADED=%s\n" "$PKG_WAS_UPGRADED"
        printf "REACHED-AFTER-REFRESH\n"
      ' _ "$SCRIPT" "$WORK"
  }

  # C1
  It 'skips the upgrade + reboot when packages are already up to date'
    When call run_refresh 'FreeBSD:15:amd64' '15.0-RELEASE' 'Your packages are up to date.' 0 0 '' '' '' ''
    The status should be success
    The output should include 'PKG_WAS_UPGRADED=0'
    The output should include 'REACHED-AFTER-REFRESH'
    The contents of file "$CALLS" should not include 'env ASSUME_ALWAYS_YES=yes pkg upgrade -y'
  End

  # C2 — real pkg(8) exits 1 (not 0) whenever a dry-run plan is PENDING
  # (upstream pkg.c: dry_run -> rc=false); rc must not gate a pending verdict.
  It 'applies a pending plan (dry-run rc=1, real pkg semantics), reboots, and re-verifies ABI/kernel major after'
    When call run_refresh 'FreeBSD:15:amd64' '15.0-RELEASE' 'Number of packages to be upgraded: 3' 1 0 '' '' '' ''
    The status should be success
    The output should include 'PKG_WAS_UPGRADED=1'
    The output should include 'REACHED-AFTER-REFRESH'
    The contents of file "$CALLS" should include '/sbin/reboot'
  End

  # F1: keep one row covering the rc=0 pending case too (some pkg versions).
  It 'applies a pending plan when the dry-run exits 0 (older/other pkg semantics)'
    When call run_refresh 'FreeBSD:15:amd64' '15.0-RELEASE' 'Number of packages to be upgraded: 3' 0 0 '' '' '' ''
    The status should be success
    The output should include 'PKG_WAS_UPGRADED=1'
    The output should include 'REACHED-AFTER-REFRESH'
  End

  # C3
  It 'fails closed when pkg upgrade -n reports a major OS version crossing'
    When call run_refresh 'FreeBSD:15:amd64' '15.0-RELEASE' 'Major OS version upgrade detected, aborting.' 0 0 '' '' '' ''
    The status should be failure
    The stderr should include 'FreeBSD major'
    The output should not include 'REACHED-AFTER-REFRESH'
    The contents of file "$CALLS" should not include 'env ASSUME_ALWAYS_YES=yes pkg upgrade -y'
  End

  # C4
  It 'fails closed when pkg upgrade -n reports a wrong-architecture plan'
    When call run_refresh 'FreeBSD:15:amd64' '15.0-RELEASE' 'wrong architecture: FreeBSD:15:* instead of FreeBSD:16:amd64' 0 0 '' '' '' ''
    The status should be failure
    The stderr should include 'FreeBSD major'
    The output should not include 'REACHED-AFTER-REFRESH'
    The contents of file "$CALLS" should not include 'env ASSUME_ALWAYS_YES=yes pkg upgrade -y'
  End

  # F3 addendum (d) — BBcan177's fixture: the plan just LISTS a foreign-major
  # package, with none of the phrase gate's wording — must still die, before -y.
  It 'fails closed when the dry-run plan lists a foreign-major package with no crossing phrase'
    When call run_refresh 'FreeBSD:15:amd64' '15.0-RELEASE' 'pkg: 1.21.3 -> 2.1.0 [FreeBSD:16:amd64]' 1 0 '' '' '' ''
    The status should be failure
    The stderr should include 'FreeBSD:16:'
    The stderr should include 'issue #2299'
    The output should not include 'REACHED-AFTER-REFRESH'
    The contents of file "$CALLS" should not include 'env ASSUME_ALWAYS_YES=yes pkg upgrade -y'
  End

  # F3 addendum (e) — each pkg(8) cross-major wording gets its own row, so
  # dropping one alternative from the phrase list turns exactly one row red.
  It 'fails closed when the dry-run plan reports a Newer FreeBSD version'
    When call run_refresh 'FreeBSD:15:amd64' '15.0-RELEASE' 'Newer FreeBSD version for package foo-1.0' 1 0 '' '' '' ''
    The status should be failure
    The stderr should include 'FreeBSD major'
    The output should not include 'REACHED-AFTER-REFRESH'
    The contents of file "$CALLS" should not include 'env ASSUME_ALWAYS_YES=yes pkg upgrade -y'
  End

  It 'fails closed when the dry-run plan asks to IGNORE_OSVERSION'
    When call run_refresh 'FreeBSD:15:amd64' '15.0-RELEASE' 'to ignore this error set IGNORE_OSVERSION=yes' 1 0 '' '' '' ''
    The status should be failure
    The stderr should include 'FreeBSD major'
    The output should not include 'REACHED-AFTER-REFRESH'
    The contents of file "$CALLS" should not include 'env ASSUME_ALWAYS_YES=yes pkg upgrade -y'
  End

  # C5
  It 'fails closed when pkg upgrade -y itself fails (no || true swallow)'
    When call run_refresh 'FreeBSD:15:amd64' '15.0-RELEASE' 'Number of packages to be upgraded: 3' 1 1 '' '' '' ''
    The status should be failure
    The stderr should include 'pkg upgrade'
    The output should not include 'REACHED-AFTER-REFRESH'
  End

  # F3a — an outdated pkg binary restricts the dry-run to pkg's own
  # self-upgrade; the real cross-major plan surfaces only in the -y log
  # (after pkg re-execs). Must die BEFORE the reboot is recorded.
  It 'fails closed when the pkg upgrade -y log reports a major OS crossing the dry-run never saw'
    When call run_refresh 'FreeBSD:15:amd64' '15.0-RELEASE' 'Number of packages to be upgraded: 1' 1 0 '' '' '' '' \
      "$(printf 'pkg: 1.21.3_8 -> 2.1.0 [FreeBSD:16:amd64]\nMajor OS version upgrade detected, aborting other packages')"
    The status should be failure
    The stderr should include 'FreeBSD major'
    The stderr should include 'pkg-upgrade.log'
    The output should not include 'REACHED-AFTER-REFRESH'
    The contents of file "$CALLS" should not include '/sbin/reboot'
  End

  It 'fails closed when the pkg upgrade -y log merely lists a foreign-major package'
    When call run_refresh 'FreeBSD:15:amd64' '15.0-RELEASE' 'Number of packages to be upgraded: 1' 1 0 '' '' '' '' \
      'pkg: 1.21.3_8 -> 2.1.0 [FreeBSD:16:amd64]'
    The status should be failure
    The stderr should include 'FreeBSD:16:'
    The stderr should include 'pkg-upgrade.log'
    The output should not include 'REACHED-AFTER-REFRESH'
    The contents of file "$CALLS" should not include '/sbin/reboot'
  End

  # C6
  It 'fails closed when the post-reboot ABI major differs from the snapshot'
    When call run_refresh 'FreeBSD:15:amd64' '15.0-RELEASE' 'Number of packages to be upgraded: 3' 1 0 '' '' 'FreeBSD:16:amd64' '16.0-RELEASE'
    The status should be failure
    The stderr should include 'FreeBSD:16:amd64'
    The stderr should include 'FreeBSD:15:amd64'
    The output should not include 'REACHED-AFTER-REFRESH'
  End

  # F3b — the box-level ABI/kernel check can pass while a single installed
  # package still carries a foreign-major ABI; the post-reboot pkg-query
  # sweep must catch and NAME it.
  It 'fails closed when a post-reboot installed package reports a foreign ABI major'
    When call run_refresh 'FreeBSD:15:amd64' '15.0-RELEASE' 'Number of packages to be upgraded: 3' 1 0 '' '' '' '' \
      '' 'straggler-pkg FreeBSD:16:amd64'
    The status should be failure
    The stderr should include 'straggler-pkg'
    The stderr should include 'FreeBSD:16:amd64'
    The output should not include 'REACHED-AFTER-REFRESH'
  End

  # F3c — happy path: every installed package (including a wildcard-arch one)
  # reports the same major as the box; must succeed.
  It 'succeeds when every post-reboot installed package matches the box major'
    When call run_refresh 'FreeBSD:15:amd64' '15.0-RELEASE' 'Number of packages to be upgraded: 3' 1 0 '' '' '' '' \
      '' "$(printf 'pkgA FreeBSD:15:amd64\npkgB FreeBSD:15:*')"
    The status should be success
    The output should include 'PKG_WAS_UPGRADED=1'
    The output should include 'REACHED-AFTER-REFRESH'
  End

  It 'fails closed when the post-reboot pkg query exits non-zero even with partial output'
    When call run_refresh 'FreeBSD:15:amd64' '15.0-RELEASE' 'Number of packages to be upgraded: 3' 1 0 '' '' '' '' \
      '' 'pkgA FreeBSD:15:amd64' '' 1
    The status should be failure
    The stderr should include 'pkg query'
    The output should not include 'REACHED-AFTER-REFRESH'
  End

  It 'ignores blank lines and fully wildcarded ABIs in the post-reboot package sweep'
    When call run_refresh 'FreeBSD:15:amd64' '15.0-RELEASE' 'Number of packages to be upgraded: 3' 1 0 '' '' '' '' \
      '' "$(printf 'pkgA FreeBSD:15:amd64\n\npkgC FreeBSD:*:*')"
    The status should be success
    The output should include 'PKG_WAS_UPGRADED=1'
    The output should include 'REACHED-AFTER-REFRESH'
  End

  # C7
  It 'fails closed when pkg update -f itself rewrote the ABI major, before any dry-run'
    When call run_refresh 'FreeBSD:15:amd64' '15.0-RELEASE' 'Your packages are up to date.' 0 0 '' 'FreeBSD:16:amd64' '' ''
    The status should be failure
    The stderr should include 'FreeBSD:16:amd64'
    The stderr should include 'FreeBSD:15:amd64'
    The output should not include 'REACHED-AFTER-REFRESH'
    The contents of file "$CALLS" should not include 'pkg upgrade -n'
  End

  # C8
  It 'fails closed when the initial pkg config ABI cannot be read'
    When call run_refresh '' '15.0-RELEASE' 'Your packages are up to date.' 0 0 '' '' '' ''
    The status should be failure
    The stderr should include 'could not read'
    The output should not include 'REACHED-AFTER-REFRESH'
  End

  # F4 — the ABI/kernel major must already agree BEFORE pkg update -f runs.
  It 'fails closed when the initial ABI major does not match the initial kernel major'
    When call run_refresh 'FreeBSD:16:amd64' '15.0-CURRENT' 'Your packages are up to date.' 0 0 '' '' '' ''
    The status should be failure
    The stderr should include 'FreeBSD:16:amd64'
    The stderr should include '15.0-CURRENT'
    The output should not include 'REACHED-AFTER-REFRESH'
    The contents of file "$CALLS" should not include 'pkg update -f'
  End

  # F2 — a foreign-major pkg binary warns on stderr for ANY command; the
  # capture must stay clean and the die message must name the two plain
  # values, not garbled multi-line noise (also proves F4 fires past the noise).
  It 'fails closed with a clean two-value message even when pkg config ABI warns on stderr'
    When call run_refresh 'FreeBSD:16:amd64' '15.0-RELEASE' 'Your packages are up to date.' 0 0 '' '' '' '' '' '' abi-warn
    The status should be failure
    The stderr should include 'pkg ABI FreeBSD:16:amd64 does not match kernel 15.0-RELEASE'
  End

  # F2 — ssh's own known-hosts banner lands on stderr on EVERY call (proven by
  # this scenario's stub firing it on every ssh_guest invocation); the happy
  # pending-upgrade path must still succeed, since every value capture either
  # discards ssh_guest's stderr or merges it into a channel this stub already
  # exercises elsewhere (C1/C9) — none of them let raw noise corrupt a value.
  It 'succeeds through a pending-upgrade refresh despite an ssh known-hosts banner on every call'
    When call run_refresh 'FreeBSD:15:amd64' '15.0-RELEASE' 'Number of packages to be upgraded: 3' 1 0 '' '' '' '' '' '' ssh-banner
    The status should be success
    The output should include 'PKG_WAS_UPGRADED=1'
    The output should include 'REACHED-AFTER-REFRESH'
  End

  # C9
  It 'retries a transient pkg database lock on pkg update -f and continues'
    When call run_refresh 'FreeBSD:15:amd64' '15.0-RELEASE' 'Your packages are up to date.' 0 0 'transient-lock' '' '' ''
    The status should be success
    The stderr should include 'pkg database locked'
    The output should include 'PKG_WAS_UPGRADED=0'
    The output should include 'REACHED-AFTER-REFRESH'
    The contents of file "${WORK}/pkg-update.log" should include 'Cannot get an exclusive lock'
    The contents of file "${WORK}/pkg-update.log" should include 'catalogue refreshed'
  End

  # C10
  It 'fails closed on a non-lock pkg update -f error (no || true swallow)'
    When call run_refresh 'FreeBSD:15:amd64' '15.0-RELEASE' 'Your packages are up to date.' 0 0 'other-error' '' '' ''
    The status should be failure
    The stderr should include 'pkg catalogue refresh failed'
    The output should not include 'REACHED-AFTER-REFRESH'
  End

  # N1 — the third uncovered fail-closed path: the lock never clears.
  It 'fails closed when the pkg database lock never clears'
    When call run_refresh 'FreeBSD:15:amd64' '15.0-RELEASE' 'Your packages are up to date.' 0 0 'permanent-lock' '' '' ''
    The status should be failure
    The stderr should include 'still locked'
    The output should not include 'REACHED-AFTER-REFRESH'
  End

  # N1 — pkg upgrade -n exits non-zero AND prints unparsable text (neither an
  # up-to-date nor a plan phrase): the fail-closed verdict must still die, and
  # the message must NAME the rc (mutation-sensitive: deleting the rc from the
  # message turns this row red without touching the die/no-die outcome).
  It 'fails closed on a non-zero dry-run rc with unparsable output (fail-closed verdict names the rc)'
    When call run_refresh 'FreeBSD:15:amd64' '15.0-RELEASE' 'pkg: http://example.test: Not Found' 3 0 '' '' '' ''
    The status should be failure
    The stderr should include 'did not report a plan'
    The stderr should include 'rc=3'
    The output should not include 'REACHED-AFTER-REFRESH'
  End

  # N1 — the same unparsable text at rc=0 must also die (content, not rc, is
  # the fail-closed signal).
  It 'fails closed on unparsable dry-run output at rc=0'
    When call run_refresh 'FreeBSD:15:amd64' '15.0-RELEASE' 'pkg: http://example.test: Not Found' 0 0 '' '' '' ''
    The status should be failure
    The stderr should include 'did not report a plan'
    The output should not include 'REACHED-AFTER-REFRESH'
  End

  # N2 — a non-digit major (garbled `pkg config ABI`) must read as unreadable,
  # never as a major that happens to compare unequal.
  It 'fails closed when pkg config ABI answers a non-digit major'
    When call run_refresh 'FreeBSD:15a:amd64' '15.0-RELEASE' 'Your packages are up to date.' 0 0 '' '' '' ''
    The status should be failure
    The stderr should include 'could not read'
  End

  # C11 — wiring: exactly one call site, and the extraction markers exist.
  It 'wires pfb_refresh_pkgs into the --upgrade-pkgs branch exactly once'
    When call grep -c '^    pfb_refresh_pkgs "\$LOCAL_DIR"$' "$SCRIPT"
    The output should equal 1
  End

  It 'exposes the pfb_refresh_pkgs extraction markers'
    When call grep -cE '^# pfb_refresh_pkgs (BEGIN|END)$' "$SCRIPT"
    The output should equal 2
  End

  # Hostile: a `\r`-laced dry-run line still matches the up-to-date phrase.
  It 'tolerates CRLF-mangled dry-run output when packages are up to date'
    dry="$(printf 'Your packages are up to date.\r')"
    When call run_refresh 'FreeBSD:15:amd64' '15.0-RELEASE' "$dry" 0 0 '' '' '' ''
    The status should be success
    The output should include 'PKG_WAS_UPGRADED=0'
  End

  # Hostile: pkg config ABI answering a bare "?" (no `:` fields) is unreadable,
  # same as empty — never treated as a major that happens to compare unequal.
  It 'fails closed when pkg config ABI answers a bare "?"'
    When call run_refresh '?' '15.0-RELEASE' 'Your packages are up to date.' 0 0 '' '' '' ''
    The status should be failure
    The stderr should include 'could not read'
  End

  # Hostile: post-reboot kernel major with no dot (e.g. 15-STABLE) never
  # coincidentally strcmp-matches a numeric ABI major — it fails closed.
  It 'fails closed when the post-reboot kernel major has no dot to parse'
    When call run_refresh 'FreeBSD:15:amd64' '15.0-RELEASE' 'Number of packages to be upgraded: 3' 1 0 '' '' '' '15-STABLE'
    The status should be failure
    The stderr should include '15-STABLE'
    The stderr should include 'FreeBSD:15:amd64'
    The output should not include 'REACHED-AFTER-REFRESH'
  End
End
