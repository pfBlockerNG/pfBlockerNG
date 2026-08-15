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

  # run_refresh ABI0 KERN0 DRY DRY_RC UPGRADE_RC UPDMODE ABI1 ABI2 KERN2 — drive
  # pfb_refresh_pkgs (plus the helpers it calls) with a stub ssh_guest that
  # answers `pkg config ABI`/`uname -r` from ABI0/KERN0 on the 1st call,
  # ABI1 on the 2nd (post `pkg update -f`), ABI2/KERN2 on the 3rd+
  # (post-reboot) — defaulting each unset ABI1/ABI2/KERN2 to its snapshot, so
  # a scenario only names the values it moves. UPDMODE shapes `pkg update -f`
  # (transient-lock / permanent-lock / other-error / unset=succeeds).
  run_refresh() {
    _abi0="$1" _kern0="$2" _dry="$3" _dryrc="$4" _upgraderc="$5" _updmode="$6" _abi1="$7" _abi2="$8" _kern2="$9" \
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
        ssh_guest() {
          printf "%s\n" "$*" >> "$CALLS"
          case "$*" in
            "/usr/local/sbin/pkg config ABI")
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
              printf "%s\n" "applying upgrades"
              return "$_upgraderc"
              ;;
            "/sbin/reboot") return 0 ;;
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

  # C2
  It 'applies a pending plan, reboots, and re-verifies ABI/kernel major after'
    When call run_refresh 'FreeBSD:15:amd64' '15.0-RELEASE' 'Number of packages to be upgraded: 3' 0 0 '' '' '' ''
    The status should be success
    The output should include 'PKG_WAS_UPGRADED=1'
    The output should include 'REACHED-AFTER-REFRESH'
    The contents of file "$CALLS" should include '/sbin/reboot'
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

  # C5
  It 'fails closed when pkg upgrade -y itself fails (no || true swallow)'
    When call run_refresh 'FreeBSD:15:amd64' '15.0-RELEASE' 'Number of packages to be upgraded: 3' 0 1 '' '' '' ''
    The status should be failure
    The stderr should include 'pkg upgrade'
    The output should not include 'REACHED-AFTER-REFRESH'
  End

  # C6
  It 'fails closed when the post-reboot ABI major differs from the snapshot'
    When call run_refresh 'FreeBSD:15:amd64' '15.0-RELEASE' 'Number of packages to be upgraded: 3' 0 0 '' '' 'FreeBSD:16:amd64' '16.0-RELEASE'
    The status should be failure
    The stderr should include 'FreeBSD:16:amd64'
    The stderr should include 'FreeBSD:15:amd64'
    The output should not include 'REACHED-AFTER-REFRESH'
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
    When call run_refresh 'FreeBSD:15:amd64' '15.0-RELEASE' 'Number of packages to be upgraded: 3' 0 0 '' '' '' '15-STABLE'
    The status should be failure
    The stderr should include '15-STABLE'
    The stderr should include 'FreeBSD:15:amd64'
    The output should not include 'REACHED-AFTER-REFRESH'
  End
End
