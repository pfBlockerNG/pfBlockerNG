#shellcheck shell=sh
# boot_vm_spec.sh — shellspec suite for tests/smoke/boot_vm.sh's SMOKE_NET_MODE toggle.
#
# Pins the assembled QEMU -netdev argv for BOTH network backends, BOTH roles:
#   - slirp (default): user-net + hostfwd, EXACTLY as before this toggle existed
#     (behaviour-preserving oracle — these assertions must stay green across the change).
#   - bridge: tap devices on the named bridges (SMOKE_WAN_TAP / SMOKE_MGMT_TAP /
#     SMOKE_CLIENT_MGMT_TAP), with the LAN crossover socket (net2/net1) and the
#     unassigned net3-7 IDENTICAL to slirp (only WAN+MGMT switch backend).
# Also pins that an error path exits NON-ZERO (the cleanup trap must not mask it).
#
# Hermetic: stubs qemu-system-x86_64 (records its argv) + qemu-img (touches the
# overlay) via SMOKE_QEMU_BIN / SMOKE_QEMU_IMG_BIN — no real VM boots.

Describe 'boot_vm.sh SMOKE_NET_MODE toggle'
  SCRIPT="${PFB_ROOT}/tests/smoke/boot_vm.sh"

  setup() {
    scrub_git_env
    unset SMOKE_NET_MODE SMOKE_WAN_TAP SMOKE_MGMT_TAP SMOKE_CLIENT_MGMT_TAP
    WORK="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/bootvmspec.XXXXXX")"
    ARGV_FILE="${WORK}/argv"
    BASE="${WORK}/base.qcow2"; : > "$BASE"
    OVERLAY="${WORK}/ovl.qcow2"
    BIN="${WORK}/bin"; mkdir -p "$BIN"

    # Stub qemu: record argv (one per line), don't boot.
    cat > "${BIN}/qemu" << 'QEOF'
#!/bin/sh
printf '%s\n' "$@" > "$ARGV_FILE"
QEOF
    chmod +x "${BIN}/qemu"
    # Stub qemu-img: create the overlay (its LAST arg) so the -drive path is valid.
    cat > "${BIN}/qemu-img" << 'QIEOF'
#!/bin/sh
while [ "$#" -gt 1 ]; do shift; done
: > "$1"
QIEOF
    chmod +x "${BIN}/qemu-img"

    SMOKE_QEMU_BIN="${BIN}/qemu"
    SMOKE_QEMU_IMG_BIN="${BIN}/qemu-img"
    export WORK ARGV_FILE BASE OVERLAY SMOKE_QEMU_BIN SMOKE_QEMU_IMG_BIN
  }
  teardown() { rm -rf "$WORK"; }
  BeforeEach 'setup'
  AfterEach 'teardown'

  # ---- slirp (default) — behaviour-preserving oracle -------------------------

  Describe 'slirp mode (default), role pfsense'
    It 'WAN net0 is user-net with the 192.168.89.2 host alias'
      When run sh "$SCRIPT" --role pfsense "$BASE" "$OVERLAY"
      The status should be success
      The stderr should include 'boot_vm:'
      The contents of file "$ARGV_FILE" should include 'user,id=net0,net=192.168.89.0/24,host=192.168.89.2'
    End

    It 'MGMT net1 is user-net with the ssh + web hostfwd'
      When run sh "$SCRIPT" --role pfsense "$BASE" "$OVERLAY"
      The status should be success
      The stderr should include 'boot_vm:'
      The contents of file "$ARGV_FILE" should include 'hostfwd=tcp::2222-192.168.43.15:22'
    End

    It 'LAN net2 is the crossover socket listener'
      When run sh "$SCRIPT" --role pfsense "$BASE" "$OVERLAY"
      The status should be success
      The stderr should include 'boot_vm:'
      The contents of file "$ARGV_FILE" should include 'socket,id=net2,listen=127.0.0.1:12340'
    End

    It 'net3 is an isolated restrict user-net'
      When run sh "$SCRIPT" --role pfsense "$BASE" "$OVERLAY"
      The status should be success
      The stderr should include 'boot_vm:'
      The contents of file "$ARGV_FILE" should include 'user,id=net3,net=10.30.0.0/24,restrict=on'
    End

    It 'emits NO tap backend'
      When run sh "$SCRIPT" --role pfsense "$BASE" "$OVERLAY"
      The status should be success
      The stderr should include 'boot_vm:'
      The contents of file "$ARGV_FILE" should not include 'tap,id=net0'
    End
  End

  # ---- bridge mode, role pfsense --------------------------------------------

  Describe 'bridge mode, role pfsense'
    It 'WAN net0 is a tap on the named WAN device'
      When run env SMOKE_NET_MODE=bridge SMOKE_WAN_TAP=tap-wan0 SMOKE_MGMT_TAP=tap-mgmt0 sh "$SCRIPT" --role pfsense "$BASE" "$OVERLAY"
      The status should be success
      The stderr should include 'boot_vm:'
      The contents of file "$ARGV_FILE" should include 'tap,id=net0,ifname=tap-wan0,script=no,downscript=no'
    End

    It 'MGMT net1 is a tap on the named MGMT device'
      When run env SMOKE_NET_MODE=bridge SMOKE_WAN_TAP=tap-wan0 SMOKE_MGMT_TAP=tap-mgmt0 sh "$SCRIPT" --role pfsense "$BASE" "$OVERLAY"
      The status should be success
      The stderr should include 'boot_vm:'
      The contents of file "$ARGV_FILE" should include 'tap,id=net1,ifname=tap-mgmt0,script=no,downscript=no'
    End

    It 'keeps the LAN crossover socket (net2) and net3 restrict unchanged'
      When run env SMOKE_NET_MODE=bridge SMOKE_WAN_TAP=tap-wan0 SMOKE_MGMT_TAP=tap-mgmt0 sh "$SCRIPT" --role pfsense "$BASE" "$OVERLAY"
      The status should be success
      The stderr should include 'boot_vm:'
      The contents of file "$ARGV_FILE" should include 'socket,id=net2,listen=127.0.0.1:12340'
      The contents of file "$ARGV_FILE" should include 'user,id=net3,net=10.30.0.0/24,restrict=on'
    End

    It 'emits NO user-net hostfwd on WAN/MGMT'
      When run env SMOKE_NET_MODE=bridge SMOKE_WAN_TAP=tap-wan0 SMOKE_MGMT_TAP=tap-mgmt0 sh "$SCRIPT" --role pfsense "$BASE" "$OVERLAY"
      The status should be success
      The stderr should include 'boot_vm:'
      The contents of file "$ARGV_FILE" should not include 'hostfwd='
    End
  End

  # ---- role client -----------------------------------------------------------

  Describe 'role client'
    It 'slirp: MGMT net0 is user-net hostfwd; data net1 is the connect socket'
      When run sh "$SCRIPT" --role client "$BASE" "$OVERLAY"
      The status should be success
      The stderr should include 'boot_vm:'
      The contents of file "$ARGV_FILE" should include 'user,id=net0,hostfwd=tcp::2223-:22'
      The contents of file "$ARGV_FILE" should include 'socket,id=net1,connect=127.0.0.1:12340'
    End

    It 'bridge: MGMT net0 is a tap; data net1 stays the connect socket; no hostfwd'
      When run env SMOKE_NET_MODE=bridge SMOKE_CLIENT_MGMT_TAP=tap-cli0 sh "$SCRIPT" --role client "$BASE" "$OVERLAY"
      The status should be success
      The stderr should include 'boot_vm:'
      The contents of file "$ARGV_FILE" should include 'tap,id=net0,ifname=tap-cli0,script=no,downscript=no'
      The contents of file "$ARGV_FILE" should include 'socket,id=net1,connect=127.0.0.1:12340'
      The contents of file "$ARGV_FILE" should not include 'hostfwd='
    End
  End

  # ---- guards (must exit NON-ZERO — the cleanup trap must not mask it) --------

  Describe 'guards'
    It 'rejects an invalid SMOKE_NET_MODE'
      When run env SMOKE_NET_MODE=wat sh "$SCRIPT" --role pfsense "$BASE" "$OVERLAY"
      The status should equal 2
      The stderr should include "SMOKE_NET_MODE must be 'slirp' or 'bridge'"
    End

    It 'pfsense bridge mode fails fast (exit 1) when SMOKE_WAN_TAP is unset'
      When run env SMOKE_NET_MODE=bridge SMOKE_MGMT_TAP=tap-mgmt0 sh "$SCRIPT" --role pfsense "$BASE" "$OVERLAY"
      The status should equal 1
      The stderr should include 'SMOKE_WAN_TAP'
    End

    It 'pfsense bridge mode fails fast (exit 1) when SMOKE_MGMT_TAP is unset'
      When run env SMOKE_NET_MODE=bridge SMOKE_WAN_TAP=tap-wan0 sh "$SCRIPT" --role pfsense "$BASE" "$OVERLAY"
      The status should equal 1
      The stderr should include 'SMOKE_MGMT_TAP'
    End

    It 'client bridge mode fails fast (exit 1) when SMOKE_CLIENT_MGMT_TAP is unset'
      When run env SMOKE_NET_MODE=bridge sh "$SCRIPT" --role client "$BASE" "$OVERLAY"
      The status should equal 1
      The stderr should include 'SMOKE_CLIENT_MGMT_TAP'
    End
  End
End
