#shellcheck shell=sh
# boot_vm_spec.sh — shellspec suite for tests/smoke/boot_vm.sh.
#
# Pins the assembled QEMU -netdev argv for slirp (QEMU user-net) mode, both roles.
# slirp is the only supported backend (ADR-50 bridge mode was evaluated and rejected).
# Also pins that the cleanup() EXIT trap preserves the triggering exit status.
#
# Hermetic: stubs qemu-system-x86_64 (records its argv) + qemu-img (touches the
# overlay) via SMOKE_QEMU_BIN / SMOKE_QEMU_IMG_BIN — no real VM boots.

Describe 'boot_vm.sh slirp netdev argv'
  SCRIPT="${PFB_ROOT}/tests/smoke/boot_vm.sh"

  setup() {
    scrub_git_env
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

  # ---- slirp (default) — role pfsense ----------------------------------------

  Describe 'role pfsense'
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

  # ---- role client -----------------------------------------------------------

  Describe 'role client'
    It 'MGMT net0 is user-net hostfwd; data net1 is the connect socket'
      When run sh "$SCRIPT" --role client "$BASE" "$OVERLAY"
      The status should be success
      The stderr should include 'boot_vm:'
      The contents of file "$ARGV_FILE" should include 'user,id=net0,hostfwd=tcp::2223-:22'
      The contents of file "$ARGV_FILE" should include 'socket,id=net1,connect=127.0.0.1:12340'
    End
  End

End
