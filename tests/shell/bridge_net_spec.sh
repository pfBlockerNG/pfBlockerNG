#shellcheck shell=sh
# bridge_net_spec.sh — shellspec suite for scripts/bridge-net.sh's 'up'/'down' API.
#
# Pins the command contract:
#   - 'up' creates br-wan (192.168.89.2/24) + br-mgmt (192.168.43.2/24) and lane-named taps
#   - 'up' starts dnsmasq DHCP-only (port=0) with static MGMT leases at .15 / .16
#   - 'up' emits SMOKE_* vars on stdout (strict allowlist KEY=value format)
#   - 'up' is idempotent: calls 'down' first (link del AND link add both present)
#   - per-lane tap names: SMOKE_LANE=1 → tap-wan1 / tap-mgmt1 / tap-cli1
#   - SMOKE_VM_MAC line-2 override drives the pfSense MGMT lease MAC
#   - 'down' deletes taps + bridges; exits 0 even when nothing exists
#   - 'down' exits 0 even when ip link del returns non-zero (missing devices)
#   - invalid SMOKE_LANE (non-numeric) → exit 2 for both up and down
#   - metacharacters in SMOKE_PFSENSE_MGMT_IP → exit 2 (injection rejected)
#   - unknown subcommand → exit 2 with usage on stderr
#
# Hermetic: stubs ip (SMOKE_IP_BIN), dnsmasq (SMOKE_DNSMASQ_BIN), and the runtime
# dir (SMOKE_BRIDGE_RUN_DIR) so no real bridges, taps, DHCP, or root-owned dirs.

Describe 'bridge-net.sh'
  SCRIPT="${PFB_ROOT}/scripts/bridge-net.sh"

  setup() {
    scrub_git_env
    unset SMOKE_LANE SMOKE_VM_MAC SMOKE_CLIENT_MGMT_MAC \
          SMOKE_PFSENSE_MGMT_IP SMOKE_CLIENT_MGMT_IP SMOKE_BRIDGE_RUN_DIR
    WORK="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/bridgenetspec.XXXXXX")"
    IP_ARGV_FILE="${WORK}/ip_argv"
    DNSMASQ_ARGV_FILE="${WORK}/dnsmasq_argv"
    BIN="${WORK}/bin"
    mkdir -p "${BIN}"

    # ip stub: each invocation appends one space-joined line to IP_ARGV_FILE.
    # "$*" (space-joined) lets assertions match multi-word argv like
    # "link add br-wan type bridge" as a single substring.
    cat > "${BIN}/ip" << 'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$IP_ARGV_FILE"
EOF
    chmod +x "${BIN}/ip"

    # dnsmasq stub: records all args as one space-joined line; exits 0 (no daemonize).
    cat > "${BIN}/dnsmasq" << 'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$DNSMASQ_ARGV_FILE"
EOF
    chmod +x "${BIN}/dnsmasq"

    # Runtime dir override: keeps the PID file out of the real /run/pfb-smoke.
    RUNDIR="${WORK}/run"
    SMOKE_IP_BIN="${BIN}/ip"
    SMOKE_DNSMASQ_BIN="${BIN}/dnsmasq"
    SMOKE_BRIDGE_RUN_DIR="${RUNDIR}"
    export WORK IP_ARGV_FILE DNSMASQ_ARGV_FILE SMOKE_IP_BIN SMOKE_DNSMASQ_BIN \
           SMOKE_BRIDGE_RUN_DIR RUNDIR
  }
  teardown() { rm -rf "${WORK}"; }
  BeforeEach 'setup'
  AfterEach  'teardown'

  # ---- up: bridge creation -----------------------------------------------

  Describe 'up creates br-wan (192.168.89.2/24)'
    It 'adds br-wan, assigns 192.168.89.2/24, and brings it up'
      When run sh "$SCRIPT" up
      The status should be success
      The stderr should include 'bridge-net:'
      The stdout should include 'SMOKE_WAN_TAP=tap-wan0'
      # Contract: ip link add br-wan type bridge + addr add 192.168.89.2/24 + link set up
      The contents of file "$IP_ARGV_FILE" should include 'link add br-wan type bridge'
      The contents of file "$IP_ARGV_FILE" should include 'addr add 192.168.89.2/24 dev br-wan'
      The contents of file "$IP_ARGV_FILE" should include 'link set br-wan up'
    End
  End

  Describe 'up creates br-mgmt (192.168.43.2/24)'
    It 'adds br-mgmt, assigns 192.168.43.2/24, and brings it up'
      When run sh "$SCRIPT" up
      The status should be success
      The stderr should include 'bridge-net:'
      The stdout should include 'SMOKE_MGMT_TAP=tap-mgmt0'
      The contents of file "$IP_ARGV_FILE" should include 'link add br-mgmt type bridge'
      The contents of file "$IP_ARGV_FILE" should include 'addr add 192.168.43.2/24 dev br-mgmt'
    End
  End

  # ---- up: tap creation and bridge attachment ----------------------------

  Describe 'up creates lane-0 taps attached to the correct bridges'
    It 'creates tap-wan0 and attaches it to br-wan'
      When run sh "$SCRIPT" up
      The status should be success
      The stderr should include 'bridge-net:'
      The stdout should include 'SMOKE_WAN_TAP=tap-wan0'
      # Contract: tuntap add tap-wan0 mode tap + link set tap-wan0 master br-wan
      The contents of file "$IP_ARGV_FILE" should include 'tuntap add tap-wan0 mode tap'
      The contents of file "$IP_ARGV_FILE" should include 'link set tap-wan0 master br-wan'
    End

    It 'creates tap-mgmt0 and attaches it to br-mgmt'
      When run sh "$SCRIPT" up
      The status should be success
      The stderr should include 'bridge-net:'
      The stdout should include 'SMOKE_MGMT_TAP=tap-mgmt0'
      The contents of file "$IP_ARGV_FILE" should include 'tuntap add tap-mgmt0 mode tap'
      The contents of file "$IP_ARGV_FILE" should include 'link set tap-mgmt0 master br-mgmt'
    End

    It 'creates tap-cli0 (civm MGMT) and attaches it to br-mgmt'
      When run sh "$SCRIPT" up
      The status should be success
      The stderr should include 'bridge-net:'
      The stdout should include 'SMOKE_CLIENT_MGMT_TAP=tap-cli0'
      # civm shares the MGMT bridge — different MAC/static-lease, same subnet
      The contents of file "$IP_ARGV_FILE" should include 'tuntap add tap-cli0 mode tap'
      The contents of file "$IP_ARGV_FILE" should include 'link set tap-cli0 master br-mgmt'
    End
  End

  # ---- up: dnsmasq DHCP --------------------------------------------------

  Describe 'up starts dnsmasq DHCP-only with correct ranges and static leases'
    It 'passes --port=0 (DHCP-only; stub DNS owns :53) and per-bridge ranges'
      When run sh "$SCRIPT" up
      The status should be success
      The stderr should include 'bridge-net:'
      The stdout should include 'SMOKE_WAN_TAP=tap-wan0'
      # §5.2 + §7.3: DHCP-only; dnsmasq auto-announces itself as gw+DNS per subnet
      The contents of file "$DNSMASQ_ARGV_FILE" should include '--port=0'
      The contents of file "$DNSMASQ_ARGV_FILE" \
        should include '--dhcp-range=192.168.89.50,192.168.89.150,255.255.255.0'
      The contents of file "$DNSMASQ_ARGV_FILE" \
        should include '--dhcp-range=192.168.43.50,192.168.43.150,255.255.255.0'
    End

    It 'adds static leases for pfSense MGMT (→.15) and civm MGMT (→.16)'
      When run sh "$SCRIPT" up
      The status should be success
      The stderr should include 'bridge-net:'
      The stdout should include 'SMOKE_PFSENSE_MGMT_IP=192.168.43.15'
      # Default CE net1 MAC → .15 (P3 PFSENSE_MGMT_IP); civm MAC → .16 (P3 CLIENT_MGMT_IP)
      The contents of file "$DNSMASQ_ARGV_FILE" \
        should include '--dhcp-host=BC:24:11:80:42:35,192.168.43.15'
      The contents of file "$DNSMASQ_ARGV_FILE" \
        should include '--dhcp-host=BC:24:11:29:A4:1B,192.168.43.16'
    End

    It 'passes a lane-scoped --pid-file so down can stop the right dnsmasq instance'
      When run sh "$SCRIPT" up
      The status should be success
      The stderr should include 'bridge-net:'
      The stdout should include 'SMOKE_CLIENT_MGMT_IP=192.168.43.16'
      The contents of file "$DNSMASQ_ARGV_FILE" \
        should include "--pid-file=${RUNDIR}/dnsmasq-0.pid"
    End
  End

  # ---- up: eval-able stdout exports --------------------------------------

  Describe 'up emits all five eval-able SMOKE_* vars on stdout'
    It 'emits tap names and MGMT IPs that match P3 conftest defaults'
      When run sh "$SCRIPT" up
      The status should be success
      The stderr should include 'bridge-net:'
      # All five required by smoke-on-box.sh's eval + export block
      The stdout should include 'SMOKE_WAN_TAP=tap-wan0'
      The stdout should include 'SMOKE_MGMT_TAP=tap-mgmt0'
      The stdout should include 'SMOKE_CLIENT_MGMT_TAP=tap-cli0'
      The stdout should include 'SMOKE_PFSENSE_MGMT_IP=192.168.43.15'
      The stdout should include 'SMOKE_CLIENT_MGMT_IP=192.168.43.16'
    End
  End

  # ---- up: idempotency (down-first) --------------------------------------

  Describe 'up is idempotent: runs down first, then creates'
    It 'ip-argv contains both link del (from down-first) and link add (from create)'
      When run sh "$SCRIPT" up
      The status should be success
      The stderr should include 'bridge-net:'
      The stdout should include 'SMOKE_WAN_TAP=tap-wan0'
      # down-first: stale taps/bridges deleted before recreating
      The contents of file "$IP_ARGV_FILE" should include 'link del br-wan'
      # create pass follows immediately after
      The contents of file "$IP_ARGV_FILE" should include 'link add br-wan type bridge'
    End
  End

  # ---- per-lane tap names ------------------------------------------------

  Describe 'per-lane tap names: SMOKE_LANE=1 → tap-wan1, tap-mgmt1, tap-cli1'
    It 'WAN tap is tap-wan1, not tap-wan0, in both stdout and ip-argv'
      When run env SMOKE_LANE=1 sh "$SCRIPT" up
      The status should be success
      The stderr should include 'bridge-net:'
      # Before/after: lane-1 names present, lane-0 names absent (lane isolation)
      The stdout should include 'SMOKE_WAN_TAP=tap-wan1'
      The stdout should not include 'SMOKE_WAN_TAP=tap-wan0'
      The contents of file "$IP_ARGV_FILE" should include 'tuntap add tap-wan1 mode tap'
      The contents of file "$IP_ARGV_FILE" should not include 'tuntap add tap-wan0 mode tap'
    End

    It 'MGMT and client taps are tap-mgmt1 and tap-cli1'
      When run env SMOKE_LANE=1 sh "$SCRIPT" up
      The status should be success
      The stderr should include 'bridge-net:'
      The stdout should include 'SMOKE_MGMT_TAP=tap-mgmt1'
      The stdout should include 'SMOKE_CLIENT_MGMT_TAP=tap-cli1'
    End
  End

  # ---- SMOKE_VM_MAC line-2 override for the pfSense MGMT lease -----------

  Describe 'SMOKE_VM_MAC line-2 override drives the pfSense MGMT static lease'
    setup_mac() {
      # Outer BeforeEach 'setup' already ran; add the MAC override on top.
      # Provide an 8-line SMOKE_VM_MAC where line 2 (net1/MGMT) is a distinct MAC.
      SMOKE_VM_MAC="$(printf '%s\n' \
          'AA:BB:CC:DD:EE:00' \
          'AA:BB:CC:DD:EE:11' \
          'AA:BB:CC:DD:EE:22' \
          'AA:BB:CC:DD:EE:33' \
          'AA:BB:CC:DD:EE:44' \
          'AA:BB:CC:DD:EE:55' \
          'AA:BB:CC:DD:EE:66' \
          'AA:BB:CC:DD:EE:77')"
      export SMOKE_VM_MAC
    }
    BeforeEach 'setup_mac'

    It 'uses line 2 of SMOKE_VM_MAC (net1) not the hardcoded CE default for the .15 lease'
      When run sh "$SCRIPT" up
      The status should be success
      The stderr should include 'bridge-net:'
      The stdout should include 'SMOKE_PFSENSE_MGMT_IP=192.168.43.15'
      # Proves bridge-net.sh mirrors boot_vm.sh's nth_mac 1 = sed -n '2p'
      The contents of file "$DNSMASQ_ARGV_FILE" \
        should include 'AA:BB:CC:DD:EE:11,192.168.43.15'
      The contents of file "$DNSMASQ_ARGV_FILE" \
        should not include 'BC:24:11:80:42:35'
    End
  End

  # ---- down: idempotent teardown -----------------------------------------

  Describe 'down deletes taps and bridges; exits 0 even when nothing exists'
    It 'issues ip link del for all taps and both bridges'
      When run sh "$SCRIPT" down
      The status should be success
      The contents of file "$IP_ARGV_FILE" should include 'link del br-wan'
      The contents of file "$IP_ARGV_FILE" should include 'link del br-mgmt'
      The contents of file "$IP_ARGV_FILE" should include 'link del tap-wan0'
    End
  End

  # ---- unknown / missing subcommand --------------------------------------

  Describe 'unknown or missing subcommand'
    It 'exits 2 with usage on stderr for an unknown subcommand'
      When run sh "$SCRIPT" blah
      The status should equal 2
      The stderr should include 'Usage:'
    End

    It 'exits 2 with usage on stderr when no subcommand is given'
      When run sh "$SCRIPT"
      The status should equal 2
      The stderr should include 'Usage:'
    End
  End

  # ---- down: tolerates ip link del errors --------------------------------

  Describe 'down tolerates ip link del errors (missing devices are not an error)'
    setup_fail_ip() {
      # Override the ip stub (setup() already ran) with one that exits 1 on
      # 'link del *' to simulate missing devices.  Proves the || true guards work.
      cat > "${BIN}/ip" << 'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$IP_ARGV_FILE"
case "$*" in link\ del*) exit 1 ;; esac
EOF
      chmod +x "${BIN}/ip"
    }
    BeforeEach 'setup_fail_ip'

    It 'exits 0 even when ip link del returns non-zero (|| true guards protect it)'
      When run sh "$SCRIPT" down
      The status should be success
      The contents of file "$IP_ARGV_FILE" should include 'link del br-wan'
    End
  End

  # ---- input validation: invalid SMOKE_LANE ------------------------------

  Describe 'input validation: non-numeric SMOKE_LANE is rejected before any command runs'
    It 'down with SMOKE_LANE=bad exits 2 with a message about SMOKE_LANE'
      # RED→GREEN: pre-validation code has no exit 2 for bad LANE → status was 0 or 1.
      # After validation: exits 2 with the SMOKE_LANE message.
      When run env SMOKE_LANE=bad sh "$SCRIPT" down
      The status should equal 2
      The stderr should include 'SMOKE_LANE'
    End

    It 'up with SMOKE_LANE=bad exits 2 with a message about SMOKE_LANE'
      When run env SMOKE_LANE=bad sh "$SCRIPT" up
      The status should equal 2
      The stderr should include 'SMOKE_LANE'
    End
  End

  # ---- input validation: injection in SMOKE_PFSENSE_MGMT_IP -------------

  Describe 'input validation: metacharacters in SMOKE_PFSENSE_MGMT_IP are rejected'
    It 'up with a semicolon-injection in SMOKE_PFSENSE_MGMT_IP exits 2'
      # RED→GREEN: pre-validation code passes the value straight to dnsmasq args;
      # after validation: exits 2 before any binary is called.
      When run env SMOKE_PFSENSE_MGMT_IP='1.2.3.4; rm -rf /' sh "$SCRIPT" up
      The status should equal 2
      The stderr should include 'invalid characters'
    End
  End
End
