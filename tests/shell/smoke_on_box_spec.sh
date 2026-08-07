#shellcheck shell=sh
# smoke_on_box_spec.sh — issue #2223: execution coverage for smoke-on-box.sh itself.
#
# WHY THIS EXISTS: smoke_on_box_channel_spec.sh used to be the only spec that RAN this
# script, and it was removed with the re-exec it tested. Its properties are covered on the
# orchestrator side, but its *execution* coverage was not: with nothing running the script,
# breaking its argument parsing or its new port-floor precondition produced no failure
# anywhere in the suite. This restores a direct run.
#
# TOPOLOGY: PFB_ONBOX_REPO_ROOT points the script at a throwaway git repo carrying only the
# libs it sources, so no image is pulled, no package is built and no VM boots. The script
# reaches the port-floor precondition and stops there, which is exactly the region this
# spec covers.

Describe 'smoke-on-box.sh (issue #2223)'
  SCRIPT="${PFB_ROOT}/scripts/smoke-on-box.sh"

  setup() {
    scrub_git_env
    WORK="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/smokeonbox.XXXXXX")"
    FAKE_ROOT="${WORK}/repo"
    mkdir -p "${FAKE_ROOT}/scripts/lib"

    # The real libs the script sources before it parses anything.
    cp "${PFB_ROOT}/scripts/lib/git-env-scrub.sh" "${FAKE_ROOT}/scripts/lib/"
    cp "${PFB_ROOT}/scripts/lib/smoke-tier.sh"    "${FAKE_ROOT}/scripts/lib/"
    cp "${PFB_ROOT}/scripts/lib/oras-refresh.sh"  "${FAKE_ROOT}/scripts/lib/"

    # Stubs for the steps between arg-parsing and the port-floor gate: the ports refresh
    # and the image refresh both shell out, and neither is what this spec covers.
    cat > "${FAKE_ROOT}/scripts/sparse-clone-ports.sh" <<'STUBEOF'
#!/bin/sh
exit 0
STUBEOF
    chmod +x "${FAKE_ROOT}/scripts/sparse-clone-ports.sh"
    mkdir -p "${WORK}/bin"
    cat > "${WORK}/bin/oras" <<'STUBEOF'
#!/bin/sh
exit 0
STUBEOF
    chmod +x "${WORK}/bin/oras"
    PATH="${WORK}/bin:${PATH}"
    export PATH

    git_fixture -C "$FAKE_ROOT" init --quiet . >/dev/null 2>&1
    git_fixture -C "$FAKE_ROOT" -c user.name=t -c user.email=t@example.com \
        commit --quiet --allow-empty -m seed >/dev/null 2>&1

    # Pin the port floor ABOVE 53 so the gate fires on every host. Reading the ambient
    # /proc value would make these examples host-dependent: on a host that already has the
    # floor lowered (this script's own container does exactly that) the run sails past the
    # gate into the real host prep, whose `pkill -9 -f qemu-system-x86_64` would kill a
    # concurrent leg's VMs on a shared box.
    printf '1024\n' > "${WORK}/port-floor"
    PFB_ONBOX_PORT_FLOOR_FILE="${WORK}/port-floor"

    PFB_ONBOX_REPO_ROOT="$FAKE_ROOT"
    PFB_ONBOX_PORTS_DIR="${WORK}/ports"
    export WORK FAKE_ROOT PFB_ONBOX_REPO_ROOT PFB_ONBOX_PORTS_DIR PFB_ONBOX_PORT_FLOOR_FILE
  }

  teardown() { rm -rf "$WORK"; }

  BeforeEach 'setup'
  AfterEach 'teardown'

  # ── the port-floor precondition ──────────────────────────────────────────── #

  It 'refuses to run when the unprivileged port floor is above 53'
    # The floor used to be lowered in-script with `sysctl -w`, which a container cannot do
    # against the host; the caller now passes --sysctl instead. If this precondition is
    # dropped the run continues and the non-root mock DNS fails to bind :53 halfway
    # through, which reads as a test failure rather than a missing docker flag.
    # A host that has NOT lowered the floor (any dev machine, and the spec runner) takes
    # this path, so the example is meaningful wherever the suite runs.
    When run sh "$SCRIPT" --ref HEAD
    The status should equal 1
    The stderr should include 'ip_unprivileged_port_start'
    The stderr should include '--sysctl'
  End

  It 'reads the floor from the seam, not from the ambient host'
    # Proves the seam is load-bearing WITHOUT letting a run past the gate: the message
    # echoes the floor it actually read, so a distinctive value can only appear if the seam
    # was honoured. Drop the seam and the script reads /proc, reporting the host's value
    # (1024 on any default host) instead of this one.
    printf '4321\n' > "${WORK}/port-floor"
    When run sh "$SCRIPT" --ref HEAD
    The status should equal 1
    The stderr should include '4321'
  End

  It 'names the flag the caller has to pass, not just the symptom'
    # A bare "cannot bind" would send the reader looking at the mock DNS instead of at the
    # invocation that is actually missing a flag.
    When run sh "$SCRIPT" --ref HEAD
    The status should equal 1
    The stderr should include 'net.ipv4.ip_unprivileged_port_start=53'
  End

  # ── argument parsing ─────────────────────────────────────────────────────── #

  It 'parses --ref and reports the ref it is running at'
    # The caller resolves the ref before invoking this script; the value still has to
    # survive parsing, because it is what the run is labelled with.
    When run sh "$SCRIPT" --ref my-test-ref
    The stderr should include 'running at ref my-test-ref'
    The status should equal 1
  End

  It 'falls back to the checked-out HEAD when no --ref is given'
    When run sh "$SCRIPT"
    The stderr should include 'running at ref'
    The status should equal 1
  End

  It 'parses every flag, not just the ones used before the precondition'
    # The precondition exits before --abi/--channel/--marker/--filter/--shard are USED, so
    # without the config echo their parsing is unobservable and a broken flag reads as a
    # leg that quietly ran the default.
    When run sh "$SCRIPT" --ref r --abi FreeBSD:16:amd64 --channel testing --marker ui \
        --filter 'a and b' --shard 2 --shard-total 5 --no-two-vm
    The stderr should include 'abi=FreeBSD:16:amd64'
    The stderr should include 'channel=testing'
    The stderr should include 'marker=ui'
    The stderr should include 'filter=a and b'
    The stderr should include 'shard=2/5'
    The stderr should include 'two-vm=no'
    The status should equal 1
  End

  It 'rejects an unknown flag instead of silently ignoring it'
    # A typo in the docker command would otherwise be dropped on the floor and the leg
    # would run with defaults, producing a green result for the wrong configuration.
    When run sh "$SCRIPT" --not-a-real-flag
    The status should not equal 0
    The stderr should be present
  End
End
