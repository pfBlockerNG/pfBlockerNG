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
    unset ORAS_DESCRIPTOR_DIGEST SMOKE_PFSENSE_REF SMOKE_PFSENSE_VERSION
    WORK="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/smokeonbox.XXXXXX")"
    FAKE_ROOT="${WORK}/repo"
    mkdir -p "${FAKE_ROOT}/scripts/lib"

    # The real libs the script sources before it parses anything.
    cp "${PFB_ROOT}/scripts/lib/git-env-scrub.sh" "${FAKE_ROOT}/scripts/lib/"
    cp "${PFB_ROOT}/scripts/lib/smoke-tier.sh"    "${FAKE_ROOT}/scripts/lib/"
    cp "${PFB_ROOT}/scripts/lib/lan-registry.sh"  "${FAKE_ROOT}/scripts/lib/"

    # Stubs for the steps between arg-parsing and the port-floor gate: the ports update
    # and image pulls both shell out, and neither is what this setup covers.
    cat > "${FAKE_ROOT}/scripts/sparse-clone-ports.sh" <<'STUBEOF'
#!/bin/sh
[ -z "${SPARSE_CHANNEL_FILE:-}" ] || printf '%s\n' "$4" > "$SPARSE_CHANNEL_FILE"
exit "${SPARSE_EXIT:-0}"
STUBEOF
    chmod +x "${FAKE_ROOT}/scripts/sparse-clone-ports.sh"
    mkdir -p "${WORK}/bin"
    cat > "${WORK}/bin/oras" <<'STUBEOF'
#!/bin/sh
printf '%s\n' "$*" >> "${ORAS_ARGV_LOG:-/dev/null}"
case "$*" in
    resolve*)
        printf '%s\n' 'sha256:manifest'
        exit 0
        ;;
    *manifest\ fetch*)
        case "$*" in
            *--descriptor*) printf '{"digest":"%s"}\n' "${ORAS_DESCRIPTOR_DIGEST:-sha256:manifest}" ;;
            *) printf '%s\n' '{"annotations":{"io.github.pfblockerng.pfsense-version":"2.8.1-RELEASE","org.opencontainers.image.version":"2.8","org.opencontainers.image.created":"2026-07-28T08:48:36Z"}}' ;;
        esac
        exit 0
        ;;
    *\ pull\ *|pull\ *)
        case "$*" in
            *civm*) true > civm.qcow2 ;;
            *)      true > pfsense.qcow2 ;;
        esac
        exit "${ORAS_PULL_EXIT:-0}"
        ;;
esac
exit 0
STUBEOF
    chmod +x "${WORK}/bin/oras"
    PATH="${WORK}/bin:${PATH}"
    ORAS_ARGV_LOG="${WORK}/oras-argv"
    true > "$ORAS_ARGV_LOG"
    export PATH ORAS_ARGV_LOG

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
    PFB_ONBOX_IMAGES_DIR="${WORK}/images"
    export WORK FAKE_ROOT PFB_ONBOX_REPO_ROOT PFB_ONBOX_PORTS_DIR PFB_ONBOX_IMAGES_DIR \
        PFB_ONBOX_PORT_FLOOR_FILE
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

  It 'prepares the same channel selected for the package build'
    # Stop at the sparse-Ports boundary: no image pull, host prep, package build or VM.
    printf '0\n' > "${WORK}/port-floor"
    SPARSE_CHANNEL_FILE="${WORK}/sparse-channel"
    SPARSE_EXIT=42
    export SPARSE_CHANNEL_FILE SPARSE_EXIT

    When run sh "$SCRIPT" --ref HEAD --channel testing
    The status should equal 42
    The stderr should include 'channel=testing'
    The contents of file "$SPARSE_CHANNEL_FILE" should equal 'testing'
  End

  It 'pulls both images into distinct container-local directories'
    printf '0\n' > "${WORK}/port-floor"
    cat > "${FAKE_ROOT}/scripts/build-leg.sh" <<'STUBEOF'
#!/bin/sh
printf '%s\n' /tmp/fake.pkg
STUBEOF
    cat > "${FAKE_ROOT}/scripts/read-version-matrix.sh" <<'STUBEOF'
#!/bin/sh
printf '%s\n' '[{"freebsd_major":"15","extra_pkgs":[],"py_flavor":"py311"}]'
STUBEOF
    cat > "${FAKE_ROOT}/scripts/run-smoke.sh" <<'STUBEOF'
#!/bin/sh
printf 'server=%s count=%s\n' "$SMOKE_IMAGE_DIR" \
    "$(find "$SMOKE_IMAGE_DIR" -maxdepth 1 -name '*.qcow2' | wc -l | tr -d ' ')"
printf 'client=%s count=%s\n' "$SMOKE_CLIENT_IMAGE_DIR" \
    "$(find "$SMOKE_CLIENT_IMAGE_DIR" -maxdepth 1 -name '*.qcow2' | wc -l | tr -d ' ')"
printf 'identity image_ref=%s expected_version=%s expected_abi=%s\n' \
    "$SMOKE_IMAGE_REF" "$SMOKE_PFSENSE_VERSION" "$SMOKE_ABI"
STUBEOF
    chmod +x "${FAKE_ROOT}/scripts/build-leg.sh" "${FAKE_ROOT}/scripts/read-version-matrix.sh" \
        "${FAKE_ROOT}/scripts/run-smoke.sh"

    mkdir -p "${FAKE_ROOT}/.venv/bin"
    true > "${FAKE_ROOT}/.venv/reuse-sentinel"
    cat > "${FAKE_ROOT}/.venv/bin/python" <<'STUBEOF'
#!/bin/sh
exit 0
STUBEOF
    chmod +x "${FAKE_ROOT}/.venv/bin/python"
    true > "${WORK}/smoke-ssh-key"
    SMOKE_SSH_KEY="${WORK}/smoke-ssh-key"
    PFB_LAN_REGISTRY=10.0.0.111
    SMOKE_GHCR_TOKEN=test-token
    PFB_ONBOX_IMAGES_DIR="${FAKE_ROOT}/out/smoke-images"
    export SMOKE_SSH_KEY PFB_LAN_REGISTRY SMOKE_GHCR_TOKEN PFB_ONBOX_IMAGES_DIR

    cat > "${WORK}/bin/pkill" <<'STUBEOF'
#!/bin/sh
exit 0
STUBEOF
    chmod +x "${WORK}/bin/pkill"

    When run sh "$SCRIPT" --ref HEAD
    The status should equal 0
    The stderr should include 'running smoke'
    The stdout should include "server=${FAKE_ROOT}/out/smoke-images/pfsense count=1"
    The stdout should include "client=${FAKE_ROOT}/out/smoke-images/civm count=1"
    The stdout should include 'identity image_ref=10.0.0.111/pfblockerng/pfsense-ce:2.8 expected_version=2.8 expected_abi=FreeBSD:15:amd64'
    The stderr should include '"pfsense_version":"2.8.1-RELEASE"'
    The file "${FAKE_ROOT}/.venv/reuse-sentinel" should be exist
    The contents of file "$ORAS_ARGV_LOG" should include 'pull --plain-http 10.0.0.111/pfblockerng/pfsense-ce:2.8@sha256:manifest'
    The contents of file "$ORAS_ARGV_LOG" should include 'pull --plain-http 10.0.0.111/pfblockerng/civm:v1@sha256:manifest'
    The contents of file "$ORAS_ARGV_LOG" should include 'resolve --plain-http 10.0.0.111/pfblockerng/pfsense-ce:2.8'
    The contents of file "$ORAS_ARGV_LOG" should include 'manifest fetch --plain-http 10.0.0.111/pfblockerng/pfsense-ce:2.8@sha256:manifest --descriptor'
    The contents of file "$ORAS_ARGV_LOG" should include 'manifest fetch --plain-http 10.0.0.111/pfblockerng/pfsense-ce:2.8@sha256:manifest'
    The contents of file "$ORAS_ARGV_LOG" should not include 'login'
  End

  It 'pulls only pfSense when --no-two-vm is set'
    printf '0\n' > "${WORK}/port-floor"
    cat > "${FAKE_ROOT}/scripts/build-leg.sh" <<'STUBEOF'
#!/bin/sh
printf '%s\n' /tmp/fake.pkg
STUBEOF
    cat > "${FAKE_ROOT}/scripts/read-version-matrix.sh" <<'STUBEOF'
#!/bin/sh
printf '%s\n' '[{"freebsd_major":"15","extra_pkgs":[],"py_flavor":"py311"}]'
STUBEOF
    cat > "${FAKE_ROOT}/scripts/run-smoke.sh" <<'STUBEOF'
#!/bin/sh
printf 'server=%s count=%s\n' "$SMOKE_IMAGE_DIR" \
    "$(find "$SMOKE_IMAGE_DIR" -maxdepth 1 -name '*.qcow2' | wc -l | tr -d ' ')"
printf 'expected_version=%s\n' "$SMOKE_PFSENSE_VERSION"
STUBEOF
    chmod +x "${FAKE_ROOT}/scripts/build-leg.sh" "${FAKE_ROOT}/scripts/read-version-matrix.sh" \
        "${FAKE_ROOT}/scripts/run-smoke.sh"
    mkdir -p "${FAKE_ROOT}/.venv/bin"
    cat > "${FAKE_ROOT}/.venv/bin/python" <<'STUBEOF'
#!/bin/sh
exit 0
STUBEOF
    chmod +x "${FAKE_ROOT}/.venv/bin/python"
    true > "${WORK}/smoke-ssh-key"
    SMOKE_SSH_KEY="${WORK}/smoke-ssh-key"
    SMOKE_GHCR_TOKEN=test-token
    SMOKE_PFSENSE_REF=ghcr.io/pfblockerng/pfsense-ce@sha256:manifest
    PFB_ONBOX_IMAGES_DIR="${FAKE_ROOT}/out/smoke-images"
    export SMOKE_SSH_KEY SMOKE_GHCR_TOKEN SMOKE_PFSENSE_REF PFB_ONBOX_IMAGES_DIR
    cat > "${WORK}/bin/pkill" <<'STUBEOF'
#!/bin/sh
exit 0
STUBEOF
    chmod +x "${WORK}/bin/pkill"

    When run sh "$SCRIPT" --ref HEAD --no-two-vm
    The status should equal 0
    The stderr should include 'running smoke'
    The stdout should include "server=${FAKE_ROOT}/out/smoke-images/pfsense count=1"
    The stdout should include 'expected_version=?'
    The contents of file "$ORAS_ARGV_LOG" should include 'login ghcr.io --username pfBlockerNG --password-stdin'
    The contents of file "$ORAS_ARGV_LOG" should include 'pull ghcr.io/pfblockerng/pfsense-ce@sha256:manifest'
    The contents of file "$ORAS_ARGV_LOG" should not include '--plain-http'
    The contents of file "$ORAS_ARGV_LOG" should not include 'civm'
  End

  It 'propagates a direct image pull failure'
    printf '0\n' > "${WORK}/port-floor"
    ORAS_PULL_EXIT=37
    export ORAS_PULL_EXIT

    When run sh "$SCRIPT" --ref HEAD --no-two-vm
    The status should equal 37
    The stderr should include 'pulling pfSense image'
    The stderr should not include 'building .pkg'
  End

  It 'rejects a descriptor that disagrees with the resolved digest before pulling'
    printf '0\n' > "${WORK}/port-floor"
    ORAS_DESCRIPTOR_DIGEST=sha256:different
    export ORAS_DESCRIPTOR_DIGEST

    When run sh "$SCRIPT" --ref HEAD --no-two-vm
    The status should equal 1
    The stderr should include 'descriptor digest sha256:different disagrees with resolved digest sha256:manifest'
    The contents of file "$ORAS_ARGV_LOG" should not include 'pull ghcr.io/pfblockerng/pfsense-ce'
  End

  It 'clears an invalid existing venv before recreating it'
    printf '0\n' > "${WORK}/port-floor"

    # Reach only the venv boundary: package/image work is unrelated and remains stubbed.
    cat > "${FAKE_ROOT}/scripts/lib/lan-registry.sh" <<'STUBEOF'
pfb_lan_registry_active() { return 1; }
pfb_rewrite_lan_registry() { printf '%s\n' "$1"; }
STUBEOF
    cat > "${FAKE_ROOT}/scripts/build-leg.sh" <<'STUBEOF'
#!/bin/sh
printf '%s\n' /tmp/fake.pkg
STUBEOF
    cat > "${FAKE_ROOT}/scripts/read-version-matrix.sh" <<'STUBEOF'
#!/bin/sh
printf '%s\n' '[{"freebsd_major":"15","extra_pkgs":[],"py_flavor":"py311"}]'
STUBEOF
    chmod +x "${FAKE_ROOT}/scripts/build-leg.sh" "${FAKE_ROOT}/scripts/read-version-matrix.sh"

    mkdir -p "${FAKE_ROOT}/.venv/bin"
    cat > "${FAKE_ROOT}/.venv/bin/python" <<'STUBEOF'
#!/bin/sh
printf '%s\n' "$*" > "$VENV_PYTHON_ARGS_FILE"
exit 1
STUBEOF
    chmod +x "${FAKE_ROOT}/.venv/bin/python"
    true > "${WORK}/smoke-ssh-key"
    SMOKE_SSH_KEY="${WORK}/smoke-ssh-key"
    VENV_ARGS_FILE="${WORK}/venv-args"
    VENV_PYTHON_ARGS_FILE="${WORK}/venv-python-args"
    export SMOKE_SSH_KEY VENV_ARGS_FILE VENV_PYTHON_ARGS_FILE

    cat > "${WORK}/bin/python3" <<'STUBEOF'
#!/bin/sh
printf '%s\n' "$*" > "$VENV_ARGS_FILE"
exit 42
STUBEOF
    cat > "${WORK}/bin/pkill" <<'STUBEOF'
#!/bin/sh
exit 0
STUBEOF
    chmod +x "${WORK}/bin/python3" "${WORK}/bin/pkill"

    When run sh "$SCRIPT" --ref HEAD --no-two-vm
    The status should equal 42
    The stderr should include 'provisioning test venv'
    The contents of file "$VENV_PYTHON_ARGS_FILE" should equal '-m pip --version'
    The contents of file "$VENV_ARGS_FILE" should equal "-m venv --clear ${FAKE_ROOT}/.venv"
  End

  It 'refuses a symlinked venv root without clearing its target'
    printf '0\n' > "${WORK}/port-floor"

    cat > "${FAKE_ROOT}/scripts/lib/lan-registry.sh" <<'STUBEOF'
pfb_lan_registry_active() { return 1; }
pfb_rewrite_lan_registry() { printf '%s\n' "$1"; }
STUBEOF
    cat > "${FAKE_ROOT}/scripts/build-leg.sh" <<'STUBEOF'
#!/bin/sh
printf '%s\n' /tmp/fake.pkg
STUBEOF
    cat > "${FAKE_ROOT}/scripts/read-version-matrix.sh" <<'STUBEOF'
#!/bin/sh
printf '%s\n' '[{"freebsd_major":"15","extra_pkgs":[],"py_flavor":"py311"}]'
STUBEOF
    chmod +x "${FAKE_ROOT}/scripts/build-leg.sh" "${FAKE_ROOT}/scripts/read-version-matrix.sh"

    VENV_TARGET="${WORK}/external-venv-target"
    mkdir -p "$VENV_TARGET" "${FAKE_ROOT}/tests/smoke"
    true > "${VENV_TARGET}/sentinel"
    true > "${FAKE_ROOT}/tests/smoke/requirements.txt"
    ln -s "$VENV_TARGET" "${FAKE_ROOT}/.venv"
    true > "${WORK}/smoke-ssh-key"
    SMOKE_SSH_KEY="${WORK}/smoke-ssh-key"
    PIP_NO_INDEX=1
    export SMOKE_SSH_KEY PIP_NO_INDEX

    cat > "${WORK}/bin/pkill" <<'STUBEOF'
#!/bin/sh
exit 0
STUBEOF
    chmod +x "${WORK}/bin/pkill"

    When run sh "$SCRIPT" --ref HEAD --no-two-vm
    The status should equal 2
    The stderr should include 'unsafe venv path'
    The file "${VENV_TARGET}/sentinel" should be exist
  End

  It 'refuses a non-directory venv root without clearing it'
    printf '0\n' > "${WORK}/port-floor"

    cat > "${FAKE_ROOT}/scripts/lib/lan-registry.sh" <<'STUBEOF'
pfb_lan_registry_active() { return 1; }
pfb_rewrite_lan_registry() { printf '%s\n' "$1"; }
STUBEOF
    cat > "${FAKE_ROOT}/scripts/build-leg.sh" <<'STUBEOF'
#!/bin/sh
printf '%s\n' /tmp/fake.pkg
STUBEOF
    cat > "${FAKE_ROOT}/scripts/read-version-matrix.sh" <<'STUBEOF'
#!/bin/sh
printf '%s\n' '[{"freebsd_major":"15","extra_pkgs":[],"py_flavor":"py311"}]'
STUBEOF
    chmod +x "${FAKE_ROOT}/scripts/build-leg.sh" "${FAKE_ROOT}/scripts/read-version-matrix.sh"

    printf 'sentinel\n' > "${FAKE_ROOT}/.venv"
    true > "${WORK}/smoke-ssh-key"
    SMOKE_SSH_KEY="${WORK}/smoke-ssh-key"
    export SMOKE_SSH_KEY

    When run sh "$SCRIPT" --ref HEAD --no-two-vm
    The status should equal 2
    The stderr should include 'unsafe venv path'
    The contents of file "${FAKE_ROOT}/.venv" should equal 'sentinel'
  End

  # ── LAN registry ref rewrite (issue #2247) ───────────────────────────────── #
  #
  # The config echo (config abi=... pfsense_ref=... civm_ref=...) fires BEFORE the
  # port-floor gate exits, so it is the seam these examples use to observe the
  # rewrite without letting the run reach real host prep (pkill, venv, oras pulls).
  # pfsense_ref/civm_ref are echoed AFTER their rewrite by construction (single
  # choke point right after PFSENSE_REF/CIVM_REF resolve).

  It 'rewrites the default ghcr.io pfsense/civm refs to the LAN registry when set'
    PFB_LAN_REGISTRY=10.0.0.111
    export PFB_LAN_REGISTRY
    When run sh "$SCRIPT" --ref HEAD
    The status should equal 1
    The stderr should include 'pfsense_ref=10.0.0.111/pfblockerng/pfsense-ce:2.8'
    The stderr should include 'civm_ref=10.0.0.111/pfblockerng/civm:v1'
  End

  It 'rewrites a workflow-injected full ghcr.io ref the same way'
    # Covers both script defaults (above) and a full ref a caller injects via
    # SMOKE_PFSENSE_REF/CIVM_REF -- one choke point, same rewrite either way.
    PFB_LAN_REGISTRY=10.0.0.111
    SMOKE_PFSENSE_REF=ghcr.io/pfblockerng/pfsense-ce:2.9
    CIVM_REF=ghcr.io/pfblockerng/civm:v2
    export PFB_LAN_REGISTRY SMOKE_PFSENSE_REF CIVM_REF
    When run sh "$SCRIPT" --ref HEAD
    The status should equal 1
    The stderr should include 'pfsense_ref=10.0.0.111/pfblockerng/pfsense-ce:2.9'
    The stderr should include 'civm_ref=10.0.0.111/pfblockerng/civm:v2'
  End

  It 'leaves a ref that does not start with ghcr.io/ untouched even when the var is set'
    PFB_LAN_REGISTRY=10.0.0.111
    SMOKE_PFSENSE_REF=quay.io/pfblockerng/pfsense-ce:2.8
    export PFB_LAN_REGISTRY SMOKE_PFSENSE_REF
    When run sh "$SCRIPT" --ref HEAD
    The status should equal 1
    The stderr should include 'pfsense_ref=quay.io/pfblockerng/pfsense-ce:2.8'
  End

  It 'leaves refs untouched when PFB_LAN_REGISTRY is unset (hosted-CI fallback)'
    When run sh "$SCRIPT" --ref HEAD
    The status should equal 1
    The stderr should include 'pfsense_ref=ghcr.io/pfblockerng/pfsense-ce:2.8'
    The stderr should include 'civm_ref=ghcr.io/pfblockerng/civm:v1'
  End

  It 'keeps an @digest suffix intact when rewriting to the LAN registry'
    PFB_LAN_REGISTRY=10.0.0.111
    SMOKE_PFSENSE_REF=ghcr.io/pfblockerng/pfsense-ce:2.8@sha256:deadbeef
    export PFB_LAN_REGISTRY SMOKE_PFSENSE_REF
    When run sh "$SCRIPT" --ref HEAD
    The status should equal 1
    The stderr should include 'pfsense_ref=10.0.0.111/pfblockerng/pfsense-ce:2.8@sha256:deadbeef'
  End

  It 'joins a port-bearing LAN registry with exactly one slash'
    PFB_LAN_REGISTRY=10.0.0.111:80
    export PFB_LAN_REGISTRY
    When run sh "$SCRIPT" --ref HEAD
    The status should equal 1
    The stderr should include 'pfsense_ref=10.0.0.111:80/pfblockerng/pfsense-ce:2.8'
  End

  It 'treats an empty-but-set PFB_LAN_REGISTRY as unset'
    PFB_LAN_REGISTRY=
    export PFB_LAN_REGISTRY
    When run sh "$SCRIPT" --ref HEAD
    The status should equal 1
    The stderr should include 'pfsense_ref=ghcr.io/pfblockerng/pfsense-ce:2.8'
  End
End
