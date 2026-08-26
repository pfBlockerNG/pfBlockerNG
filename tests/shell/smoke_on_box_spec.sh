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
    # The venv step shells out to uv; these examples cover the steps around it, not
    # dependency resolution, so the stub records its argv and cwd instead.
    cat > "${WORK}/bin/uv" <<'STUBEOF'
#!/bin/sh
printf '%s|%s\n' "$PWD" "$*" >> "${FAKE_UV_LOG:-/dev/null}"
if [ "${FAKE_UV_CREATE_PYTHON:-0}" -eq 1 ]; then
    mkdir -p "$PWD/.venv/bin"
    cat > "$PWD/.venv/bin/python" <<'PYEOF'
#!/bin/sh
printf '%s\n' "$*" > "$DEP_BUILDER_ARGV_LOG"
printf '%s\n' /tmp/fake-dep.pkg
PYEOF
    chmod +x "$PWD/.venv/bin/python"
fi
exit "${FAKE_UV_EXIT:-0}"
STUBEOF
    chmod +x "${WORK}/bin/uv"

    # The leg preflights every tool it shells out to, and several are box-only (no
    # qemu or iptables on a dev laptop, none of them in a CI container). Stub the
    # presence of exactly those so these examples assert the SCRIPT's behaviour rather
    # than the host's package list; the tools these examples actually invoke (git, jq,
    # python3) stay real.
    for _absent in qemu-system-x86_64 qemu-img iptables dig ssh; do
        printf '#!/bin/sh\nexit 0\n' > "${WORK}/bin/${_absent}"
        chmod +x "${WORK}/bin/${_absent}"
    done
    PATH="${WORK}/bin:${PATH}"
    ORAS_ARGV_LOG="${WORK}/oras-argv"
    FAKE_UV_LOG="${WORK}/uv-argv"
    true > "$ORAS_ARGV_LOG"
    true > "$FAKE_UV_LOG"
    export PATH ORAS_ARGV_LOG FAKE_UV_LOG

    git_fixture -C "$FAKE_ROOT" init --quiet . >/dev/null 2>&1
    git_fixture -C "$FAKE_ROOT" -c user.name=t -c user.email=t@example.com \
        commit --quiet --allow-empty -m seed >/dev/null 2>&1

    # Pin the port floor ABOVE 53 so the gate fires on every host. Reading the ambient
    # /proc value would make these examples host-dependent: on a host that already has the
    # floor lowered the run sails past the gate into the real host prep, whose
    # `pkill -9 -f qemu-system-x86_64` would kill a concurrent leg's VMs on a shared box.
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
    # The floor is the caller's to lower -- it needs a privilege this script does not
    # assume. If this precondition is dropped the run continues and the non-root mock DNS
    # fails to bind :53 halfway through, which reads as a test failure rather than as
    # unprepared host state. A host that has NOT lowered the floor (any dev machine, and
    # the spec runner) takes this path, so the example is meaningful wherever the suite
    # runs.
    When run sh "$SCRIPT" --ref HEAD
    The status should equal 1
    The stderr should include 'ip_unprivileged_port_start'
    The stderr should include 'sysctl -w'
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
    # A typo in the bootstrap command would otherwise be dropped on the floor and the leg
    # would run with defaults, producing a green result for the wrong configuration.
    When run sh "$SCRIPT" --not-a-real-flag
    The status should not equal 0
    The stderr should be present
  End

  It 'prepares the same channel selected for the package build'
    # Stop at the sparse-Ports boundary: no image pull, host prep, package build or VM.
    printf '0\n' > "${WORK}/port-floor"
    # The php/py the ports prep is given come from this leg's matrix row (issue #2464),
    # so the boundary needs the row present.
    cat > "${FAKE_ROOT}/scripts/read-version-matrix.sh" <<'STUBEOF'
#!/bin/sh
printf '%s\n' '[{"freebsd_major":"15","extra_pkgs":[],"py_flavor":"py311","php_version":"8.3"}]'
STUBEOF
    chmod +x "${FAKE_ROOT}/scripts/read-version-matrix.sh"
    SPARSE_CHANNEL_FILE="${WORK}/sparse-channel"
    SPARSE_EXIT=42
    export SPARSE_CHANNEL_FILE SPARSE_EXIT

    When run sh "$SCRIPT" --ref HEAD --channel testing
    The status should equal 42
    The stderr should include 'channel=testing'
    The contents of file "$SPARSE_CHANNEL_FILE" should equal 'testing'
  End

  It 'refuses to build when the matrix has no row for this ABI major'
    # issue #2464: the php/py a leg builds with come from ITS OWN matrix row. There is no
    # major -> php table to fall back on, so an unknown major must stop the run rather than
    # silently build a package with the wrong php.
    printf '0\n' > "${WORK}/port-floor"
    cat > "${FAKE_ROOT}/scripts/read-version-matrix.sh" <<'STUBEOF'
#!/bin/sh
printf '%s\n' '[{"freebsd_major":"15","extra_pkgs":[],"py_flavor":"py311","php_version":"8.3"}]'
STUBEOF
    chmod +x "${FAKE_ROOT}/scripts/read-version-matrix.sh"
    SPARSE_CHANNEL_FILE="${WORK}/sparse-channel-unused"
    SPARSE_EXIT=42
    export SPARSE_CHANNEL_FILE SPARSE_EXIT

    When run sh "$SCRIPT" --ref HEAD --abi FreeBSD:99:amd64
    The status should not equal 0
    The status should not equal 42
    The stderr should include 'no matrix row for FreeBSD major 99'
    The path "$SPARSE_CHANNEL_FILE" should not be exist
  End

  It 'pulls both images into distinct per-run directories'
    printf '0\n' > "${WORK}/port-floor"
    cat > "${FAKE_ROOT}/scripts/build-leg.sh" <<'STUBEOF'
#!/bin/sh
printf '%s\n' /tmp/fake.pkg
STUBEOF
    cat > "${FAKE_ROOT}/scripts/read-version-matrix.sh" <<'STUBEOF'
#!/bin/sh
printf '%s\n' '[{"freebsd_major":"15","extra_pkgs":[],"py_flavor":"py311","php_version":"8.3"}]'
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

    # A qcow2 left by an earlier run of a DIFFERENT variant or version. The names carry
    # both, so it would not be overwritten -- and tests/smoke/conftest.py refuses a
    # directory holding more than one, which strands the box for every later run. The
    # count=1 assertions below are what pin the emptying.
    mkdir -p "${FAKE_ROOT}/out/smoke-images/pfsense" "${FAKE_ROOT}/out/smoke-images/civm"
    true > "${FAKE_ROOT}/out/smoke-images/pfsense/pfSense-Plus_26.03.qcow2"
    true > "${FAKE_ROOT}/out/smoke-images/civm/civm_v0.qcow2"

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
printf '%s\n' '[{"freebsd_major":"15","extra_pkgs":[],"py_flavor":"py311","php_version":"8.3"}]'
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
    cat > "${FAKE_ROOT}/scripts/read-version-matrix.sh" <<'STUBEOF'
#!/bin/sh
printf '%s\n' '[{"freebsd_major":"15","extra_pkgs":[],"py_flavor":"py311","php_version":"8.3"}]'
STUBEOF
    chmod +x "${FAKE_ROOT}/scripts/read-version-matrix.sh"
    ORAS_PULL_EXIT=37
    export ORAS_PULL_EXIT

    When run sh "$SCRIPT" --ref HEAD --no-two-vm
    The status should equal 37
    The stderr should include 'pulling pfSense image'
    The stderr should not include 'building .pkg'
  End

  It 'rejects a descriptor that disagrees with the resolved digest before pulling'
    printf '0\n' > "${WORK}/port-floor"
    cat > "${FAKE_ROOT}/scripts/read-version-matrix.sh" <<'STUBEOF'
#!/bin/sh
printf '%s\n' '[{"freebsd_major":"15","extra_pkgs":[],"py_flavor":"py311","php_version":"8.3"}]'
STUBEOF
    chmod +x "${FAKE_ROOT}/scripts/read-version-matrix.sh"
    ORAS_DESCRIPTOR_DIGEST=sha256:different
    export ORAS_DESCRIPTOR_DIGEST

    When run sh "$SCRIPT" --ref HEAD --no-two-vm
    The status should equal 1
    The stderr should include 'descriptor digest sha256:different disagrees with resolved digest sha256:manifest'
    The contents of file "$ORAS_ARGV_LOG" should not include 'pull ghcr.io/pfblockerng/pfsense-ce'
  End

  It 'syncs the LOCKED smoke group into the repo-root venv, and fails the run when that fails'
    # `--locked` is the property: it resolves against the checked-out ref's uv.lock, so
    # the box gets the same transitive graph CI does. Run from REPO_ROOT, since uv reads
    # the pyproject and lock relative to its cwd. A sync failure must abort the run, not
    # fall through to a pytest that would import whatever the box happens to have.
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
printf '%s\n' '[{"freebsd_major":"15","extra_pkgs":[],"py_flavor":"py311","php_version":"8.3"}]'
STUBEOF
    chmod +x "${FAKE_ROOT}/scripts/build-leg.sh" "${FAKE_ROOT}/scripts/read-version-matrix.sh"

    true > "${WORK}/smoke-ssh-key"
    SMOKE_SSH_KEY="${WORK}/smoke-ssh-key"
    FAKE_UV_EXIT=42
    export SMOKE_SSH_KEY FAKE_UV_EXIT

    cat > "${WORK}/bin/pkill" <<'STUBEOF'
#!/bin/sh
exit 0
STUBEOF
    chmod +x "${WORK}/bin/pkill"

    When run sh "$SCRIPT" --ref HEAD --no-two-vm
    The status should equal 42
    The stderr should include 'provisioning test venv'
    The contents of file "$FAKE_UV_LOG" should equal "${FAKE_ROOT}|sync --locked --group smoke --group dep-pkg-build"
  End

  It 'syncs dep-pkg-build before an extra_pkgs leg reaches the locked builder argv'
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
printf '%s\n' '[{"freebsd_major":"15","extra_pkgs":["textproc/py-charset-normalizer"],"py_flavor":"py311","php_version":"8.3"}]'
STUBEOF
    cat > "${FAKE_ROOT}/scripts/run-smoke.sh" <<'STUBEOF'
#!/bin/sh
printf 'deps=%s\n' "$SMOKE_DEP_PKGS"
STUBEOF
    chmod +x "${FAKE_ROOT}/scripts/build-leg.sh" "${FAKE_ROOT}/scripts/read-version-matrix.sh" \
        "${FAKE_ROOT}/scripts/run-smoke.sh"

    mkdir -p "${PFB_ONBOX_PORTS_DIR}/textproc/py-charset-normalizer"
    printf 'PORTNAME=charset-normalizer\n' > "${PFB_ONBOX_PORTS_DIR}/textproc/py-charset-normalizer/Makefile"
    git_fixture -C "$PFB_ONBOX_PORTS_DIR" init --quiet .
    git_fixture -C "$PFB_ONBOX_PORTS_DIR" add .
    git_fixture -C "$PFB_ONBOX_PORTS_DIR" -c user.name=t -c user.email=t@example.com \
        commit --quiet -m seed
    git_fixture -C "$PFB_ONBOX_PORTS_DIR" sparse-checkout init --cone
    PORTS_HEAD="$(git_fixture -C "$PFB_ONBOX_PORTS_DIR" rev-parse HEAD)"
    SOURCE_EPOCH="$(git_fixture -C "$FAKE_ROOT" show -s --format=%ct HEAD)"

    true > "${WORK}/smoke-ssh-key"
    SMOKE_SSH_KEY="${WORK}/smoke-ssh-key"
    DEP_BUILDER_ARGV_LOG="${WORK}/dep-builder-argv"
    FAKE_UV_CREATE_PYTHON=1
    export SMOKE_SSH_KEY DEP_BUILDER_ARGV_LOG FAKE_UV_CREATE_PYTHON
    cat > "${WORK}/bin/pkill" <<'STUBEOF'
#!/bin/sh
exit 0
STUBEOF
    chmod +x "${WORK}/bin/pkill"

    When run sh "$SCRIPT" --ref HEAD --no-two-vm
    The status should equal 0
    The stdout should include 'deps=/tmp/fake-dep.pkg'
    The stderr should include 'dep pkgs built: /tmp/fake-dep.pkg'
    The contents of file "$FAKE_UV_LOG" should equal "${FAKE_ROOT}|sync --locked --group smoke --group dep-pkg-build"
    The contents of file "$DEP_BUILDER_ARGV_LOG" should equal \
        "scripts/build-dep-pkg-portable.py --ports ${PFB_ONBOX_PORTS_DIR} --ports-sha ${PORTS_HEAD} --port textproc/py-charset-normalizer --py-flavor py311 --freebsd-major 15 --source-date-epoch ${SOURCE_EPOCH} --out-dir ${FAKE_ROOT}/out/deppkgs"
  End

  # Parametrised over three entries drawn from different corners of the list: a box-only
  # binary (iptables), the venv driver (uv), and the process reaper the teardown calls
  # (pkill). A single-tool example proves the mechanism but not the LIST, so dropping an
  # entry from it would otherwise go unnoticed.
  # Parametrised over a tool the box always had and one this migration added. Not over a
  # tool that lives in /usr/bin: this example hides the tool by dropping every PATH entry
  # carrying it, and on Linux /bin symlinks to /usr/bin, so that would take `sh` with it
  # and the run would fail on a missing shell instead of on the preflight.
  Parameters
    uv
    iptables
  End

  It 'refuses to run at all when a required tool is missing from the box'
    # Without the tool a run that continued would grade against whatever the box happens
    # to carry, or fail far later with a worse message.
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
printf '%s\n' '[{"freebsd_major":"15","extra_pkgs":[],"py_flavor":"py311","php_version":"8.3"}]'
STUBEOF
    chmod +x "${FAKE_ROOT}/scripts/build-leg.sh" "${FAKE_ROOT}/scripts/read-version-matrix.sh"

    true > "${WORK}/smoke-ssh-key"
    SMOKE_SSH_KEY="${WORK}/smoke-ssh-key"
    export SMOKE_SSH_KEY

    cat > "${WORK}/bin/pkill" <<'STUBEOF'
#!/bin/sh
exit 0
STUBEOF
    chmod +x "${WORK}/bin/pkill"

    # Drop every PATH entry that carries the tool, the stub's included: a bare
    # "$WORK/bin only" PATH would fail on a missing `sh` instead, which proves nothing.
    rm -f "${WORK}/bin/$1"
    NOUV_PATH=''
    _oldifs="$IFS"; IFS=':'
    for _d in $PATH; do
      [ -x "${_d}/$1" ] && continue
      NOUV_PATH="${NOUV_PATH:+${NOUV_PATH}:}${_d}"
    done
    IFS="$_oldifs"

    When run sh -c "PATH='$NOUV_PATH' sh '$SCRIPT' --ref HEAD --no-two-vm"
    The status should equal 2
    The stderr should include 'missing required tools on this box'
    The stderr should include "$1"
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
printf '%s\n' '[{"freebsd_major":"15","extra_pkgs":[],"py_flavor":"py311","php_version":"8.3"}]'
STUBEOF
    chmod +x "${FAKE_ROOT}/scripts/build-leg.sh" "${FAKE_ROOT}/scripts/read-version-matrix.sh"

    VENV_TARGET="${WORK}/external-venv-target"
    mkdir -p "$VENV_TARGET" "${FAKE_ROOT}/tests/smoke"
    true > "${VENV_TARGET}/sentinel"
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
printf '%s\n' '[{"freebsd_major":"15","extra_pkgs":[],"py_flavor":"py311","php_version":"8.3"}]'
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
