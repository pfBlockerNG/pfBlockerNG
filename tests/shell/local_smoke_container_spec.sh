#shellcheck shell=sh
# local_smoke_container_spec.sh — issue #2223: the on-box leg runs inside
# ghcr.io/pfblockerng/ci-runner-vm, not against a toolchain installed on the box.
#
# WHY THIS EXISTS: the PFB_BOXES were converted to unprivileged LXCs carrying Docker and
# nothing else — qemu, oras, php and node now live in the image. The bootstrap string that
# local-smoke.sh hands to select-box.sh is therefore the ONLY thing standing between a lease
# and a working run, and every part of it is load-bearing:
#
#   * --device /dev/kvm — without it qemu silently falls back to TCG and the suite times out
#     rather than failing cleanly. Verified end to end on the fleet: the device passes from
#     the Proxmox host, through the unprivileged LXC, into the container.
#   * --sysctl net.ipv4.ip_unprivileged_port_start=53 — the non-root mock DNS binds :53.
#     This used to be an in-script `sysctl -w`, which cannot work from inside a container;
#     the namespaced sysctl replaces it, so if it is dropped the mock DNS fails to bind.
#   * the bind mounts — the repo, the shared image store, the ports tree and the guest SSH
#     key all live on the box and must be visible inside, or every run re-clones and re-pulls.
#   * the sparse checkout — a smoke leg reads only src/, scripts/ and tests/smoke/. Checking
#     out the whole tree costs 38 MB against 13 MB for what it uses.
#
# The flag-encoding examples are inherited responsibility: smoke_on_box_channel_spec.sh used
# to pin that a --channel carrying shell metacharacters survived the re-exec argv rebuild.
# That re-exec is gone, so the same property has to hold across the docker argument list,
# where word-splitting is if anything easier to get wrong.

Describe 'local-smoke.sh containerised bootstrap (issue #2223)'
  SCRIPT="${PFB_ROOT}/scripts/local-smoke.sh"

  setup() {
    scrub_git_env
    WORK="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/lscontainer.XXXXXX")"
    CALLS_DIR="${WORK}/calls"
    mkdir -p "$CALLS_DIR"

    FAKE_SELECT_BOX="${WORK}/fake-select-box.sh"
    cat > "$FAKE_SELECT_BOX" <<'EOF'
#!/bin/sh
# Record the bootstrap string select-box.sh would run on the leased box.
while [ "$#" -gt 0 ]; do
    case "$1" in
        --) shift; break ;;
        *) shift ;;
    esac
done
_call_file="$(mktemp "${CALLS_DIR}/call.XXXXXX")"
printf '%s\n' "$*" > "$_call_file"
exit 0
EOF
    chmod +x "$FAKE_SELECT_BOX"

    PFB_SELECT_BOX="$FAKE_SELECT_BOX"
    PFB_BOXES="dummy@dummy"
    export PFB_SELECT_BOX PFB_BOXES WORK CALLS_DIR
  }

  teardown() { rm -rf "$WORK"; }

  BeforeEach 'setup'
  AfterEach 'teardown'

  bootstrap() {
    sh "$SCRIPT" "$@" >/dev/null 2>&1
    cat "$CALLS_DIR"/* 2>/dev/null
  }

  # ── the container invocation ─────────────────────────────────────────────── #

  It 'runs the leg inside the VM runner image'
    When call bootstrap --ref dummy
    The output should include 'docker run'
    The output should include 'ghcr.io/pfblockerng/ci-runner-vm'
  End

  It 'passes /dev/kvm into the container'
    # Absent this, qemu falls back to TCG: the run does not fail, it crawls until the
    # job's timeout, which reads as a flake rather than a misconfiguration.
    When call bootstrap --ref dummy
    The output should include '--device /dev/kvm'
  End

  It 'lowers the unprivileged port floor via the namespaced sysctl'
    # Replaces the in-script `sysctl -w`, which a container cannot perform on the host.
    When call bootstrap --ref dummy
    The output should include '--sysctl net.ipv4.ip_unprivileged_port_start=53'
  End

  It 'mounts the repo, the shared image store, the ports tree and the guest key'
    When call bootstrap --ref dummy
    The output should include '/root/pfBlockerNG:/root/pfBlockerNG'
    The output should include '/root/images:/root/images'
    The output should include '/root/FreeBSD-ports:/root/FreeBSD-ports'
    The output should include '/root/smoke-ssh-key'
  End

  # ── the sparse checkout ──────────────────────────────────────────────────── #

  It 'checks out only the paths a smoke leg reads'
    # src/ (the .pkg build), scripts/ (the harness) and tests/smoke/ (the suite). Excludes
    # .ADRs (8.2 MB), tests/php (5.2 MB) and plugins (2.7 MB), none of which smoke touches.
    When call bootstrap --ref dummy
    The output should include 'sparse-checkout'
    The output should include 'src scripts tests/smoke'
  End

  It 'still fetches the ci-metadata orphan ref the version matrix reads'
    # read-version-matrix.sh reads origin/ci-metadata, which is a REF and not a path, so a
    # sparse checkout does not bring it: it has to be fetched explicitly or every
    # matrix-derived value on the box silently falls back.
    When call bootstrap --ref dummy
    The output should include 'ci-metadata'
  End

  # ── flag encoding across the docker argument list ────────────────────────── #

  It 'carries an explicit channel through to the container command'
    When call bootstrap --ref dummy --channel testing
    The output should include "--channel 'testing'"
  End

  It 'keeps a space-bearing filter as ONE argument across the docker command'
    # --channel cannot carry metacharacters: local-smoke.sh whitelists it to
    # stable|testing|edge|nightly and rejects anything else, which is stronger than
    # quoting. --filter is the free-form value (a pytest -k expression), so it is the one
    # that must survive the docker argument list unsplit -- inherited from the re-exec
    # spec this replaces.
    When call bootstrap --ref dummy --filter 'a and not b'
    The output should include "--filter 'a and not b'"
  End

  It 'does not re-fetch the ref inside the container'
    # The bootstrap already checks out the requested ref on the box; the container runs an
    # already-resolved tree. A second fetch inside would make the container decide which
    # code runs and force the repo mount to be writable.
    When call bootstrap --ref dummy
    The output should not include 'PFB_ONBOX_REEXEC'
  End
End
