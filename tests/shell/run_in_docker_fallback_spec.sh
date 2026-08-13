#shellcheck shell=sh
# run_in_docker_fallback_spec.sh — the wrapper's one hard invariant: it always runs the
# command it was given.
#
# WHY THIS EXISTS: the wrapper is an optimisation (the CI toolchain, and ~3x faster than
# the host for the pytest suite on Apple Silicon), but the images it wants are currently
# PRIVATE, so on a machine without a GHCR login every path to a container fails. A wrapper
# that refuses to run in that situation is worse than no wrapper — you would stop reaching
# for it, which is how a convenience becomes a liability.
#
# So every failure to reach a container degrades to a host run. The property that makes
# that safe rather than sloppy is the MESSAGE: each fallback names the reason it happened,
# because the failure mode being designed against is not "the command did not run", it is
# "the command ran on the host and I thought it ran in the container". A silent fallback
# would be the bug. Hence every example below asserts both halves — the command ran, and
# the run said why it was not containerised.
#
# The docker stub answers by exit code alone (STUB_*_RC), which is all the wrapper reads.
# `docker run` is the exception: it echoes, so the examples that must prove the container
# path was NOT abandoned have something positive to assert on.

Describe 'run-in-docker.sh host fallback'
  SCRIPT="${PFB_ROOT}/scripts/run-in-docker.sh"

  setup() {
    # Mandatory per spec_helper: the script under test asks git for the work tree, the
    # toplevel and the common dir, so an inherited GIT_* answers for the fixture and the
    # fallback examples stop falling back.
    scrub_git_env
    WORK="$(mktemp -d)"
    STUB="${WORK}/bin"
    mkdir -p "$STUB"

    # Standard dirs only, so a real docker in /usr/local/bin or /opt/homebrew/bin cannot
    # answer for the stub — and so the no-docker example genuinely has no docker.
    STUB_PATH="${STUB}:/usr/bin:/bin:/usr/sbin:/sbin"

    cat > "${STUB}/docker" <<'STUB_EOF'
#!/bin/sh
case "$1" in
	info) exit "${STUB_INFO_RC:-0}" ;;
	image) exit "${STUB_INSPECT_RC:-1}" ;;
	pull) exit "${STUB_PULL_RC:-1}" ;;
	build) exit "${STUB_BUILD_RC:-0}" ;;
	run) shift; echo "DOCKER_RUN $*"; exit 0 ;;
esac
exit 0
STUB_EOF
    chmod +x "${STUB}/docker"
  }

  teardown() { rm -rf "$WORK"; }

  BeforeEach 'setup'
  AfterEach 'teardown'

  # Always invoked from the repo root: the wrapper reads .github/docker/VERSION and the
  # git common dir from there, so anything else would be testing a different code path.
  wrapper() {
    ( cd "$PFB_ROOT" && PATH="$STUB_PATH" "$SCRIPT" "$@" )
  }

  # `docker run` is stubbed, so a containerised command never executes. A marker FILE
  # settles which side ran without ambiguity: asserting on stdout cannot, because the
  # stub echoes the argv it was handed, and the argv contains the command's own text.

  real_docker_on_std_path() {
    PATH=/usr/bin:/bin:/usr/sbin:/sbin command -v docker >/dev/null 2>&1
  }

  # ── the container path still wins when a container is available ──────────── #

  It 'runs in the container when the image is already on the machine'
    # The negative examples below only mean something if this one proves the wrapper
    # does not simply always fall back.
    export STUB_INSPECT_RC=0
    When call wrapper sh -c "echo ran > '${WORK}/host_ran'"
    The status should be success
    The output should include 'DOCKER_RUN'
    The output should include 'ci-runner:'
    # The argv, not just the flags: the stub echoes what it was handed, and without this
    # a wrapper that dropped its trailing "$@" would start an empty container and pass.
    The output should include 'host_ran'
    The path "${WORK}/host_ran" should not be exist
    The stderr should not include 'running on the host'
  End

  It 'uses an init process to reap orphaned grandchildren'
    export STUB_INSPECT_RC=0
    When call wrapper true
    The status should be success
    The output should include 'DOCKER_RUN --rm --init'
    The output should include 'ci-runner:8 true'
  End

  It 'runs in the container when the image is absent but pulls'
    export STUB_INSPECT_RC=1 STUB_PULL_RC=0
    When call wrapper sh -c "echo ran > '${WORK}/host_ran'"
    The status should be success
    The output should include 'DOCKER_RUN'
    The output should include 'host_ran'
    The path "${WORK}/host_ran" should not be exist
    The stderr should not include 'running on the host'
  End

  # ── every way of not getting a container ─────────────────────────────────── #

  It 'falls back, saying so, when docker is not installed'
    Skip if 'a real docker is on the standard PATH' real_docker_on_std_path
    rm -f "${STUB}/docker"
    When call wrapper sh -c 'echo HOST_RAN'
    The status should be success
    The output should include 'HOST_RAN'
    The stderr should include 'docker is not installed'
    The stderr should include 'running on the host'
  End

  It 'falls back, saying so, when the daemon is unreachable'
    export STUB_INFO_RC=1
    When call wrapper sh -c 'echo HOST_RAN'
    The status should be success
    The output should include 'HOST_RAN'
    The stderr should include 'daemon is not reachable'
  End

  It 'falls back, saying so, when the image is absent and cannot be pulled'
    # The live case today: the packages are private, so an unauthenticated pull 401s.
    export STUB_INSPECT_RC=1 STUB_PULL_RC=1
    When call wrapper sh -c 'echo HOST_RAN'
    The status should be success
    The output should include 'HOST_RAN'
    The stderr should include 'could not be pulled'
    # The reason is only useful if it also names the cure.
    The stderr should include 'PFB_BUILD=1'
  End

  It 'falls back, saying so, when an explicitly requested build fails'
    # PFB_BUILD is the documented answer to the previous example, so it is the one path
    # where the user has already been told "this will work" — it failing silently, or
    # refusing to run, would be the worst of the set.
    export PFB_BUILD=1 STUB_INSPECT_RC=1 STUB_BUILD_RC=1
    When call wrapper sh -c 'echo HOST_RAN'
    The status should be success
    The output should include 'HOST_RAN'
    The stderr should include 'failed to build'
  End

  It 'falls back, saying so, outside a git work tree'
    export STUB_INSPECT_RC=0
    When run sh -c "cd '$WORK' && PATH='$STUB_PATH' '$SCRIPT' sh -c 'echo HOST_RAN'"
    The status should be success
    The output should include 'HOST_RAN'
    The stderr should include 'not inside a git work tree'
  End

  It 'falls back, saying so, in a checkout with no VERSION file'
    # A shallow or historical checkout that predates the CI images: there is a repo to
    # mount, but nothing naming which image belongs to it.
    git_fixture init -q "${WORK}/repo"
    export STUB_INSPECT_RC=0
    When run sh -c "cd '${WORK}/repo' && PATH='$STUB_PATH' '$SCRIPT' sh -c 'echo HOST_RAN'"
    The status should be success
    The output should include 'HOST_RAN'
    The stderr should include 'VERSION'
    The stderr should include 'PFB_IMAGE'
  End

  # ── the fallback is a real exec, not a swallow ───────────────────────────── #

  It 'propagates the exit status of a host-run command'
    # `exec` and not a wrapped call: a fallback that reported success for a failing
    # command would turn a red gate green, which is the one outcome worse than refusing.
    export STUB_INFO_RC=1
    When call wrapper sh -c 'exit 42'
    The status should eq 42
    The stderr should include 'running on the host'
  End

  It 'still names the reason when the command itself is absent'
    # The fallback must not become the explanation for an unrelated failure.
    export STUB_INFO_RC=1
    When call wrapper definitely-not-a-real-command
    The status should not eq 0
    The stderr should include 'running on the host'
  End

  # ── telling the two runs apart after the fact ────────────────────────────── #

  It 'marks a host run in the environment, where a pipe cannot lose it'
    # The stderr line is the primary signal, but `2>/dev/null` deletes it and a captured
    # $(...) never shows it — so the fact travels with the process too, or a script that
    # graded on the host toolchain has no way to know it did.
    export STUB_INFO_RC=1
    When call wrapper sh -c 'echo "runner=${PFB_RUNNER:-unset}"'
    The status should be success
    The output should include 'runner=host'
    The stderr should include 'running on the host'
  End

  It 'marks a container run too, so an unset value means the wrapper was bypassed'
    # Two values and an absence: `container`, `host`, and unset for a command that never
    # went through the wrapper. A flag set on only one path could not express the third.
    export STUB_INSPECT_RC=0
    When call wrapper true
    The status should be success
    The output should include 'PFB_RUNNER=container'
  End

  It 'rebuilds under PFB_BUILD even when its own previous output is cached'
    # The build writes an arch-suffixed tag that is also a lookup candidate, so consulting
    # the cache first would make every run after the first reuse a stale image — silently,
    # right after the Dockerfile edit that prompted the rebuild.
    export PFB_BUILD=1 STUB_INSPECT_RC=0
    When call wrapper true
    The status should be success
    The stderr should include 'building'
    # ...and then actually uses what it built, rather than falling back after a fine build.
    The output should include 'DOCKER_RUN'
  End
End
