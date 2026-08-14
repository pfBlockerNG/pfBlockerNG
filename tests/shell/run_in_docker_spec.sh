#shellcheck shell=sh
# run_in_docker_spec.sh — the wrapper's one hard invariant: a command it accepts runs in
# the CI runner image, or it does not run at all.
#
# WHY THIS CHANGED (issue #2350): the wrapper used to degrade every unreachable-container
# path to a host run, on the reasoning that a wrapper which refuses to run is worse than
# no wrapper. That reasoning holds for a convenience and fails for a gate. The gates and
# the hooks now route through here, and a run graded against the host toolchain is not the
# run CI performs — every workflow job in test.yml executes inside this exact image. So an
# unreachable container is a REFUSAL, and the escape hatch is explicit: PFB_ALLOW_HOST=1
# restores the old degrade-to-host behaviour for ad-hoc use.
#
# Two properties are asserted on every refusal, because "did not run" and "ran somewhere
# else" fail in opposite directions:
#   1. the command did NOT execute (a marker file settles it — asserting on stdout cannot,
#      since the docker stub echoes the argv it was handed and the argv contains the
#      command's own text);
#   2. stderr names the reason AND the override, so a refusal is never a dead end.
#
# The docker stub answers by exit code alone (STUB_*_RC), which is all the wrapper reads.
# `docker run` is the exception: it echoes, so the examples that must prove the container
# path was NOT abandoned have something positive to assert on.

Describe 'run-in-docker.sh'
  SCRIPT="${PFB_ROOT}/scripts/run-in-docker.sh"

  setup() {
    # Mandatory per spec_helper: the script under test asks git for the work tree, the
    # toplevel and the common dir, so an inherited GIT_* answers for the fixture and the
    # refusal examples stop refusing.
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

  real_docker_on_std_path() {
    PATH=/usr/bin:/bin:/usr/sbin:/sbin command -v docker >/dev/null 2>&1
  }

  # ── the container path ────────────────────────────────────────────────────── #

  It 'runs in the container when the image is already on the machine'
    # The refusal examples below only mean something if this one proves the wrapper
    # does not simply always refuse.
    export STUB_INSPECT_RC=0
    When call wrapper sh -c "echo ran > '${WORK}/host_ran'"
    The status should be success
    The output should include 'DOCKER_RUN'
    The output should include 'ci-runner:'
    # The argv, not just the flags: the stub echoes what it was handed, and without this
    # a wrapper that dropped its trailing "$@" would start an empty container and pass.
    The output should include 'host_ran'
    The path "${WORK}/host_ran" should not be exist
    The stderr should not include 'host'
  End

  It 'uses an init process to reap orphaned grandchildren'
    export STUB_INSPECT_RC=0
    When call wrapper true
    The status should be success
    The output should include 'DOCKER_RUN --rm --init'
    The output should include 'ci-runner:9 true'
  End

  It 'runs in the container when the image is absent but pulls'
    export STUB_INSPECT_RC=1 STUB_PULL_RC=0
    When call wrapper sh -c "echo ran > '${WORK}/host_ran'"
    The status should be success
    The output should include 'DOCKER_RUN'
    The output should include 'host_ran'
    The path "${WORK}/host_ran" should not be exist
    The stderr should not include 'host'
  End

  # ── the working directory has to be inside the mount (issue #2362) ────────── #
  #
  # The mount path comes from git, which answers with symlinks resolved; the working
  # directory used to come from the shell's logical `pwd`, which does not. On macOS /tmp
  # is a symlink to /private/tmp, so a checkout entered through /tmp was MOUNTED at
  # /private/tmp and then RUN in a /tmp directory that exists in the image and is empty.
  # Nothing failed: pytest reported "no tests collected", phpunit found no suite, and a
  # gate that never saw the repository read as a green run.

  symlinked_repo() {
    mkdir -p "${WORK}/real/sub"
    ( cd "${WORK}/real" && git_fixture init -q . )
    ln -s "${WORK}/real" "${WORK}/alias"
    # The physical answer git will give, resolved the same way for the assertion — the
    # temp root itself is a symlink on macOS, so this cannot be spelled literally.
    REAL_SUB="$(CDPATH='' cd "${WORK}/real/sub" && pwd -P)"
  }

  wrapper_via_symlink() {
    ( cd "${WORK}/alias/sub" && PATH="$STUB_PATH" PFB_IMAGE=stub-image "$SCRIPT" "$@" )
  }

  It 'runs in the mounted directory when the tree is entered through a symlink'
    export STUB_INSPECT_RC=0
    symlinked_repo
    When call wrapper_via_symlink true
    The status should be success
    # The working directory is the mounted path, not the alias the caller typed...
    The output should include "--workdir ${REAL_SUB}"
    # ...and the alias appears nowhere, so nothing is mounted or entered under a name
    # that resolves differently inside the container than it does outside.
    The output should not include "${WORK}/alias"
  End

  # ── every way of not getting a container is now a refusal ─────────────────── #
  #
  # 125 and not 1: the exit status has to be distinguishable from the wrapped command's
  # own failure, or a caller cannot tell "the gate went red" from "the gate never ran".
  # It is docker's own reserved "could not run the container" status.

  It 'refuses, saying so, when docker is not installed'
    Skip if 'a real docker is on the standard PATH' real_docker_on_std_path
    rm -f "${STUB}/docker"
    When call wrapper sh -c "echo ran > '${WORK}/host_ran'"
    The status should equal 125
    The path "${WORK}/host_ran" should not be exist
    The stderr should include 'docker is not installed'
    The stderr should include 'PFB_ALLOW_HOST=1'
  End

  It 'refuses, saying so, when the daemon is unreachable'
    export STUB_INFO_RC=1
    When call wrapper sh -c "echo ran > '${WORK}/host_ran'"
    The status should equal 125
    The path "${WORK}/host_ran" should not be exist
    The stderr should include 'daemon is not reachable'
    The stderr should include 'PFB_ALLOW_HOST=1'
  End

  It 'refuses, saying so, when the image is absent and cannot be pulled'
    # The live case on a machine that is offline or naming a series the registry does
    # not carry. The reason is only useful if it also names the cure.
    export STUB_INSPECT_RC=1 STUB_PULL_RC=1
    When call wrapper sh -c "echo ran > '${WORK}/host_ran'"
    The status should equal 125
    The path "${WORK}/host_ran" should not be exist
    The stderr should include 'could not be pulled'
    The stderr should include 'PFB_BUILD=1'
  End

  It 'refuses, saying so, when an explicitly requested build fails'
    export PFB_BUILD=1 STUB_INSPECT_RC=1 STUB_BUILD_RC=1
    When call wrapper sh -c "echo ran > '${WORK}/host_ran'"
    The status should equal 125
    The path "${WORK}/host_ran" should not be exist
    The stderr should include 'failed to build'
  End

  It 'refuses, saying so, outside a git work tree'
    export STUB_INSPECT_RC=0
    When run sh -c "cd '$WORK' && PATH='$STUB_PATH' '$SCRIPT' sh -c \"echo ran > '${WORK}/host_ran'\""
    The status should equal 125
    The path "${WORK}/host_ran" should not be exist
    The stderr should include 'not inside a git work tree'
  End

  It 'refuses, saying so, in a checkout with no VERSION file'
    # A shallow or historical checkout that predates the CI images: there is a repo to
    # mount, but nothing naming which image belongs to it.
    git_fixture init -q "${WORK}/repo"
    export STUB_INSPECT_RC=0
    When run sh -c "cd '${WORK}/repo' && PATH='$STUB_PATH' '$SCRIPT' sh -c \"echo ran > '${WORK}/host_ran'\""
    The status should equal 125
    The path "${WORK}/host_ran" should not be exist
    The stderr should include 'VERSION'
    The stderr should include 'PFB_IMAGE'
  End

  # ── PFB_ALLOW_HOST restores the degrade-to-host behaviour ─────────────────── #

  It 'falls back to the host, saying so, under PFB_ALLOW_HOST'
    export STUB_INFO_RC=1 PFB_ALLOW_HOST=1
    When call wrapper sh -c 'echo HOST_RAN'
    The status should be success
    The output should include 'HOST_RAN'
    The stderr should include 'daemon is not reachable'
    The stderr should include 'running on the host'
  End

  It 'propagates the exit status of a host-run command under PFB_ALLOW_HOST'
    # `exec` and not a wrapped call: a fallback that reported success for a failing
    # command would turn a red gate green, which is the one outcome worse than refusing.
    export STUB_INFO_RC=1 PFB_ALLOW_HOST=1
    When call wrapper sh -c 'exit 42'
    The status should eq 42
    The stderr should include 'running on the host'
  End

  It 'still names the reason when the command itself is absent under PFB_ALLOW_HOST'
    # The fallback must not become the explanation for an unrelated failure.
    export STUB_INFO_RC=1 PFB_ALLOW_HOST=1
    When call wrapper definitely-not-a-real-command
    The status should not eq 0
    The stderr should include 'running on the host'
  End

  It 'marks a host run in the environment, where a pipe cannot lose it'
    # The stderr line is the primary signal, but `2>/dev/null` deletes it and a captured
    # $(...) never shows it — so the fact travels with the process too, or a script that
    # graded on the host toolchain has no way to know it did.
    export STUB_INFO_RC=1 PFB_ALLOW_HOST=1
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
    # ...and then actually uses what it built, rather than refusing after a fine build.
    The output should include 'DOCKER_RUN'
  End
End
