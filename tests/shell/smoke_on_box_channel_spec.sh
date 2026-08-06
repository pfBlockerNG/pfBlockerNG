#shellcheck shell=sh
# smoke_on_box_channel_spec.sh — issue #2206: smoke-on-box.sh carries --channel across the
# ref re-exec.
#
# WHY THIS EXISTS: smoke-on-box.sh re-execs ITSELF at the ref under test, rebuilding its own
# argv by hand (`set -- --ref ... --abi ...`). A flag dropped from that list is invisible —
# the run still succeeds, it just builds a different channel, which means a differently NAMED
# package (pfSense-pkg-pfBlockerNG-<channel>) than the one the verification was asked for.
# That is exactly the silent-wrong-artifact class issue #2166 was raised over.
#
# TOPOLOGY: the script's REPO_ROOT is redirected at a throwaway git repo (PFB_ONBOX_REPO_ROOT
# seam, mirroring local-smoke.sh's PFB_SELECT_BOX). That repo's scripts/smoke-on-box.sh is a
# RECORDER, so the re-exec lands on it and prints the argv it was handed instead of pulling
# images and booting qemu. Fully hermetic: no ssh, no box, no build, no network.
#
# RED→GREEN: before the change, REPO_ROOT is the hardcoded /root/pfBlockerNG, so the script
# cannot be pointed at a fixture at all — every example dies sourcing
# /root/pfBlockerNG/scripts/lib/git-env-scrub.sh long before it parses a flag.

Describe 'smoke-on-box.sh --channel'
  SCRIPT="${PFB_ROOT}/scripts/smoke-on-box.sh"

  setup() {
    scrub_git_env
    WORK="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/smokeonboxchannel.XXXXXX")"
    FAKE_ROOT="${WORK}/repo"
    mkdir -p "${FAKE_ROOT}/scripts/lib"

    # The real libs the script sources before it parses anything.
    cp "${PFB_ROOT}/scripts/lib/git-env-scrub.sh" "${FAKE_ROOT}/scripts/lib/"
    cp "${PFB_ROOT}/scripts/lib/smoke-tier.sh"    "${FAKE_ROOT}/scripts/lib/"

    # The re-exec target: record argv, run nothing.
    cat > "${FAKE_ROOT}/scripts/smoke-on-box.sh" <<'RECEOF'
#!/bin/sh
printf 'reexec-argv:'
for _a in "$@"; do printf ' [%s]' "$_a"; done
printf '\n'
exit 0
RECEOF
    chmod +x "${FAKE_ROOT}/scripts/smoke-on-box.sh"

    # A real (tiny) git repo: the no---ref path reads HEAD through `git rev-parse`.
    # git_fixture (spec_helper.sh) neutralises the ambient git config, per the
    # git-env-scrub-guard contract.
    git_fixture -C "$FAKE_ROOT" init --quiet . >/dev/null 2>&1
    git_fixture -C "$FAKE_ROOT" -c user.name=t -c user.email=t@example.com \
        commit --quiet --allow-empty -m seed >/dev/null 2>&1

    PFB_ONBOX_REPO_ROOT="$FAKE_ROOT"
    export WORK FAKE_ROOT PFB_ONBOX_REPO_ROOT
    unset PFB_ONBOX_REEXEC
  }

  teardown() {
    rm -rf "$WORK"
  }

  BeforeEach 'setup'
  AfterEach  'teardown'

  It 'carries an explicit --channel across the re-exec'
    When run sh "$SCRIPT" --channel testing
    The status should be success
    The output should include "[--channel] [testing]"
    The stderr should include 'no --ref'
  End

  It 'carries the default channel across the re-exec when none is given'
    When run sh "$SCRIPT"
    The status should be success
    The output should include "[--channel] [edge]"
    The stderr should include 'no --ref'
  End

  It 'keeps the channel one argv word even when it carries shell metacharacters'
    # The orchestrator validates the vocabulary; this pins the transport — a value reaching
    # smoke-on-box.sh directly must never be re-split or evaluated on the way through.
    When run sh "$SCRIPT" --channel "edge; touch ${WORK}/pwned"
    The status should be success
    The output should include "[--channel] [edge; touch ${WORK}/pwned]"
    The path "${WORK}/pwned" should not be exist
    The stderr should include 'no --ref'
  End
End
