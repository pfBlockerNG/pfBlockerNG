#shellcheck shell=sh
# build_repo_help_spec.sh — pin build-repo.sh --help to the header it extracts.
#
# --help prints the header's Usage/Options/Env block via a self-referential
# `sed -n '<start>,<end>p' "$0"` line-range literal. That range silently goes
# stale whenever the header above it grows or shrinks (a comment edit breaks
# runtime output), so pin the extracted block's load-bearing markers.

Describe 'build-repo.sh --help'
  SCRIPT="${PFB_ROOT}/scripts/build-repo.sh"

  It 'prints the Usage/Options/Env header block, not code or unrelated prose'
    When run sh "$SCRIPT" --help
    The status should equal 0
    The output should include 'Usage:'
    The output should include '--print-conf'
    The output should include 'PKG_BIN'
    # A stale range drags in non-comment code — a `set -eu` or assignment line.
    The output should not match pattern '*
set -eu*'
  End
End
