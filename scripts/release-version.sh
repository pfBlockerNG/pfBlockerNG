#!/bin/sh
# Usage: release-version.sh <tag> <channel> [branch]
# Tags: vX.Y.Z (stable), or vX.Y.Z.{a|b|r}N (testing/edge); optional branch
# must be the matching release/X.Y line.
# Output: legacy version/channel/prerelease/prekind/portversion first, then
#         canonical release_channel/tag/stage/sequence/target_final/release_line/
#         final/notes_required/github_release/package KEY=VALUE assignments.
# Exit 0 emits eval-safe assignments; malformed tags or wrong/unknown branches exit 1.

set -eu

script_dir=$(CDPATH='' cd "$(dirname "$0")" && pwd)
TMPDIR=${TMPDIR:-/tmp}
export TMPDIR
exec python3 "$script_dir/release_version.py" "$@"
