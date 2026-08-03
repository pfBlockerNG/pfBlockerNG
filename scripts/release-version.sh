#!/bin/sh
# Usage: release-version.sh <tag> [branch]
# Tags: vX.Y.Z (Stable), vX.Y.Z.{alpha|beta|rc}.N (Testing), or
#       vX.Y.Z.edge.YYYYMMDD.N (Edge); optional branch must be release/X.Y,
#       with main/devel accepted as legacy aliases for Stable/Testing only.
# Python API branch validation is canonical by default; pass legacy=True for those aliases.
# Output: legacy version/channel/prerelease/prekind/portversion first, then
#         canonical release_channel/tag/stage/sequence/target_final/release_line/
#         final/notes_required/github_release/package KEY=VALUE assignments.
# Exit 0 emits eval-safe assignments; malformed tags or wrong/unknown branches exit 1.

set -eu

script_dir=$(CDPATH='' cd "$(dirname "$0")" && pwd)
TMPDIR=${TMPDIR:-/tmp}
export TMPDIR
exec python3 "$script_dir/release_version.py" "$@"
