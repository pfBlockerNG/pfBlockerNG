#!/bin/sh
# run.sh OUT_DIR REPO_DIR [recovered|broken] [master|r272]
# Runs scenario.sh in a disposable container (image pfb-pkg-oracle:1, built by build.sh): the repo and the oracle are mounted read-only,
# the pinned core files read-only, results written to OUT_DIR/results. Nothing on the host is installed, changed or left running.
#   recovered  the fixed code: pfB-DNS survives the aborted removal and a retry removes the package (exit 0 iff it held)
#   broken     the base commit: the defect reproduces (no answer, nothing registered, the retry aborts again; exit 0 iff it did)
set -eu
here=$(cd "$(dirname "$0")" && pwd)
[ $# -ge 2 ] || { echo "usage: run.sh OUT_DIR REPO_DIR [recovered|broken] [master|r272]" >&2; exit 2; }
out=$(cd "$1" && pwd); repo=$(cd "$2" && pwd)
expect=${3:-recovered}; core=${4:-master}
mkdir -p "$out/results"
rev=$(git -C "$repo" rev-parse --short HEAD 2>/dev/null || echo unknown)
git -C "$repo" diff --quiet HEAD 2>/dev/null || rev="$rev+worktree"
docker run --rm --init \
	-v "$repo:/repo:ro" -v "$here:/oracle:ro" -v "$out/core:/core:ro" -v "$out/results:/results" \
	-e "ORACLE_EXPECT=$expect" -e "CORE_LABEL=$core" -e "ORACLE_REV=$rev" \
	pfb-pkg-oracle:1 sh /oracle/scenario.sh "${expect}-${core}"
