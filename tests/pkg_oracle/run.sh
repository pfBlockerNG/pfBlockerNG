#!/bin/sh
# run.sh OUT_DIR REPO_DIR [recovered|broken] [master|r272]
# Runs scenario.sh in a disposable container (image $PFB_ORACLE_IMAGE, default pfb-pkg-oracle:2, built by build.sh): the product is
# mounted read-only as /repo, the oracle and the pinned core files read-only, results written to OUT_DIR/results. Nothing on the host
# is installed, changed or left running.
#   recovered  the fixed code: pfB-DNS survives the aborted removal and a retry removes the package (exit 0 iff it held)
#   broken     the base commit: the defect reproduces (no answer, nothing registered, the retry aborts again; exit 0 iff it did)
#   ORACLE_DELETE_CAP=S  each pkg delete's cap in seconds
# /repo is a staged copy of REPO's working tree (OUT_DIR/stage; no .git, no tool indexes), not REPO itself: the pfb-dns payload has to
# sit inside the tree the appliance paths point at, and a read-only mount cannot add a directory. REPO is only read.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
[ $# -ge 2 ] || { echo "usage: run.sh OUT_DIR REPO_DIR [recovered|broken] [master|r272]" >&2; exit 2; }
out=$(cd "$1" && pwd); repo=$(cd "$2" && pwd)
expect=${3:-recovered}; core=${4:-master}
image=${PFB_ORACLE_IMAGE:-pfb-pkg-oracle:2}
mkdir -p "$out/results"
rev=$(git -C "$repo" rev-parse --short HEAD 2>/dev/null || echo unknown)
git -C "$repo" diff --quiet HEAD 2>/dev/null || rev="$rev+worktree"

# stage_gateway REPO DEST RECORD: pfb-dns, the binary pfb_dns.sh execs, built from REPO's go/pfb_dns_gateway with the pinned Go toolchain
# (scripts/go_toolchain.py). The flags mirror scripts/build-pfb-dns.py (CGO off, -mod=readonly, -trimpath, -buildvcs=false, stripped,
# GOTOOLCHAIN=local). Its target is this oracle's host, linux/amd64: build-pfb-dns.py only makes FreeBSD payloads and checks for a
# FreeBSD ELF, so this is NOT a FreeBSD-native binary (see README).
stage_gateway() {
	pinned=$(sed -n 's/^GO_VERSION = "\(go[^"]*\)"$/\1/p' "$1/scripts/go_toolchain.py")
	have=$(GOTOOLCHAIN=local go env GOVERSION) || have=''
	[ -n "$pinned" ] && [ "$have" = "$pinned" ] ||
		{ echo "run.sh: go is '${have:-missing}', the pinned toolchain (scripts/go_toolchain.py) is '${pinned:-unknown}'" >&2; exit 1; }
	mkdir -p "$(dirname "$2")"
	(cd "$1/go/pfb_dns_gateway" && env GOENV=off GOFLAGS= GOWORK=off GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build -mod=readonly -buildvcs=false -trimpath -ldflags='-s -w' -o "$2" .)
	elf=$(od -An -tx1 -N20 "$2" | tr -d ' \n')
	case "$elf" in
		7f454c46020101*3e00) ;;
		*) echo "run.sh: $2 is not a 64-bit little-endian x86-64 ELF (header $elf)" >&2; exit 1 ;;
	esac
	{
		echo "go: $have"
		echo "source: $(git -C "$1" rev-parse --short HEAD 2>/dev/null || echo unknown)"
		echo "bytes: $(wc -c < "$2")"
		echo "sha256: $(sha256sum "$2" | cut -d' ' -f1)"
		echo "elf-header: $elf"
	} > "$3"
}

stage="$out/stage"
rm -rf "$stage" && mkdir -p "$stage"
tar -C "$repo" --exclude=.git --exclude=.codegraph --exclude=graphify-out -cf - . | tar -C "$stage" -xf -
if [ -f "$repo/go/pfb_dns_gateway/go.mod" ]; then
	stage_gateway "$repo" "$stage/src/usr/local/pkg/pfblockerng/dns_proxy/bin/freebsd-amd64/pfb-dns" "$out/results/pfb-dns.txt"
fi
docker run --rm --init \
	-v "$stage:/repo:ro" -v "$here:/oracle:ro" -v "$out/core:/core:ro" -v "$out/results:/results" \
	-e "ORACLE_EXPECT=$expect" -e "CORE_LABEL=$core" -e "ORACLE_REV=$rev" \
	-e "ORACLE_DELETE_CAP=${ORACLE_DELETE_CAP:-}" \
	"$image" sh /oracle/scenario.sh "${expect}-${core}"
