#!/usr/bin/env python3
# build-pfb-dns.py — cross-compile the pfB-DNS gateway for both FreeBSD architectures.
#
# usage: build-pfb-dns.py --source-root DIR --out-dir DIR [--go GO] [--vendored] [--modules-txt FILE]
#
#   --source-root  a source tree holding go/pfb_dns_gateway (the module, with its committed
#                  go.mod and go.sum). A tree without that module is a legacy source: nothing is
#                  built, nothing is written, no Go is needed, and the result is {"targets": {}}.
#   --out-dir      receives freebsd-amd64/pfb-dns and freebsd-arm64/pfb-dns (mtime = go.mod's, so
#                  the bytes and stamps are a function of the source alone). Relative paths are
#                  taken from the caller's directory.
#   --go           the Go toolchain to run (default: `go` on PATH).
#   --vendored     build the module in place from its ready-made vendor/ tree (a ports recipe's
#                  GH_TUPLE extraction). Default: copy the module without vendor/ to a scratch
#                  directory under --out-dir and let `go mod vendor` fill it (go.sum verifies every
#                  dependency; needs the module cache or network).
#   --modules-txt  the vendor/modules.txt the caller expects (a ports recipe's files/modules.txt).
#                  With --vendored and no vendor/modules.txt it is installed there; otherwise the
#                  module's vendor/modules.txt must be byte-equal to it. Either way a mismatch
#                  exits 1 before Go compiles anything.
#
# stdout: one JSON object, {"go": "go1.x.y", "modules_txt_sha256": "<hex>" or null when the module
# vendors nothing, "targets": {"freebsd-amd64": {"goarch", "path", "sha256", "size"}, ...}}.
# Everything else goes to stderr. Exit 1, with every file this run wrote removed, when Go is
# missing or older than go.mod requires, a compile fails, or an output is not the FreeBSD ELF for
# its architecture.
#
# The build is hermetic: CGO off, -mod=vendor (the vendor tree is Go's own or checked against
# modules.txt), -trimpath, -buildvcs=false, stripped, GOTOOLCHAIN=local (never downloads a
# compiler). Ambient Go settings other than the module/build cache and proxy locations are dropped,
# so GOFLAGS, GOOS, GOEXPERIMENT and friends cannot change what is built.
#
# Called by build-pkg-portable.py after it has acquired the immutable source; also usable by hand.
# Stdlib only.

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

MODULE = Path("go") / "pfb_dns_gateway"
BINARY = "pfb-dns"
# install-layout directory -> (GOARCH, ELF e_machine)
TARGETS = {"freebsd-amd64": ("amd64", 62), "freebsd-arm64": ("arm64", 183)}
ELFOSABI_FREEBSD = 9
# The only ambient Go settings honoured: where the caches and the module proxy live.
_KEPT_GO_ENV = frozenset(
    {"GOPATH", "GOMODCACHE", "GOCACHE", "GOTMPDIR", "GOPROXY", "GOSUMDB", "GONOSUMDB", "GOPRIVATE", "GONOPROXY"}
)


class BuildError(Exception):
    pass


def _go_env(goarch: str) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k in _KEPT_GO_ENV or not k.startswith(("GO", "CGO_"))}
    env.update(
        CGO_ENABLED="0",
        GO111MODULE="on",
        GOARCH=goarch,
        GOENV="off",
        GOOS="freebsd",
        GOTOOLCHAIN="local",
        GOWORK="off",
    )
    return env


def _run_go(go: str, args: list[str], module: Path, goarch: str, what: str) -> str:
    try:
        result = subprocess.run([go, *args], cwd=module, env=_go_env(goarch), capture_output=True, text=True)
    except OSError as exc:
        raise BuildError(f"{what}: cannot run Go toolchain {go!r}: {exc}") from None
    if result.returncode != 0:
        raise BuildError(f"{what} failed ({go} {' '.join(args)}):\n{result.stderr.strip()}")
    return result.stdout.strip()


def _require_go(go: str, module: Path) -> str:
    if shutil.which(go) is None:
        directive = re.search(r"^go (\S+)$", (module / "go.mod").read_text(encoding="utf-8"), re.MULTILINE)
        needed = f" >= {directive.group(1)}" if directive else ""
        raise BuildError(f"Go toolchain not found: {go!r} is not an executable (pfB-DNS needs Go{needed})")
    return go


def _check_elf(path: Path, target: str, machine: int) -> None:
    with path.open("rb") as handle:
        head = handle.read(20)
    ok = (
        len(head) == 20
        and head[:4] == b"\x7fELF"
        and head[4:6] == b"\x02\x01"  # ELF64, little-endian
        and head[7] == ELFOSABI_FREEBSD
        and struct.unpack_from("<H", head, 18)[0] == machine
    )
    if not ok:
        raise BuildError(f"{target}: {path} is not a FreeBSD ELF for this architecture (header {head.hex()})")


def _read_modules_txt(path: Path | None) -> bytes | None:
    if path is None:
        return None
    if not path.is_file():
        raise BuildError(f"--modules-txt {path} is not a file")
    return path.read_bytes()


def _vendor_copy(go: str, module: Path, scratch: Path) -> Path:
    """A copy of ``module`` without its own vendor/, vendored by Go from go.mod and go.sum."""
    copy = scratch / MODULE.name
    shutil.copytree(module, copy, ignore=lambda src, names: ["vendor"] if src == os.fspath(module) else [])
    # A go.mod without a `require` has nothing to vendor: `go mod vendor` would only say so.
    if re.search(r"^\s*require\b", (copy / "go.mod").read_text(encoding="utf-8"), re.MULTILINE):
        _run_go(go, ["mod", "vendor"], copy, "amd64", "go mod vendor")
    return copy


def _settle_modules_txt(tree: Path, wanted: bytes | None, *, install: bool) -> str | None:
    """The sha256 of the vendor/modules.txt Go will build from, once it equals ``wanted`` (if given)."""
    path = tree / "vendor" / "modules.txt"
    have = path.read_bytes() if path.is_file() else None
    if wanted is not None and have is None and install and path.parent.is_dir():
        path.write_bytes(wanted)
        have = wanted
    if wanted is not None and have != wanted:
        shown = hashlib.sha256(have).hexdigest() if have is not None else "none"
        raise BuildError(
            f"the expected modules.txt (sha256 {hashlib.sha256(wanted).hexdigest()}) is not the "
            f"source's vendor/modules.txt (sha256 {shown})"
        )
    return hashlib.sha256(have).hexdigest() if have is not None else None


def build_pfb_dns(
    source_root: Path, out_dir: Path, go: str = "go", *, vendored: bool = False, modules_txt: Path | None = None
) -> dict[str, object]:
    module = source_root / MODULE
    if not (module / "go.mod").is_file():
        return {"targets": {}}
    go = _require_go(go, module)
    wanted = _read_modules_txt(modules_txt)
    out_dir = out_dir.resolve()  # Go runs inside the module: a relative path would land in the source tree
    stamp = int((module / "go.mod").stat().st_mtime)
    targets: dict[str, dict[str, object]] = {}
    out_dir.mkdir(parents=True, exist_ok=True)
    scratch = Path(tempfile.mkdtemp(prefix=".vendor-", dir=out_dir))
    try:
        tree = module if vendored else _vendor_copy(go, module, scratch)
        modules_sha256 = _settle_modules_txt(tree, wanted, install=vendored)
        version = _run_go(go, ["env", "GOVERSION"], tree, "amd64", "reading the Go version")
        for target, (goarch, machine) in TARGETS.items():
            dest = out_dir / target / BINARY
            dest.parent.mkdir(parents=True, exist_ok=True)
            _run_go(
                go,
                ["build", "-mod=vendor", "-buildvcs=false", "-trimpath", "-ldflags=-s -w", "-o", str(dest), "."],
                tree,
                goarch,
                f"{target} build",
            )
            _check_elf(dest, target, machine)
            os.utime(dest, (stamp, stamp))
            data = dest.read_bytes()
            targets[target] = {
                "goarch": goarch,
                "path": str(dest),
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
            }
            sys.stderr.write(
                f"==> pfb-dns {target}: sha256={targets[target]['sha256']} ({len(data)} bytes, {version})\n"
            )
    except BaseException:
        for target in TARGETS:
            shutil.rmtree(out_dir / target, ignore_errors=True)
        raise
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    return {"go": version, "modules_txt_sha256": modules_sha256, "targets": targets}


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        prog="build-pfb-dns.py", description="Cross-compile pfB-DNS for FreeBSD amd64 and arm64."
    )
    ap.add_argument("--source-root", type=Path, required=True, help="source tree holding go/pfb_dns_gateway")
    ap.add_argument("--out-dir", type=Path, required=True, help="receives freebsd-<arch>/pfb-dns")
    ap.add_argument("--go", default="go", help="Go toolchain to run (default: go on PATH)")
    ap.add_argument("--vendored", action="store_true", help="build in place from the module's ready-made vendor/")
    ap.add_argument("--modules-txt", type=Path, help="the vendor/modules.txt the module must carry (or be given)")
    args = ap.parse_args(argv)
    try:
        record = build_pfb_dns(
            args.source_root, args.out_dir, args.go, vendored=args.vendored, modules_txt=args.modules_txt
        )
    except BuildError as exc:
        sys.stderr.write(f"build-pfb-dns: {exc}\n")
        return 1
    print(json.dumps(record, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
