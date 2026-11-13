#!/usr/bin/env python3
# build-pfb-dns.py — cross-compile the pfB-DNS gateway, and the Core daemon beside it, for both FreeBSD architectures.
#
# usage: build-pfb-dns.py --source-root DIR --out-dir DIR --freebsd-major N [--go GO] [--vendored]
#                         [--modules-txt FILE]
#
#   --source-root  a source tree holding go/pfb_dns_gateway (the module, with its committed
#                  go.mod and go.sum). A tree without that module is a legacy source: nothing is
#                  built, nothing is written, no Go is needed, and the result is {"targets": {}}.
#   --out-dir      receives freebsd-amd64/pfb-dns and freebsd-arm64/pfb-dns, and freebsd-<arch>/pfb-core
#                  when the tree also holds go/pfb_core (each mtime = its module's go.mod's, so the bytes
#                  and stamps are a function of the source alone). Relative paths are taken from the
#                  caller's directory; a directory inside either module is refused.
#   --go           the Go toolchain to run (default: `go` on PATH); a relative path is resolved from the
#                  caller's directory.
#   --vendored     build the module in place from its ready-made vendor/ tree (a ports recipe's
#                  GH_TUPLE extraction). Default: copy the module without vendor/ to a scratch
#                  directory under --out-dir and let `go mod vendor` fill it (go.sum verifies every
#                  dependency; needs the module cache or network).
#   --modules-txt  the vendor/modules.txt the caller expects (a ports recipe's files/modules.txt).
#                  With --vendored and no vendor/modules.txt it is installed there; otherwise the
#                  module's vendor/modules.txt must be byte-equal to it. Either way a mismatch
#                  exits 1 before Go compiles anything.
#   --freebsd-major  N, the FreeBSD major the binaries are built for (a CI leg's ABI, a port's
#                  ${OSREL:R}). Required: the ELF checks below fail closed against it.
#
# stdout: one JSON object, {"go": "go1.x.y", "freebsd_major": N, "modules_txt_sha256": "<hex>" or
# null when the module vendors nothing, "targets": {"freebsd-amd64": {"goarch", "path", "sha256",
# "size", "freebsd_abi_note"}, ...}, "pfb_core": the same per target for pfb-core, {} for a tree without
# go/pfb_core}. --modules-txt and --vendored concern the gateway. Core may require golang.org/x/net, x/sys and x/text,
# at the versions the gateway's go.mod requires, and github.com/pfBlockerNG/xxh3 (which the gateway does not carry) at
# any version, and nothing else: it is built from a scratch copy of its module whose vendor/ is cut from the gateway's
# (those modules' packages and licenses, and their vendor/modules.txt sections) plus xxh3's root package, from
# `go mod download` (go.sum verifies it) or, with --vendored, from go/pfb_core/vendor/github.com/pfBlockerNG/xxh3 (a
# ports recipe's GH_TUPLE extraction), the only thing a Core vendor/ may then hold. Any other `require`, a `replace`, or
# any other vendor/ of Core's own exits 1, as does a package Core imports that the vendor trees lack. Everything else
# goes to stderr.
# Exit 1, with every output it wrote removed (a modules.txt installed into a --vendored tree stays: it is
# that tree's state), when Go is missing or older than go.mod requires, a compile fails, or an output
# fails a check: ELF64 little-endian, OS/ABI FreeBSD, ET_EXEC, the architecture's e_machine; static
# (no PT_INTERP, no PT_DYNAMIC); a FreeBSD ABI-tag note whose __FreeBSD_version // 100000 is at
# most N; and `go version -m` showing GOOS=freebsd, GOARCH, CGO_ENABLED=0 and GOAMD64=v1 or
# GOARM64=v8.0.
#
# The build is hermetic: CGO off, -mod=vendor (the vendor tree is Go's own or checked against
# modules.txt; Core's is cut from it), -trimpath, -buildvcs=false, stripped, GOTOOLCHAIN=local (never downloads a
# compiler), the CPU baseline pinned (GOAMD64=v1, GOARM64=v8.0). Ambient Go settings other than the
# module/build cache and proxy locations are dropped, so GOFLAGS, GOOS, GOAMD64 and friends cannot
# change what is built.
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
from collections.abc import Callable
from pathlib import Path

MODULE = Path("go") / "pfb_dns_gateway"
BINARY = "pfb-dns"
CORE_MODULE = Path("go") / "pfb_core"
CORE_BINARY = "pfb-core"
# Core's allowed dependencies, at the versions the gateway's go.mod requires: the ports recipe's vendor tree is the
# gateway's, so Core's vendor/ is cut from it.
CORE_MODULES = ("golang.org/x/net", "golang.org/x/sys", "golang.org/x/text")
# Modules Core vendors itself, at any version, because the gateway does not carry them: the xxh3 fork (issue #3925).
CORE_OWN_MODULES = ("github.com/pfBlockerNG/xxh3",)
# The files Go copies from a module's root into vendor/ beside its packages.
_LICENSE_PREFIXES = (
    "AUTHORS",
    "CONTRIBUTORS",
    "COPYING",
    "COPYLEFT",
    "COPYRIGHT",
    "LEGAL",
    "LICENSE",
    "NOTICE",
    "PATENTS",
)
# install-layout directory -> (GOARCH, ELF e_machine)
TARGETS = {"freebsd-amd64": ("amd64", 62), "freebsd-arm64": ("arm64", 183)}
ELFOSABI_FREEBSD = 9
ET_EXEC = 2
PT_DYNAMIC, PT_INTERP, PT_NOTE = 2, 3, 4
NT_FREEBSD_ABI_TAG = 1
_PHDR_SIZE = 56
# GOARCH -> (the GO<ARCH> setting, its baseline): pinned in the build environment, then read back
# from `go version -m`.
_LEVELS = {"amd64": ("GOAMD64", "v1"), "arm64": ("GOARM64", "v8.0")}
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
    env.update(_LEVELS.values())
    return env


def _run_go(go: str, args: list[str], module: Path, goarch: str, what: str) -> str:
    try:
        result = subprocess.run([go, *args], cwd=module, env=_go_env(goarch), capture_output=True, text=True)
    except OSError as exc:
        raise BuildError(f"{what}: cannot run Go toolchain {go!r}: {exc}") from None
    if result.returncode != 0:
        raise BuildError(f"{what} failed ({go} {' '.join(args)}):\n{result.stderr.strip() or result.stdout.strip()}")
    return result.stdout.strip()


def _require_go(go: str, module: Path) -> str:
    found = shutil.which(go)
    if found is None:
        directive = re.search(r"^go (\S+)$", (module / "go.mod").read_text(encoding="utf-8"), re.MULTILINE)
        needed = f" >= {directive.group(1)}" if directive else ""
        raise BuildError(f"Go toolchain not found: {go!r} is not an executable (pfB-DNS needs Go{needed})")
    return os.path.abspath(found)  # Go runs in the module's directory: a path relative to the caller would not resolve


def _abi_tags(notes: bytes) -> list[int]:
    """The __FreeBSD_version of every FreeBSD ABI-tag note in one PT_NOTE segment's bytes."""
    tags: list[int] = []
    position = 0
    while position + 12 <= len(notes):
        namesz, descsz, kind = struct.unpack_from("<III", notes, position)
        desc = position + 12 + (namesz + 3) // 4 * 4
        if desc + descsz > len(notes):
            break
        named = notes[position + 12 : position + 12 + namesz] == b"FreeBSD\x00"
        if named and kind == NT_FREEBSD_ABI_TAG and descsz == 4:
            tags.append(struct.unpack_from("<I", notes, desc)[0])
        position = desc + (descsz + 3) // 4 * 4
    return tags


def _check_elf(path: Path, data: bytes, target: str, machine: int, major: int) -> int:
    """Fail closed unless ``data`` is a static FreeBSD ET_EXEC for ``machine`` linked for FreeBSD ``major``
    or older; returns its ABI tag (__FreeBSD_version)."""
    head = data[:20]
    ok = (
        len(data) >= 64
        and head[:4] == b"\x7fELF"
        and head[4:6] == b"\x02\x01"  # ELF64, little-endian
        and head[7] == ELFOSABI_FREEBSD
        and struct.unpack_from("<H", head, 18)[0] == machine
    )
    if not ok:
        raise BuildError(f"{target}: {path} is not a FreeBSD ELF for this architecture (header {head.hex()})")
    (e_type,) = struct.unpack_from("<H", data, 16)
    if e_type != ET_EXEC:
        raise BuildError(f"{target}: {path} is not an ET_EXEC executable (e_type {e_type})")
    (phoff,) = struct.unpack_from("<Q", data, 32)
    phentsize, phnum = struct.unpack_from("<HH", data, 54)
    if phentsize != _PHDR_SIZE or phoff + phnum * _PHDR_SIZE > len(data):
        raise BuildError(f"{target}: {path} has a program header table that is not inside the file")
    segments = [struct.unpack_from("<IIQQQQQQ", data, phoff + i * _PHDR_SIZE) for i in range(phnum)]
    for kind, name in ((PT_INTERP, "PT_INTERP"), (PT_DYNAMIC, "PT_DYNAMIC")):
        if any(segment[0] == kind for segment in segments):
            raise BuildError(f"{target}: {path} is not static: it has a {name} segment")
    tags = [tag for s in segments if s[0] == PT_NOTE for tag in _abi_tags(data[s[2] : s[2] + s[5]])]
    if not tags:
        raise BuildError(f"{target}: {path} has no FreeBSD ABI tag note")
    newest = max(tags)
    if newest // 100000 > major:
        raise BuildError(
            f"{target}: {path} carries ABI tag {newest} (FreeBSD {newest // 100000}), "
            f"newer than the target FreeBSD {major}"
        )
    return newest


def _check_build_settings(go: str, binary: Path, tree: Path, target: str, goarch: str) -> None:
    """`go version -m` must show the pinned build: GOOS=freebsd, this GOARCH, CGO off, the baseline CPU level."""
    shown = _run_go(go, ["version", "-m", str(binary)], tree, goarch, f"{target} go version -m")
    settings: dict[str, str] = {}
    for line in shown.splitlines():
        kind, _, setting = line.strip().partition("\t")
        if kind == "build":
            key, _, value = setting.partition("=")
            settings[key] = value
    level, baseline = _LEVELS[goarch]
    for key, wanted in (("GOOS", "freebsd"), ("GOARCH", goarch), ("CGO_ENABLED", "0"), (level, baseline)):
        if settings.get(key) != wanted:
            raise BuildError(f"{target}: go version -m shows {key}={settings.get(key)!r}, not {wanted!r}")


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
    _run_go(go, ["mod", "vendor"], copy, "amd64", "go mod vendor")  # a module with no require: "no dependencies"
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


def _parse_go_mod(path: Path) -> tuple[list[tuple[str, str]], bool]:
    """The (module, version) of every `require` in a go.mod, and whether it has a `replace`."""
    requires: list[tuple[str, str]] = []
    replaced = False
    block = ""
    for line in path.read_text(encoding="utf-8").splitlines():
        fields = line.split("//")[0].replace("(", " ( ").split()  # Go reads `require(` as `require (`
        if not fields:
            continue
        if fields == [")"]:
            block = ""
            continue
        directive, args = (block, fields) if block else (fields[0], fields[1:])
        if args == ["("]:
            block = directive
        elif directive == "require":
            if len(args) < 2:
                raise BuildError(f"{path}: malformed require line {line.strip()!r}")
            requires.append((args[0], args[1]))
        elif directive == "replace":
            replaced = True
    return requires, replaced


def _stray_vendor_entries(vendor: Path) -> list[str]:
    """What ``vendor`` holds besides the directories of CORE_OWN_MODULES (and the directories on the way to them)."""
    own = [Path(module) for module in CORE_OWN_MODULES]
    stray: list[str] = []

    def walk(directory: Path) -> None:
        for entry in sorted(directory.iterdir()):
            relative = entry.relative_to(vendor)
            if entry.is_dir() and relative in own:
                continue
            if entry.is_dir() and any(relative in module.parents for module in own):
                walk(entry)
            else:
                stray.append(relative.as_posix())

    walk(vendor)
    return stray


def _check_core_module(core: Path, gateway: Path, *, vendored: bool) -> dict[str, str]:
    """The (module, version) Core requires, once each is a CORE_MODULES at the gateway's version or a CORE_OWN_MODULES,
    with no replace and no vendor/ (--vendored: none beyond the own modules' directories)."""
    vendor = core / "vendor"
    if vendor.exists():
        if not vendored:
            raise BuildError(
                f"{CORE_MODULE}/vendor/ is refused: Core's vendor/ is cut from the gateway's "
                f"(--vendored allows only the directories of {', '.join(CORE_OWN_MODULES)} there)"
            )
        stray = _stray_vendor_entries(vendor) if vendor.is_dir() else [vendor.name]
        if stray:
            raise BuildError(
                f"{CORE_MODULE}/vendor/ may hold only the directories of {', '.join(CORE_OWN_MODULES)}: "
                f"{', '.join(stray)}"
            )
    requires, replaced = _parse_go_mod(core / "go.mod")
    if replaced:
        raise BuildError(f"{CORE_MODULE}/go.mod has a replace, which the gateway's vendor tree cannot honour")
    gateway_requires, _ = _parse_go_mod(gateway / "go.mod")
    for module, version in requires:
        if module in CORE_OWN_MODULES:
            continue
        if module not in CORE_MODULES:
            allowed = ", ".join((*CORE_MODULES, *CORE_OWN_MODULES))
            raise BuildError(f"{CORE_MODULE} requires {module}; Core may require only {allowed}")
        have = sorted({v for m, v in gateway_requires if m == module})
        if version not in have:
            raise BuildError(
                f"{CORE_MODULE} requires {module} {version}, but the gateway requires "
                f"{', '.join(have) or 'no version of it'}"
            )
    return dict(requires)


def _copy_files(src: Path, dst: Path, wanted: Callable[[str], bool] = lambda _name: True) -> None:
    """The files (not the subdirectories) of ``src`` that ``wanted`` accepts, copied into ``dst``."""
    if not src.is_dir():
        raise BuildError(f"{src} is listed in the gateway's vendor/modules.txt but is not in its vendor tree")
    dst.mkdir(parents=True, exist_ok=True)
    for entry in src.iterdir():
        if entry.is_file() and wanted(entry.name):
            shutil.copy2(entry, dst / entry.name)


def _vendor_own(go: str, core: Path, copy: Path, module: str, version: str, *, vendored: bool) -> list[str]:
    """Vendor an own module's root package into ``copy``'s vendor/ as `go mod vendor` would; its modules.txt lines.

    The module's tree is Core's vendor/<module> with --vendored, else the download of module@version, which go.sum
    must pin (`go mod download` would otherwise add the sum, to the scratch copy)."""
    if vendored:
        tree = core / "vendor" / module
        if not tree.is_dir():
            raise BuildError(f"{CORE_MODULE} requires {module}, but {CORE_MODULE}/vendor/{module}/ is missing")
    else:
        args = ["mod", "download", "-json", f"{module}@{version}"]
        got = json.loads(_run_go(go, args, copy, "amd64", f"go mod download {module}"))
        sums = core / "go.sum"
        pinned = f"{module} {version} {got['Sum']}"
        if not sums.is_file() or pinned not in sums.read_text(encoding="utf-8").splitlines():
            raise BuildError(f"{CORE_MODULE}/go.sum does not pin the download of {module} {version} (`{pinned}`)")
        tree = Path(got["Dir"])
    go_mod = tree / "go.mod"
    text = go_mod.read_text(encoding="utf-8") if go_mod.is_file() else ""
    named = re.search(r"^module\s+(\S+)", text, re.MULTILINE)
    if not named or named.group(1) != module:
        raise BuildError(f"{go_mod} does not name `module {module}`")
    directive = re.search(r"^go (\S+)$", text, re.MULTILINE)
    if not directive:
        raise BuildError(f"{go_mod} has no go directive")
    # shortcut: a root .go file tagged `//go:build ignore` is copied (Go's vendor drops it), upgrade if one appears
    # shortcut: only the module's root package is vendored (all Core imports today); a subpackage import fails go build
    _copy_files(
        tree, copy / "vendor" / module, lambda name: not name.endswith("_test.go") and name not in ("go.mod", "go.sum")
    )
    return [f"# {module} {version}", f"## explicit; go {directive.group(1)}", module]


def _vendor_core(
    go: str, core: Path, requires: dict[str, str], gateway_vendor: Path, scratch: Path, *, vendored: bool
) -> Path:
    """A copy of ``core`` whose vendor/ is what `go mod vendor` would write for it: its CORE_MODULES as the gateway
    vendors them (packages, licenses, modules.txt sections) and its CORE_OWN_MODULES from their own trees."""
    modules_txt = gateway_vendor / "modules.txt"
    if not modules_txt.is_file():
        raise BuildError(
            f"{MODULE}/vendor/modules.txt is missing, so {CORE_MODULE}'s modules cannot be vendored from it"
        )
    sections: dict[str, list[str]] = {}
    lines: list[str] = []
    for line in modules_txt.read_text(encoding="utf-8").splitlines():
        if line.startswith("# "):
            lines = sections.setdefault(line[2:].split()[0], [])
        lines.append(line)
    shared = [module for module in requires if module in CORE_MODULES]
    for module in shared:
        if module not in sections:
            raise BuildError(
                f"the gateway's vendor/modules.txt has no section for {module}, which {CORE_MODULE} requires"
            )
    copy = scratch / CORE_MODULE.name
    shutil.copytree(core, copy, ignore=lambda src, names: ["vendor"] if src == os.fspath(core) else [])
    vendor = copy / "vendor"
    kept: dict[str, list[str]] = {}
    for module in shared:
        kept[module] = sections[module]
        if (gateway_vendor / module).is_dir():  # a module whose packages the gateway does not use has no directory
            _copy_files(gateway_vendor / module, vendor / module, lambda name: name.startswith(_LICENSE_PREFIXES))
        for package in (line for line in sections[module] if line and not line.startswith("#")):
            _copy_files(gateway_vendor / package, vendor / package)
    for module in (module for module in requires if module in CORE_OWN_MODULES):
        kept[module] = _vendor_own(go, core, copy, module, requires[module], vendored=vendored)
    # sorted by module path, as `go mod vendor` writes it
    (vendor / "modules.txt").write_text(
        "".join(f"{line}\n" for module in sorted(kept) for line in kept[module]), encoding="utf-8"
    )
    return copy


def _build_one(
    go: str, tree: Path, dest: Path, target: str, goarch: str, machine: int, major: int, stamp: int
) -> dict[str, object]:
    """Build the module at ``tree`` into ``dest`` for one target, check the output, and describe it."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    _run_go(
        go,
        ["build", "-mod=vendor", "-buildvcs=false", "-trimpath", "-ldflags=-s -w", "-o", str(dest), "."],
        tree,
        goarch,
        f"{dest.name} {target} build",
    )
    data = dest.read_bytes()
    abi_tag = _check_elf(dest, data, target, machine, major)
    _check_build_settings(go, dest, tree, target, goarch)
    os.utime(dest, (stamp, stamp))
    return {
        "goarch": goarch,
        "path": str(dest),
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "freebsd_abi_note": abi_tag,
    }


def build_pfb_dns(
    source_root: Path,
    out_dir: Path,
    go: str = "go",
    *,
    freebsd_major: int,
    vendored: bool = False,
    modules_txt: Path | None = None,
) -> dict[str, object]:
    module = source_root / MODULE
    if not (module / "go.mod").is_file():
        return {"targets": {}}
    go = _require_go(go, module)
    wanted = _read_modules_txt(modules_txt)
    core = source_root / CORE_MODULE
    has_core = (core / "go.mod").is_file()
    out_dir = out_dir.resolve()  # Go runs inside the module: a relative path would land in the source tree
    for built in (module, core) if has_core else (module,):
        if out_dir.is_relative_to(built.resolve()):
            raise BuildError(f"--out-dir {out_dir} is inside the module being built")
    core_modules = _check_core_module(core, module, vendored=vendored) if has_core else {}
    stamp = int((module / "go.mod").stat().st_mtime)
    core_stamp = int((core / "go.mod").stat().st_mtime) if has_core else 0
    targets: dict[str, dict[str, object]] = {}
    core_targets: dict[str, dict[str, object]] = {}
    out_dir.mkdir(parents=True, exist_ok=True)
    scratch = Path(tempfile.mkdtemp(prefix=".vendor-", dir=out_dir))
    try:
        tree = module if vendored else _vendor_copy(go, module, scratch)
        modules_sha256 = _settle_modules_txt(tree, wanted, install=vendored)
        core_tree = (
            _vendor_core(go, core, core_modules, tree / "vendor", scratch, vendored=vendored) if core_modules else core
        )
        version = _run_go(go, ["env", "GOVERSION"], tree, "amd64", "reading the Go version")
        for target, (goarch, machine) in TARGETS.items():
            builds = [(tree, BINARY, stamp, targets)]
            if has_core:
                builds.append((core_tree, CORE_BINARY, core_stamp, core_targets))
            for built, binary, mtime, record in builds:
                record[target] = _build_one(
                    go, built, out_dir / target / binary, target, goarch, machine, freebsd_major, mtime
                )
                done = record[target]
                sys.stderr.write(f"==> {binary} {target}: sha256={done['sha256']} ({done['size']} bytes, {version})\n")
    except BaseException:
        for target in TARGETS:
            shutil.rmtree(out_dir / target, ignore_errors=True)
        raise
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    return {
        "go": version,
        "freebsd_major": freebsd_major,
        "modules_txt_sha256": modules_sha256,
        "targets": targets,
        "pfb_core": core_targets,
    }


def _positive_int(text: str) -> int:
    if not (text.isascii() and text.isdecimal() and int(text) >= 1):
        raise argparse.ArgumentTypeError(f"{text!r} is not a positive integer")
    return int(text)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        prog="build-pfb-dns.py", description="Cross-compile pfB-DNS and pfb-core for FreeBSD amd64 and arm64."
    )
    ap.add_argument("--source-root", type=Path, required=True, help="source tree holding go/pfb_dns_gateway")
    ap.add_argument("--out-dir", type=Path, required=True, help="receives freebsd-<arch>/pfb-dns and pfb-core")
    ap.add_argument("--go", default="go", help="Go toolchain to run (default: go on PATH)")
    ap.add_argument("--vendored", action="store_true", help="build in place from the module's ready-made vendor/")
    ap.add_argument("--modules-txt", type=Path, help="the vendor/modules.txt the module must carry (or be given)")
    ap.add_argument(
        "--freebsd-major", type=_positive_int, required=True, metavar="N", help="the FreeBSD major to build for"
    )
    args = ap.parse_args(argv)
    try:
        record = build_pfb_dns(
            args.source_root,
            args.out_dir,
            args.go,
            freebsd_major=args.freebsd_major,
            vendored=args.vendored,
            modules_txt=args.modules_txt,
        )
    except BuildError as exc:
        sys.stderr.write(f"build-pfb-dns: {exc}\n")
        return 1
    print(json.dumps(record, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
