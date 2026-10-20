"""A stand-in `go` for the pfB-DNS builder tests (issue #3515): the REAL toolchain, plus one lie.

`write_go_wrapper` writes an executable that forwards every call to the real Go and then, for the
one thing under test, misreports it: a built binary is forged (its ABI tag, program headers or ELF
type are rewritten), `go version -m` output is edited, or the environment each `go build` ran in is
recorded. The builder under test cannot tell it from Go, so its checks are exercised end to end.
"""

from __future__ import annotations

import json
import os
import shutil
import struct
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from tests.elf_facts import PT_DYNAMIC, PT_INTERP, PT_PHDR, abi_note_offsets

ROOT = Path(__file__).resolve().parent.parent
ET_DYN = 3
E_TYPE_OFFSET = 16
E_PHOFF_OFFSET = 32
# A note type no loader knows: the FreeBSD ABI tag is then missing from the file.
UNKNOWN_NOTE_TYPE = 0x7F


def _patched(data: bytes, offset: int, fmt: str, value: int) -> bytes:
    patched = bytearray(data)
    struct.pack_into(fmt, patched, offset, value)
    return bytes(patched)


def _retype_segment(data: bytes, old: int, new: int) -> bytes:
    (e_phoff,) = struct.unpack_from("<Q", data, E_PHOFF_OFFSET)
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 54)
    for index in range(e_phnum):
        offset = e_phoff + index * e_phentsize
        if struct.unpack_from("<I", data, offset)[0] == old:
            return _patched(data, offset, "<I", new)
    raise AssertionError(f"the binary has no program header of type {old} to retype")


def _located_abi_note(data: bytes) -> tuple[int, int]:
    located = abi_note_offsets(data)
    assert located is not None, "the binary has no FreeBSD ABI-tag note to forge"
    return located


def _forge_abi_note(data: bytes, value: int | None) -> bytes:
    assert value is not None
    return _patched(data, _located_abi_note(data)[1], "<I", value)


def _forge_no_abi_note(data: bytes, _value: int | None) -> bytes:
    return _patched(data, _located_abi_note(data)[0] + 8, "<I", UNKNOWN_NOTE_TYPE)


# name -> forge(binary bytes, value); each leaves everything else in the file as Go wrote it.
FORGERIES: dict[str, Callable[[bytes, int | None], bytes]] = {
    "abi-note": _forge_abi_note,
    "no-abi-note": _forge_no_abi_note,
    "interpreter": lambda data, _value: _retype_segment(data, PT_PHDR, PT_INTERP),
    "dynamic-section": lambda data, _value: _retype_segment(data, PT_PHDR, PT_DYNAMIC),
    "shared-object": lambda data, _value: _patched(data, E_TYPE_OFFSET, "<H", ET_DYN),
    "truncated": lambda data, _value: data[:120],
    "program-headers-outside-file": lambda data, _value: _patched(data, E_PHOFF_OFFSET, "<Q", len(data)),
}


def run(config: dict[str, Any], real_go: str, argv: list[str]) -> int:
    """The wrapper's body: forward ``argv`` to ``real_go``, then apply the configured lie."""
    if config["record"] and argv[:1] == ["build"]:
        with open(config["record"], "a", encoding="utf-8") as record:
            record.write(json.dumps({k: os.environ.get(k) for k in ("GOARCH", "GOAMD64", "GOARM64")}) + "\n")
    result = subprocess.run([real_go, *argv], capture_output=True, text=True, check=False)
    sys.stderr.write(result.stderr)
    stdout = result.stdout
    if config["replace"] and argv[:2] == ["version", "-m"]:
        stdout = stdout.replace(*config["replace"])
    sys.stdout.write(stdout)
    if result.returncode == 0 and config["forgery"] and argv[:1] == ["build"] and "-o" in argv:
        built = Path(argv[argv.index("-o") + 1])
        built.write_bytes(FORGERIES[config["forgery"]](built.read_bytes(), config["value"]))
    return result.returncode


def write_go_wrapper(
    dest: Path,
    *,
    forgery: str | None = None,
    value: int | None = None,
    replace: tuple[str, str] | None = None,
    record: Path | None = None,
) -> Path:
    """Write the wrapper to ``dest`` (named `go` when it must be found on PATH); returns ``dest``.

    ``forgery`` names an entry of FORGERIES applied to every binary `go build` writes (``value`` is its
    argument); ``replace`` rewrites text in `go version -m` output; ``record`` receives one JSON line
    with GOARCH, GOAMD64 and GOARM64 per `go build`.
    """
    real_go = shutil.which("go")
    assert real_go is not None, "the real Go toolchain is required"
    config = {"forgery": forgery, "value": value, "replace": replace, "record": str(record) if record else None}
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(
        f"#!{sys.executable}\n"
        "import sys\n"
        f"sys.path.insert(0, {str(ROOT)!r})\n"
        "from tests.go_wrapper import run\n"
        f"sys.exit(run({config!r}, {real_go!r}, sys.argv[1:]))\n",
        encoding="utf-8",
    )
    dest.chmod(0o755)
    return dest
