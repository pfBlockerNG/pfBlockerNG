"""ELF header facts for the pfB-DNS payload tests (issue #3513, dual-arch package).

A cross-built binary is only the right payload if its OWN header says FreeBSD, the right CPU
and a static executable; the package tests read these facts from the bytes instead of trusting
the file name or the build command that was meant to produce them.
"""

from __future__ import annotations

import struct

ELFOSABI_FREEBSD = 9
ET_EXEC = 2
PT_INTERP = 3
EM_X86_64 = 62
EM_AARCH64 = 183

# The `.note.tag` vendor string FreeBSD's kernel checks before it accepts a static executable.
FREEBSD_ABI_NOTE = b"FreeBSD\x00"


def elf_facts(data: bytes) -> dict[str, object]:
    """Parse the ELF64 little-endian header of ``data``; raise ``ValueError`` for anything else."""
    if data[:4] != b"\x7fELF":
        raise ValueError(f"not an ELF file (first bytes {data[:4]!r})")
    ei_class, ei_data, ei_osabi = data[4], data[5], data[7]
    if (ei_class, ei_data) != (2, 1):
        raise ValueError(f"expected ELF64 little-endian, got class={ei_class} data={ei_data}")
    e_type, e_machine = struct.unpack_from("<HH", data, 16)
    (e_phoff,) = struct.unpack_from("<Q", data, 32)
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 54)
    segment_types = [struct.unpack_from("<I", data, e_phoff + i * e_phentsize)[0] for i in range(e_phnum)]
    return {
        "osabi": ei_osabi,
        "type": e_type,
        "machine": e_machine,
        "has_interpreter": PT_INTERP in segment_types,
        "has_freebsd_abi_note": FREEBSD_ABI_NOTE in data[:4096],
    }
