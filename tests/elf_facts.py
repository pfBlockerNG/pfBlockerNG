"""ELF facts for the pfB-DNS payload tests (issue #3513, dual-arch package).

A cross-built binary is only the right payload if its OWN header says FreeBSD, the right CPU
and a static executable, and its ABI tag names a FreeBSD no newer than the target; the package
tests read these facts from the bytes instead of trusting the file name or the build command that
was meant to produce them.
"""

from __future__ import annotations

import struct

ELFOSABI_FREEBSD = 9
ET_EXEC = 2
PT_DYNAMIC = 2
PT_INTERP = 3
PT_NOTE = 4
PT_PHDR = 6
NT_FREEBSD_ABI_TAG = 1
EM_X86_64 = 62
EM_AARCH64 = 183

# The `.note.tag` vendor string FreeBSD's kernel checks before it accepts a static executable.
FREEBSD_ABI_NOTE = b"FreeBSD\x00"


def segment_types(data: bytes) -> list[int]:
    """The ``p_type`` of every program header of an ELF64 little-endian file."""
    (e_phoff,) = struct.unpack_from("<Q", data, 32)
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 54)
    return [struct.unpack_from("<I", data, e_phoff + i * e_phentsize)[0] for i in range(e_phnum)]


def abi_note_offsets(data: bytes) -> tuple[int, int] | None:
    """File offsets of the first FreeBSD ABI-tag note's header and its 4-byte ``__FreeBSD_version``."""
    (e_phoff,) = struct.unpack_from("<Q", data, 32)
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 54)
    for index in range(e_phnum):
        p_type, _flags, p_offset, _va, _pa, p_filesz = struct.unpack_from(
            "<IIQQQQ", data, e_phoff + index * e_phentsize
        )
        if p_type != PT_NOTE:
            continue
        position = p_offset
        while position + 12 <= p_offset + p_filesz:
            namesz, descsz, note_type = struct.unpack_from("<III", data, position)
            name = data[position + 12 : position + 12 + namesz]
            desc = position + 12 + (namesz + 3) // 4 * 4
            if name == FREEBSD_ABI_NOTE and note_type == NT_FREEBSD_ABI_TAG and descsz == 4:
                return position, desc
            position = desc + (descsz + 3) // 4 * 4
    return None


def freebsd_abi_note(data: bytes) -> int | None:
    """The ``__FreeBSD_version`` the executable was linked for (its ABI-tag note), or None without one."""
    located = abi_note_offsets(data)
    return None if located is None else struct.unpack_from("<I", data, located[1])[0]


def elf_facts(data: bytes) -> dict[str, object]:
    """Parse the ELF64 little-endian header of ``data``; raise ``ValueError`` for anything else."""
    if data[:4] != b"\x7fELF":
        raise ValueError(f"not an ELF file (first bytes {data[:4]!r})")
    ei_class, ei_data, ei_osabi = data[4], data[5], data[7]
    if (ei_class, ei_data) != (2, 1):
        raise ValueError(f"expected ELF64 little-endian, got class={ei_class} data={ei_data}")
    e_type, e_machine = struct.unpack_from("<HH", data, 16)
    return {
        "osabi": ei_osabi,
        "type": e_type,
        "machine": e_machine,
        "has_interpreter": PT_INTERP in segment_types(data),
        "has_freebsd_abi_note": FREEBSD_ABI_NOTE in data[:4096],
    }
