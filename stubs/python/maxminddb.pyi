# Minimal dev/test stub for the third-party `maxminddb` module.
#
# pfb_unbound.py uses maxminddb for DNS-reply GeoIP logging. At runtime the
# module is provided by pfSense's py-maxminddb package; it is not a dependency
# of this repo and is not installed in the dev environment. This stub lets
# Pylance/mypy resolve the import (the matching "source missing" notice is
# silenced via reportMissingModuleSource in .vscode/settings.json).
#
# Mirrors the unboundmodule.py stub pattern: dev/test stand-in only, not shipped.

from typing import Any

# ---------------------------------------------------------------------------
# Database open modes — passed as the ``mode`` argument to open_database().
# ---------------------------------------------------------------------------
MODE_AUTO: int
"""Try MODE_MMAP_EXT first, fall back to MODE_MMAP then MODE_FILE. Default."""

MODE_MMAP_EXT: int
"""Use the C extension backed by memory-mapped I/O. Fastest; requires the
optional C extension to be compiled/installed."""

MODE_MMAP: int
"""Pure-Python memory-mapped read. No C extension required."""

MODE_FILE: int
"""Pure-Python standard file read (no memory mapping)."""

MODE_MEMORY: int
"""Load the entire database file into RAM. Fast random access; high memory use."""

MODE_FD: int
"""Load from an already-open file descriptor passed as the ``database``
argument to open_database(). Database is read into memory."""

class Reader:
    """Low-level reader for MaxMind DB files (e.g. GeoLite2-City.mmdb).

    Obtain via :func:`open_database`; use as a context manager to ensure the
    underlying file/mmap is released::

        with maxminddb.open_database("GeoLite2-City.mmdb") as reader:
            record = reader.get("1.2.3.4")

    The return value of :meth:`get` and :meth:`get_with_prefix_len` is a plain
    ``dict`` (or ``None``) whose keys depend on the specific database variant
    (City, Country, ASN, …).
    """

    def get(self, ip_address: str) -> Any:
        """Return the record for *ip_address*, or ``None`` if not found.

        Args:
            ip_address: IPv4 or IPv6 address as a string, e.g. ``"1.2.3.4"``
                        or ``"2001:db8::1"``.

        Returns:
            A ``dict`` with the database record, or ``None`` if the address
            is not present in the database.
        """
        ...

    def get_with_prefix_len(self, ip_address: str) -> tuple[Any, int]:
        """Return ``(record, prefix_len)`` for *ip_address*.

        Like :meth:`get` but also returns the network prefix length of the
        matched subnet, which is useful when you need the CIDR block alongside
        the lookup result.

        Args:
            ip_address: IPv4 or IPv6 address string.

        Returns:
            A ``(record, prefix_len)`` tuple.  ``record`` is ``None`` if the
            address is not in the database; ``prefix_len`` is still valid.
        """
        ...

    def close(self) -> None:
        """Release the database file handle / memory mapping.

        Calling this while reads are in progress may raise exceptions.
        Prefer using the context-manager form instead.
        """
        ...

    def __enter__(self) -> Reader: ...
    def __exit__(self, *args: Any) -> None: ...

def open_database(database: Any, mode: int = ...) -> Reader:
    """Open a MaxMind DB database file and return a :class:`Reader`.

    Args:
        database: Path to the ``.mmdb`` file as a ``str``, ``bytes``, or
                  ``os.PathLike``; or a file descriptor (``int``) when using
                  ``MODE_FD``.
        mode:     One of the ``MODE_*`` constants (default ``MODE_AUTO``).

    Returns:
        A :class:`Reader` instance. Use as a context manager to ensure the
        file is closed when done.

    Example::

        with maxminddb.open_database("/usr/local/share/GeoLite2-City.mmdb") as db:
            record = db.get("1.2.3.4")
            country = record["country"]["iso_code"] if record else None
    """
    ...
