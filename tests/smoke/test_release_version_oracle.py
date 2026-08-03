"""Observed libpkg ordering contract for project release channels (issue #2140)."""

from __future__ import annotations

from itertools import pairwise

import pytest

from .conftest import SmokeVM

pytestmark = pytest.mark.smoke

PKG = "/usr/local/sbin/pkg"

ORDERED_VERSIONS = (
    "3.2.0",
    "3.2.1.alpha.1",
    "3.2.1.alpha.2",
    "3.2.1.beta.1",
    "3.2.1.rc.1",
    "3.2.1.snapshot.1.20260803.1",
    "3.2.1.snapshot.1.20260803.2",
    "3.2.1.snapshot.2.20260803.1",
    "3.2.1",
)


def test_supported_pkg_orders_every_release_channel(smoke_vm: SmokeVM) -> None:
    """The appliance's pkg implementation orders every adjacent contract row."""
    implementation = smoke_vm.ssh(PKG, "-v")
    assert implementation.returncode == 0, implementation.stderr

    observed: list[str] = []
    for older, newer in pairwise(ORDERED_VERSIONS):
        result = smoke_vm.ssh(PKG, "version", "-t", older, newer)
        assert result.returncode == 0, result.stderr
        comparison = result.stdout.strip()
        observed.append(f"{older} {comparison} {newer}")
        assert comparison == "<", observed[-1]

    print(f"pkg={implementation.stdout.strip()}")
    print("\n".join(observed))
