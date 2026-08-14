"""Observed libpkg ordering contract for issue #2140."""

from __future__ import annotations

from itertools import pairwise

import pytest

from .conftest import SmokeVM

pytestmark = pytest.mark.smoke

PKG = "/usr/local/sbin/pkg"

ORDERED_VERSIONS = (
    "3.2.15",
    "3.2.16.a1",
    "3.2.16.b1",
    "3.2.16.r1",
    "3.2.16",
    "4.0.0.a1",
    "4.0.0.b1",
    "4.0.0.r1",
    "4.0.0",
    f"20260804120000.{'a' * 7}",
    f"20260804120001.{'f' * 7}",
    f"20260805120000.{'0' * 7}",
)


def test_ordering_oracle_fixture_is_exact() -> None:
    assert ORDERED_VERSIONS == (
        "3.2.15",
        "3.2.16.a1",
        "3.2.16.b1",
        "3.2.16.r1",
        "3.2.16",
        "4.0.0.a1",
        "4.0.0.b1",
        "4.0.0.r1",
        "4.0.0",
        f"20260804120000.{'a' * 7}",
        f"20260804120001.{'f' * 7}",
        f"20260805120000.{'0' * 7}",
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
