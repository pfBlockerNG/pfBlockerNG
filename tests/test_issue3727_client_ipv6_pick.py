"""Issue #3727: the pinned client source must sit inside pfSense's LAN prefix, not be the first global address."""

from __future__ import annotations

import importlib
from collections.abc import Callable

import pytest

# civm after the DNS rig swapped pfSense LAN to 2001:db8:51:1::1 and back to fd00::1 (SLAAC keeps the stale prefix).
TAIL = " \\       valid_lft 86376sec preferred_lft 14376sec"
STALE_FIRST = "\n".join(
    [
        "1: lo    inet6 ::1/128 scope host noprefixroute" + TAIL,
        "2: ens4    inet6 fec0::be24:11ff:fe29:a41b/64 scope site dynamic mngtmpaddr noprefixroute" + TAIL,
        "3: ens5    inet6 2001:db8:51:1:49:e4ff:fece:9272/64 scope global dynamic mngtmpaddr noprefixroute" + TAIL,
        "3: ens5    inet6 fd00::1000/128 scope global dynamic noprefixroute" + TAIL,
        "3: ens5    inet6 fd00::49:e4ff:fece:9272/64 scope global dynamic mngtmpaddr noprefixroute" + TAIL,
        "3: ens5    inet6 fe80::49:e4ff:fece:9272/64 scope link proto kernel_ll" + TAIL,
    ]
)


@pytest.fixture
def pick() -> Callable[[str, str, str], str]:
    return importlib.import_module("tests.smoke.helpers").pick_client_ipv6


def test_skips_stale_prefix_listed_first(pick: Callable[[str, str, str], str]) -> None:
    assert pick(STALE_FIRST, "ens5", "fd00::1") == "fd00::1000"


def test_follows_the_lan_address_it_is_given(pick: Callable[[str, str, str], str]) -> None:
    assert pick(STALE_FIRST, "ens5", "2001:db8:51:1::1") == "2001:db8:51:1:49:e4ff:fece:9272"


def test_ignores_other_nics_and_unusable_addresses(pick: Callable[[str, str, str], str]) -> None:
    text = (
        "2: ens4    inet6 fd00::4/64 scope global dynamic \\\n"
        "3: ens5    inet6 fd00::5/64 scope global tentative \\\n"
        "3: ens5    inet6 fd00::6/64 scope global deprecated \\\n"
        "3: ens5    inet6 fd00::7/64 scope global temporary \\\n"
        "3: ens5    inet6 fd00::8/64 scope global dynamic \\\n"
    )
    assert pick(text, "ens5", "fd00::1") == "fd00::8"


def test_prefix_boundary_is_exactly_64(pick: Callable[[str, str, str], str]) -> None:
    other_64_same_48 = "3: ens5    inet6 fd00:0:0:1::5/64 scope global dynamic \\\n"
    other_65_same_64 = "3: ens5    inet6 fd00::8000:0:0:5/64 scope global dynamic \\\n"
    assert pick(other_65_same_64, "ens5", "fd00::1") == "fd00::8000:0:0:5"
    with pytest.raises(RuntimeError):
        pick(other_64_same_48, "ens5", "fd00::1")


def test_no_match_raises_with_the_listing(pick: Callable[[str, str, str], str]) -> None:
    with pytest.raises(RuntimeError) as exc:
        pick(STALE_FIRST, "ens5", "fd00:1::1")
    assert "fd00:1::1" in str(exc.value)
    assert "2001:db8:51:1:49:e4ff:fece:9272" in str(exc.value)
