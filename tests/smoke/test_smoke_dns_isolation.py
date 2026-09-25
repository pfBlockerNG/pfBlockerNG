"""Issue #3325 regression: the shared session VM's DNS-forwarding config must not
leak from one smoke module into the next.

``tests/smoke/helpers.py``'s ``use_system_dns_upstream`` / ``set_unbound_forwarding`` /
``use_stub_for_safesearch`` rewrite ``system/dnsserver``, ``system/dnsallowoverride``,
``unbound/forwarding``, ``unbound/dnssec`` and ``unbound/custom_options`` on the SHARED
session VM and never restored them themselves -- the change persisted for every later
smoke module. ``conftest.py``'s autouse, module-scoped ``_restore_dns_config_per_module``
fixture now calls ``helpers.restore_dns_config()`` after every module, which puts those
five keys back to whatever ``helpers._remember_dns_baseline`` captured before the FIRST
DNS mutator ran this module.

This module proves the restore directly: mutate via ``use_system_dns_upstream``, then call
``restore_dns_config()`` (the same call the autouse teardown makes) and confirm every one
of the five keys is back to its pre-mutation value -- read through this module's OWN
independent PHP reader, not the code under test.

DESELECTED from the default ``python -m pytest`` (``--ignore=tests/smoke``).
Run via the smoke workflow or locally::

    python -m pytest tests/smoke -m smoke --override-ini="addopts="

Requires the booted ``smoke_vm`` fixture, the branch ``.pkg`` (``SMOKE_PKG``), and
the smoke deps; without them these tests skip cleanly.
"""

from __future__ import annotations

import json

import pytest

from . import helpers as h
from .conftest import SmokeVM, _StubDnsServer

pytestmark = pytest.mark.smoke

# Deliberately re-listed rather than imported from helpers._DNS_CONFIG_KEYS: this is the
# test's own independent oracle for what use_system_dns_upstream touches, not a mirror of
# the code under test.
_DNS_KEYS = (
    "system/dnsserver",
    "system/dnsallowoverride",
    "unbound/forwarding",
    "unbound/dnssec",
    "unbound/custom_options",
)

_JSON_OPEN = "<<<DNSISO>>>"
_JSON_CLOSE = "<<<DNSISOEND>>>"


def _read_dns_config(vm: SmokeVM) -> dict[str, dict[str, object]]:
    """Read the five DNS-forwarding config keys, own PHP reader (independent of
    ``helpers._remember_dns_baseline``'s snapshot snippet -- this is the oracle, not the
    code under test). Each key reads as ``{'present': bool, 'value': ...}`` so an ABSENT
    key round-trips distinctly from a PRESENT-but-empty one.
    """
    php_paths = ", ".join(h._php_str(p) for p in _DNS_KEYS)
    snippet = (
        f"$paths = array({php_paths});\n"
        "$out = array();\n"
        "foreach ($paths as $p) {\n"
        "    $v = config_get_path($p, NULL);\n"
        "    $out[$p] = array('present' => $v !== NULL, 'value' => $v);\n"
        "}\n"
        f"echo {h._php_str(_JSON_OPEN)} . json_encode($out) . {h._php_str(_JSON_CLOSE)};"
    )
    result = h.php_eval(vm, snippet, timeout=30.0)
    out = result.stdout
    start, end = out.find(_JSON_OPEN), out.find(_JSON_CLOSE)
    if result.returncode != 0 or start == -1 or end == -1:
        raise RuntimeError(f"_read_dns_config failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}")
    payload: dict[str, dict[str, object]] = json.loads(out[start + len(_JSON_OPEN) : end])
    return payload


@pytest.mark.timeout(300)
def test_restore_dns_config_returns_every_key_to_its_pre_mutation_value(
    smoke_vm: SmokeVM, stub_dns: _StubDnsServer
) -> None:
    """``restore_dns_config()`` must put all five DNS-forwarding keys back exactly as
    ``use_system_dns_upstream`` found them -- the same call the autouse per-module
    teardown makes, proven directly here rather than only inferred from a later module's
    behaviour.
    """
    before = _read_dns_config(smoke_vm)
    try:
        h.use_system_dns_upstream(smoke_vm)
        mid = _read_dns_config(smoke_vm)
        assert mid != before, (
            f"precondition failed: use_system_dns_upstream did not change the DNS config "
            f"-- before={before!r} mid={mid!r}"
        )

        h.restore_dns_config()
        after = _read_dns_config(smoke_vm)
        assert after == before, (
            f"restore_dns_config left the DNS config different from its pre-mutation state "
            f"-- expected={before!r} actual={after!r}"
        )
    finally:
        # Never leave forwarding-to-stub on for whatever runs next in this module, whatever
        # the outcome above (e.g. a failed precondition assert leaves it un-restored).
        h.restore_dns_config()
