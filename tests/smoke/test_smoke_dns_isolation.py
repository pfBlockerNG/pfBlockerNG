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

This module proves the restore directly and FOR EVERY TRACKED KEY: seed all five keys to
values that ``use_system_dns_upstream`` is GUARANTEED to change (not just whatever the
image default happens to already differ on), confirm every key actually moved, then call
``restore_dns_config()`` (the same call the autouse teardown makes) and confirm every one
of the five keys is back to its pre-mutation (seeded) value -- read through this module's
OWN independent PHP reader, not the code under test.

DESELECTED from the default ``python -m pytest`` (``--ignore=tests/smoke``).
Run via the smoke workflow or locally::

    python -m pytest tests/smoke -m smoke --override-ini="addopts="

Requires the booted ``smoke_vm`` fixture, the branch ``.pkg`` (``SMOKE_PKG``), and
the smoke deps; without them these tests skip cleanly.
"""

from __future__ import annotations

import base64
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

# Seed state: every key differs from what use_system_dns_upstream (helpers.py) sets, so
# the mid-mutation assert below proves EVERY key moved -- not just the ones
# use_system_dns_upstream happened to already change from the image default.
#
#   - system/dnsserver: an RFC 5737 TEST-NET-2 address, never
#     helpers.GUEST_TO_HOST_ALIAS (what use_system_dns_upstream writes).
#   - system/dnsallowoverride / unbound/dnssec: pfSense saves both checkboxes with the
#     SAME isset()-boolean pattern -- system.php:388
#     ``config_set_path('system/dnsallowoverride', $_POST['dnsallowoverride'] ? true : false)``
#     and services_unbound.php:187
#     ``config_set_path('unbound/dnssec', isset($pconfig['dnssec']))``. A PHP `true`
#     round-tripped through the XML writer (xmlparse.inc dump_xml_config_sub(), the
#     ``(is_bool($val) && ($val == true)) ... "<{$ent}></{$ent}>\n"`` branch) becomes an
#     EMPTY element, which parses back as ``""`` -- so the real "checked" config.xml
#     value for either field is present/``""``, never a literal ``'on'`` string.
#   - unbound/forwarding: ABSENT (use_system_dns_upstream always sets it 'on').
#   - unbound/custom_options: base64-encoded, matching the pfBlockerNG textarea
#     convention helpers.use_stub_for_safesearch's forward-zone also uses.
_SEED_DNSSERVER = ["198.51.100.53"]  # RFC 5737 TEST-NET-2
_SEED_CUSTOM_OPTIONS_TEXT = "# pfb smoke dns-isolation seed\n"


def _seed_state() -> dict[str, dict[str, object]]:
    """The seed :func:`_read_dns_config`-shaped state every DNS key is set to before
    mutating, chosen so ``use_system_dns_upstream`` is guaranteed to change every key.
    """
    return {
        "system/dnsserver": {"present": True, "value": _SEED_DNSSERVER},
        "system/dnsallowoverride": {"present": True, "value": ""},
        "unbound/forwarding": {"present": False, "value": None},
        "unbound/dnssec": {"present": True, "value": ""},
        "unbound/custom_options": {
            "present": True,
            "value": base64.b64encode(_SEED_CUSTOM_OPTIONS_TEXT.encode()).decode(),
        },
    }


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
    start = out.find(_JSON_OPEN)
    end = out.find(_JSON_CLOSE, start + len(_JSON_OPEN)) if start != -1 else -1
    if result.returncode != 0 or start == -1 or end == -1:
        raise RuntimeError(f"_read_dns_config failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}")
    payload: dict[str, dict[str, object]] = json.loads(out[start + len(_JSON_OPEN) : end])
    return payload


def _write_dns_config(vm: SmokeVM, state: dict[str, dict[str, object]]) -> None:
    """Write ``state`` (the shape :func:`_read_dns_config` returns) back to the guest.

    This module's OWN independent PHP writer -- the seed/cleanup counterpart of
    :func:`_read_dns_config`, never the code under test. Embeds ``state`` as a
    json_decode-d string literal (sidesteps PHP-literal escaping for the mixed
    str/list/None values) then, per key, ``config_set_path``s a present entry or
    ``config_del_path``s an absent one, exactly mirroring
    ``helpers.restore_dns_config``'s own restore loop -- a separate implementation of
    the same shape, not a call into it.
    """
    snippet = (
        f"$__state = json_decode({h._php_str(json.dumps(state))}, true);\n"
        "foreach ($__state as $__p => $__entry) {\n"
        "    if ($__entry['present']) {\n"
        "        config_set_path($__p, $__entry['value']);\n"
        "    } else {\n"
        "        config_del_path($__p);\n"
        "    }\n"
        "}\n"
        "write_config('pfBlockerNG smoke: dns isolation seed/cleanup');\n"
        "services_unbound_configure();\n"
        "echo 'OK';"
    )
    result = h.php_eval(vm, snippet, timeout=60.0)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"_write_dns_config failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}")
    h.wait_unbound_ready(vm)


@pytest.mark.timeout(300)  # seed + mutate + restore + cleanup, each a full Unbound reload/wait
def test_restore_dns_config_returns_every_key_to_its_pre_mutation_value(
    smoke_vm: SmokeVM, stub_dns: _StubDnsServer
) -> None:
    """``restore_dns_config()`` must put ALL FIVE DNS-forwarding keys back exactly as
    they were before the mutation. Every tracked key is first seeded to a value
    ``use_system_dns_upstream`` is guaranteed to change (never a value it happens to
    already share with the image default), so the mid-mutation assert proves EVERY key
    actually moved -- not just the ones the mutator happened to touch from the image
    default -- and the post-restore assert proves every one of them is returned to its
    pre-mutation value, the same call the autouse per-module teardown makes.
    """
    original = _read_dns_config(smoke_vm)
    try:
        seed = _seed_state()
        _write_dns_config(smoke_vm, seed)
        seeded = _read_dns_config(smoke_vm)
        assert seeded == seed, (
            f"precondition failed: seeded DNS config does not match the seed written "
            f"-- expected={seed!r} actual={seeded!r}"
        )

        h.use_system_dns_upstream(smoke_vm)
        mid = _read_dns_config(smoke_vm)
        unchanged = {k: seeded[k] for k in _DNS_KEYS if mid[k] == seeded[k]}
        assert not unchanged, (
            f"precondition failed: use_system_dns_upstream left these keys unchanged "
            f"-- unchanged={unchanged!r} seeded={seeded!r} mid={mid!r}"
        )

        h.restore_dns_config()
        after = _read_dns_config(smoke_vm)
        assert after == seeded, (
            f"restore_dns_config left the DNS config different from its pre-mutation "
            f"(seeded) state -- expected={seeded!r} actual={after!r}"
        )
    finally:
        # Never leave forwarding-to-stub on for whatever runs next in this module, whatever
        # the outcome above (e.g. a failed precondition assert leaves it un-restored).
        try:
            h.restore_dns_config()
        except Exception as exc:  # noqa: BLE001 -- best-effort; _write_dns_config below still runs
            print(f"[smoke] dns-isolation restore_dns_config teardown failed (non-fatal): {exc!r}")
        # restore_dns_config() only restores back to the SEED (its own baseline); always
        # put the VM back to what it looked like before this test ever ran, regardless.
        _write_dns_config(smoke_vm, original)
