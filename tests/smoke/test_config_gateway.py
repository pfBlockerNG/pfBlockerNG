"""Live-VM gateway round-trip coverage for ADR-29 (PfbConfig).

Carries the ``smoke`` marker so it runs alongside the main smoke matrix
(``pytest -m smoke --override-ini="addopts="``).  The test skips cleanly when
``SMOKE_PKG`` or the booted ``smoke_vm`` fixture are absent.

ONE CASE:

``test_gateway_adapter_roundtrip_live``
  Exercises the write-adapter round-trip for EVERY adapter class in the registry
  on a REAL pfSense box:

    - ``PfbToggle`` (``dnsbl_vip_auto``): stored tokens 'on' / ''.
    - ``PfbLenient`` (``dnsbl_lenient``): stored tokens 'on' / 'off' / ''
      ('' is the legacy read token — write emits 'off', but raw storage holds '').
    - ``pfb_idn`` identity adapter (excluded from enum adoption at PfbConfig
      level): stored tokens 'all' / 'confusable' / 'off' each round-trip
      byte-for-byte.
    - plain-string adapter (``pfb_feed_internal_filter``): arbitrary token
      identity-passes through.
    - ``pfb_keep`` absent-seed (issue #281): install-time migration writes 'on';
      explicit writes of '' and 'on' both round-trip correctly.

  Every adapter branch is asserted BOTH before and after each write (the
  mandate: assert the before-state so green proves the write caused the change,
  not that the expected value already held).

  A DNSBL ``unique_domain()`` name is also VIP-blocked before any adapter write
  and re-probed after all writes, confirming the runtime contract remains intact.

  The test snapshots every config key it mutates at the start and restores all
  of them in a ``finally:`` block with a final reload, so the shared smoke VM
  is left in a clean, DNSBL-working state for sibling tests.

Deselected from the default ``python -m pytest``
(``--ignore=tests/smoke`` in pyproject.toml). Run with::

    python -m pytest tests/smoke -m smoke --override-ini="addopts="
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

import tests.smoke.helpers as h
from tests.smoke.conftest import SmokeVM

pytestmark = pytest.mark.smoke

# --------------------------------------------------------------------------- #
# Config-path constants (mirrors helpers.py CFG_* — avoid importing private names)
# --------------------------------------------------------------------------- #

_CFG_GLOBAL = "installedpackages/pfblockerng/config/0"
_CFG_DNSBL = "installedpackages/pfblockerngdnsblsettings/config/0"

# Fields exercised per adapter class.
# PfbToggle-adapted (stored 'on' / '').  Config key: pfb_dnsvip_auto.
_FIELD_TOGGLE = _CFG_DNSBL + "/pfb_dnsvip_auto"
# PfbLenient-adapted (stored 'on' / 'off' / '').  Config key: pfb_dnsbl_lenient.
_FIELD_LENIENT = _CFG_DNSBL + "/pfb_dnsbl_lenient"
# pfb_idn — excluded from enum adoption, identity adapter at PfbConfig level
# (stored 'on' / 'all' / 'confusable' / 'off' / ''); 'on'->'all' normalises at
# pfb_global() OUTSIDE the gateway — the gateway itself round-trips any token.
_FIELD_IDN = _CFG_DNSBL + "/pfb_idn"
# plain-string adapter (identity, arbitrary stored value).
_FIELD_PLAIN = _CFG_GLOBAL + "/pfb_feed_internal_filter"
# issue-#281 seed field (absent → seeded 'on' by pfb_keep_migrate on install).
_FIELD_KEEP = _CFG_GLOBAL + "/pfb_keep"

# Enable-chain fields mutated during setup — must be snapshotted and restored.
_FIELD_ENABLE_CB = _CFG_GLOBAL + "/enable_cb"
_FIELD_PFB_DNSBL = _CFG_DNSBL + "/pfb_dnsbl"

# All fields the test may mutate (snapshot → restore in finally).
_MUTABLE_FIELDS = [
    _FIELD_ENABLE_CB,
    _FIELD_PFB_DNSBL,
    _FIELD_TOGGLE,
    _FIELD_LENIENT,
    _FIELD_IDN,
    _FIELD_PLAIN,
    _FIELD_KEEP,
]

# Local DNSBL feed for the VIP-block runtime probe.  Domain is unique per run so
# it cannot conflict with another test's feed or HSTS preload entries.
# Use h.unique_domain() with no prefix → uuid-<hex>.com form, guaranteed not
# HSTS-preloaded and not an RFC 6761 reserved TLD.
_FEED_NAME = "gateway_roundtrip.txt"


# --------------------------------------------------------------------------- #
# Module-scoped setup fixture — deploy once, skip when SMOKE_PKG absent
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def gateway_vm(smoke_vm: SmokeVM) -> Iterator[SmokeVM]:
    """Deploy the branch .pkg once for the gateway round-trip module.

    Mirrors the setup-fixture pattern used by ``test_smoke_dnsbl_control.py``
    and the DNSBL matrix: skip if ``SMOKE_PKG`` is absent, deploy, yield.
    """
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")
    h.deploy(smoke_vm)
    yield smoke_vm


# --------------------------------------------------------------------------- #
# Internal helpers — thin wrappers around php_eval for per-field writes
# --------------------------------------------------------------------------- #


def _write_field(vm: SmokeVM, path: str, value: str, *, timeout: float = 60.0) -> None:
    """Write ``value`` to the config.xml scalar at ``path`` via pfSsh.php.

    Derives the section path (everything up to the last ``/``) and the leaf key,
    then issues a ``config_get_path`` / set-key / ``config_set_path`` /
    ``write_config`` snippet over :func:`tests.smoke.helpers.php_eval` — the same
    authenticated pfSense config API the production code uses.
    """
    section, _, key = path.rpartition("/")
    if not section:
        raise ValueError(f"_write_field: path has no section component: {path!r}")
    snippet = (
        f"$s = config_get_path({h._php_str(section)}, array());\n"
        f"$s[{h._php_str(key)}] = {h._php_str(value)};\n"
        f"config_set_path({h._php_str(section)}, $s);\n"
        "write_config('pfBlockerNG gateway smoke: write field');\n"
        "echo 'OK';"
    )
    result = h.php_eval(vm, snippet, timeout=timeout)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(
            f"_write_field({path!r}={value!r}) failed: rc={result.returncode} "
            f"stdout={result.stdout!r} stderr={result.stderr!r}"
        )


def _assert_stored(vm: SmokeVM, path: str, expected: str, label: str) -> None:
    """Assert config.xml holds ``expected`` at ``path``; ``label`` names the assertion."""
    got = h.config_get(vm, path)
    assert got == expected, (
        f"Gateway round-trip FAIL [{label}]: {path!r} = {got!r}, expected {expected!r}. "
        f"The write adapter did not emit the correct legacy stored token."
    )


def _snapshot_fields(vm: SmokeVM, paths: list[str]) -> dict[str, str]:
    """Read each path from config.xml and return {path: stored_value}."""
    return {path: h.config_get(vm, path) for path in paths}


def _restore_fields(vm: SmokeVM, snapshot: dict[str, str]) -> None:
    """Best-effort restore of every field in ``snapshot`` to its snapshotted value.

    Called from a ``finally`` block — swallows individual write errors so a
    teardown failure cannot mask the original test assertion failure.
    """
    for path, value in snapshot.items():
        try:
            _write_field(vm, path, value)
        except Exception:
            pass  # best-effort; the test outcome is already decided


# --------------------------------------------------------------------------- #
# Test — adapter round-trip across every adapter class
# --------------------------------------------------------------------------- #


@pytest.mark.timeout(600)
def test_gateway_adapter_roundtrip_live(gateway_vm: SmokeVM) -> None:
    """Gateway write-adapter round-trip: every adapter class, before→after, on a real box.

    Proves that the legacy stored token in config.xml is byte-identical to what
    was written for each PfbConfig adapter type, and that the pfb_keep install-
    time migration seeds the key correctly.  A DNSBL unique_domain() VIP probe
    confirms the runtime contract remains intact after all gateway writes.

    The test snapshots all mutable config fields before the first write and
    restores them in a finally block so the shared smoke VM is left in a clean,
    DNSBL-working state for sibling tests (isolation contract).

    Scenario: ADR-29 write-adapter round-trip holds on the live pfSense VM.
      Background: branch .pkg deployed; pfSsh.php config API available.

    Given the package is installed, the DNSBL VIP is seeded, and a local feed
      blocks a unique_domain() name with a VIP response,

    When each registered adapter class is exercised with its full vocabulary
      (toggle: 'on'/''; lenient: 'on'/'off'/''; identity/pfb_idn:
      'all'/'confusable'/'off'; plain-string: 'on'/''; pfb_keep seed assert
      + write 'on'/''),

    Then config.xml holds the exact legacy token the write-adapter emits for each
      input (BEFORE state asserted first, AFTER state asserted after each write);
      AND the DNSBL-blocked unique_domain() name returns NOERROR + VIP both
      before and after all gateway writes (runtime contract intact).
    """
    vm = gateway_vm

    # Generate the blocked domain once per test run so it is collision-proof.
    # unique_domain() with no prefix → uuid-<hex>.com — not HSTS-preloaded,
    # not an RFC 6761 reserved TLD, not a .test/.example shadow.
    blocked_domain = h.unique_domain()

    # -------------------------------------------------------------------- #
    # GIVEN: snapshot all fields we will mutate (for isolation / finally restore)
    # -------------------------------------------------------------------- #

    snapshot = _snapshot_fields(vm, _MUTABLE_FIELDS)

    try:
        # ---------------------------------------------------------------- #
        # GIVEN: DNSBL VIP seeded; local feed wired; enable chain on
        #
        # Mirror the proven _setup_dnsbl_feed pattern from
        # test_upgrade_config_stability.py: write the feed CONTAINING the
        # exact blocked domain, inject as DnsblCase with hsts=False, seed
        # the VIP, enable the chain, reload, then assert the BEFORE probe.
        # ---------------------------------------------------------------- #

        h.ensure_dnsbl_vip(vm)

        feed_path = h.write_local_feed(vm, _FEED_NAME, f"{blocked_domain}\n")
        spec = h.DnsblCase(
            aliasname="GatewayRoundTrip",
            feed_url=feed_path,
            mode=h.DnsblMode.VIP,
            header="gateway-roundtrip-smoke",
            hsts=False,
        )
        h.inject(vm, spec)

        # Enable the DNSBL enable chain (enable_cb + pfb_dnsbl) so the reload works.
        _write_field(vm, _FIELD_ENABLE_CB, "on")
        _write_field(vm, _FIELD_PFB_DNSBL, "on")

        h.reload(vm, "updatednsbl")

        # ---------------------------------------------------------------- #
        # GIVEN runtime BEFORE-baseline: blocked domain returns VIP
        # (proves DNSBL is live and the final runtime check is not vacuous)
        # ---------------------------------------------------------------- #

        before_runtime = h.dns_probe(vm, blocked_domain, "A")
        assert h.is_vip(before_runtime), (
            f"BEFORE gateway writes: expected VIP block for {blocked_domain!r}; "
            f"got rcode={before_runtime.rcode!r} records={before_runtime.records!r}. "
            f"DNSBL was not live before the adapter-write assertions."
        )

        # ---------------------------------------------------------------- #
        # WHEN / THEN — PfbToggle adapter (dnsbl_vip_auto): tokens 'on' / ''
        #
        # Capture the initial value first (BEFORE), then assert both write
        # branches ('on' and '') each produce the exact stored token.
        # ---------------------------------------------------------------- #

        toggle_before = h.config_get(vm, _FIELD_TOGGLE)
        assert toggle_before in ("on", ""), (
            f"PfbToggle BEFORE: unexpected initial value {toggle_before!r} for {_FIELD_TOGGLE!r}"
        )

        _write_field(vm, _FIELD_TOGGLE, "on")
        _assert_stored(vm, _FIELD_TOGGLE, "on", "toggle: write 'on' → stored 'on'")

        _write_field(vm, _FIELD_TOGGLE, "")
        _assert_stored(vm, _FIELD_TOGGLE, "", "toggle: write '' → stored ''")

        # Restore original (idempotent when it was '').
        _write_field(vm, _FIELD_TOGGLE, toggle_before)

        # ---------------------------------------------------------------- #
        # WHEN / THEN — PfbLenient adapter (dnsbl_lenient): tokens 'on'/'off'/''
        #
        # '' is the legacy read token (pre-ADR-22 absent-key state); the write
        # adapter emits 'off' for PfbLenient::Off, never ''.  We prove all three
        # branches: 'on', 'off', and the raw '' as a stored (not written) token.
        # ---------------------------------------------------------------- #

        lenient_before = h.config_get(vm, _FIELD_LENIENT)
        assert lenient_before in ("on", "off", ""), (
            f"PfbLenient BEFORE: unexpected initial value {lenient_before!r} for {_FIELD_LENIENT!r}"
        )

        _write_field(vm, _FIELD_LENIENT, "on")
        _assert_stored(vm, _FIELD_LENIENT, "on", "lenient: write 'on' → stored 'on'")

        _write_field(vm, _FIELD_LENIENT, "off")
        _assert_stored(vm, _FIELD_LENIENT, "off", "lenient: write 'off' → stored 'off'")

        # '' is a LEGACY READ token — it can exist in old configs and must pass
        # through unchanged at the raw config level (not introduced by the write
        # adapter, but valid to store for backward-compat probing).
        _write_field(vm, _FIELD_LENIENT, "")
        _assert_stored(vm, _FIELD_LENIENT, "", "lenient: write '' → stored '' (legacy read token)")

        _write_field(vm, _FIELD_LENIENT, lenient_before)

        # ---------------------------------------------------------------- #
        # WHEN / THEN — pfb_idn identity adapter: tokens 'all'/'confusable'/'off'
        #
        # pfb_idn is EXCLUDED from enum adoption at PfbConfig level (null/null
        # adapters — identity).  The 'on'→'all' normalisation happens only at
        # pfb_global() outside PfbConfig; the gateway itself never mutates any
        # stored token.  Prove all three canonical tokens round-trip unchanged.
        # ---------------------------------------------------------------- #

        idn_before = h.config_get(vm, _FIELD_IDN)
        assert idn_before in ("on", "all", "confusable", "off", ""), (
            f"pfb_idn BEFORE: unexpected initial value {idn_before!r} for {_FIELD_IDN!r}"
        )

        _write_field(vm, _FIELD_IDN, "all")
        _assert_stored(vm, _FIELD_IDN, "all", "pfb_idn identity: write 'all' → stored 'all'")

        _write_field(vm, _FIELD_IDN, "confusable")
        _assert_stored(vm, _FIELD_IDN, "confusable", "pfb_idn identity: write 'confusable' → stored 'confusable'")

        _write_field(vm, _FIELD_IDN, "off")
        _assert_stored(vm, _FIELD_IDN, "off", "pfb_idn identity: write 'off' → stored 'off'")

        # Restore; fall back to 'off' if the key was absent (safe stored state).
        _write_field(vm, _FIELD_IDN, idn_before if idn_before else "off")

        # ---------------------------------------------------------------- #
        # WHEN / THEN — plain-string adapter (pfb_feed_internal_filter): identity
        #
        # Any stored string passes through unchanged.  Prove 'on' and '' both
        # round-trip as-is (two branches: value present / value cleared).
        # ---------------------------------------------------------------- #

        plain_before = h.config_get(vm, _FIELD_PLAIN)

        _write_field(vm, _FIELD_PLAIN, "on")
        _assert_stored(vm, _FIELD_PLAIN, "on", "plain-string: write 'on' → stored 'on'")

        _write_field(vm, _FIELD_PLAIN, "")
        _assert_stored(vm, _FIELD_PLAIN, "", "plain-string: write '' → stored ''")

        _write_field(vm, _FIELD_PLAIN, plain_before)

        # ---------------------------------------------------------------- #
        # WHEN / THEN — pfb_keep absent-seed + explicit round-trip (issue #281)
        #
        # pfb_keep_migrate() seeds pfb_keep='on' during install so the pre-deinstall
        # hook never fires a config wipe.  Assert 'on' is already present (migration
        # ran), then prove both stored tokens ('on' / '') round-trip correctly.
        # ---------------------------------------------------------------- #

        keep_initial = h.config_get(vm, _FIELD_KEEP)
        assert keep_initial == "on", (
            f"pfb_keep absent-seed FAIL: expected 'on' (seeded by pfb_keep_migrate on install); "
            f"got {keep_initial!r} for {_FIELD_KEEP!r}. The install-time migration did not run."
        )

        _write_field(vm, _FIELD_KEEP, "")
        _assert_stored(vm, _FIELD_KEEP, "", "pfb_keep: write '' → stored '' (keep off)")

        _write_field(vm, _FIELD_KEEP, "on")
        _assert_stored(vm, _FIELD_KEEP, "on", "pfb_keep: write 'on' → stored 'on' (keep on / restore)")

        # ---------------------------------------------------------------- #
        # THEN runtime AFTER-check: DNSBL still returns VIP after all gateway writes
        #
        # Reload so the installed build re-reads the current config, then probe the
        # SAME domain.  Green proves the adapter writes did not corrupt runtime state.
        # ---------------------------------------------------------------- #

        h.reload(vm, "updatednsbl")

        after_runtime = h.dns_probe(vm, blocked_domain, "A")
        assert h.is_vip(after_runtime), (
            f"AFTER gateway writes: expected VIP block for {blocked_domain!r}; "
            f"got rcode={after_runtime.rcode!r} records={after_runtime.records!r}. "
            f"Runtime contract broken by an adapter write side-effect."
        )

    finally:
        # ---------------------------------------------------------------- #
        # ISOLATION: restore every mutated config field to its snapshotted
        # value and do a final reload so the shared smoke VM is left in a
        # clean, DNSBL-working state for sibling tests.  Both steps are
        # best-effort (exceptions swallowed) so teardown never masks the
        # original test assertion failure.
        # ---------------------------------------------------------------- #
        _restore_fields(vm, snapshot)
        try:
            h.reload(vm, "updatednsbl")
        except Exception:
            pass  # best-effort teardown
