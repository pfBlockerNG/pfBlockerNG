"""ADR-43 Phase 3 — explicit trigger API and deprecated verb adapters (smoke tests).

Live-VM tests for:
  - helpers.reload() now routes non-cron scopes through the ``pfb_trigger`` CLI verb
    (new API); CaseContext exercises this automatically for all existing DNSBL/IP cases.
  - Deprecated verb adapters (``update``/``updateip``/``updatednsbl``) still complete
    a reload AND emit 'DEPRECATED: pfblockerng verb ...' in pfblockerng.log.

HA-sync (secondary-VM XMLRPC resync) is an out-of-CI limitation — no secondary VM is
available in the CI smoke environment.  The pfblockerng.xml diff (trigger='manual' array
form) was reviewed manually as part of Phase 3.

Authored Phase 3, run in Phase 7 fan-out:
  gh workflow run smoke.yml -f pytest_k="trigger_api"

Local (docs/misc/local-smoke-debian.md):
  scripts/local-smoke.sh -k "trigger_api"
"""

from __future__ import annotations

import pytest

from . import helpers as h
from .conftest import SmokeVM, _MockFeedServer

pytestmark = pytest.mark.smoke


# ---------------------------------------------------------------------------
# New pfb_trigger CLI verb — exercises the path helpers.reload() uses
# ---------------------------------------------------------------------------


@pytest.mark.smoke
def test_pfb_trigger_verb_reloads_dnsbl(smoke_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """Scenario: pfb_trigger scope=both force=false trigger=cron reloads DNSBL.

    Given a DNSBL feed containing a unique test domain.
    When helpers.reload(vm, "update") runs — now uses pfb_trigger internally (Phase 3).
    Then the domain is blocked (NOERROR + VIP shape).

    This pins the pfb_trigger-via-helpers.reload() path: if the verb is not wired, the
    PHP CLI returns rc!=0 and reload() raises RuntimeError before any DNS assertion.
    """
    domain = h.unique_domain()
    feed_url = mock_feeds.feed_url("dnsbl_plain.txt")
    spec = h.DnsblCase(
        aliasname="pfb_trigger_dnsbl",
        feed_url=feed_url,
        header="pfb_trigger_dnsbl",
        mode=h.DnsblMode.VIP,
    )
    with h.CaseContext(smoke_vm, spec):
        # CaseContext.__enter__ already called reload("update") via pfb_trigger.
        # Assert the block is live.
        answer = h.dns_probe(smoke_vm, domain)
        assert h.is_vip(answer), (
            f"domain {domain!r} must be VIP-blocked after pfb_trigger reload\ngot answer: {answer!r}"
        )


# ---------------------------------------------------------------------------
# Deprecated verb adapters
# ---------------------------------------------------------------------------


@pytest.mark.smoke
@pytest.mark.parametrize("verb", ["update", "updateip", "updatednsbl"])
def test_deprecated_verb_logs_deprecation_warning(smoke_vm: SmokeVM, verb: str) -> None:
    """Scenario: deprecated verb emits DEPRECATED line in pfblockerng.log.

    Given the count of 'DEPRECATED: pfblockerng verb {verb}' lines in pfblockerng.log.
    When helpers.reload_deprecated_verb(vm, verb) runs.
    Then the count has increased by at least 1.

    This pins the sync_package_pfblockerng() string-path deprecation log (Phase 3):
    pfb_verb_deprecation_warning() is called for 'update'/'updateip'/'updatednsbl' and
    the result is written via pfb_logger(). A future removal of the log line breaks this.
    """
    marker = f"DEPRECATED: pfblockerng verb '{verb}'"
    before = h.count_log_marker(smoke_vm, h.PFB_LOG, marker)
    h.reload_deprecated_verb(smoke_vm, verb)
    after = h.count_log_marker(smoke_vm, h.PFB_LOG, marker)
    assert after > before, (
        f"deprecated verb {verb!r}: expected a new '{marker}' line in {h.PFB_LOG}\nbefore={before}, after={after}"
    )


@pytest.mark.smoke
def test_deprecated_update_verb_still_reloads_dnsbl(smoke_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """Scenario: deprecated 'update' verb adapter still completes a DNSBL reload.

    Given a DNSBL feed containing a unique test domain.
    When reload_deprecated_verb(vm, "update") runs (the deprecated adapter path).
    Then the domain is blocked — the adapter preserved the reload behaviour.

    This is the adapter coverage test: reload_deprecated_verb() exercises the
    deprecated string path directly (bypassing the pfb_trigger abstraction in reload()).
    """
    domain = h.unique_domain()
    feed_url = mock_feeds.feed_url("dnsbl_plain.txt")
    spec = h.DnsblCase(
        aliasname="pfb_dep_update_dnsbl",
        feed_url=feed_url,
        header="pfb_dep_update_dnsbl",
        mode=h.DnsblMode.VIP,
    )
    # Inject manually (no CaseContext — we control the reload verb ourselves)
    h.inject(smoke_vm, spec)
    h.reload_deprecated_verb(smoke_vm, "update")
    answer = h.dns_probe(smoke_vm, domain)
    assert h.is_vip(answer), (
        f"domain {domain!r} must be VIP-blocked after deprecated 'update' reload\ngot answer: {answer!r}"
    )
