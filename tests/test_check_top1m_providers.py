"""Tests for scripts/misc/check_top1m_providers.py (issue #884).

Nothing caught the Alexa Top1M source rotting silently (its hardcoded URL died
years ago; cleaned up in #877). These tests pin the guard that would have:
extracting every top1m provider URL straight from pfblockerng.php (so adding
or removing a provider arm needs no edit here), and validating a fetched
payload is actually a healthy, fresh Top1M list -- not just a 200.

No network: --check-url's HTTP fetch lives in check_url(); every test below
targets the pure functions (extract_providers / validate_top1m / is_stale)
with injected bytes/headers/now, per CLAUDE.md's no-network-in-unit-tests
branch-coverage rule.
"""

from __future__ import annotations

import csv
import http.client
import importlib.util
import io
import sys
import urllib.error
import zipfile
from datetime import datetime, timedelta, timezone
from email.utils import formatdate
from pathlib import Path
from typing import Any

_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "misc" / "check_top1m_providers.py"
_spec = importlib.util.spec_from_file_location("check_top1m_providers", _SCRIPT)
assert _spec is not None and _spec.loader is not None
ctp = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = ctp
_spec.loader.exec_module(ctp)


# --------------------------------------------------------------------------- #
# extract_providers -- PHP fixtures mirror the real extras-slot shape
# --------------------------------------------------------------------------- #

# Mirrors src/usr/local/www/pfblockerng/pfblockerng.php's real shape: extras[0]
# is a geoip slot (must NOT be picked up), extras[2] is the top1m slot with its
# URL set inside an if/else -- the type assignment trails both branches.
_PHP_TWO_PROVIDERS = """
$pfb['extras'][0]		= array();
$pfb['extras'][0]['url']	= 'https://download.maxmind.com/geoip/databases/GeoLite2-Country/download?suffix=tar.gz';
$pfb['extras'][0]['type']	= 'geoip';

$pfb['extras'][2]			= array();
if ($pfb['dnsbl_top1m_type'] === Top1mSource::Tranco) {
	$pfb['extras'][2]['url']	= 'https://tranco-list.eu/top-1m.csv.zip';
} else {
	$pfb['extras'][2]['url']	= 'https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip';  // Cisco
}
$pfb['extras'][2]['file_dwn']	= 'top-1m.csv.zip';
$pfb['extras'][2]['type']	= 'top1m';
"""

# A third provider arm added to the SAME slot (elseif) -- the crux case: the
# extractor must pick this up with no code change, proving add/remove coverage
# is automatic rather than a hardcoded Tranco/Cisco pair.
_PHP_THREE_PROVIDERS = """
$pfb['extras'][2]			= array();
if ($pfb['dnsbl_top1m_type'] === Top1mSource::Tranco) {
	$pfb['extras'][2]['url']	= 'https://tranco-list.eu/top-1m.csv.zip';
} elseif ($pfb['dnsbl_top1m_type'] === Top1mSource::Quad9) {
	$pfb['extras'][2]['url']	= 'https://example-quad9.test/top-1m.csv.zip';
} else {
	$pfb['extras'][2]['url']	= 'https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip';  // Cisco
}
$pfb['extras'][2]['type']	= 'top1m';
"""


def test_extract_providers_finds_both_top1m_urls() -> None:
    providers = ctp.extract_providers(_PHP_TWO_PROVIDERS)
    urls = {p["url"] for p in providers}
    assert urls == {
        "https://tranco-list.eu/top-1m.csv.zip",
        "https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip",
    }


def test_extract_providers_ignores_non_top1m_slot() -> None:
    providers = ctp.extract_providers(_PHP_TWO_PROVIDERS)
    urls = {p["url"] for p in providers}
    assert "https://download.maxmind.com/geoip/databases/GeoLite2-Country/download?suffix=tar.gz" not in urls


# A provider line commented out with `//` (a dead/retired provider left in
# place for reference) must not be extracted as live -- the extractor
# previously matched raw text with no regard for comments.
_PHP_WITH_A_COMMENTED_OUT_PROVIDER = """
$pfb['extras'][2]			= array();
// $pfb['extras'][2]['url']	= 'https://dead-provider.test/top-1m.csv.zip';
if ($pfb['dnsbl_top1m_type'] === Top1mSource::Tranco) {
	$pfb['extras'][2]['url']	= 'https://tranco-list.eu/top-1m.csv.zip';
} else {
	$pfb['extras'][2]['url']	= 'https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip';  // Cisco
}
$pfb['extras'][2]['type']	= 'top1m';
"""


def test_extract_providers_skips_a_commented_out_provider_line() -> None:
    providers = ctp.extract_providers(_PHP_WITH_A_COMMENTED_OUT_PROVIDER)
    urls = {p["url"] for p in providers}
    assert "https://dead-provider.test/top-1m.csv.zip" not in urls
    assert urls == {
        "https://tranco-list.eu/top-1m.csv.zip",
        "https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip",
    }


def test_extract_providers_auto_covers_a_newly_added_provider_arm() -> None:
    # This is the guarantee issue #884 asks for: add a provider arm to the PHP
    # and the extractor picks it up with zero changes to this script.
    providers = ctp.extract_providers(_PHP_THREE_PROVIDERS)
    urls = {p["url"] for p in providers}
    assert urls == {
        "https://tranco-list.eu/top-1m.csv.zip",
        "https://example-quad9.test/top-1m.csv.zip",
        "https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip",
    }


# --------------------------------------------------------------------------- #
# validate_top1m / _scan_csv -- in-memory zips, no network
# --------------------------------------------------------------------------- #


def _zip_of(rows: list[tuple[str, str]], member: str = "top-1m.csv") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        text = io.StringIO()
        writer = csv.writer(text)
        writer.writerows(rows)
        zf.writestr(member, text.getvalue())
    return buf.getvalue()


_NOW = datetime(2026, 7, 6, tzinfo=timezone.utc)
_FRESH_LM = "Sun, 05 Jul 2026 00:00:00 GMT"  # 1 day old
_STALE_LM = "Mon, 01 Jun 2026 00:00:00 GMT"  # 35 days old


def test_validate_top1m_passes_with_enough_valid_fresh_rows() -> None:
    rows = [(str(i), f"example{i}.com") for i in range(10)]
    body = _zip_of(rows)
    reasons = ctp.validate_top1m(body, _FRESH_LM, _NOW, min_rows=10, max_age_days=30)
    assert reasons == []


def test_validate_top1m_fails_when_row_count_below_min_rows() -> None:
    # Truncated payload: 5 good rows, floor set to 10.
    rows = [(str(i), f"example{i}.com") for i in range(5)]
    body = _zip_of(rows)
    reasons = ctp.validate_top1m(body, _FRESH_LM, _NOW, min_rows=10, max_age_days=30)
    assert len(reasons) == 1
    assert "expected >= 10" in reasons[0]
    assert "found 5" in reasons[0]


def test_validate_top1m_fails_when_body_is_not_a_zip() -> None:
    reasons = ctp.validate_top1m(b"<html>error</html>", _FRESH_LM, _NOW, min_rows=10, max_age_days=30)
    assert len(reasons) == 1
    assert "ZIP" in reasons[0]


def test_validate_top1m_fails_on_a_malformed_row_non_int_rank_no_dot_domain() -> None:
    # 9 good rows + 1 malformed ("foo,bar": non-int rank, no-dot domain) with
    # min_rows=10 -- the malformed row doesn't count as valid, so the floor
    # check itself catches it, AND the report names the exact bad row.
    rows = [(str(i), f"example{i}.com") for i in range(9)]
    rows.append(("foo", "bar"))
    body = _zip_of(rows)
    reasons = ctp.validate_top1m(body, _FRESH_LM, _NOW, min_rows=10, max_age_days=30)
    assert len(reasons) == 1
    assert "found 9" in reasons[0]
    assert "foo" in reasons[0] and "bar" in reasons[0]


def test_validate_top1m_rejects_a_bare_dot_as_a_domain() -> None:
    # A bare "." has no real label on either side of the dot -- must not read
    # as a valid "rank,domain" row just because it contains a "." and no space.
    rows = [(str(i), f"example{i}.com") for i in range(9)]
    rows.append(("9", "."))
    body = _zip_of(rows)
    reasons = ctp.validate_top1m(body, _FRESH_LM, _NOW, min_rows=10, max_age_days=30)
    assert len(reasons) == 1
    assert "found 9" in reasons[0]


def test_validate_top1m_flags_staleness_only_once_last_modified_ages_past_the_limit() -> None:
    # Before-state: same payload is healthy while Last-Modified is fresh...
    rows = [(str(i), f"example{i}.com") for i in range(10)]
    body = _zip_of(rows)
    assert ctp.validate_top1m(body, _FRESH_LM, _NOW, min_rows=10, max_age_days=30) == []

    # ...and only the Last-Modified age flips it to stale -- proving staleness,
    # not row count, caused the failure.
    reasons = ctp.validate_top1m(body, _STALE_LM, _NOW, min_rows=10, max_age_days=30)
    assert len(reasons) == 1
    assert "35 days old" in reasons[0]


# --------------------------------------------------------------------------- #
# is_stale -- fresh / old / missing header, against an injected `now`
# --------------------------------------------------------------------------- #


def test_is_stale_false_for_a_fresh_last_modified() -> None:
    assert ctp.is_stale(_FRESH_LM, _NOW, max_age_days=30) is False


def test_is_stale_true_once_last_modified_exceeds_max_age_days() -> None:
    assert ctp.is_stale(_STALE_LM, _NOW, max_age_days=30) is True


def test_is_stale_false_right_at_the_max_age_days_boundary() -> None:
    boundary = (_NOW - timedelta(days=30)).strftime("%a, %d %b %Y %H:%M:%S GMT")
    assert ctp.is_stale(boundary, _NOW, max_age_days=30) is False


def test_is_stale_false_when_last_modified_header_is_absent() -> None:
    # No header means "unknown", not "stale" -- a provider that omits
    # Last-Modified must not be flagged purely for that omission.
    assert ctp.is_stale(None, _NOW, max_age_days=30) is False


# --------------------------------------------------------------------------- #
# check_url -- urllib.request.urlopen mocked out, no real network (#884
# review: the gap that let the tz-crash and read-crash bugs ship unnoticed).
# --------------------------------------------------------------------------- #


class _FakeResponse:
    """Minimal stand-in for the context-manager `http.client.HTTPResponse`."""

    def __init__(self, body: bytes, headers: dict[str, str], status: int = 200) -> None:
        self._body = body
        self.headers = headers
        self.status = status

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, *exc_info: object) -> None:
        return None


class _FailingReadResponse:
    """A response whose `.read()` raises -- simulates a cut-short download."""

    def __init__(self, exc: BaseException) -> None:
        self._exc = exc
        self.status = 200
        self.headers: dict[str, str] = {}

    def read(self) -> bytes:
        raise self._exc

    def __enter__(self) -> "_FailingReadResponse":
        return self

    def __exit__(self, *exc_info: object) -> None:
        return None


_ALWAYS_FRESH_LM = formatdate(usegmt=True)  # "now", so never stale regardless of wall-clock date


def _healthy_zip_body(rows: int = 10) -> bytes:
    return _zip_of([(str(i), f"example{i}.com") for i in range(rows)])


def test_check_url_reports_a_clean_reason_on_http_error(monkeypatch: Any) -> None:
    def fake_urlopen(request: Any, timeout: int) -> Any:
        raise urllib.error.HTTPError(request.full_url, 404, "Not Found", hdrs=None, fp=None)  # type: ignore[arg-type]

    monkeypatch.setattr(ctp.urllib.request, "urlopen", fake_urlopen)
    reasons = ctp.check_url("https://example.test/top-1m.csv.zip")
    assert len(reasons) == 1
    assert "404" in reasons[0]


def test_check_url_reports_a_clean_reason_when_the_body_read_is_cut_short(monkeypatch: Any) -> None:
    # The #3 fix: IncompleteRead mid-download of the multi-MB zip is neither
    # HTTPError nor URLError -- a narrower except let this raise a raw
    # traceback instead of a clean FAIL report.
    exc = http.client.IncompleteRead(partial=b"only some bytes")
    monkeypatch.setattr(ctp.urllib.request, "urlopen", lambda request, timeout: _FailingReadResponse(exc))
    reasons = ctp.check_url("https://example.test/top-1m.csv.zip")
    assert len(reasons) == 1
    assert "connection error" in reasons[0]


def test_check_url_reports_a_non_2xx_status_that_urlopen_does_not_raise_for(monkeypatch: Any) -> None:
    body = _healthy_zip_body()
    monkeypatch.setattr(
        ctp.urllib.request,
        "urlopen",
        lambda request, timeout: _FakeResponse(body, {"Last-Modified": _ALWAYS_FRESH_LM}, status=304),
    )
    reasons = ctp.check_url("https://example.test/top-1m.csv.zip", min_rows=10)
    assert len(reasons) == 1
    assert "304" in reasons[0]


def test_check_url_delegates_to_validate_top1m_on_a_healthy_2xx_response(monkeypatch: Any) -> None:
    body = _healthy_zip_body()
    monkeypatch.setattr(
        ctp.urllib.request,
        "urlopen",
        lambda request, timeout: _FakeResponse(body, {"Last-Modified": _ALWAYS_FRESH_LM}),
    )
    reasons = ctp.check_url("https://example.test/top-1m.csv.zip", min_rows=10)
    assert reasons == []


def test_check_url_handles_a_stale_tz_less_last_modified_without_crashing(monkeypatch: Any) -> None:
    # The #2 crash: a Last-Modified with no timezone (RFC-822-legal, e.g.
    # "Mon, 01 Jan 2001 00:00:00") used to raise TypeError subtracting a naive
    # datetime from the aware `now` inside the staleness-message branch.
    body = _healthy_zip_body()
    monkeypatch.setattr(
        ctp.urllib.request,
        "urlopen",
        lambda request, timeout: _FakeResponse(body, {"Last-Modified": "Mon, 01 Jan 2001 00:00:00"}),
    )
    reasons = ctp.check_url("https://example.test/top-1m.csv.zip", min_rows=10)
    assert len(reasons) == 1
    assert "days old" in reasons[0]


# --------------------------------------------------------------------------- #
# main -- exit code reflects check_url's verdict
# --------------------------------------------------------------------------- #


def test_main_exits_zero_when_check_url_reports_healthy(monkeypatch: Any, capsys: Any) -> None:
    monkeypatch.setattr(ctp, "check_url", lambda url, **_kwargs: [])
    code = ctp.main(["--check-url", "https://example.test/top-1m.csv.zip"])
    assert code == 0
    assert "OK" in capsys.readouterr().out


def test_main_exits_nonzero_when_check_url_reports_unhealthy(monkeypatch: Any, capsys: Any) -> None:
    monkeypatch.setattr(ctp, "check_url", lambda url, **_kwargs: ["expected a reachable URL, got a connection error"])
    code = ctp.main(["--check-url", "https://example.test/top-1m.csv.zip"])
    assert code != 0
    out = capsys.readouterr().out
    assert "FAIL" in out
    assert "connection error" in out
