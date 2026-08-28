"""Tests for scripts/misc/check_top1m_providers.py (issue #884, ADR-59 P6).

Nothing caught the Alexa Top1M source rotting silently (its hardcoded URL died
years ago; cleaned up in #877). These tests pin the guard that would have:
extracting every top1m provider straight from `pfb_top1m_providers()`'s
descriptor table (pfblockerng_extra.inc) -- so adding or removing a provider
row needs no edit here -- classifying each by its `auth` (keyless vs a CI-secret
-gated token provider), and validating a fetched payload is actually a
healthy, fresh Top1M list -- not just a 200.

ADR-59 moved the provider URLs off pfblockerng.php's literal
`$pfb['extras'][2]['url'] = '...'` assignment (the shape these tests used to
target) into the descriptor table -- that assignment is now an expression
reading the table, so the OLD extraction regex no longer matches anything.
This suite targets the table directly.

No network: --check-url's HTTP fetch lives in check_url(); every test below
targets the pure functions (extract_providers / validate_top1m / is_stale /
main's classification) with injected bytes/headers/now/env, per CLAUDE.md's
no-network-in-unit-tests branch-coverage rule.
"""

from __future__ import annotations

import csv
import http.client
import importlib.util
import io
import json
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
# extract_providers -- descriptor-table fixtures mirror pfb_top1m_providers()
# --------------------------------------------------------------------------- #

# Mirrors the real pfb_top1m_providers() shape: two keyless zip providers
# (Tranco/Cisco, no 'label'/'container' -- exercises the fallback defaults),
# one keyless plain-CSV provider (Majestic-shaped), and one token provider
# (Cloudflare-shaped) whose 'auth' is a structured {header, scheme} array.
_PHP_DESCRIPTOR_TABLE = """
function pfb_top1m_providers(): array
{
	return array(
		PfbTop1mSource::Tranco->value	=> array(
			'url'		=> 'https://tranco-list.eu/top-1m.csv.zip',
			'container'	=> 'zip',
			'auth'		=> 'none',
			'label'		=> 'Tranco',
		),
		PfbTop1mSource::Cisco->value	=> array(
			'url'		=> 'https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip',
			'container'	=> 'zip',
			'auth'		=> 'none',
			'label'		=> 'Cisco Umbrella',
		),
		PfbTop1mSource::Majestic->value	=> array(
			'url'		=> 'https://downloads.majestic.com/majestic_million.csv',
			'container'	=> 'plain',
			'auth'		=> 'none',
			'label'		=> 'Majestic Million',
			'licence'	=> 'CC BY 3.0 -- attribution required',
		),
		PfbTop1mSource::Cloudflare->value	=> array(
			'url'		=> 'https://api.cloudflare.com/client/v4/radar/datasets/ranking_top_1000000',
			'container'	=> 'plain',
			'auth'		=> array('header' => 'Authorization', 'scheme' => 'Bearer'),
			'label'		=> 'Cloudflare Radar',
			'licence'	=> 'CC BY-NC 4.0 -- non-commercial use, attribution required',
		),
	);
}
"""


def test_extract_providers_finds_every_row_in_the_descriptor_table() -> None:
    providers = ctp.extract_providers(_PHP_DESCRIPTOR_TABLE)
    urls = {p["url"] for p in providers}
    assert urls == {
        "https://tranco-list.eu/top-1m.csv.zip",
        "https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip",
        "https://downloads.majestic.com/majestic_million.csv",
        "https://api.cloudflare.com/client/v4/radar/datasets/ranking_top_1000000",
    }


def test_extract_providers_reads_label_and_container_per_row() -> None:
    providers = {p["name"]: p for p in ctp.extract_providers(_PHP_DESCRIPTOR_TABLE)}
    assert providers["Tranco"]["container"] == "zip"
    assert providers["Majestic Million"]["container"] == "plain"


def test_extract_providers_classifies_keyless_providers_as_auth_none() -> None:
    providers = {p["name"]: p for p in ctp.extract_providers(_PHP_DESCRIPTOR_TABLE)}
    for name in ("Tranco", "Cisco Umbrella", "Majestic Million"):
        assert providers[name]["auth"] == "none"
        assert providers[name]["secret_env"] == ""


def test_extract_providers_classifies_a_token_provider_and_derives_its_secret_env() -> None:
    # The load-bearing new behaviour: a structured {header, scheme} 'auth'
    # marks the provider as token-gated, and the CI secret env-var name is
    # DERIVED from its label -- "Cloudflare Radar" -> CLOUDFLARE_RADAR_TOKEN,
    # matching the ADR's own example (S2.7) with no separate mapping table.
    providers = {p["name"]: p for p in ctp.extract_providers(_PHP_DESCRIPTOR_TABLE)}
    cloudflare = providers["Cloudflare Radar"]
    assert cloudflare["auth"] == "token"
    assert cloudflare["secret_env"] == "CLOUDFLARE_RADAR_TOKEN"
    assert cloudflare["auth_header"] == "Authorization"
    assert cloudflare["auth_scheme"] == "Bearer"


# A fifth descriptor row (a plain new top-level array entry, the actual shape
# a new provider takes in the real table) alongside the same four -- the
# crux case: the extractor must pick this up with zero code changes, proving
# add/remove coverage is automatic against the new source of truth, not a
# hardcoded 4-provider list.
_PHP_DESCRIPTOR_TABLE_WITH_A_FIFTH_ROW = """
function pfb_top1m_providers(): array
{
	return array(
		PfbTop1mSource::Tranco->value	=> array(
			'url'		=> 'https://tranco-list.eu/top-1m.csv.zip',
			'container'	=> 'zip',
			'auth'		=> 'none',
			'label'		=> 'Tranco',
		),
		PfbTop1mSource::Cisco->value	=> array(
			'url'		=> 'https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip',
			'container'	=> 'zip',
			'auth'		=> 'none',
			'label'		=> 'Cisco Umbrella',
		),
		PfbTop1mSource::Majestic->value	=> array(
			'url'		=> 'https://downloads.majestic.com/majestic_million.csv',
			'container'	=> 'plain',
			'auth'		=> 'none',
			'label'		=> 'Majestic Million',
		),
		PfbTop1mSource::Cloudflare->value	=> array(
			'url'		=> 'https://api.cloudflare.com/client/v4/radar/datasets/ranking_top_1000000',
			'container'	=> 'plain',
			'auth'		=> array('header' => 'Authorization', 'scheme' => 'Bearer'),
			'label'		=> 'Cloudflare Radar',
		),
		PfbTop1mSource::Quad9->value	=> array(
			'url'		=> 'https://example-quad9.test/top-1m.csv.zip',
			'container'	=> 'zip',
			'auth'		=> 'none',
			'label'		=> 'Quad9',
		),
	);
}
"""


def test_extract_providers_auto_covers_a_newly_added_descriptor_row() -> None:
    # This is the guarantee issue #884 asks for: add a row to the descriptor
    # table and the extractor picks it up with zero changes to this script.
    providers = ctp.extract_providers(_PHP_DESCRIPTOR_TABLE_WITH_A_FIFTH_ROW)
    names = {p["name"] for p in providers}
    assert names == {"Tranco", "Cisco Umbrella", "Majestic Million", "Cloudflare Radar", "Quad9"}


# A row commented out with `//` (a dead/retired provider left in place for
# reference) must not be extracted as live -- mirrors the pre-existing
# comment-stripping guarantee, now against the descriptor table.
_PHP_WITH_A_COMMENTED_OUT_ROW = """
function pfb_top1m_providers(): array
{
	return array(
		// PfbTop1mSource::Dead->value	=> array('url' => 'https://dead.test/x', 'auth' => 'none', 'label' => 'Dead'),
		PfbTop1mSource::Tranco->value	=> array(
			'url'		=> 'https://tranco-list.eu/top-1m.csv.zip',
			'container'	=> 'zip',
			'auth'		=> 'none',
			'label'		=> 'Tranco',
		),
	);
}
"""


def test_extract_providers_skips_a_commented_out_row() -> None:
    providers = ctp.extract_providers(_PHP_WITH_A_COMMENTED_OUT_ROW)
    names = {p["name"] for p in providers}
    assert names == {"Tranco"}


_PHP_ONE_PROVIDER_NO_LABEL_NO_CONTAINER = """
function pfb_top1m_providers(): array
{
	return array(
		PfbTop1mSource::Tranco->value	=> array(
			'url'	=> 'https://tranco-list.eu/top-1m.csv.zip',
			'auth'	=> 'none',
		),
	);
}
"""


def test_extract_providers_falls_back_to_url_netloc_and_zip_container_when_absent() -> None:
    (provider,) = ctp.extract_providers(_PHP_ONE_PROVIDER_NO_LABEL_NO_CONTAINER)
    assert provider["name"] == "tranco-list.eu"
    assert provider["container"] == "zip"


def test_extract_providers_reads_the_real_descriptor_file_and_finds_all_five() -> None:
    # #892 review (finding 6): every other test above feeds a hand-built fixture table --
    # none couples the extractor to the REAL pfblockerng_extra.inc shape, so a silent
    # reformat of the actual descriptor (a renamed field, a changed quoting style) could
    # go undetected here while still breaking check_top1m_providers.py in CI. Read the
    # real file straight off disk instead of a fixture.
    providers = {p["name"]: p for p in ctp.extract_providers(ctp.DEFAULT_DESCRIPTOR_FILE.read_text(encoding="utf-8"))}
    assert set(providers) == {"Tranco", "Cisco Umbrella", "OpenPageRank", "Majestic Million", "Cloudflare Radar"}

    for name in ("Tranco", "Cisco Umbrella", "OpenPageRank", "Majestic Million"):
        assert providers[name]["auth"] == "none", name
        assert providers[name]["secret_env"] == "", name

    cloudflare = providers["Cloudflare Radar"]
    assert cloudflare["auth"] == "token"
    assert cloudflare["secret_env"] == "CLOUDFLARE_RADAR_TOKEN"
    assert cloudflare["auth_header"] == "Authorization"
    assert cloudflare["auth_scheme"] == "Bearer"


# --------------------------------------------------------------------------- #
# _matching_paren -- string-literal-aware paren counting (issue #908)
# --------------------------------------------------------------------------- #

# A 'label' with an unbalanced ')' inside the string (one '(', two ')') --
# the current table is paren-free, but a future provider naming its mirror
# "Tranco Mirror (EU))" (or any label/licence containing a stray paren) must
# not confuse the block-boundary scanner.
#
# FAIL-BEFORE/PASS-AFTER (#908): pre-fix, the naive char-counting
# `_matching_paren` treats every '(' / ')' in the raw text as real -- the
# extra ')' inside this label makes its depth hit 0 one field early, cutting
# the provider's block off mid-string (before the closing quote). The
# resulting truncated block has no closing `'` for 'label' to match, so
# `_LABEL_FIELD_RE` fails to match at all and the provider silently falls
# back to its URL's netloc ("tranco-list.eu") instead of the real label --
# confirmed against pre-fix code (`git stash`): the assertion below FAILS,
# `providers["Tranco Mirror (EU))"]` is absent (KeyError) because the name
# came out as "tranco-list.eu" instead. Post-fix, the scanner never leaves
# the quoted span for those parens, so the real closing paren is found and
# every field (url/container/auth/label) survives intact.
_PHP_DESCRIPTOR_TABLE_WITH_AN_UNBALANCED_PAREN_IN_A_LABEL = """
function pfb_top1m_providers(): array
{
	return array(
		PfbTop1mSource::Tranco->value	=> array(
			'url'		=> 'https://tranco-list.eu/top-1m.csv.zip',
			'container'	=> 'zip',
			'auth'		=> 'none',
			'label'		=> 'Tranco Mirror (EU))',
			'licence'	=> 'CC0',
		),
		PfbTop1mSource::Cisco->value	=> array(
			'url'		=> 'https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip',
			'container'	=> 'zip',
			'auth'		=> 'none',
			'label'		=> 'Cisco Umbrella',
			'licence'	=> 'proprietary',
		),
	);
}
"""


def test_extract_providers_handles_an_unbalanced_paren_inside_a_label_string() -> None:
    providers = {p["name"]: p for p in ctp.extract_providers(_PHP_DESCRIPTOR_TABLE_WITH_AN_UNBALANCED_PAREN_IN_A_LABEL)}
    assert set(providers) == {"Tranco Mirror (EU))", "Cisco Umbrella"}

    tranco = providers["Tranco Mirror (EU))"]
    assert tranco["url"] == "https://tranco-list.eu/top-1m.csv.zip"
    assert tranco["container"] == "zip"
    assert tranco["auth"] == "none"

    # The block boundary must not have leaked into Cisco's row either.
    cisco = providers["Cisco Umbrella"]
    assert cisco["url"] == "https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip"


def test_matching_paren_treats_a_backslash_escaped_quote_as_not_ending_the_string() -> None:
    # FAIL-BEFORE/PASS-AFTER (#908): the literal PHP string is  Rob's)  -- an
    # escaped quote (\\') followed by a stray, unmatched ')' still inside the
    # quotes. Pre-fix (no quote-awareness at all), the scanner reads every
    # character literally: it hits the escaped "'" and treats it as a normal
    # char (no effect), but then the following genuine ')' balances the
    # opening '(' and returns index 13 -- the ')' INSIDE the string, not the
    # array's real closing paren at index 23 (confirmed against pre-fix code
    # via `git stash`). Post-fix, the scanner recognizes `\'` as an escaped
    # quote that keeps the string open, so the stray ')' is skipped and the
    # true closing paren (index 23) is returned.
    text = r"""array('Rob\'s)', 'more')"""
    open_idx = text.index("(")
    assert ctp._matching_paren(text, open_idx) == len(text) - 1 == 23


def _zip_of(rows: list[tuple[str, ...]], member: str = "top-1m.csv") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        text = io.StringIO()
        writer = csv.writer(text)
        writer.writerows(rows)
        zf.writestr(member, text.getvalue())
    return buf.getvalue()


def _plain_csv_of(rows: list[tuple[str, ...]]) -> bytes:
    text = io.StringIO()
    csv.writer(text).writerows(rows)
    return text.getvalue().encode("utf-8")


_NOW = datetime(2026, 7, 6, tzinfo=timezone.utc)
_FRESH_LM = "Sun, 05 Jul 2026 00:00:00 GMT"  # 1 day old
_STALE_LM = "Mon, 01 Jun 2026 00:00:00 GMT"  # 35 days old


def test_validate_top1m_passes_with_enough_valid_fresh_rows() -> None:
    rows: list[tuple[str, ...]] = [(str(i), f"example{i}.com") for i in range(10)]
    body = _zip_of(rows)
    reasons = ctp.validate_top1m(body, _FRESH_LM, _NOW, min_rows=10, max_age_days=30)
    assert reasons == []


def test_validate_top1m_fails_when_row_count_below_min_rows() -> None:
    # Truncated payload: 5 good rows, floor set to 10.
    rows: list[tuple[str, ...]] = [(str(i), f"example{i}.com") for i in range(5)]
    body = _zip_of(rows)
    reasons = ctp.validate_top1m(body, _FRESH_LM, _NOW, min_rows=10, max_age_days=30)
    assert len(reasons) == 1
    assert "expected >= 10" in reasons[0]
    assert "found 5" in reasons[0]


def test_validate_top1m_fails_when_a_zip_container_body_is_not_a_zip() -> None:
    reasons = ctp.validate_top1m(b"<html>error</html>", _FRESH_LM, _NOW, min_rows=10, max_age_days=30, container="zip")
    assert len(reasons) == 1
    assert "ZIP" in reasons[0]


def test_validate_top1m_fails_on_a_malformed_row_non_int_rank_no_dot_domain() -> None:
    # 9 good rows + 1 malformed ("foo,bar": neither field has a dot) with
    # min_rows=10 -- the malformed row doesn't count as valid, so the floor
    # check itself catches it, AND the report names the exact bad row.
    rows: list[tuple[str, ...]] = [(str(i), f"example{i}.com") for i in range(9)]
    rows.append(("foo", "bar"))
    body = _zip_of(rows)
    reasons = ctp.validate_top1m(body, _FRESH_LM, _NOW, min_rows=10, max_age_days=30)
    assert len(reasons) == 1
    assert "found 9" in reasons[0]
    assert "foo" in reasons[0] and "bar" in reasons[0]


def test_validate_top1m_rejects_a_bare_dot_as_a_domain() -> None:
    # A bare "." has no real label on either side of the dot -- must not read
    # as a valid domain row just because it contains a "." and no space.
    rows: list[tuple[str, ...]] = [(str(i), f"example{i}.com") for i in range(9)]
    rows.append(("9", "."))
    body = _zip_of(rows)
    reasons = ctp.validate_top1m(body, _FRESH_LM, _NOW, min_rows=10, max_age_days=30)
    assert len(reasons) == 1
    assert "found 9" in reasons[0]


def test_validate_top1m_flags_staleness_only_once_last_modified_ages_past_the_limit() -> None:
    # Before-state: same payload is healthy while Last-Modified is fresh...
    rows: list[tuple[str, ...]] = [(str(i), f"example{i}.com") for i in range(10)]
    body = _zip_of(rows)
    assert ctp.validate_top1m(body, _FRESH_LM, _NOW, min_rows=10, max_age_days=30) == []

    # ...and only the Last-Modified age flips it to stale -- proving staleness,
    # not row count, caused the failure.
    reasons = ctp.validate_top1m(body, _STALE_LM, _NOW, min_rows=10, max_age_days=30)
    assert len(reasons) == 1
    assert "35 days old" in reasons[0]


# A ~5-month-old Last-Modified: past the old 30-day default, well within the new
# 6-month one. A provider that refreshes only monthly/quarterly (e.g. OpenPageRank) is
# not dead at this age.
_WITHIN_SIX_MONTHS_LM = "Fri, 06 Feb 2026 00:00:00 GMT"  # 150 days before _NOW


def test_validate_top1m_default_staleness_window_is_six_months_not_thirty_days() -> None:
    # FAIL-BEFORE/PASS-AFTER for the 30 -> 180 day default bump: this calls
    # validate_top1m WITHOUT max_age_days, so it exercises the MAX_AGE_DAYS
    # default. A 150-day-old feed is stale under the old 30-day default (test
    # fails) and fresh under the new 6-month one (test passes).
    rows: list[tuple[str, ...]] = [(str(i), f"example{i}.com") for i in range(10)]
    body = _zip_of(rows)
    assert ctp.validate_top1m(body, _WITHIN_SIX_MONTHS_LM, _NOW, min_rows=10) == []


# --- 'plain' container (Majestic/Cloudflare's real shape): no zip wrapper --- #


def test_validate_top1m_passes_a_plain_container_body_with_no_zip_wrapper() -> None:
    # FAIL-BEFORE/PASS-AFTER for the container-awareness fix: the pre-P6
    # script assumed every body was a zip unconditionally, so a real (never
    # vendored) Majestic/Cloudflare-shaped plain CSV response would have been
    # misread as "not a valid ZIP archive" and reported unhealthy even though
    # the feed itself is perfectly fine.
    rows: list[tuple[str, ...]] = [(str(i), f"example{i}.com") for i in range(10)]
    body = _plain_csv_of(rows)
    reasons = ctp.validate_top1m(body, _FRESH_LM, _NOW, min_rows=10, max_age_days=30, container="plain")
    assert reasons == []


def test_validate_top1m_skips_a_header_row_in_a_plain_wide_csv_with_domain_not_in_column_zero() -> None:
    # Majestic/OpenPageRank-shaped: a header row, then real rows with the domain in
    # a column other than 0/1 -- _is_valid_row must find it anywhere in the
    # row (provider-agnostic), and the header row (no dotted field) must not
    # count as valid or as the "first bad row".
    rows: list[tuple[str, ...]] = [("GlobalRank", "TldRank", "Domain", "TLD")]
    rows += [(str(i), str(i), f"example{i}.com", "com") for i in range(10)]
    body = _plain_csv_of(rows)
    reasons = ctp.validate_top1m(body, _FRESH_LM, _NOW, min_rows=10, max_age_days=30, container="plain")
    assert reasons == []


def test_validate_top1m_fails_a_plain_container_body_with_too_few_domain_rows() -> None:
    # A plain body that never validates (empty/garbage) fails via the row-count
    # floor with an informative message -- not the "ZIP" message, since a
    # 'plain' container never attempts a zip parse.
    reasons = ctp.validate_top1m(
        b"<html>error</html>", _FRESH_LM, _NOW, min_rows=10, max_age_days=30, container="plain"
    )
    assert len(reasons) == 1
    assert "found 0" in reasons[0]
    assert "ZIP" not in reasons[0]


def test_validate_top1m_single_domain_only_column_cloudflare_shape_passes() -> None:
    # Cloudflare's real shape: ONE 'domain' column, no rank at all.
    rows: list[tuple[str, ...]] = [("domain",)]
    rows += [(f"example{i}.com",) for i in range(10)]
    body = _plain_csv_of(rows)
    reasons = ctp.validate_top1m(body, _FRESH_LM, _NOW, min_rows=10, max_age_days=30, container="plain")
    assert reasons == []


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
    # The #3 fix: IncompleteRead mid-download of the multi-MB body is neither
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


def test_check_url_passes_the_caller_supplied_headers_through_to_the_request(monkeypatch: Any) -> None:
    # A token provider's Authorization header must actually reach the
    # request object, alongside (not instead of) the User-Agent.
    body = _healthy_zip_body()
    seen: dict[str, Any] = {}

    def fake_urlopen(request: Any, timeout: int) -> Any:
        seen["headers"] = dict(request.headers)
        return _FakeResponse(body, {"Last-Modified": _ALWAYS_FRESH_LM})

    monkeypatch.setattr(ctp.urllib.request, "urlopen", fake_urlopen)
    reasons = ctp.check_url(
        "https://example.test/top-1m.csv.zip", min_rows=10, headers={"Authorization": "Bearer sekrit-token-value"}
    )
    assert reasons == []
    # urllib.request.Request title-cases header names on the wire.
    assert seen["headers"]["Authorization"] == "Bearer sekrit-token-value"
    assert seen["headers"]["User-agent"] == "pfBlockerNG-top1m-healthcheck/1.0"


# --------------------------------------------------------------------------- #
# main -- exit code reflects check_url's verdict, and the auth classification
# ('auth: none' vs a CI-secret-gated token provider, ADR-59 S2.7)
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


def test_main_never_calls_check_url_for_a_keyless_provider_and_behaves_as_before(monkeypatch: Any, capsys: Any) -> None:
    # Before-state: a keyless provider (no --secret-env) is unchanged -- it is
    # validated exactly like every prior release of this script.
    called: dict[str, Any] = {}

    def fake_check_url(url: str, **kwargs: Any) -> list[str]:
        called["headers"] = kwargs.get("headers")
        return []

    monkeypatch.setattr(ctp, "check_url", fake_check_url)
    code = ctp.main(["--check-url", "https://example.test/top-1m.csv.zip"])
    assert code == 0
    assert called["headers"] is None
    assert "OK" in capsys.readouterr().out


def test_main_skips_a_token_provider_with_no_reason_to_fail_when_its_secret_is_absent(
    monkeypatch: Any, capsys: Any
) -> None:
    # The new behaviour this phase adds: a token-gated provider (Cloudflare)
    # with no configured CI secret must be VISIBLY skipped and exit 0 -- never
    # silently, and never counted as an unhealthy/failing leg.
    monkeypatch.delenv("CLOUDFLARE_RADAR_TOKEN", raising=False)

    def fail_if_called(url: str, **kwargs: Any) -> list[str]:
        raise AssertionError("check_url must not be called when the secret is absent")

    monkeypatch.setattr(ctp, "check_url", fail_if_called)
    code = ctp.main(
        [
            "--check-url",
            "https://api.cloudflare.com/client/v4/radar/datasets/ranking_top_1000000",
            "--container",
            "plain",
            "--secret-env",
            "CLOUDFLARE_RADAR_TOKEN",
            "--auth-header",
            "Authorization",
            "--auth-scheme",
            "Bearer",
        ]
    )
    assert code == 0
    out = capsys.readouterr().out
    assert "SKIP" in out
    assert "needs token" in out
    assert "CLOUDFLARE_RADAR_TOKEN" in out


def test_main_validates_a_token_provider_once_its_mocked_secret_is_present(monkeypatch: Any, capsys: Any) -> None:
    # ...and once a secret IS configured (mocked here via monkeypatch.setenv,
    # standing in for a real repo secret in CI), the SAME provider is
    # validated -- proving the secret's presence, not its absence, drives the
    # behaviour change (before/after pair with the test above).
    monkeypatch.setenv("CLOUDFLARE_RADAR_TOKEN", "mock-token-value")
    seen: dict[str, Any] = {}

    def fake_check_url(url: str, **kwargs: Any) -> list[str]:
        seen["container"] = kwargs.get("container")
        seen["headers"] = kwargs.get("headers")
        return []

    monkeypatch.setattr(ctp, "check_url", fake_check_url)
    code = ctp.main(
        [
            "--check-url",
            "https://api.cloudflare.com/client/v4/radar/datasets/ranking_top_1000000",
            "--container",
            "plain",
            "--secret-env",
            "CLOUDFLARE_RADAR_TOKEN",
            "--auth-header",
            "Authorization",
            "--auth-scheme",
            "Bearer",
        ]
    )
    assert code == 0
    assert seen["container"] == "plain"
    assert seen["headers"] == {"Authorization": "Bearer mock-token-value"}
    out = capsys.readouterr().out
    assert "OK" in out
    assert "mock-token-value" not in out, "the token must never be printed, even in the healthy report"


def test_main_never_prints_the_token_on_an_unhealthy_token_provider_result(monkeypatch: Any, capsys: Any) -> None:
    # Security-relevant: the token must not leak even in a FAIL report's
    # reason text (e.g. a real connection-error string echoing request state).
    monkeypatch.setenv("CLOUDFLARE_RADAR_TOKEN", "mock-token-value")
    monkeypatch.setattr(ctp, "check_url", lambda url, **_kwargs: ["expected HTTP 2xx, got HTTP 401 Unauthorized"])
    code = ctp.main(
        [
            "--check-url",
            "https://api.cloudflare.com/client/v4/radar/datasets/ranking_top_1000000",
            "--secret-env",
            "CLOUDFLARE_RADAR_TOKEN",
        ]
    )
    assert code != 0
    out = capsys.readouterr().out
    assert "mock-token-value" not in out


# --------------------------------------------------------------------------- #
# main --extract -- the --min-providers floor (issue #908 defect 2): a
# partial extractor breakage silently dropping providers must FAIL, not pass
# a too-small matrix on to the workflow.
# --------------------------------------------------------------------------- #


def test_main_extract_fails_when_discovered_providers_are_below_the_floor(monkeypatch: Any, capsys: Any) -> None:
    # Before-state below pairs with the at-floor pass test right after it --
    # together they prove the count, not something else, drives the verdict.
    monkeypatch.setattr(ctp, "extract_providers", lambda _text: [{"name": "Only One"}])
    code = ctp.main(["--extract", "--min-providers", "2"])
    assert code != 0
    err = capsys.readouterr().err
    assert "expected >= 2" in err
    assert "found 1" in err


def test_main_extract_passes_when_discovered_providers_meet_the_floor(monkeypatch: Any, capsys: Any) -> None:
    fake_providers = [{"name": "One"}, {"name": "Two"}]
    monkeypatch.setattr(ctp, "extract_providers", lambda _text: fake_providers)
    code = ctp.main(["--extract", "--min-providers", "2"])
    assert code == 0
    out = capsys.readouterr().out
    assert json.loads(out) == fake_providers


def test_main_extract_default_min_providers_matches_the_real_descriptor_file() -> None:
    # Regression guard: the default floor (MIN_PROVIDERS) must equal the
    # ACTUAL committed provider count, else either a legitimate table would
    # spuriously fail this gate, or the floor would silently tolerate a
    # dropped provider. Pairs with
    # test_extract_providers_reads_the_real_descriptor_file_and_finds_all_five
    # -- both must move together whenever a provider is added/removed.
    real_count = len(ctp.extract_providers(ctp.DEFAULT_DESCRIPTOR_FILE.read_text(encoding="utf-8")))
    assert ctp.MIN_PROVIDERS == real_count
