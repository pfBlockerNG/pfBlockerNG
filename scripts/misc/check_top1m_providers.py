#!/usr/bin/env python3
"""check_top1m_providers.py -- health-check the Top1M provider URLs we ship.

Issue #884: nothing caught the Alexa Top1M source rotting silently (its
hardcoded URL died years ago; cleaned up in #877). This script gives the
weekly top1m-healthcheck.yml workflow something to fail on the day the next
provider dies the same way.

ADR-59 moved the provider URLs off a literal `$pfb['extras'][2]['url'] = '...'`
assignment in pfblockerng.php into a descriptor table,
`pfb_top1m_providers()` (pfblockerng_extra.inc) -- this script reads THAT
table instead, and now also classifies each provider by its descriptor's
`auth`: keyless providers are GET-validated as always; a token provider
(e.g. Cloudflare Radar) is validated only when its matching CI secret is
present, else visibly skipped (never silently -- #884's own ethos).

We do NOT vendor the ~1M-row lists -- they're runtime-downloaded per box.
This is validate-only: fetch, check it's a real recent Top1M list, report.

Two modes:
  --extract           Parse pfblockerng_extra.inc's pfb_top1m_providers()
                       descriptor table, print every provider as a JSON list
                       to stdout (name/url/container/auth/secret_env/
                       auth_header/auth_scheme). Feeds the workflow's
                       matrix -- add/remove a descriptor row and this picks
                       it up with no edit here.
  --check-url <url>   Fetch + validate one URL. Prints an expected-vs-actual
                       report. Exit 0 = healthy (or visibly skipped for a
                       token provider with no configured secret), non-zero
                       = unhealthy. Options: --container {zip,plain}
                       (default zip); --secret-env NAME (env var holding the
                       token -- absent/empty ⇒ skip, never fail) plus
                       --auth-header/--auth-scheme to shape the header.

Dev-host tooling (scripts/): bare `python3` is fine here, this never runs on
the pfSense appliance (CLAUDE.md's appliance-python carve-out).
"""

from __future__ import annotations

import argparse
import csv
import http.client
import io
import json
import os
import re
import sys
import urllib.error
import urllib.request
import zipfile
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.parse import urlparse

# A real Top1M list is ~1M rows; 100k is a generous floor that still rejects a
# truncated/error payload. Lists update ~daily; 30 days is generously frozen.
MIN_ROWS = 100_000
MAX_AGE_DAYS = 30

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DESCRIPTOR_FILE = REPO_ROOT / "src/usr/local/pkg/pfblockerng/pfblockerng_extra.inc"

# Matches "Top1mSource::<Case>->value => array(" -- the start of one provider's
# descriptor block in pfb_top1m_providers()'s return array. Unique to that
# table (grepped): every other `->value` use in the file is `$this->value`
# inside the enum body, which this pattern doesn't match.
_PROVIDER_ENTRY_RE = re.compile(r"Top1mSource::\w+->value\s*=>\s*array\(")
_URL_FIELD_RE = re.compile(r"'url'\s*=>\s*'([^']*)'")
_LABEL_FIELD_RE = re.compile(r"'label'\s*=>\s*'([^']*)'")
_CONTAINER_FIELD_RE = re.compile(r"'container'\s*=>\s*'([^']*)'")
# The structured shape 'auth' takes for a token provider (see
# pfb_top1m_auth_headers()'s docblock): array('header' => '...', 'scheme' => '...').
# Any other 'auth' value (the string 'none', or anything unrecognized) reads as
# keyless -- mirrors pfb_top1m_auth_headers()'s own fail-open-to-no-header default.
_AUTH_TOKEN_RE = re.compile(r"'auth'\s*=>\s*array\(\s*'header'\s*=>\s*'([^']*)'\s*,\s*'scheme'\s*=>\s*'([^']*)'\s*\)")


def _strip_php_line_comments(php_text: str) -> str:
    """Drop whole-line `//`-commented-out lines before extraction.

    Without this, a commented-out `// Top1mSource::Dead->value => array(...`
    is still picked up as a live provider (the regex matches raw text). A
    trailing comment on a live line is unaffected -- the field is already
    matched before the comment starts.

    ponytail: only whole-line `//` comments are stripped, matching this
    file's style; a `/* */` block comment would need its own handling.
    """
    return "\n".join(line for line in php_text.splitlines() if not line.strip().startswith("//"))


def _matching_paren(text: str, open_idx: int) -> int:
    """Index of the ')' that balances the '(' at text[open_idx]."""
    depth = 0
    for i in range(open_idx, len(text)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return i
    raise ValueError("unbalanced parentheses scanning a provider descriptor block")


def _name_from_url(url: str) -> str:
    # Cosmetic fallback only, used when a block has no 'label' field.
    return urlparse(url).netloc or url


def _secret_env_from_label(label: str) -> str:
    """Derive the CI secret env-var name for a token provider from its label.

    "Cloudflare Radar" -> "CLOUDFLARE_RADAR_TOKEN" -- matches the ADR's own
    example secret name (ADR-59 S2.7), so a future token provider needs no
    separate name-mapping table: give its repo secret the same derived name
    as its descriptor's 'label'.
    """
    slug = re.sub(r"[^A-Za-z0-9]+", "_", label).strip("_").upper()
    return f"{slug}_TOKEN"


def extract_providers(php_text: str) -> list[dict[str, str]]:
    """Every provider row in `pfb_top1m_providers()`'s descriptor table.

    ADR-59 moved the TOP1M URLs off a literal
    `$pfb['extras'][2]['url'] = '...'` assignment in pfblockerng.php into the
    descriptor table in pfblockerng_extra.inc -- a new provider row (or a
    removed one) is picked up here with zero code change, same add/remove
    guarantee issue #884 originally asked for, now against the real source
    of truth.

    Ceiling: matches the table's current single-quoted, non-concatenated
    literal style; a double-quoted string or `'base' . $expr` concatenation
    would need extending the field regexes.
    """
    php_text = _strip_php_line_comments(php_text)
    providers: list[dict[str, str]] = []
    for match in _PROVIDER_ENTRY_RE.finditer(php_text):
        open_idx = match.end() - 1  # the '(' this match ends on
        close_idx = _matching_paren(php_text, open_idx)
        block = php_text[open_idx : close_idx + 1]

        url_match = _URL_FIELD_RE.search(block)
        if not url_match or not url_match.group(1):
            continue
        url = url_match.group(1)

        label_match = _LABEL_FIELD_RE.search(block)
        name = label_match.group(1) if label_match else _name_from_url(url)

        container_match = _CONTAINER_FIELD_RE.search(block)
        container = container_match.group(1) if container_match else "zip"

        token_match = _AUTH_TOKEN_RE.search(block)
        if token_match:
            auth = "token"
            auth_header, auth_scheme = token_match.group(1), token_match.group(2)
            secret_env = _secret_env_from_label(name)
        else:
            auth = "none"
            auth_header = auth_scheme = secret_env = ""

        providers.append(
            {
                "name": name,
                "url": url,
                "container": container,
                "auth": auth,
                "secret_env": secret_env,
                "auth_header": auth_header,
                "auth_scheme": auth_scheme,
            }
        )
    return providers


def _parse_http_date(value: str | None) -> datetime | None:
    """Parse an HTTP-date header into a tz-aware UTC datetime.

    Returns None for an absent or unparseable header. A bare RFC-822 date with
    no zone (legal HTTP, e.g. "Mon, 01 Jun 2026 00:00:00") parses to a naive
    datetime -- pin it to UTC here so no caller ever subtracts a naive value
    from an aware `now` (that raised TypeError; see #884 review).
    """
    if not value:
        return None
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def is_stale(last_modified: str | None, now: datetime, max_age_days: int) -> bool:
    """True iff a present, parseable Last-Modified is older than max_age_days.

    No header, or one we can't parse, means "unknown" -- not a staleness
    verdict we can make, so it reads as not-stale rather than a false alarm.
    """
    modified = _parse_http_date(last_modified)
    if modified is None:
        return False
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    return (now - modified) > timedelta(days=max_age_days)


def _looks_like_domain(value: str) -> bool:
    """A plausible dotted domain label: no whitespace, >= 2 non-empty labels."""
    value = value.strip()
    if not value or any(c.isspace() for c in value):
        return False
    labels = value.split(".")
    return len(labels) >= 2 and all(labels)


def _is_valid_row(row: list[str]) -> bool:
    """A plausible Top1M row: at least one field looks like a dotted domain.

    Provider-agnostic across every descriptor shape -- Tranco/Cisco's 2-col
    rank+domain, DomCop's 3-col Rank/Domain/OpenPageRank, Majestic's wide
    12-col layout, Cloudflare's bare single 'domain' column. The health-check
    only needs proof real domain rows are still flowing, not which exact
    column holds them. A header row's field names ("Domain", "GlobalRank",
    ...) have no dot, so header rows fail this check with no separate
    header-skip needed.
    """
    return any(_looks_like_domain(field) for field in row)


def _scan_rows(text: io.TextIOBase, member: str) -> tuple[str, int, int, tuple[int, list[str]] | None]:
    total = 0
    valid = 0
    first_bad: tuple[int, list[str]] | None = None
    for line_num, row in enumerate(csv.reader(text), start=1):
        if not row:
            continue
        total += 1
        if _is_valid_row(row):
            valid += 1
        elif first_bad is None:
            first_bad = (line_num, row)
    return member, total, valid, first_bad


def _scan_csv(body: bytes, container: str = "zip") -> tuple[str, int, int, tuple[int, list[str]] | None]:
    """Scan `body`'s CSV rows per its descriptor `container` ('zip'/'plain').

    Returns (member_name, total_rows, valid_rows, first_bad_row). 'zip' may
    raise zipfile.BadZipFile on a non-zip/corrupt body (the caller catches
    zip-shape errors); 'plain' scans the raw body as CSV text directly --
    Majestic and Cloudflare ship an uncompressed CSV, not a zip.
    """
    if container == "plain":
        text: io.TextIOBase = io.TextIOWrapper(io.BytesIO(body), encoding="utf-8", errors="replace", newline="")
        return _scan_rows(text, "(plain body)")

    with zipfile.ZipFile(io.BytesIO(body)) as zf:
        names = zf.namelist()
        if not names:
            raise zipfile.BadZipFile("zip archive has no members")
        member = next((n for n in names if n.lower().endswith(".csv")), names[0])
        with zf.open(member) as fh:
            text = io.TextIOWrapper(fh, encoding="utf-8", errors="replace", newline="")
            return _scan_rows(text, member)


def validate_top1m(
    body: bytes,
    last_modified: str | None,
    now: datetime,
    min_rows: int = MIN_ROWS,
    max_age_days: int = MAX_AGE_DAYS,
    container: str = "zip",
) -> list[str]:
    """Validate a fetched Top1M payload. Empty return = healthy."""
    try:
        member, total, valid, first_bad = _scan_csv(body, container)
    except zipfile.BadZipFile as exc:
        return [f"expected a valid non-empty ZIP archive, got {len(body)} bytes that failed to parse ({exc})"]

    reasons = []
    if valid < min_rows:
        detail = f"; first bad row at {member}:{first_bad[0]}: {first_bad[1]!r}" if first_bad else ""
        reasons.append(
            f"expected >= {min_rows} valid domain rows in {member!r}, found {valid} (of {total} total rows){detail}"
        )
    if is_stale(last_modified, now, max_age_days):
        modified = _parse_http_date(last_modified)
        assert modified is not None, "is_stale() only returns True when the header is parseable"
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        age_days = (now - modified).days
        reasons.append(
            f"expected Last-Modified within {max_age_days} days of {now.isoformat()}, "
            f"found {last_modified!r} ({age_days} days old)"
        )
    return reasons


def check_url(
    url: str,
    min_rows: int = MIN_ROWS,
    max_age_days: int = MAX_AGE_DAYS,
    container: str = "zip",
    headers: dict[str, str] | None = None,
) -> list[str]:
    """Fetch `url` and validate it. Empty return = healthy.

    `headers` (if given) rides the request alongside the User-Agent -- the
    only caller is main()'s token-provider path, building an
    Authorization header from a CI secret that is never logged or echoed:
    the header VALUE never appears in any reason string this function or
    validate_top1m() returns (both only ever quote HTTP status/exception
    text and the response body's own row content).
    """
    now = datetime.now(timezone.utc)
    request_headers = {"User-Agent": "pfBlockerNG-top1m-healthcheck/1.0"}
    if headers:
        request_headers.update(headers)
    request = urllib.request.Request(url, headers=request_headers)
    try:
        with urllib.request.urlopen(request, timeout=120) as resp:
            body = resp.read()
            last_modified = resp.headers.get("Last-Modified")
            status = resp.status
    except urllib.error.HTTPError as exc:
        return [f"expected HTTP 2xx, got HTTP {exc.code} {exc.reason}"]
    except (urllib.error.URLError, OSError, http.client.HTTPException) as exc:
        # Covers the whole fetch+read span: resp.read() on a multi-MB body can
        # raise IncompleteRead/socket.timeout/ConnectionResetError mid-download
        # -- none are urllib.error.URLError, so a narrower except let those
        # raise a raw traceback instead of a clean FAIL report (#884 review).
        return [f"expected a reachable URL, got a connection error: {exc}"]

    if not (200 <= status < 300):
        return [f"expected HTTP 2xx, got HTTP {status}"]
    return validate_top1m(body, last_modified, now, min_rows, max_age_days, container)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--extract", action="store_true", help="print every top1m provider as JSON")
    group.add_argument("--check-url", metavar="URL", help="fetch + validate one provider URL")
    parser.add_argument(
        "--container", choices=("zip", "plain"), default="zip", help="--check-url's body shape (default: zip)"
    )
    parser.add_argument(
        "--secret-env",
        metavar="ENVVAR",
        default="",
        help="--check-url: env var holding the auth token; unset/empty ⇒ visibly skip (never fail)",
    )
    parser.add_argument("--auth-header", metavar="NAME", default="Authorization", help="token provider header name")
    parser.add_argument("--auth-scheme", metavar="SCHEME", default="Bearer", help="token provider header scheme")
    args = parser.parse_args(argv)

    if args.extract:
        providers = extract_providers(DEFAULT_DESCRIPTOR_FILE.read_text(encoding="utf-8"))
        print(json.dumps(providers))
        return 0

    headers = None
    if args.secret_env:
        # A token provider (ADR-59 S2.7): validated only when its CI secret is
        # actually configured -- never fail the run merely because a maintainer
        # hasn't wired one yet; that's a config gap, not a dead provider.
        token = os.environ.get(args.secret_env, "").strip()
        if not token:
            print(f"SKIP {args.check_url}: needs token, no secret configured (env {args.secret_env})")
            return 0
        header_value = f"{args.auth_scheme} {token}".strip() if args.auth_scheme else token
        headers = {args.auth_header: header_value}

    reasons = check_url(args.check_url, container=args.container, headers=headers)
    if not reasons:
        print(f"OK  {args.check_url}: healthy (>= {MIN_ROWS} rows, not stale)")
        return 0
    print(f"FAIL {args.check_url}: unhealthy")
    for reason in reasons:
        print(f"  - {reason}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
