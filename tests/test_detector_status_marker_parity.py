"""The smoke suite's detector marker must stay byte-identical to the PHP producer — issue #3115.

``tests.smoke.helpers.detector_status_marker`` reimplements ``pfb_log_status_line()``'s header
field in Python because ``count_log_marker`` matches the Update log with ``grep -F``: the marker
has to carry the producer's exact padding. Two copies of one formula drift, and the drift is not
obvious at the call site — the smoke assertions would just stop seeing their verdict.

So this compares the two implementations by executing the shipped PHP, the same way
``test_dnsbl_log_csv_quoting`` round-trips its rows through the real ``fgetcsv``.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from tests.smoke import helpers

BOOTSTRAP = Path(__file__).resolve().parent / "php" / "bootstrap.php"

# Header lengths that matter: inside the field, on both sides of its edge, and past it — plus
# non-ASCII, where PHP's byte padding and a codepoint-based mirror diverge.
HEADERS = [
    "a",
    "ISC_Block_v4",
    "a" * 27,
    "a" * 28,
    "a" * 29,
    "a" * 40,
    "é" * 10,
    "Ünïcode-Fêed",
]

STATUS = "( content changed )"


def _php_status_lines(headers: list[str], status: str) -> dict[str, str]:
    """Render ``pfb_log_status_line($header, $status, '')`` with the shipped PHP, per header."""
    script = (
        f"require {json.dumps(str(BOOTSTRAP))};"
        f"$out = [];"
        f"foreach (json_decode({json.dumps(json.dumps(headers))}) as $h) {{"
        f"    $out[$h] = pfb_log_status_line($h, {json.dumps(status)}, '');"
        f"}}"
        f"echo json_encode($out, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);"
    )
    result = subprocess.run(
        ["php", "-r", script],
        capture_output=True,
        check=True,
        text=True,
    )
    rendered = json.loads(result.stdout)
    assert isinstance(rendered, dict), f"PHP returned unexpected JSON: {result.stdout!r}"
    return rendered


@pytest.mark.skipif(shutil.which("php") is None, reason="php CLI not installed")
def test_detector_status_marker_matches_the_php_producer() -> None:
    """Every marker the smoke suite greps for is a prefix of the row PHP actually writes."""
    rendered = _php_status_lines(HEADERS, STATUS)
    assert set(rendered) == set(HEADERS), f"PHP skipped headers: {sorted(set(HEADERS) - set(rendered))}"

    for header, php_row in rendered.items():
        marker = helpers.detector_status_marker(header, STATUS)
        assert php_row.startswith(marker), (
            f"marker drifted from the producer for a {len(header.encode())}-byte header\n"
            f"  marker: {marker!r}\n"
            f"  PHP:    {php_row!r}"
        )
