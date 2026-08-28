"""Structural pins for the DoH/DoT-block conf <-> UI option coupling (issue #740).

pfb_dnsbl.doh.conf ships one `local-zone: "<host>" always_nxdomain` line per DoH/DoT
endpoint; pfblockerng_dnsbl.php's $options_safesearch_doh_list array offers one
substring-matching option key per line (pfblockerng.inc uncomments a conf line iff
`strpos($line, $key) !== FALSE` for a selected key — see pfblockerng.inc's SafeSearch
DoH validation block). Issue #740: the shipped Yandex entry was the malformed
hostname "yandex.dns" (not a real endpoint), so selecting Yandex never blocked
anything. Fixed by replacing it with 9 real Yandex encrypted-DNS hostnames under the
new 'dns.yandex' option key.

These tests parse both files as text (no PHP runtime needed) and pin:
- the 9 real Yandex endpoints are present in the conf (the issue-#740 fix itself);
- the malformed 'yandex.dns' token is gone from both the conf and the option keys
  (regression guard for the exact defect);
- the 'dns.yandex' option key is present;
- the UI<->conf substring-coupling invariant holds in both directions across the
  whole catalog (an option matching no conf host is a dead toggle; a conf host
  matched by no option is unreachable -- the #740 defect class).
"""

from __future__ import annotations

import re
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CONF = _ROOT / "src" / "usr" / "local" / "pkg" / "pfblockerng" / "pfb_dnsbl.doh.conf"
_DNSBL_PHP = _ROOT / "src" / "usr" / "local" / "www" / "pfblockerng" / "pfblockerng_dnsbl.php"

_YANDEX_REAL_HOSTS = {
    "dns.yandex.ru",
    "safe.dns.yandex.ru",
    "family.dns.yandex.ru",
    "secondary.dns.yandex.ru",
    "secondary.safe.dns.yandex.ru",
    "secondary.family.dns.yandex.ru",
    "common.dot.dns.yandex.net",
    "safe.dot.dns.yandex.net",
    "family.dot.dns.yandex.net",
}

_MALFORMED_TOKEN = "yandex.dns"


def _conf_hosts() -> list[str]:
    """Every local-zone hostname in pfb_dnsbl.doh.conf (commented or not)."""
    text = _CONF.read_text(encoding="utf-8")
    return re.findall(r'local-zone:\s*"([^"]+)"\s*always_nxdomain', text)


def _option_keys() -> list[str]:
    """Every quoted option key in $options_safesearch_doh_list => 'Label' pairs."""
    text = _DNSBL_PHP.read_text(encoding="utf-8")
    match = re.search(r"\$options_safesearch_doh_list\s*=\s*\[(.*?)\n\s*\];", text, re.DOTALL)
    assert match is not None, "$options_safesearch_doh_list array not found in pfblockerng_dnsbl.php"
    return re.findall(r"'([^']+)'\s*=>", match.group(1))


def test_real_yandex_endpoints_present_in_conf() -> None:
    """Issue #740: the 9 real Yandex DoH/DoT hostnames must ship in the conf."""
    hosts = set(_conf_hosts())
    missing = _YANDEX_REAL_HOSTS - hosts
    assert not missing, (
        f"Real Yandex endpoints missing from {_CONF.name}.\n"
        f"  Expected (subset): {sorted(_YANDEX_REAL_HOSTS)}\n"
        f"  Missing:           {sorted(missing)}"
    )


def test_malformed_yandex_token_absent_from_conf_and_options() -> None:
    """Regression guard: the malformed 'yandex.dns' host must never reappear."""
    hosts = _conf_hosts()
    keys = _option_keys()
    assert _MALFORMED_TOKEN not in hosts, (
        f"Malformed token {_MALFORMED_TOKEN!r} still present as a conf host in {_CONF.name} "
        f"(expected: gone, replaced by the real Yandex endpoints)"
    )
    assert _MALFORMED_TOKEN not in keys, (
        f"Malformed token {_MALFORMED_TOKEN!r} still present as an option key in "
        f"{_DNSBL_PHP.name} (expected: gone, replaced by 'dns.yandex')"
    )


def test_dns_yandex_option_key_present() -> None:
    """The replacement option key 'dns.yandex' must be offered in the UI."""
    keys = _option_keys()
    assert "dns.yandex" in keys, f"'dns.yandex' option key missing from $options_safesearch_doh_list — got {keys}"


def test_every_option_key_matches_at_least_one_conf_host() -> None:
    """Given every UI option key, when matched by substring against conf hosts,
    then each key must match at least one host -- an option matching nothing is a
    dead toggle (the #740 defect class: 'yandex.dns' matched no real endpoint).
    """
    hosts = _conf_hosts()
    keys = _option_keys()

    dead_keys = [key for key in keys if not any(key in host for host in hosts)]
    assert not dead_keys, (
        f"Option key(s) match no conf host (dead toggle — issue #740 defect class): {dead_keys}\n"
        f"  conf hosts checked: {hosts}"
    )


def test_every_conf_host_matched_by_at_least_one_option_key() -> None:
    """Given every conf host, when matched by substring against UI option keys,
    then each host must be matched by at least one key -- an unmatched conf line is
    unreachable (can never be enabled from the UI).
    """
    hosts = _conf_hosts()
    keys = _option_keys()

    unreachable_hosts = [host for host in hosts if not any(key in host for key in keys)]
    assert not unreachable_hosts, (
        f"Conf host(s) matched by no option key (unreachable from the UI): {unreachable_hosts}\n"
        f"  option keys checked: {keys}"
    )
