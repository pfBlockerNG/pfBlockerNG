"""Names and fixture text shared by the DNS gateway tests."""

from __future__ import annotations

import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SHIPPED_DIR = REPO_ROOT / "src" / "usr" / "local" / "pkg" / "pfblockerng"
PROTO_DIR = SHIPPED_DIR / "dns_proxy"

DNSBL_IPV4 = "10.10.10.1"
DNSBL_IPV6 = "fd00::1"
BLOCKED = "blocked.example."
ALLOWED = "allowed.example."

# python_blocking/python_cname on: the DNSBL VIP answers blocks and CNAME chains are validated.
INI = f"""[MAIN]
python_enable = true
python_blocking = true
python_reply = true
python_cname = true
python_control = true
python_control_legacy = true
dnsbl_ipv4 = {DNSBL_IPV4}
dnsbl_ipv6 = {DNSBL_IPV6}

[noAAAA]
row1 = noaaaa.example,0
"""

# pfb_py_ss.txt as pfb_ss_csv_rows() writes a CNAME redirect: domain,cname,target,baked_v4,baked_v6. The baked
# addresses differ from every address the fake authoritative serves, so an answer shows whether the CNAME target
# was chased or the module's baked fallback ran.
SAFESEARCH_CSV = """duck.example,cname,safe.duck.example,198.51.100.7,2001:db8::7
www.duck.example,cname,safe.duck.example,198.51.100.7,2001:db8::7
nodata.example,cname,nodata-target.example,198.51.100.8,2001:db8::8
nx.example,cname,nx-target.example,198.51.100.10,2001:db8::10
servfail.example,cname,servfail-target.example,198.51.100.11,2001:db8::11
silent.example,cname,silent-target.example,198.51.100.12,2001:db8::12
nobaked.example,cname,nodata-target.example,,
trap.example,cname,blocked.example,198.51.100.9,2001:db8::9
big.example,cname,big-target.example,198.51.100.13,2001:db8::13
"""

# Group Policy bypass: a client on [GP_Bypass_List] is never DNSBL-blocked.
BYPASSED_CLIENT = "127.0.0.5"
FILTERED_CLIENT = "127.0.0.6"
GP_BYPASS_INI = f"""
[GP_Bypass_List]
row1 = {BYPASSED_CLIENT}
"""


def write_module_dir(root: Path, *, forwarding: bool = False) -> None:
    """Shape `root` like /var/unbound: the shipped module (symlinked, byte-identical), ini, manifest and raw feed. With
    `forwarding` the ini says the Resolver forwards, the only mode in which upstream blocks are detected."""
    (root / "pfb_dnsbl_regex_rules.py").symlink_to(SHIPPED_DIR / "pfb_dnsbl_regex_rules.py")
    (root / "pfb_py_raw").mkdir()
    (root / "pfb_py_raw" / "feed.txt").write_text("blocked.example\n", encoding="utf-8")
    feed = {"raw": "pfb_py_raw/feed.txt", "feed": "TestFeed", "group": "TestGroup", "log_flag": "1"}
    (root / "pfb_py_sources.json").write_text(
        json.dumps({"version": 1, "config": {}, "feeds": [feed]}), encoding="utf-8"
    )
    ini = INI.replace("[MAIN]\n", "[MAIN]\nforwarding = true\n", 1) if forwarding else INI
    (root / "pfb_unbound.ini").write_text(ini, encoding="utf-8")
