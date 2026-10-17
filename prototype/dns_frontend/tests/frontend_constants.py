"""Names and fixture text shared by the prototype tests (imports nothing from the prototype itself)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from types import ModuleType

PROTO_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = PROTO_DIR.parents[1]
SHIPPED_DIR = REPO_ROOT / "src" / "usr" / "local" / "pkg" / "pfblockerng"

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
"""

# Group Policy bypass: a client on [GP_Bypass_List] is never DNSBL-blocked (pfb_unbound.py _load_gp_bypass_list).
BYPASSED_CLIENT = "127.0.0.5"
FILTERED_CLIENT = "127.0.0.6"
GP_BYPASS_INI = f"""
[GP_Bypass_List]
row1 = {BYPASSED_CLIENT}
"""


@dataclass
class Booted:
    module: ModuleType
    log: list[tuple[str, str]]  # (log file, line) the module tried to write
