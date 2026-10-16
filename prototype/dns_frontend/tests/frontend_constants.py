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


@dataclass
class Booted:
    module: ModuleType
    log: list[tuple[str, str]]  # (log file, line) the module tried to write
