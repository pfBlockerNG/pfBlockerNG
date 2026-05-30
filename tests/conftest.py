import builtins
import os
import sys
from collections import defaultdict

# pfb_unbound.py is designed to run inside Unbound's Python plugin loader, which
# injects Unbound-specific functions and integer constants as module-level
# globals before executing the script. Reproduce that here by copying the symbols
# from the shared stubs/python/unboundmodule.py stub onto builtins, so the file
# can be imported in a plain Python environment for unit testing. That same stub
# is what static type checkers resolve for pfb_unbound.py's TYPE_CHECKING
# `from unboundmodule import ...` block, keeping a single source of truth.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "stubs", "python"))

import unboundmodule  # noqa: E402

for _name in unboundmodule.__all__:
    setattr(builtins, _name, getattr(unboundmodule, _name))

# Make pfb_unbound importable from its installed location within the repo.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src", "usr", "local", "pkg", "pfblockerng"))

import pytest  # noqa: E402

import pfb_unbound  # noqa: E402


@pytest.fixture(autouse=True)
def reset_pfb_globals():
    unboundmodule.DNSMessage.instances = []

    pfb_unbound.pfb = {
        "mod_threading": True,
        "mod_ipaddress": True,
        "mod_maxminddb": False,
        "mod_sqlite3": True,
        "python_enable": False,
        "python_blacklist": False,
        "python_blocking": False,
        "python_reply": False,
        "python_nolog": False,
        "python_cname": False,
        "python_control": False,
        "python_hsts": False,
        "python_idn": False,
        "python_tld": False,
        "python_maxmind": False,
        "python_tld_seg": 2,
        "python_tlds": [],
        "dnsbl_ipv4": "10.10.10.1",
        "dnsbl_ipv6": "::1",
        "dataDB": False,
        "zoneDB": False,
        "regexDB": False,
        "whiteDB": False,
        "hstsDB": False,
        "gpListDB": False,
        "noAAAADB": False,
        "safeSearchDB": False,
        "sqlite3_dnsbl_con": False,
        "sqlite3_resolver_con": False,
        "rr_types": (1, 28, 255, 5, 39, 24, 15, 2, 12, 33, 16, 64, 65),
        "hsts_tlds": (
            "android",
            "app",
            "bank",
            "chrome",
            "dev",
            "foo",
            "gle",
            "gmail",
            "google",
            "hangout",
            "insurance",
            "meet",
            "new",
            "page",
            "play",
            "search",
            "youtube",
        ),
        "pfb_py_dnsbl": ":memory:",
        "pfb_py_resolver": ":memory:",
        "pfb_py_cache": ":memory:",
    }
    pfb_unbound.dataDB = defaultdict(list)
    pfb_unbound.zoneDB = defaultdict(list)
    pfb_unbound.dnsblDB = defaultdict(list)
    pfb_unbound.safeSearchDB = defaultdict(list)
    pfb_unbound.feedGroupIndexDB = defaultdict(list)
    pfb_unbound.regexDB = defaultdict(str)
    pfb_unbound.whiteDB = defaultdict(str)
    pfb_unbound.hstsDB = defaultdict(str)
    pfb_unbound.gpListDB = defaultdict(str)
    pfb_unbound.noAAAADB = defaultdict(str)
    pfb_unbound.excludeDB = []
    pfb_unbound.excludeAAAADB = []
    pfb_unbound.excludeSS = []
    pfb_unbound.threads = []
