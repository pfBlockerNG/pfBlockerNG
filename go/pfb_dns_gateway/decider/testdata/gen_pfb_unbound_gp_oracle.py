# Records what pfb_unbound.py (CPython 3.11) does with each GP_Bypass_List row and client address in
# pfb_unbound_operate_test.go: _load_gp_bypass_list, _gp_net_match and the exact-key lookup of _gp_bypassed.
# Run from the repo root: uv run python go/pfb_dns_gateway/decider/testdata/gen_pfb_unbound_gp_oracle.py
# It rewrites testdata/pfb_unbound_gp_oracle.json.
import builtins
import contextlib
import io
import json
import sys
from collections import defaultdict
from configparser import ConfigParser
from pathlib import Path

HERE = Path(__file__).resolve().parent
root = str(HERE.parents[3])
sys.path.insert(0, root + "/stubs/python")
import unboundmodule

for _name in unboundmodule.__all__:
    setattr(builtins, _name, getattr(unboundmodule, _name))
sys.path.insert(0, root + "/src/usr/local/pkg/pfblockerng")
sys.path.insert(0, root)
import pfb_unbound as P

ROWS = [
    "10.0.0.0/24",
    "10.0.0.1/24",
    "10.0.0.0/255.255.255.0",
    "10.0.0.0/0.0.0.255",
    "10.1.2.3/255.255.0.0",
    "10.0.0.0/255.0.255.0",
    "10.0.0.0/0.255.0.0",
    "1.2.3.4/0.0.0.0",
    "1.2.3.4/255.255.255.255",
    "1.2.3.4/0.0.0.1",
    "1.2.3.4",
    "1.2.3.4/32",
    "1.2.3.4/0",
    "1.2.3.4/08",
    "1.2.3.4/033",
    "1.2.3.4/33",
    "1.2.3.4/-1",
    "1.2.3.4/+8",
    "1.2.3.4/ 8",
    "1.2.3.4/8 ",
    "1.2.3.4/",
    "/8",
    "1.2.3",
    "1.2.3.4.5",
    "01.2.3.4",
    "1.2.3.256",
    "1.2.3.4/8/8",
    "0.0.0.0/0",
    "::/0",
    "::1",
    "::1/128",
    "::1/129",
    "::1/ffff::",
    "2001:db8:1::/64",
    "2001:db8::1/128",
    "2001:0db8:0:0:0:0:0:1",
    "2001:DB8::1",
    "2001:db8:9::/129",
    "2001:db8::/32",
    "2001:db8::1/32",
    "fe80::1%em0",
    "fe80::/10",
    "fe80::%em0/10",
    "fe80::1%em0/64",
    "fe80::1%em0/128",
    "fe80::1%",
    "fe80::1%em0%x",
    "1.2.3.4%em0",
    "::ffff:1.2.3.4",
    "::ffff:1.2.3.4/128",
    "::ffff:1.2.3.0/120",
    "::ffff:0:0/96",
    "::1.2.3.4",
    "1::",
    ":::",
    "1:2:3:4:5:6:7:8",
    "1:2:3:4:5:6:7:8:9",
    "12345::1",
    "g::1",
    "::ffff:1.2.3.04",
    "",
    "   ",
    "# comment",
    "example.com",
    "xn--abc",
    "10.0.0.0/24 extra",
    "\u0663.2.3.4",
    "1.2.3.4\u00a0",
]
PROBES = [
    "1.2.3.4",
    "1.2.3.5",
    "10.0.0.0",
    "10.0.0.77",
    "10.0.0.255",
    "10.0.1.0",
    "10.1.9.9",
    "10.3.2.1",
    "9.255.255.255",
    "203.0.113.9",
    "0.0.0.0",
    "255.255.255.255",
    "::",
    "::1",
    "::2",
    "2001:db8::1",
    "2001:db8::2",
    "2001:db8:1::abcd",
    "2001:db8:1:1::1",
    "2001:db8:9::1",
    "2001:db9:1::1",
    "fe80::1",
    "fe80::1%em0",
    "fe80::2%em0",
    "fec0::1%em0",
    "::ffff:1.2.3.4",
    "::ffff:102:304",
    "::ffff:1.2.3.5",
    "::ffff:0:1",
    "::1.2.3.4",
    "not-an-address",
    "",
    "Unknown",
    "1.2.3",
    "1.2.3.4%em0",
    "FE80::1%em0",
    "2001:DB8::1",
    "2001:0db8:0:0:0:0:0:1",
]

out = []
for row in ROWS:
    config = ConfigParser(interpolation=None)
    config.read_string("[GP_Bypass_List]\nrow = " + row.replace("\n", " ") + "\n")
    # the value the ini parser hands over: stripped, as read
    value = config.get("GP_Bypass_List", "row")
    P.gpListDB = defaultdict(str)
    P.gpNetDB = []
    P.pfb["gpListDB"] = False
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        P._load_gp_bypass_list(config)
    verdicts = {}
    for probe in PROBES:
        verdicts[probe] = P.gpListDB.get(probe) is not None or (bool(P.gpNetDB) and P._gp_net_match(probe))
    out.append(
        {
            "value": value,
            "gate": P.pfb["gpListDB"],
            "exact": list(P.gpListDB),
            "nets": [str(n) for n in P.gpNetDB],
            "bypassed": [probe for probe in PROBES if verdicts[probe]],
        }
    )

(HERE / "pfb_unbound_gp_oracle.json").write_text(
    json.dumps({"probes": PROBES, "rows": out}, indent=1, ensure_ascii=True) + "\n"
)
print(len(out), "rows")
