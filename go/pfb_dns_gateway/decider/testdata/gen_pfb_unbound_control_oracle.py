# Records what pfb_unbound.py (CPython 3.11) does for the DNSBL-control inputs pfb_unbound_control_test.go and
# pfb_unbound_control_channel_test.go describe: pfb_apply_control_command (each scenario is a command sequence, with the
# timers it would start and the state it leaves), python_control_duration, and the record reader
# (_control_read_record, _control_record_to_command, the seq check of the watcher).
# Run from the repo root: uv run python go/pfb_dns_gateway/decider/testdata/gen_pfb_unbound_control_oracle.py
# It rewrites testdata/pfb_unbound_control_oracle.json.
import builtins
import contextlib
import io
import json
import os
import sys
import tempfile
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

C = "python_control"

# the stats-DB open is the log/stats PR's: no-op here, enable and the timed re-enable call it
P._open_dnsbl_stats_db_if_wanted = lambda: None

# [pre-state, commands]: pre = (python_blacklist, gpListDB gate, gpListDB entries, timers already running)
SCENARIOS = {
    "disable-without-duration": (True, False, [], [], [[C, "disable"]]),
    "disable-with-empty-duration-token": (True, False, [], [], [[C, "disable", ""]]),
    "disable-with-valid-duration": (True, False, [], [], [[C, "disable", "30"]]),
    "disable-duration-lower-bound": (True, False, [], [], [[C, "disable", "1"]]),
    "disable-duration-upper-bound": (True, False, [], [], [[C, "disable", "3600"]]),
    "disable-duration-zero": (True, False, [], [], [[C, "disable", "0"]]),
    "disable-duration-over-range": (True, False, [], [], [[C, "disable", "3601"]]),
    "disable-duration-text": (True, False, [], [], [[C, "disable", "abc"]]),
    "disable-duration-negative": (True, False, [], [], [[C, "disable", "-5"]]),
    "disable-duration-superscript-two": (True, False, [], [], [[C, "disable", "\u00b2"]]),
    "disable-duration-arabic-indic-three": (True, False, [], [], [[C, "disable", "\u0663"]]),
    "disable-duration-arabic-indic-thirty-three": (True, False, [], [], [[C, "disable", "\u0663\u0663"]]),
    "disable-duration-fullwidth-digits": (True, False, [], [], [[C, "disable", "\uff11\uff10"]]),
    "disable-extra-token-ignores-duration": (True, False, [], [], [[C, "disable", "30", "x"]]),
    "disable-twice-with-duration": (True, False, [], [], [[C, "disable", "30"], [C, "disable", "40"]]),
    "disable-while-timer-runs": (True, False, [], ["sleep"], [[C, "disable", "30"]]),
    "disable-then-enable": (True, False, [], [], [[C, "disable"], [C, "enable"]]),
    "enable-sets-blacklist": (False, False, [], [], [[C, "enable"]]),
    "enable-with-extra-token": (False, False, [], [], [[C, "enable", "x"]]),
    "unknown-command": (True, False, [], [], [[C, "nosuchcommand"]]),
    "single-token": (True, False, [], [], [[C]]),
    "empty-command": (True, False, [], [], [[]]),
    "addbypass-missing-ip": (True, False, [], [], [[C, "addbypass"]]),
    "addbypass-empty-ip": (True, False, [], [], [[C, "addbypass", ""]]),
    "removebypass-missing-ip": (True, False, [], [], [[C, "removebypass"]]),
    "addbypass-invalid-ip": (True, False, [], [], [[C, "addbypass", "not-an-ip"]]),
    "addbypass-invalid-ip-after-dash-mapping": (True, False, [], [], [[C, "addbypass", "1-2-3"]]),
    "addbypass-leading-zero-octet": (True, False, [], [], [[C, "addbypass", "01.2.3.4"]]),
    "addbypass-ipv4-dotted": (True, False, [], [], [[C, "addbypass", "10.0.0.5"]]),
    "addbypass-ipv4-dashed": (True, False, [], [], [[C, "addbypass", "10-0-0-5"]]),
    "addbypass-ipv6": (True, False, [], [], [[C, "addbypass", "2001:db8::5"]]),
    "addbypass-ipv6-scoped": (True, False, [], [], [[C, "addbypass", "fe80::1%em0"]]),
    "addbypass-ipv6-uppercase-is-kept-verbatim": (True, False, [], [], [[C, "addbypass", "2001:DB8::5"]]),
    "addbypass-keeps-gate-already-on": (True, True, ["10.0.0.9"], [], [[C, "addbypass", "10.0.0.5"]]),
    "addbypass-with-valid-duration": (True, False, [], [], [[C, "addbypass", "10-0-0-5", "60"]]),
    "addbypass-with-empty-duration-token": (True, False, [], [], [[C, "addbypass", "10-0-0-5", ""]]),
    "addbypass-duration-zero": (True, False, [], [], [[C, "addbypass", "10-0-0-5", "0"]]),
    "addbypass-duration-over-range": (True, False, [], [], [[C, "addbypass", "10-0-0-5", "3601"]]),
    "addbypass-duration-text": (True, False, [], [], [[C, "addbypass", "10-0-0-5", "abc"]]),
    "addbypass-duration-superscript-two": (True, False, [], [], [[C, "addbypass", "10-0-0-5", "\u00b2"]]),
    "addbypass-duration-arabic-indic-three": (True, False, [], [], [[C, "addbypass", "10-0-0-5", "\u0663"]]),
    "addbypass-extra-token-ignores-duration": (True, False, [], [], [[C, "addbypass", "10-0-0-5", "60", "x"]]),
    "addbypass-duplicate-timer": (
        True,
        False,
        [],
        [],
        [[C, "addbypass", "10-0-0-5", "60"], [C, "addbypass", "10-0-0-5", "90"]],
    ),
    "addbypass-timer-for-another-ip-is-independent": (
        True,
        False,
        [],
        [],
        [[C, "addbypass", "10-0-0-5", "60"], [C, "addbypass", "10-0-0-6", "90"]],
    ),
    "addbypass-invalid-duration-keeps-gate-on-adds-nothing": (True, False, [], [], [[C, "addbypass", "10-0-0-5", "0"]]),
    "removebypass-present": (True, True, ["10.0.0.5", "10.0.0.6"], [], [[C, "removebypass", "10-0-0-5"]]),
    "removebypass-absent": (True, True, ["10.0.0.6"], [], [[C, "removebypass", "10-0-0-5"]]),
    "removebypass-absent-turns-the-gate-on": (True, False, [], [], [[C, "removebypass", "10-0-0-5"]]),
    "removebypass-invalid-ip": (True, False, [], [], [[C, "removebypass", "nope"]]),
    "removebypass-ignores-duration": (True, True, ["10.0.0.5"], [], [[C, "removebypass", "10-0-0-5", "60"]]),
    "addbypass-then-removebypass": (
        True,
        False,
        [],
        [],
        [[C, "addbypass", "10-0-0-5"], [C, "removebypass", "10-0-0-5"]],
    ),
}

DURATIONS = [
    "60",
    "1",
    "3600",
    "0",
    "3601",
    "abc",
    "-1",
    "",
    "\u00b2",
    "\u0663",
    "\u0663\u0663",
    "\uff11",
    "12 ",
    "+1",
    "1_0",
    "\U0001d7d1",
    "00060",
    "\u2155",
    "99999999999999999999999999",
]

# raw channel file texts (UTF-8 str; the invalid-UTF-8 and lone-surrogate rows are Go-side hostile rows)
RECORDS = [
    "",
    " \n\t ",
    "\u00a0",
    "{",
    "[]",
    '[{"seq": 1, "cmd": "enable"}]',
    '"seq"',
    "null",
    "3",
    "{}",
    '{"cmd": "enable"}',
    '{"seq": 1}',
    '{"seq": 1, "cmd": "enable"}',
    '{"seq": 1, "cmd": "enable"} trailing',
    '{"seq": 1, "cmd": "enable",}',
    '{"seq": 01, "cmd": "enable"}',
    '{"seq": "1", "cmd": "enable"}',
    '{"seq": 2.0, "cmd": "enable"}',
    '{"seq": 1e2, "cmd": "enable"}',
    '{"seq": true, "cmd": "enable"}',
    '{"seq": false, "cmd": "enable"}',
    '{"seq": null, "cmd": "enable"}',
    '{"seq": -0, "cmd": "enable"}',
    '{"seq": -7, "cmd": "enable"}',
    '{"seq": 123456789012345678901234567890, "cmd": "enable"}',
    '{"seq": NaN, "cmd": "enable"}',
    '{"seq": 5, "cmd": "enable", "extra": NaN}',
    '{"seq": 5, "cmd": "enable", "extra": Infinity, "more": -Infinity}',
    '{"seq": 1, "seq": 2, "cmd": "enable"}',
    '{"seq": 1, "cmd": "enable", "cmd": "disable"}',
    '{"seq": 1, "cmd": "disable"}',
    '{"seq": 1, "cmd": "disable", "duration": 30}',
    '{"seq": 1, "cmd": "disable", "duration": "30"}',
    '{"seq": 1, "cmd": "disable", "duration": 1.5}',
    '{"seq": 1, "cmd": "disable", "duration": 30.0}',
    '{"seq": 1, "cmd": "disable", "duration": 1e2}',
    '{"seq": 1, "cmd": "disable", "duration": 1e16}',
    '{"seq": 1, "cmd": "disable", "duration": 1e22}',
    '{"seq": 1, "cmd": "disable", "duration": 1E-5}',
    '{"seq": 1, "cmd": "disable", "duration": 0.0001}',
    '{"seq": 1, "cmd": "disable", "duration": -0.0}',
    '{"seq": 1, "cmd": "disable", "duration": 123456789012345678.0}',
    '{"seq": 1, "cmd": "disable", "duration": 5e-324}',
    '{"seq": 1, "cmd": "disable", "duration": 1e999}',
    '{"seq": 1, "cmd": "disable", "duration": -1e999}',
    '{"seq": 1, "cmd": "disable", "duration": true}',
    '{"seq": 1, "cmd": "disable", "duration": false}',
    '{"seq": 1, "cmd": "disable", "duration": null}',
    '{"seq": 1, "cmd": "disable", "duration": -5}',
    '{"seq": 1, "cmd": "disable", "duration": -0}',
    '{"seq": 1, "cmd": "disable", "duration": 123456789012345678901234567890}',
    '{"seq": 1, "cmd": "disable", "duration": "\\u00b2"}',
    '{"seq": 1, "cmd": "disable", "duration": "\\u0663"}',
    '{"seq": 1, "cmd": "disable", "duration": ""}',
    '{"seq": 1, "cmd": "disable", "duration": []}',
    '{"seq": 1, "cmd": "disable", "duration": {}}',
    '{"seq": 1, "cmd": "disable", "duration": [1, "a", true, null, 2.0, [3], {"k": "v"}]}',
    '{"seq": 1, "cmd": "disable", "duration": {"b": 1, "a": [true, null], "b": 2}}',
    '{"seq": 1, "cmd": "disable", "duration": ["it\'s", "say \\"hi\\"", "both \' and \\"", "tab\\there", "nl\\n",'
    ' "bs\\\\", "\\u00e9", "\\u2028", "\\u0007", "\\ud83d\\ude00"]}',
    '{"seq": 1, "cmd": "disable", "duration": "plain"}',
    '{"seq": 1, "cmd": "disable", "duration": 30, "ip": "ignored"}',
    '{"seq": 1, "cmd": "enable", "duration": 30}',
    '{"seq": 1, "cmd": "addbypass", "ip": "10.0.0.5"}',
    '{"seq": 1, "cmd": "addbypass", "ip": "10.0.0.5", "duration": 60}',
    '{"seq": 1, "cmd": "addbypass", "ip": "10.0.0.5", "duration": "60"}',
    '{"seq": 1, "cmd": "addbypass", "ip": "10.0.0.5", "duration": null}',
    '{"seq": 1, "cmd": "addbypass", "ip": "10-0-0-5"}',
    '{"seq": 1, "cmd": "addbypass", "ip": ""}',
    '{"seq": 1, "cmd": "addbypass"}',
    '{"seq": 1, "cmd": "addbypass", "ip": 5}',
    '{"seq": 1, "cmd": "addbypass", "ip": null}',
    '{"seq": 1, "cmd": "addbypass", "ip": ["10.0.0.5"]}',
    '{"seq": 1, "cmd": "removebypass", "ip": "10.0.0.5"}',
    '{"seq": 1, "cmd": "removebypass", "ip": "10.0.0.5", "duration": 60}',
    '{"seq": 1, "cmd": "removebypass", "ip": ""}',
    '{"seq": 1, "cmd": "removebypass"}',
    '{"seq": 1, "cmd": "removebypass", "ip": false}',
    '{"seq": 1, "cmd": "wipe-everything"}',
    '{"seq": 1, "cmd": "ENABLE"}',
    '{"seq": 1, "cmd": " enable"}',
    '{"seq": 1, "cmd": 5}',
    '{"seq": 1, "cmd": null}',
    '{"seq": 1, "cmd": ["enable"]}',
    '{"seq": 1, "cmd": {"enable": 1}}',
    '{"seq": 1, "cmd": "en\\u0061ble"}',
    '{"seq": 1, "cmd": "enable"}\n',
    '\n\t {"seq": 1, "cmd": "enable"}\r\n',
    '{"seq" : 1 ,\n "cmd" : "enable" }',
    "{'seq': 1, 'cmd': 'enable'}",
    '{"seq": 1, "cmd": "enable"}\x00',
    '{"seq": 1, "cmd": "enable"}\u00a0',
    '\u00a0{"seq": 1, "cmd": "enable"}',
    '{"seq": 1, "cmd": "enable", "k": "\\ud800"}',
    '{"seq": 1, "cmd": "enable", "bad": tru}',
    '{"seq": 1, "cmd": "enable", "bad": "a\nb"}',
    '{"seq": 1, "cmd": "enable", "bad": "\\x41"}',
    '{"seq": 1, "cmd": "enable", "ok": "\\/\\b\\f"}',
    '{"seq": 1, "cmd": "enable", "bad": .5}',
    '{"seq": 1, "cmd": "enable", "bad": 1.}',
    '{"seq": 1, "cmd": "enable", "bad": +1}',
    '{"seq": 1, "cmd": "enable", "bad": 1e}',
    '{"seq": 1, "cmd": "enable", "bad": "unterminated}',
    '{"seq": 1, "cmd": "enable", 5: 1}',
    '{"seq": 1 "cmd": "enable"}',
    '{"seq": 1, "cmd": "enable"',
    '\ufeff{"seq": 1, "cmd": "enable"}',
    '{"seq": ' + "1" * 4300 + ', "cmd": "enable"}',
    '{"seq": ' + "1" * 4301 + ', "cmd": "enable"}',
    '{"seq": 1, "cmd": "enable", "deep": ' + "[" * 60 + "]" * 60 + "}",
]


def run_handler(pre, commands):
    blacklist, gate, entries, active, _ = pre
    P.pfb["python_blacklist"] = blacklist
    P.pfb["gpListDB"] = gate
    P.pfb["mod_threading"] = True
    P.gpListDB = {ip: 0 for ip in entries}
    started = []
    names = set(active)
    P.python_control_thread = lambda name: name in names

    def start_thread(name, fcall, arg1, arg2):
        names.add(name)
        started.append([name, arg1, arg2 if isinstance(arg2, str) else None])
        return True

    P.python_control_start_thread = start_thread
    results = []
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        for command in commands:
            applied, msg = P.pfb_apply_control_command(list(command))
            results.append([applied, msg])
    return results, {
        "python_blacklist": P.pfb["python_blacklist"],
        "gate": P.pfb["gpListDB"],
        "entries": sorted(P.gpListDB),
        "timers": started,
    }


handler = []
for sid, (blacklist, gate, entries, active, commands) in SCENARIOS.items():
    results, post = run_handler((blacklist, gate, entries, active, commands), commands)
    handler.append(
        {
            "id": sid,
            "pre": {"python_blacklist": blacklist, "gate": gate, "entries": entries, "timers": active},
            "commands": commands,
            "results": results,
            "post": post,
        }
    )

# the timers' bodies: python_control_sleep and python_control_addbypass after time.sleep returns
P.time.sleep = lambda seconds: None
P.pfb["python_blacklist"] = False
P.python_control_sleep(30, None)
sleep_expiry = {"python_blacklist": P.pfb["python_blacklist"]}
P.gpListDB = {"10.0.0.5": 0, "10.0.0.6": 0}
popped = P.python_control_addbypass(60, "10.0.0.5")
absent = P.python_control_addbypass(60, "10.0.0.5")
addbypass_expiry = {"first": popped, "second": absent, "entries": sorted(P.gpListDB)}

durations = []
for text in DURATIONS:
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        value = P.python_control_duration(text)
    durations.append({"text": text, "value": value, "stderr": err.getvalue()})

records = []
with tempfile.TemporaryDirectory() as tmp:
    channel = os.path.join(tmp, "pfb_py_control")
    for text in RECORDS:
        Path(channel).write_text(text, encoding="utf-8", newline="")
        row = {"text": text}
        try:
            record = P._control_read_record(channel)
        except RecursionError:
            row["raises"] = "RecursionError"
            records.append(row)
            continue
        row["record"] = record is not None
        row["seq"] = None
        row["command"] = None
        if record is not None:
            seq = record.get("seq")
            if isinstance(seq, int):
                row["seq"] = str(int(seq))
            command = P._control_record_to_command(record)
            row["command"] = command
        records.append(row)

(HERE / "pfb_unbound_control_oracle.json").write_text(
    json.dumps(
        {
            "handler": handler,
            "sleep_expiry": sleep_expiry,
            "addbypass_expiry": addbypass_expiry,
            "durations": durations,
            "records": records,
        },
        indent=1,
        ensure_ascii=True,
    )
    + "\n"
)
print(len(handler), "handler scenarios,", len(durations), "durations,", len(records), "records")
