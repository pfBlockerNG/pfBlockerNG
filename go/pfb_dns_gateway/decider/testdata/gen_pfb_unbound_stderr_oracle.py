# Records what the shipped pfb_unbound.py writes to py_error.log for a run of sys.stderr writes;
# pfb_unbound_stderr_test.go replays them. The logger is not rebuilt here: init_standard's own lines (the log_stderr
# class, the basicConfig loop and the assignment to sys.stderr) are cut out of the shipped source and run as they are,
# on a log file of a temporary directory.
# Run from the repo root:
#   uv run --python 3.11.15 python go/pfb_dns_gateway/decider/testdata/gen_pfb_unbound_stderr_oracle.py
# It rewrites testdata/pfb_unbound_stderr_oracle.json.
import json
import logging
import re
import sys
import tempfile
import textwrap
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parents[3] / "src" / "usr" / "local" / "pkg" / "pfblockerng" / "pfb_unbound.py"
OUT = HERE / "pfb_unbound_stderr_oracle.json"

START = "    # Store previous error message to avoid repeating\n"
END = '    sys.stderr = log_stderr(logging.getLogger("pfb_stderr"))\n'

# What the module writes, in order: a plain message, the same again (not logged), the same with a newline (a different
# message, logged), that again, an unrelated one, the first once more (logged: only the previous message counts), a
# message with trailing whitespace of several kinds, a message of several lines, and one that is only whitespace.
WRITES = [
    "[pfBlockerNG]: Failed to load ini configuration: boom",
    "[pfBlockerNG]: Failed to load ini configuration: boom",
    "[pfBlockerNG]: Failed to load ini configuration: boom\n",
    "[pfBlockerNG]: Failed to load ini configuration: boom\n",
    "[pfBlockerNG]: sqlite write failed db a.sqlite: x\n",
    "[pfBlockerNG]: Failed to load ini configuration: boom",
    "[pfBlockerNG]: trailing \t \n\n",
    "[pfBlockerNG]: first line\nsecond line\n",
    "\n",
]


def main() -> None:
    lines = SOURCE.read_text().splitlines(keepends=True)
    first = lines.index(START)
    last = lines.index(END)
    body = textwrap.dedent("".join(lines[first : last + 1]))
    with tempfile.TemporaryDirectory() as tmp:
        logfile = Path(tmp) / "py_error.log"
        body = body.replace('"/var/log/pfblockerng/py_error.log"', repr(str(logfile)))
        assert str(logfile) in body, "the log file name is no longer where the generator looks for it"
        scope = {
            "pfb": {},
            "pfb_async": lambda func, *args: func(*args),
            "logging": logging,
            "os": __import__("os"),
            "sys": sys,
        }
        saved = sys.stderr
        try:
            exec(body, scope)  # noqa: S102 - the shipped init_standard lines, nothing else
            for text in WRITES:
                sys.stderr.write(text)
        finally:
            sys.stderr = saved
        rows = logfile.read_text()
    stamp = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}\|", re.M)
    assert len(stamp.findall(rows)) == rows.count("|ERROR| "), rows
    OUT.write_text(
        json.dumps({"writes": WRITES, "file": stamp.sub("<ASCTIME>|", rows)}, indent=1, ensure_ascii=False) + "\n"
    )


main()
