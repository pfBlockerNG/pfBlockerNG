"""SCRATCH live check for issue #4117 — never lands; the branch is deleted after the run.

Black-box reproduction (shortened to SCRATCH_SOAK seconds, default 300): the real bouncer runs against a LAPI address
that drops packets; the metrics verb runs every few seconds; count scrapes with source_up{source="crowdsec"} 0 while
`pgrep -F /var/run/pfb_crowdsec.pid` succeeds, and the status file's largest mtime lag. Then SIGSTOP: the source must
read 0 within 3 x update_frequency plus one scrape. An optional baseline repeats the soak with the devel binary.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from collections.abc import Iterator

import pytest

from . import helpers as h

pytestmark = pytest.mark.smoke

SECTION = "installedpackages/pfblockerngcrowdsec/config/0"
MASTER = f"{h.CFG_GLOBAL}/enable_cb"
PID = "/var/run/pfb_crowdsec.pid"
STATUS = "/var/run/pfb_crowdsec.json"
PROM_DIR = "/var/tmp/node_exporter"
PROM = f"{PROM_DIR}/pfblockerng.prom"
BIN = "/usr/local/pkg/pfblockerng/crowdsec/bin/freebsd-amd64/pfb_crowdsec"
RC = "/usr/local/etc/rc.d/pfb_crowdsec.sh"
BLACKHOLE = "http://192.0.2.10:8080"  # RFC 5737; replaced by a never-answering listener if SLIRP refuses it
LISTENER = "http://127.0.0.1:18080"
SOAK = int(os.environ.get("SCRATCH_SOAK", "300"))
BASE_SHA = "492feceb5e9731a4f19205e3a53ce45cb2c7183f"

# One line per scrape: "<now> <source_up> <alive> <status mtime> <updated_at>"
SCRAPE = (
    "now=$(date +%s); "
    f"/usr/local/bin/php {h.PFB_CLI} metrics >/dev/null 2>&1; "
    f"up=$(grep 'pfblockerng_metrics_source_up{{source=\"crowdsec\"}}' {PROM} | awk '{{print $2}}'); "
    f"if pgrep -F {PID} >/dev/null 2>&1; then alive=1; else alive=0; fi; "
    f"m=$(stat -f %m {STATUS} 2>/dev/null || echo 0); "
    f"u=$(sed -n 's/.*\"updated_at\":\\([0-9]*\\).*/\\1/p' {STATUS} 2>/dev/null); "
    'echo "$now ${up:-none} $alive $m ${u:-0}"'
)


_OUT: list[object] = []


def say(*parts: object, end: str = "\n") -> None:
    line = " ".join(str(p) for p in parts)
    if _OUT:
        _OUT[0].write_line(line)  # type: ignore[attr-defined]
    else:
        print(line, end=end)


@pytest.fixture(autouse=True)
def _reporter(request: pytest.FixtureRequest) -> Iterator[None]:
    _OUT[:] = [request.config.pluginmanager.get_plugin("terminalreporter")]
    yield
    _OUT.clear()


def sh(vm: h.SmokeVM, cmd: str, timeout: float = 120.0) -> str:
    r = vm.ssh("/bin/sh", "-c", cmd, timeout=timeout)
    assert r.returncode == 0, f"{cmd!r}: rc={r.returncode} out={r.stdout!r} err={r.stderr!r}"
    return r.stdout


def php(vm: h.SmokeVM, snippet: str) -> None:
    r = h.php_eval(vm, snippet + "\necho 'OK';")
    assert r.returncode == 0 and "OK" in r.stdout, (r.stdout[-800:], r.stderr[-800:])


def configure(vm: h.SmokeVM, on: bool, url: str = BLACKHOLE) -> None:
    if on:
        section = (
            "array('enable' => 'on', 'lapi_url' => '" + url + "', 'api_key' => 'scratch4117key', "
            "'log_level' => 'debug', 'rules_all_interfaces' => '', 'rules_interfaces' => '', 'rules_log' => '', "
            "'rules_tag' => '', 'rule_v4' => 'on', 'rule_v6' => 'on')"
        )
        write = f"config_set_path('{SECTION}', {section});"
    else:
        write = f"config_del_path('{SECTION}');"
    php(
        vm,
        "require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');\n"
        f"{write}\nwrite_config('scratch 4117');\npfb_global();\npfb_crowdsec_apply();",
    )


def scrapes(vm: h.SmokeVM, seconds: int) -> list[tuple[int, str, int, int, int]]:
    loop = f"end=$(( $(date +%s) + {seconds} )); while [ $(date +%s) -lt $end ]; do {SCRAPE}; sleep 2; done"
    out = sh(vm, loop, timeout=seconds + 300)
    rows = []
    for line in out.splitlines():
        now, up, alive, mtime, upd = line.split()
        rows.append((int(now), up, int(alive), int(mtime), int(upd)))
    return rows


def summarize(label: str, rows: list[tuple[int, str, int, int, int]]) -> tuple[int, int, int]:
    alive = [r for r in rows if r[2] == 1]
    zeros = [r for r in alive if r[1] != "1"]
    lag = max(r[0] - r[3] for r in alive)
    age = max(r[0] - r[4] for r in alive)
    say(
        f"[4117] {label}: scrapes={len(rows)} alive={len(alive)} source_up!=1 while alive={len(zeros)} "
        f"max mtime lag={lag}s max updated_at age={age}s first={rows[0]} last={rows[-1]}"
    )
    if zeros:
        say(f"[4117] {label}: first zero rows: {zeros[:5]}")
    return len(zeros), lag, age


def wait_running(vm: h.SmokeVM) -> None:
    sh(
        vm,
        f"i=0; until pgrep -F {PID} >/dev/null 2>&1 && test -s {STATUS}; do i=$((i+1)); "
        f'[ $i -gt 120 ] && echo "not running" && exit 1; sleep 1; done',
        timeout=200,
    )


def restart(vm: h.SmokeVM) -> None:
    sh(vm, f"{RC} stop; rm -f {STATUS}; {RC} start")
    wait_running(vm)


def old_binary() -> str | None:
    go = shutil.which("go") or (os.path.join(os.environ.get("PFB_GO_ROOT", ""), "bin", "go"))
    if not go or not os.path.exists(go):
        say("[4117] baseline skipped: no Go toolchain in the pytest environment")
        return None
    src = tempfile.mkdtemp(prefix="pfb4117-")
    root = subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True, check=True).stdout
    arch = subprocess.run(
        f"git -C {root.strip()} archive {BASE_SHA} go/pfb_crowdsec | tar -x -C {src}",
        shell=True,
        capture_output=True,
        text=True,
    )
    if arch.returncode != 0:
        say(f"[4117] baseline skipped: {arch.stderr.strip()}")
        return None
    out = os.path.join(src, "pfb_crowdsec.old")
    env = dict(os.environ, CGO_ENABLED="0", GOOS="freebsd", GOARCH="amd64")
    b = subprocess.run(
        [go, "build", "-o", out, "."], cwd=os.path.join(src, "go/pfb_crowdsec"), env=env, capture_output=True, text=True
    )
    if b.returncode != 0:
        say(f"[4117] baseline skipped: build failed {b.stderr.strip()}")
        return None
    return out


def upload(vm: h.SmokeVM, local: str, remote: str) -> None:
    with open(local, "rb") as f:
        argv = vm.ssh_argv(f"cat > {remote} && chmod 0755 {remote}")
        r = subprocess.run(argv, stdin=f, capture_output=True, timeout=300)
    assert r.returncode == 0, r.stderr


@pytest.fixture
def bouncer(smoke_vm: h.SmokeVM) -> Iterator[h.SmokeVM]:
    vm = smoke_vm
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set")
    h.deploy(vm)
    master = h.config_get_state(vm, MASTER)
    h.config_set(vm, MASTER, "on")
    sh(vm, f"/usr/bin/install -d -m 0755 {PROM_DIR}")
    php(
        vm,
        "require_once('/usr/local/pkg/pfblockerng/pfblockerng_extra.inc');\n"
        "PfbConfig::writeSystem('gen/pfb_metrics_export', PfbToggle::On);\nwrite_config('scratch 4117 metrics on');",
    )
    probe = vm.ssh("/bin/sh", "-c", f"curl -s -o /dev/null -m 5 {BLACKHOLE}/; echo $?", timeout=30).stdout.strip()
    url = BLACKHOLE
    if probe != "28":
        sh(vm, "/usr/sbin/daemon -f /usr/bin/nc -lk 127.0.0.1 18080")
        url = LISTENER
    say(f"[4117] blackhole probe curl exit={probe} (28 = timed out); LAPI url used: {url}")
    configure(vm, True, url)
    try:
        wait_running(vm)
        yield vm
    finally:
        undo = f"pkill -CONT -F {PID}; cp -f {BIN}.new {BIN} 2>/dev/null; pkill -f 'nc -lk 127.0.0.1 18080'; true"
        vm.ssh("/bin/sh", "-c", undo)
        configure(vm, False)
        php(
            vm,
            "require_once('/usr/local/pkg/pfblockerng/pfblockerng_extra.inc');\n"
            "PfbConfig::writeSystem('gen/pfb_metrics_export', PfbToggle::Off);\n"
            "write_config('scratch 4117 metrics off');",
        )
        h.config_restore_state(vm, MASTER, master)


def test_4117_blackholed_lapi_soak_and_sigstop(bouncer: h.SmokeVM) -> None:
    vm = bouncer
    say("[4117] binary:", sh(vm, f"{BIN} -version; sha256 -q {BIN}").replace("\n", " "))

    # 1. the fixed daemon against the blackholed LAPI
    zeros, lag, _ = summarize("fixed", scrapes(vm, SOAK))
    st = sh(vm, f"cat {STATUS}")
    say("[4117] status after the soak:", st.strip())
    assert '"last_pull":0' in st and '"lapi_errors":0' not in st, "the LAPI requests did not fail as a blackhole"
    assert "Timeout" in st or "deadline" in st or "timeout" in st, "the last error is not a timeout"
    assert zeros == 0, f"source_up read 0 in {zeros} scrapes while the bouncer ran"
    assert lag <= 10 + 1, f"status file mtime lagged {lag}s; want at most update_frequency + 1 s"

    # 2. SIGSTOP: stale within 3 x update_frequency plus one scrape
    stop = int(sh(vm, f"date +%s; kill -STOP $(cat {PID})").split()[0])
    seen = None
    rows = []
    for _ in range(40):
        row = scrapes(vm, 1)[0]
        rows.append(row)
        if row[1] == "0":
            seen = row
            break
    say(f"[4117] SIGSTOP at {stop}; scrapes after: {rows}")
    assert seen is not None, "source_up never read 0 after SIGSTOP"
    assert seen[2] == 1, "the stopped bouncer's pid must still be live"
    elapsed = seen[0] - stop
    say(f"[4117] source_up 0 after SIGSTOP: {elapsed}s after the stop (3 x 10 s = 30 s plus one scrape)")
    sh(vm, f"kill -CONT $(cat {PID})")
    back = None
    for _ in range(20):
        row = scrapes(vm, 1)[0]
        if row[1] == "1":
            back = row
            break
    say(f"[4117] after SIGCONT: {back}")
    assert back is not None, "source_up did not come back after SIGCONT"
    assert elapsed <= 3 * 10 + 1 + 4, f"source_up 0 came {elapsed}s after SIGSTOP"

    # 3. optional baseline: the devel binary, same soak (informational)
    old = old_binary()
    if old is None:
        return
    sh(vm, f"cp -f {BIN} {BIN}.new")
    upload(vm, old, f"{BIN}.old")
    sh(vm, f"cp -f {BIN}.old {BIN}")
    restart(vm)
    say("[4117] baseline binary sha256:", sh(vm, f"sha256 -q {BIN}").strip())
    summarize("devel baseline", scrapes(vm, SOAK))
    sh(vm, f"cp -f {BIN}.new {BIN}")
    restart(vm)
