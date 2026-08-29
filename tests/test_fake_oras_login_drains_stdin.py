"""FAKE_ORAS login must drain stdin (issue #2753).

The gather-step snippet is:

    printf '%s' "$SMOKE_GHCR_TOKEN" | oras login ... --password-stdin

under ``set -euo pipefail``. Real ``oras login`` reads stdin. A fake that
``exit 0`` without draining races SIGPIPE 141 on printf (CI on unrelated PRs;
reproduced 1/3000 locally). This file pins the one-line contract: drain, then
exit 0. It does not change ``.github/``; dropping pipefail on the real snippet
is out of scope.
"""

from __future__ import annotations

import os
import re
import signal
import subprocess
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_CONTRACT = ROOT / "tests" / "test_version_tracker_reconcile_contract.py"
_WORKFLOW = ROOT / ".github" / "workflows" / "version-tracker.yml"

_FAKE_ORAS_ASSIGN = re.compile(r'^FAKE_ORAS = """(.*?)"""', re.M | re.S)
_SUDO_TUPLE = re.compile(r'\("sudo",\s*(?P<q>[\'"])(?P<body>.*?)(?P=q)\)', re.S)


def _fake_oras() -> str:
    text = _CONTRACT.read_text(encoding="utf-8")
    match = _FAKE_ORAS_ASSIGN.search(text)
    assert match is not None, "FAKE_ORAS assignment missing from contract test"
    return match.group(1)


def _fake_sudo() -> str:
    text = _CONTRACT.read_text(encoding="utf-8")
    match = _SUDO_TUPLE.search(text)
    assert match is not None, "sudo fake assignment missing from contract test"
    return bytes(match.group("body"), "utf-8").decode("unicode_escape")


def _assert_drains(argv: list[str], label: str) -> None:
    """Write past the pipe buffer so an undrained reader EPIPE-s every time.

    A blocking reader must fail, not hang: the writer runs on a joined
    thread with a deadline. ``start_new_session`` plus ``killpg`` reaps
    grandchildren (``proc.kill()`` only kills the immediate ``sh``).
    """
    proc = subprocess.Popen(
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    caught: list[BaseException] = []

    def write() -> None:
        assert proc.stdin is not None
        payload = b"x" * (256 * 1024)
        chunk = 65536
        try:
            offset = 0
            while offset < len(payload):
                proc.stdin.write(payload[offset : offset + chunk])
                proc.stdin.flush()
                offset += chunk
            proc.stdin.close()
        except BrokenPipeError as exc:
            caught.append(exc)

    writer = threading.Thread(target=write, daemon=True)
    try:
        writer.start()
        writer.join(timeout=5)
        if writer.is_alive():
            raise AssertionError(f"{label} hung without draining stdin")
        if caught:
            raise AssertionError(f"{label} exited without draining stdin") from caught[0]
        rc = proc.wait(timeout=5)
        assert proc.stderr is not None
        assert rc == 0, f"{label} rc={rc} stderr={proc.stderr.read()!r}"
    finally:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        if proc.poll() is None:
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass


def test_fake_oras_login_consumes_piped_password(tmp_path: Path) -> None:
    """A pipe-buffer-sized password must not EPIPE when the fake login exits.

    ``subprocess.run(..., input=)`` is the wrong probe: CPython's
    ``communicate()`` swallows ``BrokenPipeError``, so an undrained login
    looks green. Write the pipe ourselves.
    """
    oras = tmp_path / "oras"
    oras.write_text(_fake_oras(), encoding="utf-8")
    oras.chmod(0o755)
    _assert_drains(
        [str(oras), "login", "ghcr.io", "--username", "u", "--password-stdin"],
        "FAKE_ORAS login",
    )


def test_fake_sudo_tee_consumes_piped_rules(tmp_path: Path) -> None:
    """The gather-step ``echo | sudo tee`` stub must drain, same class as oras."""
    sudo = tmp_path / "sudo"
    sudo.write_text(_fake_sudo(), encoding="utf-8")
    sudo.chmod(0o755)
    _assert_drains([str(sudo), "tee", "/etc/udev/rules.d/99-kvm4all.rules"], "sudo tee")


def test_gather_step_still_pipes_token_under_pipefail() -> None:
    """Wrong fix is dropping pipefail or --password-stdin on the real snippet."""
    script = _WORKFLOW.read_text(encoding="utf-8")
    gather = script.split("Gather box facts (boot newest images)", 1)[1].split("\n      - name:", 1)[0]
    assert "pipefail" in gather
    assert "--password-stdin" in gather
    assert "oras login" in gather
