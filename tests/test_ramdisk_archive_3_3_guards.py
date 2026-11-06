from __future__ import annotations

import io
import json
import os
import shlex
import signal
import subprocess
import tarfile
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def archive_harness(tmp_path: Path, *, ramdisk: bool) -> Path:
    source = (ROOT / "src/usr/local/pkg/pfblockerng/pfblockerng.inc").read_text()
    start = source.index("function pfb_aliastables($mode) {")
    end = source.index("\n}\n", start) + 2
    function = source[start:end].replace("/var/unbound/", f"{tmp_path}/unbound/")
    function = function.replace("/usr/bin/tar -jcvf", f"{tmp_path}/tar -jcvf")
    start = source.index("// Commandline arguments for daemons")
    end = source.index("// Function to convert string to lowercase", start)
    dispatcher = source[start:end]
    for name in ("etc", "aliases", "unbound"):
        (tmp_path / name).mkdir()
    (tmp_path / "aliases/pfB_test.txt").write_text("192.0.2.17\n")
    (tmp_path / "ramdisk").write_text("on" if ramdisk else "off")
    config = {
        "system/earlyshellcmd": ["/usr/local/pkg/pfblockerng/pfblockerng.sh aliastables"],
        "installedpackages/shellcmdsettings/config": [
            {"cmd": "/usr/local/pkg/pfblockerng/pfblockerng.sh aliastables"}
        ],
    }
    (tmp_path / "config.json").write_text(json.dumps(config))
    stubs = r"""
function config_read_file(...$args) {}
function pfb_global() {}
function config_path_enabled(...$args) {
    return file_get_contents(__DIR__ . '/ramdisk') === 'on';
}
function config_get_path($path, $default = NULL) {
    $config = json_decode(file_get_contents(__DIR__ . '/config.json'), TRUE);
    return $config[$path] ?? $default;
}
function config_set_path(...$args) {
    throw new RuntimeException('shutdown save attempted config mutation');
}
function write_config(...$args) {
    throw new RuntimeException('shutdown save attempted config.xml write');
}
function pfb_logger(...$args) {}
function unlink_if_exists($path) { if (file_exists($path)) { unlink($path); } }
$pfb = [
    'aliasdir' => __DIR__ . '/aliases',
    'aliasarchive' => __DIR__ . '/etc/aliastables.tar.bz2',
    'dnsbl_file' => __DIR__ . '/unbound/dnsbl',
];
"""
    harness = tmp_path / "harness.php"
    harness.write_text("<?php\n" + stubs + function + "\n" + dispatcher + "\npfb_aliastables($argv[1]);\n")
    return harness


def test_disabled_save_with_missing_archive_keeps_stale_hooks(tmp_path: Path) -> None:
    """The OFF guard must protect absent archives, not just short-circuit on present ones."""
    harness = archive_harness(tmp_path, ramdisk=False)
    before = (tmp_path / "config.json").read_bytes()
    for mode in ("save", "aliastables_save"):
        result = subprocess.run(["php", str(harness), mode], capture_output=True, text=True, check=False)
        assert result.returncode == 0, f"{mode}: {result.stdout}{result.stderr}"
        assert (tmp_path / "config.json").read_bytes() == before
        assert not (tmp_path / "etc/aliastables.tar.bz2").exists()
        assert list((tmp_path / "etc").iterdir()) == []


def test_terminated_archive_build_removes_only_its_staged_file(tmp_path: Path) -> None:
    """TERM from the bounded supervisor must not leave persistent staging garbage."""
    harness = archive_harness(tmp_path, ramdisk=True)
    archive = tmp_path / "etc/aliastables.tar.bz2"
    with tarfile.open(archive, "w:bz2") as previous:
        member = tarfile.TarInfo("previous.txt")
        member.size = len(b"previous state\n")
        previous.addfile(member, io.BytesIO(b"previous state\n"))
    before = archive.read_bytes()
    unrelated = tmp_path / "etc/aliastables.other-writer"
    unrelated.write_bytes(b"another writer's staging data")
    ready = tmp_path / "ready"
    fifo = tmp_path / "release"
    os.mkfifo(fifo)
    wrapper = tmp_path / "tar"
    wrapper.write_text(
        "#!/bin/sh\n"
        f"printf ready > {shlex.quote(str(ready))}\n"
        f"read value < {shlex.quote(str(fifo))}\n"
        'exec /usr/bin/tar "$@"\n'
    )
    wrapper.chmod(0o700)
    process = subprocess.Popen(
        ["timeout", "-s", "TERM", "-k", "2", "60", "php", str(harness), "update"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        deadline = time.monotonic() + 10
        while not ready.exists():
            assert process.poll() is None, "archive writer exited before tar readiness"
            assert time.monotonic() < deadline, "STUCK: tar readiness was not signalled"
            time.sleep(0.01)
        os.kill(process.pid, signal.SIGTERM)
        stdout, stderr = process.communicate(timeout=10)
        assert process.returncode != 0, f"terminated writer reported success: {stdout}{stderr}"
        assert archive.read_bytes() == before, "terminated build replaced the previous archive"
        assert unrelated.read_bytes() == b"another writer's staging data"
        assert sorted(path.name for path in archive.parent.iterdir()) == [
            "aliastables.other-writer",
            "aliastables.tar.bz2",
        ], f"terminated build left staging files: {list(archive.parent.iterdir())}"
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.communicate(timeout=10)
