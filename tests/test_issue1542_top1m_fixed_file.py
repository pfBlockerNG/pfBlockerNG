from __future__ import annotations

import builtins
import json
import os
import subprocess
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Literal

import pytest

import pfb_unbound as P
from tests.test_adr06_golden_oracle import _build_cfg, _decision_label

REPO_ROOT = Path(__file__).resolve().parents[1]

REPROCESS_PROBE = r"""
require 'tests/php/bootstrap.php';
require_once 'src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc';
memory_reset_peak_usage();
$before = memory_get_usage();
$reprocess = pfb_top1m_reprocess_needed(getenv('PFB_TOP1M_PROBE_DIR'));
echo json_encode([
    'reprocess' => $reprocess,
    'peak_delta' => memory_get_peak_usage() - $before,
], JSON_THROW_ON_ERROR);
"""

OFFLINE_PUBLICATION_PROBE = r"""
require 'tests/php/bootstrap.php';
$root = getenv('PFB_TOP1M_PROBE_DIR');
$GLOBALS['pfb']['dbdir'] = $root . '/db';
$GLOBALS['pfb']['dnsdir'] = $root . '/dnsbl';
$GLOBALS['pfb']['dnsbl_top1m'] = PfbToggle::On;
$GLOBALS['pfb']['dnsbl_tld_wildcard'] = '';
$GLOBALS['pfb']['dnsblconfig'] = ['tld_wildcard_blacklist' => '', 'tld_wildcard_exclusion' => '', 'whitelist' => ''];
$GLOBALS['pfb']['unbound_py_rawdir'] = $root . '/pfb_py_raw';
$GLOBALS['pfb']['unbound_py_sources'] = $root . '/pfb_py_sources.json';
$GLOBALS['pfb']['unbound_py_top1m'] = $root . '/pfb_py_top1m.txt';
$result = pfb_unbound_python_sources([], ['top1m_atomic' => [
    'chown' => static fn(string $file, string $owner): bool => TRUE,
    'chgrp' => static fn(string $file, string $group): bool => TRUE,
    'chmod' => static fn(string $file, int $mode): bool => TRUE,
]]);
echo json_encode(['published' => is_array($result)], JSON_THROW_ON_ERROR);
"""


def _run_reprocess_probe(tmp_path: Path, *, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PFB_TOP1M_PROBE_DIR"] = str(tmp_path)
    return subprocess.run(
        ["php", "-r", REPROCESS_PROBE],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
    )


def _manifest(tmp_path: Path, *, enabled: bool = True) -> Path:
    raw = tmp_path / "feed.raw"
    raw.write_text("blocked.example\n", encoding="utf-8")
    path = tmp_path / "pfb_py_sources.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "config": {"top1m_enabled": enabled, "user_whitelist": []},
                "feeds": [{"raw": raw.name, "feed": "feed", "group": "g", "log_flag": "1"}],
            }
        ),
        encoding="utf-8",
    )
    return path


@pytest.mark.parametrize("current_baseline", [False, True], ids=["missing-baseline", "current-baseline"])
def test_nonregular_whitelist_never_triggers_reprocessing(tmp_path: Path, current_baseline: bool) -> None:
    (tmp_path / "top-1m.csv").write_text("1,current.example\n", encoding="utf-8")
    if current_baseline:
        (tmp_path / "top-1m.csv.zip.orig").write_text("detector baseline\n", encoding="utf-8")
    whitelist = tmp_path / "pfbalexawhitelist.txt"
    os.mkfifo(whitelist)
    fifo = os.open(whitelist, os.O_RDWR | os.O_NONBLOCK)

    try:
        os.write(fifo, b".legacy.example,,\n")
        proc = _run_reprocess_probe(tmp_path)
    finally:
        os.close(fifo)

    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["reprocess"] is False


def test_current_canonical_whitelist_check_has_bounded_peak_memory(tmp_path: Path) -> None:
    (tmp_path / "top-1m.csv").write_text("1,current.example\n", encoding="utf-8")
    (tmp_path / "top-1m.csv.zip.orig").write_text("detector baseline\n", encoding="utf-8")
    with (tmp_path / "pfbalexawhitelist.txt").open("w", encoding="utf-8") as handle:
        for index in range(200_000):
            handle.write(f"domain-{index:06d}.example\n")

    proc = _run_reprocess_probe(tmp_path)

    assert proc.returncode == 0, proc.stderr
    result = json.loads(proc.stdout)
    assert result["reprocess"] is False
    assert result["peak_delta"] < 1024 * 1024


@pytest.mark.parametrize(
    "legacy_wire",
    [
        b".offline.example,,\n,offline.example,,\n,www.offline.example,,\n",
        b'.offline.example 60\n"offline.example 60\n"www.offline.example 60\n',
    ],
    ids=["python-mode", "native-mode"],
)
def test_offline_legacy_publication_projects_strict_exact_allow(tmp_path: Path, legacy_wire: bytes) -> None:
    dbdir = tmp_path / "db"
    dbdir.mkdir()
    (tmp_path / "dnsbl").mkdir()
    source = dbdir / "pfbalexawhitelist.txt"
    source.write_bytes(legacy_wire)
    env = os.environ.copy()
    env["PFB_TOP1M_PROBE_DIR"] = str(tmp_path)

    proc = subprocess.run(
        ["php", "-r", OFFLINE_PUBLICATION_PROBE],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )

    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout) == {"published": True}
    assert not (dbdir / "top-1m.csv.zip.orig").exists()
    assert source.read_bytes() == legacy_wire
    assert (tmp_path / "pfb_py_top1m.txt").read_bytes() == b"offline.example\n"

    result = P.dnsbl_build_from_manifest(str(tmp_path / "pfb_py_sources.json"))
    assert result is not None
    assert result.white_db["offline.example"]["wildcard"] is False
    assert P.whitelist_check_domain("offline.example", result.white_db, 1)
    assert P.whitelist_check_domain("www.offline.example", result.white_db, 1)
    assert not P.whitelist_check_domain("deep.offline.example", result.white_db, 1)


@pytest.mark.parametrize(
    "legacy_wire",
    [
        b".legacy.com,,\n,legacy.com,,\n,www.legacy.com,,\n",
        b'.legacy.com 60\n"legacy.com 60\n"www.legacy.com 60\n',
    ],
    ids=["python-mode", "native-mode"],
)
def test_legacy_whitelist_reprocesses_to_python_exact_allow(tmp_path: Path, legacy_wire: bytes) -> None:
    (tmp_path / "top-1m.csv").write_text("1,LEGACY.COM\n", encoding="utf-8")
    (tmp_path / "top-1m.csv.zip.orig").write_text("detector baseline\n", encoding="utf-8")
    (tmp_path / "pfbalexawhitelist.txt").write_bytes(legacy_wire)
    php = r"""
require 'tests/php/bootstrap.php';
require_once 'src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc';
$dbdir = getenv('PFB_TOP1M_PROBE_DIR');
mkdir($dbdir . '/dnsbl');
$GLOBALS['pfb']['dbdir'] = $dbdir;
$GLOBALS['pfb']['dnsdir'] = $dbdir . '/dnsbl';
$GLOBALS['pfb']['dnsbl_top1m'] = PfbToggle::On;
$GLOBALS['pfb']['dnsbl_top1m_inc'] = 'com';
$GLOBALS['pfb']['dnsbl_top1m_cnt'] = '1000';
$GLOBALS['pfb']['dnsblconfig'] = ['tld_wildcard_blacklist' => '', 'tld_wildcard_exclusion' => '', 'whitelist' => ''];
$GLOBALS['pfb']['unbound_py_rawdir'] = $dbdir . '/raw';
$GLOBALS['pfb']['unbound_py_sources'] = $dbdir . '/pfb_py_sources.json';
$GLOBALS['pfb']['unbound_py_top1m'] = $dbdir . '/pfb_py_top1m.txt';
$GLOBALS['pfb']['log'] = $dbdir . '/pfblockerng.log';
$GLOBALS['pfb']['errlog'] = $dbdir . '/pfblockerng_error.log';
$reprocess = pfb_top1m_reprocess_needed($dbdir);
if ($reprocess) {
    pfblockerng_top1m();
    $published = pfb_unbound_python_sources([], ['top1m_atomic' => [
        'chown' => static fn(string $file, string $owner): bool => TRUE,
        'chgrp' => static fn(string $file, string $group): bool => TRUE,
        'chmod' => static fn(string $file, int $mode): bool => TRUE,
    ]]);
    if ($published === FALSE) {
        throw new RuntimeException('TOP1M fixed-file publication failed');
    }
}
echo json_encode(['reprocess' => $reprocess], JSON_THROW_ON_ERROR);
"""
    env = os.environ.copy()
    env["PFB_TOP1M_PROBE_DIR"] = str(tmp_path)
    proc = subprocess.run(
        ["php", "-r", php],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout) == {"reprocess": True}
    assert (tmp_path / "pfbalexawhitelist.txt").read_bytes() == b"legacy.com\n"

    result = P.dnsbl_build_from_manifest(str(_manifest(tmp_path)))
    assert result is not None
    assert result.white_db["legacy.com"]["wildcard"] is False
    assert P.whitelist_check_domain("legacy.com", result.white_db, 1)
    assert P.whitelist_check_domain("www.legacy.com", result.white_db, 1)
    assert not P.whitelist_check_domain("deep.legacy.com", result.white_db, 1)


def test_disabled_does_not_require_fixed_file(tmp_path: Path) -> None:
    result = P.dnsbl_build_from_manifest(str(_manifest(tmp_path, enabled=False)))
    assert result is not None
    assert result.white_db == {}


def test_enabled_streams_fixed_file_with_crlf_blanks_and_first_writer_duplicates(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)
    (tmp_path / "pfb_py_top1m.txt").write_bytes(b"first.example\r\n\r\n SECOND.EXAMPLE \r\nfirst.example\r\n")
    result = P.dnsbl_build_from_manifest(str(manifest))
    assert result is not None
    assert set(result.white_db) == {"first.example", "second.example"}
    assert result.white_db["first.example"]["important"] is True


@pytest.mark.parametrize("legacy", [".legacy.example,,\n", ",legacy.example,,\n", ",www.legacy.example,,\n"])
def test_enabled_rejects_retired_comma_framed_top1m_lines(tmp_path: Path, legacy: str) -> None:
    manifest = _manifest(tmp_path)
    (tmp_path / "pfb_py_top1m.txt").write_text(legacy, encoding="utf-8")

    result = P.dnsbl_build_from_manifest(str(manifest))

    assert result is not None
    assert result.white_db == {}, f"retired TOP1M record became a whitelist key: {result.white_db!r}"
    assert all("," not in key for key in result.white_db)


@pytest.mark.parametrize(
    "invalid",
    [
        "dotless\n",
        "a" * 63 + "." + "b" * 63 + "." + "c" * 63 + "." + "d" * 63 + ".com\n",
    ],
)
def test_enabled_rejects_invalid_top1m_domain_shape_and_wire_cap(tmp_path: Path, invalid: str) -> None:
    manifest = _manifest(tmp_path)
    (tmp_path / "pfb_py_top1m.txt").write_text(invalid, encoding="utf-8")

    result = P.dnsbl_build_from_manifest(str(manifest))

    assert result is not None
    assert result.white_db == {}


def test_enabled_top1m_is_exact_allow_with_www_fallback_not_deeper_wildcard(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)
    (tmp_path / "feed.raw").write_text("||blocked.example^\n", encoding="utf-8")
    (tmp_path / "pfb_py_top1m.txt").write_text("blocked.example\nblocked.example\n", encoding="utf-8")

    result = P.dnsbl_build_from_manifest(str(manifest))

    assert result is not None
    assert result.white_db["blocked.example"]["wildcard"] is False
    assert P.whitelist_check_domain("blocked.example", result.white_db, 1)
    assert P.whitelist_check_domain("www.blocked.example", result.white_db, 1)
    assert not P.whitelist_check_domain("deep.blocked.example", result.white_db, 1)

    containers = {
        "dataDB": result.data_db,
        "zoneDB": result.zone_db,
        "whiteDB": result.white_db,
        "regexDB": {},
        "feedGroupIndexDB": result.feed_group_index_db,
        "hstsDB": {},
    }
    cfg = _build_cfg({}, has_white=True)
    assert (
        _decision_label(P.evaluate_domain("blocked.example", "blocked.example", "example", False, cfg, containers))
        == "whitelist"
    )
    assert (
        _decision_label(
            P.evaluate_domain("www.blocked.example", "www.blocked.example", "example", False, cfg, containers)
        )
        == "whitelist"
    )
    deep_decision = P.evaluate_domain("deep.blocked.example", "deep.blocked.example", "example", False, cfg, containers)
    assert deep_decision.is_found is True
    assert deep_decision.in_whitelist is False
    assert _decision_label(deep_decision) == "block-null"


@pytest.mark.parametrize(
    "kind",
    [
        "missing",
        "directory",
        pytest.param(
            "unreadable",
            marks=pytest.mark.skipif(
                os.geteuid() == 0,
                reason="root bypasses file permissions — denial cannot be simulated",
            ),
        ),
    ],
)
def test_enabled_missing_directory_or_unreadable_fixed_file_fails_closed(tmp_path: Path, kind: str) -> None:
    manifest = _manifest(tmp_path)
    path = tmp_path / "pfb_py_top1m.txt"
    if kind == "directory":
        path.mkdir()
    elif kind == "unreadable":
        path.write_text("blocked.example\n", encoding="utf-8")
        path.chmod(0)
    assert P.dnsbl_build_from_manifest(str(manifest)) is None
    if kind == "unreadable":
        path.chmod(0o600)


def test_enabled_mid_read_failure_discards_candidate(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)
    path = tmp_path / "pfb_py_top1m.txt"
    path.write_text("first.example\nsecond.example\n", encoding="utf-8")
    real_open = builtins.open

    class FailingReader:
        def __enter__(self) -> FailingReader:
            return self

        def __exit__(self, exc_type: object, exc: object, tb: object) -> Literal[False]:
            return False

        def __iter__(self) -> Iterator[str]:
            yield "first.example\n"
            raise OSError("injected mid-read")

    def injected_open(name: str | os.PathLike[str], *args: Any, **kwargs: Any) -> Any:
        if os.fspath(name) == os.fspath(path):
            return FailingReader()
        return real_open(name, *args, **kwargs)

    monkeypatch.setattr("builtins.open", injected_open)
    assert P.dnsbl_build_from_manifest(str(manifest)) is None


def test_enabled_truncation_after_open_discards_candidate(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)
    path = tmp_path / "pfb_py_top1m.txt"
    path.write_text("".join("domain-{}.example\n".format(index) for index in range(100_000)), encoding="utf-8")
    opened = threading.Event()
    truncated = threading.Event()
    real_open = builtins.open

    def truncate_when_opened() -> None:
        assert opened.wait(5), "TOP1M open was not reached"
        os.truncate(path, 0)
        truncated.set()

    def injected_open(name: str | os.PathLike[str], *args: Any, **kwargs: Any) -> Any:
        handle = real_open(name, *args, **kwargs)
        if os.fspath(name) == os.fspath(path):
            opened.set()
            assert truncated.wait(5), "TOP1M truncation did not complete"
        return handle

    worker = threading.Thread(target=truncate_when_opened)
    worker.start()
    monkeypatch.setattr("builtins.open", injected_open)
    try:
        assert P.dnsbl_build_from_manifest(str(manifest)) is None
    finally:
        worker.join(5)
    assert not worker.is_alive(), "TOP1M truncation worker did not finish"
