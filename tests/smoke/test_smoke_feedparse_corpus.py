"""issue #3977: the feed parse parity corpus replayed through Core's parser on a real pfSense box.

The corpus (go/pfb_core/feedparse/testdata/, schema in its README.md) is what Core produces line for line; PHP no longer
parses feeds. The Go corpus runners are cross-compiled for the appliance (`go test -c`) and run there against a copy
of the corpus, so the byte-exact expectations (`expect`; `old_expect` rows stay recorded in the corpus) are checked
on FreeBSD rather than the build host. The runners use Core's pure-Go parser, not the retired PHP/ICU path.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from . import helpers as h
from .conftest import SmokeVM

pytestmark = pytest.mark.smoke

FEEDPARSE = Path(__file__).resolve().parents[2] / "go" / "pfb_core" / "feedparse"
# Every corpus runner in the package; each must report PASS on the appliance, none may skip.
CORPUS_TESTS = (
    "TestNormalizeCorpus",
    "TestIPCorpus",
    "TestIPParseTypeCorpus",
    "TestDNSBLCorpus",
    "TestIPFeedCorpus",
    "TestDNSBLFeedCorpus",
    "TestNormCacheCorpus",
    "TestPreScriptCorpus",
)
GOARCH = {"amd64": "amd64", "arm64": "arm64", "aarch64": "arm64"}


def _put(vm: SmokeVM, path: str, content: bytes) -> None:
    done = subprocess.run(vm.ssh_argv(f"cat > {path}"), input=content, capture_output=True, timeout=300, check=False)
    assert done.returncode == 0, f"upload of {path} failed: {done.stderr!r}"


def _build(goarch: str, out: Path) -> None:
    go = shutil.which("go")
    if go is None:
        pytest.skip("no Go toolchain to cross-compile the Core corpus runners")
    env = {**os.environ, "GOOS": "freebsd", "GOARCH": goarch, "CGO_ENABLED": "0"}
    built = subprocess.run(
        [go, "test", "-c", "-o", str(out), "."],
        cwd=FEEDPARSE,
        env=env,
        capture_output=True,
        text=True,
        timeout=900,
        check=False,
    )
    assert built.returncode == 0, f"cross-compiling the corpus runners failed:\n{built.stderr}"


def test_core_parses_the_corpus_on_the_appliance(smoke_vm: SmokeVM, tmp_path: Path) -> None:
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")
    h.deploy(smoke_vm)
    arch = smoke_vm.ssh("uname -m", timeout=30)
    assert arch.returncode == 0, arch.stderr
    goarch = GOARCH.get(arch.stdout.strip())
    assert goarch is not None, f"unsupported appliance architecture {arch.stdout.strip()!r}"
    binary = tmp_path / "feedparse.test"
    _build(goarch, binary)
    archive = tmp_path / "testdata.tar"
    shutil.make_archive(str(archive.with_suffix("")), "tar", root_dir=FEEDPARSE, base_dir="testdata")

    made = smoke_vm.ssh("mktemp -d /var/tmp/pfb_fpc.XXXXXX", timeout=30)
    assert made.returncode == 0, made.stderr
    work = made.stdout.strip()
    try:
        _put(smoke_vm, f"{work}/feedparse.test", binary.read_bytes())
        _put(smoke_vm, f"{work}/testdata.tar", archive.read_bytes())
        run = smoke_vm.ssh(
            f"cd {work} && tar -xf testdata.tar && chmod 0755 feedparse.test && "
            f"./feedparse.test -test.v -test.count=1 -test.run '^({'|'.join(CORPUS_TESTS)})$'",
            timeout=900,
        )
        report = f"rc={run.returncode}\n{run.stdout[-6000:]}\n{run.stderr[-2000:]}"
        assert run.returncode == 0, f"Core's corpus runners failed on the appliance:\n{report}"
        passed = set(re.findall(r"^--- PASS: (\w+) ", run.stdout, re.MULTILINE))
        skipped = set(re.findall(r"^\s*--- SKIP: (\S+) ", run.stdout, re.MULTILINE))
        assert skipped == set(), f"corpus runners skipped on the appliance: {sorted(skipped)}\n{report}"
        assert set(CORPUS_TESTS) <= passed, f"corpus runners missing a PASS: {sorted(set(CORPUS_TESTS) - passed)}"
    finally:
        smoke_vm.ssh(f"rm -rf {work}", timeout=60)
