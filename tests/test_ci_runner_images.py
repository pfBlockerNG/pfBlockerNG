"""Drift guards for the CI runner container images (issue #2214).

The two images under ``.github/docker/`` replace the per-job toolchain install every
workflow does today. That moves the gate-deciding tool versions out of the workflow YAML
and into a Dockerfile, so the pins need a guard in their new home or CI silently starts
grading against whatever the image happens to carry:

* the base image must stay a NUMBERED Debian 13 slim tag pinned by digest — ``13-slim``
  or ``stable-slim`` would re-point under us on the next Debian point release;
* every tool the image downloads must be checksum-verified, exactly as the workflow steps
  it replaces already do;
* the ShellCheck / shellspec / kcov pins must equal the ones ``test.yml`` documents (and
  ``tests/test_ci_tool_pins.py`` guards) — two homes for one pin is a drift source;
* the baked PHP and Python versions must equal the live supported-version matrix, so a
  version added to ``supported-versions.json`` that the image cannot run fails HERE
  instead of at the first red matrix leg.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from tests.test_ci_tool_pins import KCOV_PIN, SHELLCHECK_PIN, SHELLSPEC_PIN

ROOT = Path(__file__).resolve().parents[1]
DOCKER_DIR = ROOT / ".github/docker"
BASE_DOCKERFILE = DOCKER_DIR / "ci-runner.Dockerfile"
VM_DOCKERFILE = DOCKER_DIR / "ci-runner-vm.Dockerfile"
VERSION_FILE = DOCKER_DIR / "VERSION"
PUBLISH_WORKFLOW = ROOT / ".github/workflows/ci-images.yml"
MATRIX_READER = ROOT / "scripts/read-version-matrix.sh"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _run_blocks(dockerfile: str) -> list[str]:
    """Return each Dockerfile instruction with its line continuations folded in.

    A checksum lives in the same ``RUN`` as the download it verifies; asserting over
    whole-file text would let a verified download elsewhere vouch for an unverified one.
    """
    folded = re.sub(r"\\\n", " ", dockerfile)
    blocks: list[str] = []
    for line in folded.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if re.match(r"^(FROM|RUN|COPY|ADD|ENV|ARG|WORKDIR|SHELL|ENTRYPOINT|CMD|LABEL|USER)\b", stripped):
            blocks.append(stripped)
        elif blocks:
            blocks[-1] += " " + stripped
    return blocks


def _arg_defaults(dockerfile: str) -> dict[str, str]:
    """``ARG NAME=value`` defaults, so a ``FROM ${NAME}`` can be resolved to a real ref."""
    defaults: dict[str, str] = {}
    for block in _run_blocks(dockerfile):
        match = re.match(r"^ARG\s+([A-Za-z_][A-Za-z0-9_]*)=(\S+)", block)
        if match:
            defaults[match.group(1)] = match.group(2)
    return defaults


def _expanded_blocks(dockerfile: str) -> list[str]:
    """``_run_blocks`` with ``${ARG}`` references replaced by their defaults.

    Every pin in these Dockerfiles is an ``ARG`` so the build can be re-pointed without
    editing the recipe; asserting against the raw text would only ever see ``${FOO}`` and
    pass vacuously.
    """
    defaults = _arg_defaults(dockerfile)
    blocks = []
    for block in _run_blocks(dockerfile):
        for name, value in defaults.items():
            block = block.replace("${" + name + "}", value).replace("$" + name, value)
        blocks.append(block)
    return blocks


def _stage_bases(dockerfile: str) -> list[str]:
    """Every ``FROM`` image with its ARG indirection resolved, minus intra-file stages."""
    defaults = _arg_defaults(dockerfile)
    stage_names = set(re.findall(r"^FROM\s+\S+\s+AS\s+(\S+)", dockerfile, re.MULTILINE | re.IGNORECASE))
    resolved: list[str] = []
    for block in _run_blocks(dockerfile):
        if not block.startswith("FROM "):
            continue
        image = block.split()[1]
        arg = re.fullmatch(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?", image)
        if arg:
            image = defaults.get(arg.group(1), image)
        if image in stage_names:
            continue
        resolved.append(image)
    return resolved


def _matrix_versions() -> tuple[list[str], list[str]]:
    """(python_versions, php_versions) from the live supported-version matrix."""
    proc = subprocess.run(
        ["sh", str(MATRIX_READER), "--print-test"],
        capture_output=True,
        text=True,
        cwd=ROOT,
        check=False,
    )
    if proc.returncode != 0:
        pytest.skip(f"supported-version matrix unavailable: {proc.stderr.strip()[:200]}")
    python_blob = proc.stdout.split("python_versions:", 1)[1].split("php_versions:", 1)[0]
    php_blob = proc.stdout.split("php_versions:", 1)[1]
    return json.loads(python_blob), json.loads(php_blob)


pytestmark = pytest.mark.skipif(
    shutil.which("git") is None or shutil.which("jq") is None,
    reason="read-version-matrix.sh requires git + jq",
)


def test_base_image_is_a_digest_pinned_numbered_debian_13_slim() -> None:
    """A floating ``13-slim``/``stable-slim`` tag silently re-bases the whole CI
    toolchain on the next Debian point release; the digest makes a rebase a diff."""
    froms = [b for b in _run_blocks(_read(BASE_DOCKERFILE)) if b.startswith(("FROM", "ARG"))]
    debian_refs = [b for b in froms if "debian:" in b]

    assert debian_refs, f"no Debian base reference found; FROM/ARG lines were:\n{froms}"
    for ref in debian_refs:
        assert re.search(r"debian:13\.\d+-slim@sha256:[0-9a-f]{64}", ref), (
            f"the Debian base must be a NUMBERED 13.x slim tag pinned by digest; got:\n{ref}"
        )


def test_every_stage_base_is_pinned_by_digest() -> None:
    """The Python and Node toolchains are copied out of official images; an unpinned
    stage base makes the baked interpreter version a moving target."""
    for dockerfile in (BASE_DOCKERFILE, VM_DOCKERFILE):
        for image in _stage_bases(_read(dockerfile)):
            if "/ci-runner" in image:
                continue  # our own image: pinned by the VERSION series, asserted below
            assert "@sha256:" in image, f"{dockerfile.name}: stage base {image!r} is not digest-pinned"


def test_every_downloaded_tool_is_checksum_verified() -> None:
    """Same floor the workflow steps this image replaces already hold: a release asset is
    only immutable once its bytes are checked."""
    for dockerfile in (BASE_DOCKERFILE, VM_DOCKERFILE):
        for block in _expanded_blocks(_read(dockerfile)):
            if not block.startswith("RUN ") or "https://" not in block:
                continue
            if re.search(r"git .*fetch .*[0-9a-f]{40}", block):
                continue  # a commit id IS the checksum: git cannot serve other bytes for it
            if "packages.sury.org" in block and "apt-get install" in block:
                continue  # apt verifies the archive signature against the key pinned below
            assert "sha256sum -c" in block or "sha256sum --check" in block, (
                f"{dockerfile.name}: download is not checksum-verified:\n{block[:400]}"
            )


def test_the_sury_php_repository_key_is_pinned_by_checksum() -> None:
    """The PHP versions come from a third-party archive; an unverified key fetch means
    the whole PHP toolchain trusts whatever that URL served that morning."""
    text = _read(BASE_DOCKERFILE)
    assert "packages.sury.org" in text, "PHP 8.3/8.5 need the sury archive on Debian 13"
    key_block = next(b for b in _expanded_blocks(text) if "sury" in b and "apt.gpg" in b)
    assert re.search(r"[0-9a-f]{64}", key_block), (
        f"the sury signing key must be pinned by SHA-256; block was:\n{key_block[:400]}"
    )


def test_shellcheck_shellspec_and_kcov_pins_match_the_workflow_pins() -> None:
    """One pin, one value: the image and CONTRIBUTING.md/test.yml must not drift apart."""
    text = _read(BASE_DOCKERFILE)

    assert f"SHELLCHECK_VERSION={SHELLCHECK_PIN}" in text, f"the image must bake ShellCheck {SHELLCHECK_PIN}"
    assert f"SHELLSPEC_VERSION={SHELLSPEC_PIN}" in text, f"the image must bake shellspec {SHELLSPEC_PIN}"
    assert f"KCOV_COMMIT={KCOV_PIN}" in text, f"the image must build kcov at {KCOV_PIN}"


def test_baked_php_versions_are_exactly_the_supported_matrix() -> None:
    """A matrix PHP version the image cannot run must red THIS test, not the php-syntax
    leg that discovers `php8.6: not found` three workflows later."""
    _, php_versions = _matrix_versions()
    text = _read(BASE_DOCKERFILE)
    baked = sorted(set(re.findall(r"php(\d+\.\d+)-cli", text)))

    assert baked == sorted(php_versions), (
        f"image bakes PHP {baked}, supported-versions.json wants {sorted(php_versions)}"
    )


def test_baked_python_versions_are_exactly_the_supported_matrix() -> None:
    """Same contract as PHP: the pytest matrix legs come from this list."""
    python_versions, _ = _matrix_versions()
    text = _read(BASE_DOCKERFILE)
    baked = sorted(set(re.findall(r"/opt/python/(\d+\.\d+)\b", text)))

    assert baked == sorted(python_versions), (
        f"image bakes Python {baked}, supported-versions.json wants {sorted(python_versions)}"
    )


def test_php_selection_is_available_as_alternatives() -> None:
    """Every PHP matrix leg selects its version at job start; without the alternatives
    entry a leg would silently grade under whichever `php` the image defaulted to."""
    text = _read(BASE_DOCKERFILE)
    assert "update-alternatives" in text and "--install /usr/bin/php" in text, (
        "the image must register each baked PHP under the `php` alternative"
    )


def test_vm_image_is_built_on_the_base_image_at_the_same_version() -> None:
    """Two independently-pinned toolchains would let the VM legs grade under a different
    ShellCheck/PHP than the non-VM legs."""
    version = _read(VERSION_FILE).strip()
    bases = _stage_bases(_read(VM_DOCKERFILE))

    assert bases, "the VM Dockerfile has no resolvable base image"
    assert bases[0].endswith(f"/ci-runner:{version}"), (
        f"the VM image must build on ci-runner:{version}; its base resolves to {bases[0]!r}"
    )


def test_vm_image_carries_every_vm_workload_dependency() -> None:
    """Enumerated from the `apt-get install` lines of the VM workflows this image
    replaces (smoke-single, ui-tests, build-image, image-refresh, version-tracker)."""
    # The VM image is the base image plus its own layer, so a dependency satisfied by
    # either file is present in the built image.
    text = _read(VM_DOCKERFILE) + _read(BASE_DOCKERFILE)
    for package in ("qemu-system-x86", "qemu-utils", "dnsutils", "openssh-client", "rsync"):
        assert package in text, f"the VM image is missing {package}"
    assert "oras" in _read(VM_DOCKERFILE), "the VM image must bake oras (GHCR qcow2 pulls)"


def test_vm_image_bakes_chromium_against_the_pinned_playwright() -> None:
    """The browser binary is downloaded per Playwright version. Baking it from any list
    other than tests/smoke/requirements.txt — the one the smoke jobs install at runtime —
    would leave the job re-downloading a browser for a different version."""
    requirements_path = "tests/smoke/requirements.txt"
    assert re.search(r"^playwright==\S+$", _read(ROOT / requirements_path), re.MULTILINE), (
        f"{requirements_path} no longer pins playwright"
    )

    vm_dockerfile = _read(VM_DOCKERFILE)
    assert requirements_path in vm_dockerfile, (
        f"the VM image must install {requirements_path} itself, not a second copy of its pins"
    )
    assert re.search(r"playwright install .*chromium", vm_dockerfile), (
        "the VM image must bake the Chromium build, not just the Python bindings"
    )
    assert "PLAYWRIGHT_BROWSERS_PATH" in vm_dockerfile, (
        "the baked browser needs a fixed PLAYWRIGHT_BROWSERS_PATH or the runtime install "
        "looks for it under a per-user cache that does not exist in the job"
    )


def test_every_baked_python_package_is_pinned_exactly() -> None:
    """A range or bare name would let the lint/type verdict move between two runs of the
    same image tag — the exact failure mode baking the toolchain exists to remove."""
    for line in _read(DOCKER_DIR / "ci-requirements.txt").splitlines():
        requirement = line.split("#", 1)[0].strip()
        if not requirement:
            continue
        assert re.fullmatch(r"[A-Za-z0-9._-]+==[\w.]+", requirement), (
            f"baked requirement is not an exact pin: {requirement!r}"
        )


def test_baked_pins_match_their_own_sources_of_truth() -> None:
    """ruff and dnspython are pinned elsewhere in the repo for a reason (a lint-verdict
    pin and an import-time test dependency); the image must not fork either."""
    baked = _read(DOCKER_DIR / "ci-requirements.txt")

    ruff_in_workflow = re.search(r"pip install ruff==(\S+)", _read(ROOT / ".github/workflows/test.yml"))
    assert ruff_in_workflow, "test.yml no longer pins ruff"
    assert f"ruff=={ruff_in_workflow.group(1)}" in baked, (
        f"the image must bake ruff=={ruff_in_workflow.group(1)}, the version test.yml gates on"
    )

    dnspython = re.search(r"^dnspython==(\S+)$", _read(ROOT / "tests/smoke/requirements.txt"), re.MULTILINE)
    assert dnspython, "tests/smoke/requirements.txt no longer pins dnspython"
    assert f"dnspython=={dnspython.group(1)}" in baked, (
        f"the image must bake dnspython=={dnspython.group(1)} (issue #861 shard-splitter gate)"
    )


def test_image_version_is_an_integer_series() -> None:
    assert re.fullmatch(r"\d+", _read(VERSION_FILE).strip()), (
        "the image tag series is a bare integer, bumped on every .github/docker change"
    )


def test_publish_workflow_builds_and_pushes_both_images() -> None:
    workflow = _read(PUBLISH_WORKFLOW)
    for image in ("ci-runner", "ci-runner-vm"):
        assert image in workflow, f"the publish workflow never mentions {image}"
    assert "packages: write" in workflow, "pushing to GHCR needs packages: write"


def test_publish_workflow_refuses_to_overwrite_a_published_tag() -> None:
    """The image tag is what every workflow pins to. Re-pushing it under a changed
    Dockerfile would swap the toolchain of already-merged workflows with no diff — the
    push must fail and demand a VERSION bump instead."""
    workflow = _read(PUBLISH_WORKFLOW)
    assert "manifest fetch" in workflow or "manifest inspect" in workflow, (
        "the publish workflow must probe the registry for the tag before pushing"
    )
    assert re.search(r"bump.*VERSION", workflow, re.IGNORECASE), (
        "the overwrite guard must tell the reader to bump .github/docker/VERSION"
    )


def test_publish_workflow_only_pushes_from_the_release_branches() -> None:
    """A branch push that published the shared tag would hand every open PR a toolchain
    built from that branch's Dockerfile."""
    workflow = _read(PUBLISH_WORKFLOW)
    push_steps = [
        block
        for block in workflow.split("      - name: ")
        if "docker push" in block or "buildx build" in block and "--push" in block
    ]
    assert push_steps, "no push step found in the publish workflow"
    for step in push_steps:
        assert "github.ref" in step or "if:" in step, (
            f"the push step must be gated on the branch; step was:\n{step[:400]}"
        )
