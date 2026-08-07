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
import subprocess
from pathlib import Path

import pytest

from tests._workflow_steps import extract_step as _step
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


def _requirement_pins(requirements: str) -> set[str]:
    """The ``name==version`` pins a pip requirements file actually installs.

    Comments are stripped rather than searched: a substring test against the raw text
    would also match a commented-out pin, which pip never installs.
    """
    pins = set()
    for line in requirements.splitlines():
        pin = line.split("#", 1)[0].strip()
        if re.fullmatch(r"[A-Za-z0-9._-]+==[\w.]+", pin):
            pins.add(pin)
    return pins


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


# No module-level skip for a missing git/jq: only the two matrix tests need the reader,
# and _matrix_versions() skips itself when it cannot run.


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
            # Plain http:// for a FETCH is never acceptable: without TLS the bytes are
            # attacker-controllable in transit. Scoped to the fetch verbs so a URL merely
            # mentioned in a comment or string does not trip it.
            assert not re.search(r"\b(curl|wget|ADD)\b[^;|]*\bhttp://", block), (
                f"{dockerfile.name}: tool fetched over plain http://:\n{block[:400]}"
            )
            # ADD <url> cannot be checksum-verified in the same instruction, so it is banned.
            assert not (block.startswith("ADD ") and "://" in block), (
                f"{dockerfile.name}: ADD-from-URL cannot be verified; use RUN curl + sha256sum:\n{block[:400]}"
            )
            if not block.startswith("RUN ") or "https://" not in block:
                continue
            if re.search(r"git .*fetch .*[0-9a-f]{40}", block):
                continue  # a commit id IS the checksum: git cannot serve other bytes for it
            # No exception for the sury block: it downloads the signing key over https and
            # must verify it like any other download. An exemption there would let a future
            # edit drop the checksum while leaving an unused hash behind.
            assert "sha256sum -c" in block or "sha256sum --check" in block, (
                f"{dockerfile.name}: download is not checksum-verified:\n{block[:400]}"
            )


def test_the_sury_php_repository_key_is_pinned_by_checksum() -> None:
    """The PHP versions come from a third-party archive; an unverified key fetch means
    the whole PHP toolchain trusts whatever that URL served that morning."""
    text = _read(BASE_DOCKERFILE)
    assert "packages.sury.org" in text, "PHP 8.3/8.5 need the sury archive on Debian 13"
    key_block = next(b for b in _expanded_blocks(text) if "sury" in b and "apt.gpg" in b)
    digest = re.search(r"\b([0-9a-f]{64})\b", key_block)
    assert digest, f"the sury signing key must be pinned by SHA-256; block was:\n{key_block[:400]}"

    # The hash must be FED to sha256sum, not merely present: a leftover constant beside a
    # dropped verification would otherwise pass.
    assert re.search(rf"echo\s+\"?{digest.group(1)}\s+\S+\"?\s*\|\s*sha256sum (?:-c|--check)", key_block), (
        f"the pinned key digest must be piped into `sha256sum -c`; block was:\n{key_block[:400]}"
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


def test_image_self_checks_cannot_be_masked_by_a_pipeline() -> None:
    """A shell reports a pipeline's LAST exit status and POSIX sh has no `pipefail`, so
    `tool --version | head -n1` succeeds even when the tool is absent. A self-check built
    that way is unfailable — the whole point of these checks is that they fail."""
    for dockerfile in (BASE_DOCKERFILE, VM_DOCKERFILE):
        checks = [b for b in _expanded_blocks(_read(dockerfile)) if "--version" in b or "-v;" in b]
        for block in checks:
            if not block.startswith("RUN set -eu"):
                continue
            masked = re.findall(r"[\w./-]+ +--?[Vv](?:ersion)?[^;|]*\| *(head|tail|sed|cut|awk)", block)
            assert not masked, (
                f"{dockerfile.name}: self-check pipes a version probe into {masked}, "
                f"which swallows the probe's exit status:\n{block[:400]}"
            )


def test_the_base_image_carries_the_github_cli() -> None:
    """Twelve workflows shell out to `gh`. It is preinstalled on the GitHub-hosted runner
    images and absent from a container, so migrating those jobs (#2215) without it would
    fail every one of them at the first `gh api` call."""
    text = _read(BASE_DOCKERFILE)
    declared = re.search(r"ARG GH_VERSION=(\d+\.\d+\.\d+)", text)
    assert declared, "the GitHub CLI version must be declared as an ARG"

    # Bind the declared version to the artifact actually downloaded. Asserting only that
    # the ARG exists would still pass on a Dockerfile that fetches /latest/ and ignores it.
    install = next(b for b in _expanded_blocks(text) if "cli/cli/releases/download" in b)
    assert f"v{declared.group(1)}/gh_{declared.group(1)}_linux_amd64.tar.gz" in install, (
        f"the download must use the declared GH_VERSION; block was:\n{install[:400]}"
    )
    assert "sha256sum -c" in install, "the gh download must be checksum-verified"
    assert "/usr/local/bin/gh" in install, "gh must land on PATH as /usr/local/bin/gh"


def test_baked_python_toolchain_covers_the_benchmarks_job() -> None:
    """ci-requirements.txt claims to carry every package the non-VM jobs install. The
    manual `benchmarks` job installs benchmarks/requirements.txt, so those pins are part
    of that claim — and must not drift from their source file."""
    # Compare parsed pins, not substrings: `pin in text` also matches a COMMENTED-OUT pin
    # or one embedded in prose, so the guard would pass on a package that is not installed.
    baked = _requirement_pins(_read(DOCKER_DIR / "ci-requirements.txt"))
    wanted = _requirement_pins(_read(ROOT / "benchmarks/requirements.txt"))

    assert wanted, "benchmarks/requirements.txt has no pins to check against"
    missing = wanted - baked
    assert not missing, f"the image must bake the benchmarks pins {sorted(missing)}"


def test_the_vm_image_chromium_check_actually_launches_the_browser() -> None:
    """`chromium.executable_path` is a plain string getter — it returns a path whether or
    not a browser is installed there, so a self-check built on it passes on an image with
    no Chromium at all. The check must launch and render."""
    checker = _read(DOCKER_DIR / "check-chromium.py")
    assert "chromium.launch" in checker, "the check must launch Chromium, not just path it"
    assert "set_content" in checker and "text_content" in checker, (
        "the check must render and read back, so a browser that starts and dies fails it"
    )
    assert "is_file()" in checker, "the check must confirm the executable exists on disk"
    assert "check-chromium.py" in _read(VM_DOCKERFILE), "the VM image build must actually run the Chromium check"


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


def test_publish_workflow_pushes_exactly_the_two_images_it_builds() -> None:
    """An image name can survive in the build step with its `docker push` deleted, so
    naming proves nothing — assert the commands themselves."""
    workflow = _read(PUBLISH_WORKFLOW)
    assert "packages: write" in workflow, "pushing to GHCR needs packages: write"

    for image in ("ci-runner", "ci-runner-vm"):
        assert re.search(rf'docker push "\$\{{IMAGE_REPO\}}/{image}:\$\{{TAG\}}"', workflow), (
            f"the workflow must push {image} at the pinned tag"
        )
        assert re.search(rf'--tag "\$\{{IMAGE_REPO\}}/{image}:\$\{{TAG\}}"', workflow), (
            f"the workflow must build {image} at the pinned tag"
        )

    pushes = re.findall(r"docker push \S+", workflow)
    assert len(pushes) == 2, f"expected exactly two pushes (one per image), found: {pushes}"


def test_publish_workflow_refuses_to_overwrite_a_published_tag() -> None:
    """The image tag is what every workflow pins to. Re-pushing it under a changed
    Dockerfile would swap the toolchain of already-merged workflows with no diff — the
    push must fail and demand a VERSION bump instead."""
    step = _step(_read(PUBLISH_WORKFLOW), "Refuse to overwrite a published tag")
    # Strip comment lines: the rationale comment names the very things being asserted, so
    # matching the whole step passed even when the body was reverted to the fail-open
    # `docker manifest inspect` implementation this guard exists to keep out.
    guard = "\n".join(ln for ln in step.splitlines() if not ln.lstrip().startswith("#"))

    assert "docker manifest inspect" not in guard, (
        "docker manifest inspect exits 1 for BOTH a missing tag and an auth/network "
        "failure, so it cannot tell 'free' from 'unknown' and fails OPEN"
    )
    assert "%{http_code}" in guard, "the guard must branch on an HTTP status, not an exit code"
    for status in ("404", "200"):
        assert status in guard, f"the guard must handle HTTP {status} explicitly"
    # Both images, not just the first: a clash on either is a clash.
    assert "for image in ci-runner ci-runner-vm" in guard, f"the guard must probe BOTH images; step was:\n{guard}"
    assert "exit 1" in guard, f"a detected clash must fail the job; step was:\n{guard}"
    assert re.search(r"bump .*VERSION", guard, re.IGNORECASE), (
        "the guard must tell the reader to bump .github/docker/VERSION"
    )


def test_publish_workflow_publishes_only_from_devel_and_main() -> None:
    """A pull-request or feature-branch publish would hand every other open PR a
    toolchain built from that branch, so the gate is asserted exactly, not just present."""
    workflow = _read(PUBLISH_WORKFLOW)
    decision = _step(workflow, "Decide whether this run publishes")

    assert '"${{ github.event_name }}" != "pull_request"' in decision, (
        f"a pull_request run must never publish; step was:\n{decision}"
    )
    branches = re.findall(r'"\$\{\{ github\.ref \}\}" = "refs/heads/(\w+)"', decision)
    assert sorted(branches) == ["devel", "main"], f"publishing must be limited to devel and main, found {branches}"

    # Every step that can mutate the registry hangs off that one decision, so there is a
    # single place where the branch policy lives.
    for step_name in ("Log in to GHCR", "Refuse to overwrite a published tag", "Push both images"):
        step = _step(workflow, step_name)
        assert "if: steps.publish.outputs.enabled == 'true'" in step, (
            f"{step_name!r} must be gated on the publish decision; step was:\n{step}"
        )


def test_publish_workflow_checks_for_a_clash_before_it_pushes() -> None:
    """Order is the whole guarantee: a probe that ran AFTER the push would report the tag
    this very run just wrote."""
    workflow = _read(PUBLISH_WORKFLOW)
    assert workflow.index("- name: Refuse to overwrite a published tag") < workflow.index("- name: Push both images"), (
        "the overwrite guard must run before the push step"
    )
