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
import os
import re
import subprocess
import tempfile
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


# The architectures the images are published for. A tool gaining a third would have to
# gain a pin for it here too — which is the point: this list is what makes "we forgot an
# architecture" a test failure instead of a broken image someone finds at `docker run`.
PUBLISHED_ARCHES = ("amd64", "arm64")


def test_every_prebuilt_binary_is_pinned_for_every_published_architecture() -> None:
    """A download that varies by architecture needs one checksum PER architecture.

    Upstream ships a different tarball per arch, so a single hash can only ever verify
    one of them. Before the images went multi-arch (#2256) that was invisible: the URL
    said `amd64` and the one pin matched it. The failure mode this guards is a tool being
    made arch-aware in the URL while keeping a single pin — the arm64 build would then
    either fail the checksum or, worse, a `|| true` somewhere would let an unverified
    binary through.

    Scoped to blocks that actually select on TARGETARCH: an arch-independent artifact
    (composer's .phar, the shellspec shell distribution, the sury signing key) legitimately
    has exactly one hash, and demanding two of it would be noise.
    """
    for dockerfile in (BASE_DOCKERFILE, VM_DOCKERFILE):
        for block in _expanded_blocks(_read(dockerfile)):
            if not block.startswith("RUN ") or "https://" not in block:
                continue
            if "TARGETARCH" not in block:
                continue
            # The URL must actually vary by architecture — a block that reads TARGETARCH
            # only to pick a hash, while still fetching one fixed arch's tarball, would
            # install an x86 binary on arm64 and pass every other check in this file.
            #
            # Derived from the URL itself, never from a variable NAME: an earlier version
            # accepted any block merely containing "_arch", which the ShellCheck block
            # satisfies through its `sc_arch` variable no matter what the URL fetches.
            url = re.search(r"https://\S+", block)
            assert url, f"{dockerfile.name}: arch-selecting block with no URL:\n{block[:400]}"
            interpolated = re.findall(r"\$\{(\w+)\}", url.group(0))
            varies = "TARGETARCH" in interpolated or any(
                re.search(rf"\b{arch}\)[^;]*\b{var}=", block) for var in interpolated for arch in PUBLISHED_ARCHES
            )
            assert varies, (
                f"{dockerfile.name}: block selects on TARGETARCH but its URL does not vary "
                f"by architecture (interpolates {interpolated}):\n{block[:400]}"
            )
            for arch in PUBLISHED_ARCHES:
                assert re.search(rf"\b{arch}\)", block), (
                    f"{dockerfile.name}: no branch for {arch} in an arch-selecting download:\n{block[:400]}"
                )
            # Two arches, two DIFFERENT hashes. Copy-pasting one pin into both branches
            # is the mistake that looks right in review and fails only on the second arch.
            hashes = re.findall(r"\b([0-9a-f]{64})\b", block)
            assert len(hashes) >= len(PUBLISHED_ARCHES), (
                f"{dockerfile.name}: expected one pin per architecture, found {len(hashes)}:\n{block[:400]}"
            )
            assert len(set(hashes)) == len(hashes), (
                f"{dockerfile.name}: the same checksum is pinned for more than one "
                f"architecture, so at least one of them is wrong:\n{block[:400]}"
            )
            # An architecture nobody pinned must stop the build, not fall through to a
            # default that installs the wrong binary.
            assert re.search(r"\*\)\s*echo[^;]*>&2;\s*exit 1", block), (
                f"{dockerfile.name}: an unpinned TARGETARCH must fail the build:\n{block[:400]}"
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
    assert f"v{declared.group(1)}/gh_{declared.group(1)}_linux_${{TARGETARCH}}.tar.gz" in install, (
        f"the download must use the declared GH_VERSION; block was:\n{install[:400]}"
    )
    assert "sha256sum -c" in install, "the gh download must be checksum-verified"
    assert "/usr/local/bin/gh" in install, "gh must land on PATH as /usr/local/bin/gh"


def test_the_base_image_carries_actionlint() -> None:
    """The test.yml actionlint job gates workflow-file validity (issue #2231's
    duplicate-key class). Baking the binary retires that job's per-run download
    (#2232) — and the image pin MUST stay locked to the version the workflow
    names, so the job's swap to the baked binary cannot silently change the
    lint verdict."""
    text = _read(BASE_DOCKERFILE)
    declared = re.search(r"ARG ACTIONLINT_VERSION=(\d+\.\d+\.\d+)", text)
    assert declared, "the actionlint version must be declared as an ARG"

    install = next(b for b in _expanded_blocks(text) if "rhysd/actionlint/releases/download" in b)
    assert f"v{declared.group(1)}/actionlint_{declared.group(1)}_linux_${{TARGETARCH}}.tar.gz" in install, (
        f"the download must use the declared ACTIONLINT_VERSION; block was:\n{install[:400]}"
    )
    assert "sha256sum -c" in install, "the actionlint download must be checksum-verified"
    assert "/usr/local/bin/actionlint" in install, "actionlint must land on PATH"

    workflow = _read(ROOT / ".github/workflows/test.yml")
    wf_version = re.search(r"ACTIONLINT_VERSION: (\d+\.\d+\.\d+)", workflow)
    if wf_version:  # the interim download step; PR-B removes it and this branch with it
        assert wf_version.group(1) == declared.group(1), (
            "test.yml's interim actionlint download and the baked binary must pin the "
            f"same version; workflow={wf_version.group(1)} image={declared.group(1)}"
        )


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
    """dnspython is pinned by tests/smoke/requirements.txt as an import-time test
    dependency (issue #861); the image must not fork it. ruff no longer has a second home:
    the workflow installs nothing, so ci-requirements.txt IS the source of truth."""
    baked = _read(DOCKER_DIR / "ci-requirements.txt")

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
    naming proves nothing — assert the commands themselves.

    Since #2256 each image is built and pushed once PER ARCHITECTURE under a suffixed
    tag, and the tag every other workflow pins is assembled from those by the publish
    job. Both halves are asserted: an arch that is built but never pushed, or pushed but
    never folded into the manifest list, leaves the final tag resolving for one
    architecture only — which fails at `docker run` on the other, long after this
    workflow reported success.
    """
    workflow = _read(PUBLISH_WORKFLOW)
    assert "packages: write" in workflow, "pushing to GHCR needs packages: write"

    for image in ("ci-runner", "ci-runner-vm"):
        assert re.search(rf'--tag "\$\{{IMAGE_REPO\}}/{image}:\$\{{TAG\}}-\$\{{ARCH\}}"', workflow), (
            f"the workflow must build {image} at the pinned tag, per architecture"
        )
        assert re.search(rf'docker push "\$\{{IMAGE_REPO\}}/{image}:\$\{{TAG\}}-\$\{{ARCH\}}"', workflow), (
            f"the workflow must push {image} at the pinned tag, per architecture"
        )

    pushes = re.findall(r"docker push \S+", workflow)
    assert len(pushes) == 2, f"expected exactly two pushes (one per image), found: {pushes}"

    # The manifest list is what the rest of the repo pins, and it must be composed from
    # every published architecture — not just whichever one ran last.
    merge = _step(workflow, "Create the manifest lists")
    assert "imagetools create" in merge, "the final tag must be assembled with imagetools create"
    assert re.search(r'--tag "\$\{IMAGE_REPO\}/\$\{image\}:\$\{TAG\}"', merge), (
        f"the manifest list must be tagged at the bare pinned tag; step was:\n{merge}"
    )
    for arch in PUBLISHED_ARCHES:
        assert f"${{TAG}}-{arch}" in merge, f"the manifest list must include the {arch} image; step was:\n{merge}"


def test_publish_workflow_builds_every_architecture_natively() -> None:
    """Each architecture builds on a runner of that architecture (#2256).

    Not a performance preference: the in-image self-checks and the toolchain report both
    EXECUTE the binaries they are checking, so a cross-build under emulation would either
    need QEMU in the loop or stop proving the arm64 binaries actually run. It is also the
    difference between a routine refresh and a tens-of-minutes job, because kcov is
    compiled from source.
    """
    workflow = _read(PUBLISH_WORKFLOW)
    runners = dict(re.findall(r"- arch: (\S+)\n\s+runner: (\S+)", workflow))
    assert set(runners) == set(PUBLISHED_ARCHES), (
        f"the build matrix must cover exactly {PUBLISHED_ARCHES}, got {sorted(runners)}"
    )
    assert "arm" in runners["arm64"], f"arm64 must build on an arm64 runner, not {runners['arm64']!r} under emulation"
    assert "arm" not in runners["amd64"], f"amd64 must build on an x86 runner, got {runners['amd64']!r}"


def test_the_published_index_is_verified_to_carry_every_architecture() -> None:
    """A tag that resolves for only one architecture must fail the run that made it.

    This is the failure the whole restructure invites: `fail-fast: false` lets one matrix
    leg push while the other dies, and `imagetools create` will happily assemble an index
    from whatever it is given. Without this step the workflow reports success and the
    breakage surfaces later, on the other architecture, at `docker run`.

    The step shipped with no coverage at all — deleting it, or dropping one architecture
    from it, left the suite green.
    """
    step = _step(_read(PUBLISH_WORKFLOW), "Verify both architectures are in the published index")
    body = "\n".join(ln for ln in step.splitlines() if not ln.lstrip().startswith("#"))

    for arch in PUBLISHED_ARCHES:
        assert re.search(rf'\*" {arch} "\*\)', body), f"the index check must require {arch}; step was:\n{body}"
        assert re.search(rf"{arch} missing", body), f"a missing {arch} must be named in the failure; step was:\n{body}"
    assert body.count("exit 1") >= len(PUBLISHED_ARCHES), (
        f"each missing architecture must fail the job; step was:\n{body}"
    )
    # Parsed as a document, not pattern-matched: a greedy line regex over the raw index
    # collapses to one architecture whenever the registry serves it compact.
    assert "jq -r" in body, f"the index must be parsed with jq, not a regex over raw JSON:\n{body}"


def test_published_images_are_checked_for_public_pullability_without_credentials() -> None:
    """The runner images must be pullable by someone with no token, and the check that
    proves it must not authenticate.

    Package visibility is per-package, UI-only (no REST endpoint), and a newly created
    package defaults to PRIVATE — so this is a state the project can silently fall into,
    and every job inside the org keeps passing when it does, because they all
    authenticate. The ones that break are fresh clones and FORK pull requests, whose
    GITHUB_TOKEN cannot read the org's private packages; they fail at `docker pull` with
    `manifest unknown`, nowhere near the cause.

    The vacuity trap this pins: adding credentials to the check would make it pass on a
    private package, which is precisely the case it exists to catch. So the step must
    carry no Authorization header of its own and no token from the job environment —
    the only bearer allowed is the one the REGISTRY hands back anonymously.
    """
    step = _step(_read(PUBLISH_WORKFLOW), "Verify the published tags are pullable ANONYMOUSLY")
    body = "\n".join(ln for ln in step.splitlines() if not ln.lstrip().startswith("#"))

    # It must ask the registry for an anonymous pull token, and act on the answer.
    assert "ghcr.io/token?service=ghcr.io&scope=repository:" in body, (
        f"the check must request an anonymous pull token; step was:\n{body}"
    )
    assert "manifests/" in body, f"the check must fetch a manifest, not just a token; step was:\n{body}"
    assert "exit 1" in body, f"a private package must fail the job; step was:\n{body}"

    # No credential may reach it: GHCR issues an anonymous token only for a PUBLIC
    # package, so any token from the job would mask exactly the failure being hunted.
    for leak in ("GHCR_TOKEN", "secrets.GITHUB_TOKEN", "github.token", "docker login"):
        assert leak not in step, f"the anonymous pullability check must not authenticate, found {leak!r}:\n{step}"

    # The one Authorization header allowed is the registry's own anonymous bearer.
    auth_headers = re.findall(r"Authorization: ([^\"']+)", body)
    assert auth_headers == ["Bearer ${bearer}"], (
        f"the only Authorization allowed is the anonymously-obtained bearer, found {auth_headers}"
    )


def _guard_script() -> str:
    """The overwrite guard's `run:` body, dedented so it can be executed."""
    step = _step(_read(PUBLISH_WORKFLOW), "Refuse to overwrite a published tag")
    body = step.split("run: |\n", 1)[1]
    lines = body.splitlines()
    indent = len(lines[0]) - len(lines[0].lstrip())
    out = []
    for line in lines:
        if line.strip() and not line.startswith(" " * indent):
            break  # dedented past the block: the next YAML key
        out.append(line[indent:])
    return "\n".join(out)


def _run_guard(
    tmp_path: Path,
    manifest_status: str,
    *,
    curl_fails: bool = False,
    marker_status: str | None = None,
    arch_status: str | None = None,
    vm_status: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """Execute the guard with a stubbed curl.

    `manifest_status` answers the bare series tag, `arch_status` the per-architecture
    tags, `marker_status` the build-inputs marker (each defaulting to the bare tag's),
    and `vm_status` overrides EVERY ref of the second image.

    Answering per ref, and per image, is what makes the interesting cases expressible
    at all: one status for every request cannot distinguish "the series carries this
    build's marker" (a re-run — nothing to do) from "it does not" (the overwrite this
    guard refuses), cannot tell a loop over three refs from a loop over one, and cannot
    reach the half-published states where one image owns the series and the other does
    not — which is precisely where an overwrite hides.
    """
    marker_status = manifest_status if marker_status is None else marker_status
    arch_status = manifest_status if arch_status is None else arch_status
    stub = tmp_path / "bin"
    stub.mkdir(exist_ok=True)
    (stub / "curl").write_text(
        "#!/bin/sh\n"
        'for a in "$@"; do case "$a" in *"/token?"*) printf \'{"token":"stub"}\'; exit 0;; esac; done\n'
        f"{'exit 7' if curl_fails else ''}\n"
        # The second image is a distinct path segment, so it can be answered wholesale
        # before any ref matching — that is the only way to express a partial publish.
        + (
            f'for a in "$@"; do case "$a" in *"/ci-runner-vm/"*) printf \'%s\' \'{vm_status}\'; exit 0;; esac; done\n'
            if vm_status is not None
            else ""
        )
        # Order matters: the marker ref also ends in a suffix, so match it first.
        + 'for a in "$@"; do case "$a" in *"-inputs-"*)'
        f" printf '%s' '{marker_status}'; exit 0;; esac; done\n"
        'for a in "$@"; do case "$a" in *"-amd64"|*"-arm64")'
        f" printf '%s' '{arch_status}'; exit 0;; esac; done\n"
        f"printf '%s' '{manifest_status}'\n"
    )
    (stub / "curl").chmod(0o755)

    return subprocess.run(
        ["sh", "-c", _guard_script()],
        capture_output=True,
        text=True,
        env={
            "PATH": f"{stub}:/usr/bin:/bin",
            "IMAGE_REPO": "ghcr.io/pfblockerng",
            "TAG": "1",
            "MARKER": "inputs-deadbeefdeadbeef",
            "WANT_PUBLISH": "true",
            "GHCR_TOKEN": "stub-token",
            "GITHUB_OUTPUT": str(tmp_path / "gh_out"),
        },
        check=False,
    )


def _guard_publish_output(tmp_path: Path) -> str:
    """The `publish=` the guard wrote to GITHUB_OUTPUT, or '' if it wrote none."""
    out = tmp_path / "gh_out"
    text = out.read_text(encoding="utf-8") if out.exists() else ""
    match = re.search(r"^publish=(\S+)$", text, re.MULTILINE)
    return match.group(1) if match else ""


def test_the_overwrite_guard_permits_a_push_only_when_the_tag_is_absent(tmp_path: Path) -> None:
    """EXECUTED, not grepped. A text assertion cannot tell this guard from a fail-open
    rewrite: two different fail-open bodies were shown to satisfy the previous version of
    this test. Only running it against known HTTP answers pins the behaviour."""
    proc = _run_guard(tmp_path, "404")
    assert proc.returncode == 0, f"HTTP 404 means the tag is free; the push must proceed\n{proc.stderr}"
    assert _guard_publish_output(tmp_path) == "true", "a free series must leave publishing enabled"


def test_the_overwrite_guard_treats_its_own_republish_as_a_no_op(tmp_path: Path) -> None:
    """A series already published FROM THESE EXACT INPUTS is nothing to push, not a clash.

    Two ordinary flows land here and both were unrecoverable while the check was
    existence-only: re-running a publish, and merging the branch a dispatch published
    from — the latter guaranteed, because the dispatch escape hatch exists so the series
    can land before the PR that pins it. The run must go green having pushed nothing.
    """
    proc = _run_guard(tmp_path, "200", marker_status="200")
    assert proc.returncode == 0, f"an identical republish must not fail the run\n{proc.stdout}\n{proc.stderr}"
    assert _guard_publish_output(tmp_path) == "false", f"publishing must be switched OFF, not left on:\n{proc.stdout}"


def test_the_overwrite_guard_blocks_on_anything_that_is_not_a_clean_absence(tmp_path: Path) -> None:
    """200 without this build's marker is a clash. 403/401 mean we could not read the tag
    (wrong scope, revoked credential); 000 means the request itself failed. None of those
    prove the tag is free, and pushing on them is exactly the fail-open mode this guard
    exists to prevent."""
    # The series exists but was built from DIFFERENT inputs — the overwrite case.
    proc = _run_guard(tmp_path, "200", marker_status="404")
    assert proc.returncode != 0, "a published series without this build's marker must be refused"
    assert "DIFFERENT inputs" in proc.stdout, f"the refusal must say why:\n{proc.stdout}"

    for status in ("401", "403", "500", "502"):
        assert _run_guard(tmp_path, status).returncode != 0, (
            f"HTTP {status} does not prove the tag is free; the guard must refuse to push"
        )
        # An unreadable MARKER is equally undeterminable: treating it as absent would turn
        # a re-run into a clash, and treating it as present would wave an overwrite through.
        # The series is left FREE here on purpose — with it published, the clash path
        # refuses on its own and this assertion would pass without the guard ever
        # consulting the marker status at all.
        assert _run_guard(tmp_path, "404", marker_status=status).returncode != 0, (
            f"an unreadable marker (HTTP {status}) must refuse, not guess"
        )

    assert _run_guard(tmp_path, "000", curl_fails=True).returncode != 0, (
        "a failed request must refuse the push, not treat the tag as free"
    )


def test_the_overwrite_guard_catches_a_half_published_series(tmp_path: Path) -> None:
    """A leftover per-architecture tag is a clash, even when the bare series tag is free.

    `fail-fast: false` exists so one architecture's failure does not cancel the other, so
    one leg CAN push `:N-amd64` and the other die before `:N-arm64` — leaving a partial
    series and no manifest list. If the guard only looked at the bare tag it would call
    that "free" and let the next run complete somebody else's half-finished series with
    freshly built bytes, which is precisely the silent-mismatch the immutability rule
    exists to prevent.
    """
    proc = _run_guard(tmp_path, "404", arch_status="200", marker_status="404")
    assert proc.returncode != 0, f"a leftover per-arch tag must be refused even with the bare tag free\n{proc.stdout}"
    assert "-amd64" in proc.stdout or "-arm64" in proc.stdout, (
        f"the refusal must name the per-architecture tag it found:\n{proc.stdout}"
    )


def test_the_overwrite_guard_refuses_a_partly_published_series(tmp_path: Path) -> None:
    """One image owning the series while the other does not is NOT a no-op.

    The marker excuses tags that this exact build published, so a state where only one
    image carries it reads as "no clash" — and if that fell through to publishing, the
    run would re-push the image that already exists, replacing published bytes under a
    tag ~60 workflow references resolve. The Dockerfiles pin no apt versions, so those
    bytes are a different toolchain, which is the silent-swap the series exists to stop.

    Reachable two ways: the publish loop completing one image and failing on the other,
    and deleting one package to fix its visibility (what the gate below tells you to do).
    """
    for vm in ("404", "200"):
        published, missing = ("ci-runner", "ci-runner-vm") if vm == "404" else ("ci-runner-vm", "ci-runner")
        proc = _run_guard(tmp_path, "200" if vm == "404" else "404", vm_status=vm)
        assert proc.returncode != 0, (
            f"{published} owns the series and {missing} does not — publishing would "
            f"overwrite {published}, so the guard must refuse:\n{proc.stdout}"
        )
        assert _guard_publish_output(tmp_path) != "true", "a partial publish must never enable the push"


def test_the_overwrite_guard_needs_the_series_itself_not_just_its_marker(tmp_path: Path) -> None:
    """A marker with no series behind it must not read as "already published".

    Keyed on the marker alone, this state is a permanent green no-op: the run reports
    success, pushes nothing, and every later run decides the same, so the series never
    gets published at all. The guard must key on the series being THERE as well.
    """
    proc = _run_guard(tmp_path, "404", marker_status="200")
    assert proc.returncode != 0, f"a marker without the series behind it must not be a no-op:\n{proc.stdout}"


def test_the_marker_is_produced_as_well_as_consumed() -> None:
    """The guard is executed against stubs, which only pins the READING half.

    Every link in the writing half was mutable in silence: dropping the marker `--tag`,
    dropping either preflight output, or deriving the marker from a constant all left the
    suite green while breaking the mechanism — the worst of them (reverting preflight's
    `publish` output to the branch decision) turning the guard's `publish=false` into a
    real overwrite on every merge-after-dispatch, i.e. strictly worse than the bug it fixes.
    """
    workflow = _read(PUBLISH_WORKFLOW)

    # The consumers read `needs.preflight.outputs.*`, so the job must export the guard's
    # decision — not the branch decision it narrows.
    assert re.search(r"publish:\s*\$\{\{\s*steps\.guard\.outputs\.publish\s*\}\}", workflow), (
        "preflight must export the GUARD's decision as `publish`; exporting the branch "
        "decision would let the publish job push a series the guard just declared present"
    )
    assert re.search(r"marker:\s*\$\{\{\s*steps\.version\.outputs\.marker\s*\}\}", workflow), (
        "preflight must export `marker`; unset, the publish job tags `:${TAG}-` and the "
        "guard looks for a marker that will never exist"
    )

    # Derived from git, not from a constant or a timestamp: a constant would make every
    # build of a series share one marker, so a real Dockerfile change would read as
    # "already published from these exact inputs" and be silently dropped.
    version_step = _step(workflow, "Read the image tag series")
    assert 'git rev-parse "HEAD:.github/docker"' in version_step, "the marker must hash the Dockerfile tree"
    assert "tests/smoke/requirements.txt" in version_step, "the marker must cover the requirement files COPYed in"

    # Written in the SAME imagetools call that creates the series, so the two cannot
    # diverge: no state exists where the series is published without its marker.
    merge = _step(workflow, "Create the manifest lists")
    assert re.search(r'--tag "\$\{IMAGE_REPO\}/\$\{image\}:\$\{TAG\}-\$\{MARKER\}"', merge), (
        f"the marker tag must be pushed alongside the series tag:\n{merge}"
    )


def test_the_preflight_visibility_probe_is_uncredentialed() -> None:
    """The probe asks whether a STRANGER can pull, so a credential makes it vacuous.

    More exposed than its post-publish twin: `GH_TOKEN` is legitimately in this step's
    env for the `gh api` existence check, so a credential is right there to be reached
    for, and adding one to the curl makes the step pass on the private package it exists
    to catch.
    """
    step = _step(_read(PUBLISH_WORKFLOW), "Refuse to publish into a package nobody can pull")
    probe = "\n".join(ln for ln in step.splitlines() if "curl" in ln or "ghcr.io/token" in ln)
    assert probe, "the preflight probe must ask the registry for an anonymous token"
    assert "-u " not in probe and "Authorization" not in probe and "GH_TOKEN" not in probe, (
        f"the anonymous-pull probe must carry no credentials:\n{probe}"
    )

    # It must also run on every publishing-branch run, not only when this run pushes:
    # gating it on the guard means a series is checked once, at birth, and never again.
    assert re.search(r"if:\s*steps\.publish\.outputs\.enabled == 'true'", step), (
        f"the visibility probe must be gated on the BRANCH decision, not the push decision:\n{step[:400]}"
    )


def _run_visibility_probe(
    tmp_path: Path,
    *,
    token: str,
    gh_rc: int,
    gh_err: str = "",
    will_push: str = "true",
) -> subprocess.CompletedProcess[str]:
    """Execute the visibility probe with `curl` and `gh` stubbed.

    `token` is what the registry's token endpoint returns ('' = refused, i.e. the package
    is private OR absent), and `gh_rc`/`gh_err` are how the existence check answers.
    """
    step = _step(_read(PUBLISH_WORKFLOW), "Refuse to publish into a package nobody can pull")
    body = step.split("run: |\n", 1)[1]
    lines = body.splitlines()
    indent = len(lines[0]) - len(lines[0].lstrip())
    out = []
    for line in lines:
        if line.strip() and not line.startswith(" " * indent):
            break
        out.append(line[indent:])

    stub = tmp_path / "bin"
    stub.mkdir(exist_ok=True)
    (stub / "curl").write_text(f"#!/bin/sh\nprintf '%s' '{{\"token\":\"{token}\"}}'\n")
    (stub / "gh").write_text(f"#!/bin/sh\nprintf '%s\\n' '{gh_err}' >&2\nexit {gh_rc}\n")
    for name in ("curl", "gh"):
        (stub / name).chmod(0o755)

    return subprocess.run(
        ["sh", "-c", "\n".join(out)],
        capture_output=True,
        text=True,
        env={
            "PATH": f"{stub}:/usr/bin:/bin",
            "IMAGE_REPO": "ghcr.io/pfblockerng",
            "WILL_PUSH": will_push,
            "GH_TOKEN": "stub-token",
        },
        check=False,
    )


def test_the_visibility_probe_refuses_when_it_cannot_prove_the_package_is_absent(tmp_path: Path) -> None:
    """A package that refuses an anonymous token is private OR absent, and only the API
    can say which. Every way of ASKING can also fail — 401, 403 (the likely answer for a
    job token against the org packages endpoint), a rate limit, a DNS error — and none of
    those prove absence. Guessing "absent" there is a silent fail-open on the single case
    this step exists to catch, which is worse than not having the step.
    """
    # The happy paths first, so the refusals below are not passing for a trivial reason.
    assert _run_visibility_probe(tmp_path, token="anon", gh_rc=1).returncode == 0, (
        "an anonymously readable package must pass"
    )
    absent = _run_visibility_probe(tmp_path, token="", gh_rc=1, gh_err="gh: Not Found (HTTP 404)")
    assert absent.returncode == 0, f"a package that does not exist yet is the first publish:\n{absent.stdout}"

    private = _run_visibility_probe(tmp_path, token="", gh_rc=0)
    assert private.returncode != 0, (
        f"a package that exists and refuses an anonymous token is private:\n{private.stdout}"
    )

    for err in (
        "gh: Resource not accessible by integration (HTTP 403)",
        "gh: Bad credentials (HTTP 401)",
        "gh: API rate limit exceeded (HTTP 429)",
        "dial tcp: lookup api.github.com: no such host",
    ):
        proc = _run_visibility_probe(tmp_path, token="", gh_rc=1, gh_err=err)
        assert proc.returncode != 0, (
            f"{err!r} does not prove the package is absent, so it must not be waved through:\n{proc.stdout}"
        )

    # ...but only the run that is about to push is FAILED by it. A no-op run reports the
    # condition and stays green: it is real, and it needs a human with UI access, but
    # blocking an unrelated merge on something this workflow cannot fix helps nobody.
    warned = _run_visibility_probe(tmp_path, token="", gh_rc=0, will_push="false")
    assert warned.returncode == 0, f"a run that publishes nothing must not be failed by it:\n{warned.stdout}"
    assert "::warning::" in warned.stdout, f"...but it must still say so, loudly:\n{warned.stdout}"


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


def _run_publish_decision(step: str, event: str, ref: str) -> str:
    """Execute the publish decision's `run:` body and return the `enabled=` it writes.

    The body is real shell wrapped around two GitHub expressions, so the expressions are
    substituted and the rest is run verbatim — no reimplementation of the policy here,
    which is the whole point: a test that restated the rule could agree with itself while
    disagreeing with the workflow.
    """
    body = step.split("run: |\n", 1)[1]
    lines = body.splitlines()
    indent = len(lines[0]) - len(lines[0].lstrip())
    script_lines = []
    for line in lines:
        if line.strip() and not line.startswith(" " * indent):
            break
        script_lines.append(line[indent:])
    script = "\n".join(script_lines)
    script = script.replace("${{ github.event_name }}", event).replace("${{ github.ref }}", ref)

    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "gh_output"
        out.touch()
        proc = subprocess.run(
            ["sh", "-c", script],
            capture_output=True,
            text=True,
            env={**os.environ, "GITHUB_OUTPUT": str(out)},
            check=False,
        )
        assert proc.returncode == 0, f"the decision script failed: {proc.stderr}"
        written = out.read_text(encoding="utf-8")
    match = re.search(r"^enabled=(\S+)$", written, re.MULTILINE)
    assert match, f"the decision must write an `enabled=` output; it wrote:\n{written!r}"
    return match.group(1)


def test_publish_workflow_publishes_only_from_devel_and_main() -> None:
    """A pull-request or feature-branch publish would hand every other open PR a
    toolchain built from that branch, so the gate is asserted exactly, not just present."""
    workflow = _read(PUBLISH_WORKFLOW)
    decision = _step(workflow, "Decide whether this run publishes")

    # EXECUTED, not grepped — the same standard the overwrite guard below is held to. The
    # policy gained a branch when a manual dispatch was allowed to publish a new series
    # (#2256), and a substring assertion cannot tell a correct truth table from one that
    # accidentally lets a pull_request through.
    for event, ref, expected in (
        # A pull request NEVER publishes, whatever it targets — that is the invariant
        # that stops one PR handing every other open PR a toolchain built from it.
        ("pull_request", "refs/heads/devel", "false"),
        ("pull_request", "refs/heads/main", "false"),
        ("pull_request", "refs/heads/issue/2256-example", "false"),
        # Pushes publish only from the two long-lived branches.
        ("push", "refs/heads/devel", "true"),
        ("push", "refs/heads/main", "true"),
        ("push", "refs/heads/issue/2256-example", "false"),
        # A manual dispatch may publish from any ref: a VERSION bump needs the new series
        # to exist before the PR pinning it can go green. Safe because a dispatch cannot
        # be provoked by a PR and the overwrite guard still refuses an existing tag.
        ("workflow_dispatch", "refs/heads/issue/2256-example", "true"),
        ("workflow_dispatch", "refs/heads/devel", "true"),
    ):
        assert _run_publish_decision(decision, event, ref) == expected, (
            f"event={event} ref={ref} must yield enabled={expected}"
        )

    # Every step that can MUTATE the registry hangs off that one decision, so there is a
    # single place where the branch policy lives. Since #2256 the decision is made once in
    # the preflight job and consumed by the others through `needs`, so which expression is
    # correct depends on where the step lives — but "gated on nothing" is wrong everywhere.
    same_job = "if: steps.guard.outputs.publish == 'true'"
    downstream = "if: needs.preflight.outputs.publish == 'true'"
    for step_name in ("Log in to GHCR", "Push this architecture"):
        step = _step(workflow, step_name)
        assert same_job in step or downstream in step, (
            f"{step_name!r} must be gated on the publish decision; step was:\n{step}"
        )

    # The visibility probe mutates nothing, so it is deliberately WIDER: it runs on every
    # publishing-branch run and reports what is published, because gating a package-level
    # fact on a tag-level decision would check a series once, at birth, and never again.
    # What stays gated is its VERDICT — it only fails the run that is about to push.
    probe = _step(workflow, "Refuse to publish into a package nobody can pull")
    assert "if: steps.publish.outputs.enabled == 'true'" in probe, (
        f"the visibility probe must run on every publishing-branch run; step was:\n{probe}"
    )
    assert "WILL_PUSH: ${{ steps.guard.outputs.publish }}" in probe, (
        f"the probe must consume the push decision to know whether to fail; step was:\n{probe}"
    )
    assert re.search(r'if \[ "\$WILL_PUSH" = .true. \]; then\n\s+echo "::error', probe), (
        f"a private package must be a hard error on the run that would push into it:\n{probe}"
    )

    # The overwrite guard is the one exception, and deliberately so: it CONSUMES the
    # branch decision and narrows it (an identical republish turns publishing off), so it
    # cannot also be gated by its own output. It must still honour the branch policy
    # rather than ignoring it — hence reading it, and refusing to run the probes at all
    # when this is not a publishing run.
    guard = _step(workflow, "Refuse to overwrite a published tag")
    assert "WANT_PUBLISH: ${{ steps.publish.outputs.enabled }}" in guard, (
        f"the guard must consume the branch decision; step was:\n{guard}"
    )
    assert re.search(r'if \[ "\$WANT_PUBLISH" != .true. \]', guard), (
        f"the guard must short-circuit when this run does not publish; step was:\n{guard}"
    )

    # The job that assembles and pushes the manifest list is gated as a whole, so a
    # pull-request run cannot create the tag even though its builds ran.
    assert re.search(r"publish:\n(?:.*\n)*?\s+if: needs\.preflight\.outputs\.publish == 'true'", workflow), (
        "the manifest-publishing job must itself be gated on the publish decision"
    )


def test_publish_workflow_checks_for_a_clash_before_it_pushes() -> None:
    """Order is the whole guarantee: a probe that ran AFTER the push would report the tag
    this very run just wrote.

    The guard and the pushes now live in different jobs, so file order alone no longer
    proves anything — the `needs` edge is what sequences them, and it is asserted here.
    """
    workflow = _read(PUBLISH_WORKFLOW)
    assert workflow.index("- name: Refuse to overwrite a published tag") < workflow.index(
        "- name: Push this architecture"
    ), "the overwrite guard must run before the push step"

    # The build job cannot start until preflight (which holds the guard) has passed, and
    # the manifest list cannot be created until every build has pushed its architecture.
    assert re.search(r"build:\n(?:.*\n)*?\s+needs: preflight\b", workflow), (
        "the per-architecture build must depend on the preflight guard"
    )
    assert re.search(r"publish:\n(?:.*\n)*?\s+needs: \[preflight, build\]", workflow), (
        "the manifest publish must depend on both the guard and every architecture build"
    )
