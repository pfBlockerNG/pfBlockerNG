import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

SHELLCHECK_PIN = "v0.11.0"
SHELLSPEC_PIN = "0.28.1"
KCOV_PIN = "a39874f938ce13f7a65f253120d1ec946b349ffe"  # the commit tag v43 pointed at


def _workflow() -> str:
    return (ROOT / ".github/workflows/test.yml").read_text(encoding="utf-8")


def _contributing() -> str:
    return (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")


def _job(workflow: str, name: str, next_name: str) -> str:
    return workflow.split(f"\n  {name}:\n", 1)[1].split(f"\n  {next_name}:\n", 1)[0]


def test_ruff_ci_install_is_pinned() -> None:
    workflow = _workflow()
    ruff_job = _job(workflow, "ruff", "shellcheck")
    install_step = ruff_job.split("      - name: Install Ruff\n", 1)[1].split("\n      - name:", 1)[0].strip()
    ruff_installs = [line.strip() for line in ruff_job.splitlines() if "pip install" in line and "ruff" in line]

    assert install_step == "run: pip install ruff==0.16.0"
    assert ruff_installs == ["run: pip install ruff==0.16.0"]


def test_shellcheck_ci_install_is_pinned_to_a_verified_release_tarball() -> None:
    """The lint verdict must come from a named ShellCheck, not from whatever the runner
    image ships: ubuntu-24.04 preinstalls 0.9.0, so an apt install is a silent no-op."""
    shellcheck_job = _job(_workflow(), "shellcheck", "shell-tests")
    install_step = shellcheck_job.split("      - name: Install ShellCheck\n", 1)[1].split("\n      - name:", 1)[0]

    assert f"SHELLCHECK_VERSION: {SHELLCHECK_PIN}" in install_step, (
        f"the ShellCheck install must pin {SHELLCHECK_PIN}; step was:\n{install_step}"
    )
    assert re.search(r"SHELLCHECK_SHA256: [0-9a-f]{64}\b", install_step), (
        f"the pinned download must carry a SHA-256 to verify against; step was:\n{install_step}"
    )
    assert "sha256sum -c" in install_step, (
        f"the downloaded tarball must be checked against SHELLCHECK_SHA256; step was:\n{install_step}"
    )
    assert "apt-get install" not in install_step and "apt install" not in install_step, (
        f"apt would re-pin the gate to the runner image's ShellCheck; step was:\n{install_step}"
    )


def test_ci_shellcheck_pin_matches_the_documented_local_version() -> None:
    """CI and a clean local run must agree — 0.11.0 accepts constructs 0.9.0 rejects
    (`A && B || C` / SC2015, issue #2185), so a drift here reds CI after a green local run."""
    documented = re.findall(
        r"ShellCheck.{0,200}?\bv(\d+\.\d+\.\d+)\b",
        (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8"),
        re.DOTALL,
    )

    assert documented, "CONTRIBUTING.md must document the ShellCheck version contributors install locally"
    assert set(documented) == {SHELLCHECK_PIN.lstrip("v")}, (
        f"CONTRIBUTING.md documents ShellCheck {documented}, CI pins {SHELLCHECK_PIN}"
    )


def test_shellspec_ci_install_is_pinned_to_a_verified_release_asset() -> None:
    """The POSIX gate must run the shellspec whose bytes we pinned. A
    `/archive/refs/tags/` tarball is generated on demand from the tag, so it is not a
    stable artifact: a re-tag upstream changes what runs the suite and nothing notices
    (#2194). Same shape as the ShellCheck pin — release asset, fetched to a file, then
    `sha256sum -c` before anything is extracted."""
    install_step = (
        _job(_workflow(), "shell-tests", "php-syntax")
        .split("      - name: Install shellspec\n", 1)[1]
        .split("\n      - name:", 1)[0]
    )

    assert f"SHELLSPEC_VERSION: {SHELLSPEC_PIN}" in install_step, (
        f"the shellspec install must pin {SHELLSPEC_PIN}; step was:\n{install_step}"
    )
    assert re.search(r"SHELLSPEC_SHA256: [0-9a-f]{64}\b", install_step), (
        f"the pinned download must carry a SHA-256 to verify against; step was:\n{install_step}"
    )
    assert "sha256sum -c" in install_step, (
        f"the downloaded tarball must be checked against SHELLSPEC_SHA256; step was:\n{install_step}"
    )
    assert "/releases/download/" in install_step and "/archive/refs/tags/" not in install_step, (
        f"pin the uploaded release asset, not the on-demand tag archive; step was:\n{install_step}"
    )
    # A pipe into tar unpacks the bytes before (or instead of) checking them — the
    # verification has to gate the extraction, so the download must land in a file.
    assert not re.search(r"\|\s*tar\b", install_step), (
        f"fetch to a file and verify it before extracting, never pipe the download into tar; step was:\n{install_step}"
    )


def test_contributing_documents_the_shellspec_version_ci_pins() -> None:
    """A contributor whose local shellspec differs from the verified CI one gets a verdict
    CI will not reproduce, so the documented install names the pinned version (#2198)."""
    documented = re.findall(r"shellspec.{0,200}?\b(\d+\.\d+\.\d+)\b", _contributing(), re.DOTALL | re.IGNORECASE)

    assert documented, "CONTRIBUTING.md must document the shellspec version contributors install locally"
    assert set(documented) == {SHELLSPEC_PIN}, (
        f"CONTRIBUTING.md documents shellspec {documented}, CI pins {SHELLSPEC_PIN}"
    )


def test_kcov_ci_build_is_pinned_to_an_immutable_commit() -> None:
    """`--branch v43` resolves through a tag, which upstream can move: the coverage tool
    that gets built — and cached under the key below — would change silently (#2198)."""
    shell_tests_job = _job(_workflow(), "shell-tests", "php-syntax")
    build_step = shell_tests_job.split("      - name: Build kcov from source (cache miss)\n", 1)[1].split(
        "\n      - name:", 1
    )[0]

    assert f"KCOV_COMMIT: {KCOV_PIN}" in shell_tests_job, (
        f"the kcov build must pin the commit v43 resolves to; job was:\n{shell_tests_job}"
    )
    # A clone by tag is fine as long as what it produced is checked against the pin before
    # anything is built from it — the guard is the branch that fails, not the clone.
    assert re.search(r"^\s*\[ \"\$cloned\" = \"\$KCOV_COMMIT\" \] \|\|", build_step, re.MULTILINE), (
        f"the cloned tree must be asserted to be the pinned commit, with a branch that fails"
        f" the step when it is not; step was:\n{build_step}"
    )
    # Anchored on the build invocation, not a bare `cmake` — the apt-get line installs a
    # package by that name, and matching it would pass no matter where the check sits.
    assert build_step.index("rev-parse HEAD") < build_step.index("cmake -S kcov"), (
        f"verify the clone before building from it; step was:\n{build_step}"
    )

    keys = re.findall(r"^\s+key: (kcov-.+)$", shell_tests_job, re.MULTILINE)

    assert len(keys) == 2, f"expected a restore key and a save key for the kcov cache; found {keys}"
    for key in keys:
        assert "env.KCOV_COMMIT" in key, (
            f"a re-pinned kcov must roll the cache over, so the key carries the pin, not a tag name; key was: {key}"
        )


def test_shellspec_job_requires_jq_and_dash_instead_of_installing_them() -> None:
    """ubuntu-24.04 ships both and neither changes a verdict by version, but the suite
    pins dash as the test shell — its absence must fail the job, not fall back silently."""
    shell_tests_job = _job(_workflow(), "shell-tests", "php-syntax")

    assert not re.search(r"apt-get install[^\n]*\bdash\b", shell_tests_job), (
        "dash must be required and asserted present, not installed over whatever the image ships"
    )
    assert not re.search(r"apt-get install[^\n]*\bjq\b", shell_tests_job), (
        "jq must be required and asserted present, not installed over whatever the image ships"
    )
    # Scoped to the step that owns the guard, and matched on the guard's shape: a bare
    # substring search is satisfied by any incidental `command -v <tool>` — the shellspec
    # step resolves dash that way, and so does this step's own diagnostic line.
    require_step = shell_tests_job.split("      - name: Require jq and dash\n", 1)[1].split("\n      - name:", 1)[0]

    for tool in ("jq", "dash"):
        assert re.search(rf"^\s*command -v {tool} [^\n]*\|\|", require_step, re.MULTILINE), (
            f"{tool} must be asserted present, with a branch that fails the job when it is not;"
            f" step was:\n{require_step}"
        )
