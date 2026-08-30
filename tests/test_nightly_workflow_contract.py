"""Static contract for the branch-independent Nightly workflow."""

import itertools
import json
import os
import subprocess
from pathlib import Path

import pytest
import yaml

WORKFLOW = Path(__file__).parents[1] / ".github" / "workflows" / "nightly.yml"
ALERT_WORKFLOW = Path(__file__).parents[1] / ".github" / "workflows" / "nightly-failure-alert.yml"


def _extract_indented_block(text: str, anchor: str) -> str:
    """Return the ``anchor:`` line plus every following line indented deeper than
    it (blank lines pass through), stopping at the first line back at or above
    the anchor's own indent.

    Replaces a fixed-width slice: a hardcoded character count silently
    truncates (or reads past the block into an unrelated sibling key) the
    moment the block's rendered length drifts from the guess.
    """
    lines = text.splitlines()
    anchor_index = next(i for i, line in enumerate(lines) if line.strip() == anchor)
    anchor_indent = len(lines[anchor_index]) - len(lines[anchor_index].lstrip(" "))
    body = itertools.takewhile(
        lambda line: not line.strip() or (len(line) - len(line.lstrip(" "))) > anchor_indent,
        lines[anchor_index + 1 :],
    )
    return "\n".join([lines[anchor_index], *body])


def test_nightly_workflow_exists_and_is_branch_independent() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")

    assert "name: Nightly snapshot" in text
    assert "workflow_dispatch:" in text
    assert "schedule:" in text
    assert "NIGHTLY_SOURCE_REF: ${{ vars.NIGHTLY_SOURCE_REF }}" in text
    assert "source_ref:" in text
    assert "source_sha:" in text
    assert "rev-parse HEAD" in text
    assert "cancel-in-progress: false" in text
    assert "queue: max" in text
    assert "read-version-matrix.sh" in text
    assert "--print-build" in text
    assert "--print-route" in text
    assert "build-record" in text
    assert "pkgversion" in text
    assert "actions/upload-artifact@" in text
    assert "nightly-handoff-" in text
    assert "nightly-state" not in text
    assert "contents: write" not in _extract_indented_block(text, "permissions:")
    assert "::error::missing live BUILD/ROUTE matrix rows" in text
    assert 'nightly_provenance.py" handoff' in text
    assert '--pkg-version "$PKG_VERSION"' in text
    assert "PORTS_REF_COUNT" in text
    assert "PORTS_HEAD_SHA" in text
    assert "PORTS_TAG_SHA" in text
    assert "refs/tags/${PORTS_REF}^{}" in text
    assert "LC_ALL=C sort -u" in text
    assert "^[0-9a-f]{40}$" in text
    assert 'PKG_VERSION="$(sh "$TRUSTED_DIR/scripts/nightly-pkgversion.sh" "$SOURCE_SHA")"' in text

    forbidden = ("gh release", "git tag", "git push", "release notes", "PORTVERSION")
    assert not any(token in text for token in forbidden), "Nightly workflow must not publish or mutate Ports"


def test_matrix_gate_red_canary_guards_live_matrix_enforcement() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    start = text.index("      - name: Resolve pinned source, Ports, and live matrices")
    end = text.index("\n      - name: Expose pinned plan", start)
    step = text[start:end]

    canary = (
        "if matrix_gate '[]' '[]'; then\n"
        '            echo "::error::matrix gate red canary passed"\n'
        "            exit 1\n"
        "          fi"
    )
    assert "matrix_nonempty() {" in step
    assert "matrix_gate() {" in step
    assert canary in step
    assert 'echo "matrix gate red canary: expected rejection"' in step
    assert '(cd "$TRUSTED_DIR" && sh scripts/read-version-matrix.sh \\' in step
    assert 'if ! matrix_gate "$BUILD_MATRIX" "$ROUTE_MATRIX"; then' in step
    assert 'echo "::error::missing live BUILD/ROUTE matrix rows"' in step
    assert "TOOLS_SHA=" in step
    assert "matrix_sha" in step
    assert "tools_sha" in step
    assert step.index(canary) < step.index('if ! matrix_gate "$BUILD_MATRIX" "$ROUTE_MATRIX"')


def test_nightly_failure_alert_watches_snapshot_workflow() -> None:
    text = ALERT_WORKFLOW.read_text(encoding="utf-8")

    assert '- "Nightly snapshot"' in text


def _build_and_verify_step(text: str) -> str:
    start = text.index("      - name: Build and verify package")
    end = text.index("\n      - name: Upload verified build", start)
    return text[start:end]


def _build_leg_invocation(step: str) -> str:
    marker = 'sh "$TRUSTED_DIR/scripts/build-leg.sh"'
    start = step.index(marker)
    end = step.index(")", start)
    return step[start:end]


def _assert_build_leg_pins_prepare_sha(build_leg: str) -> None:
    assert '--ports-ref "$PORTS_SHA"' in build_leg
    assert '--ports-ref "$PORTS_REF"' not in build_leg


def test_build_step_clones_ports_at_prepare_sha() -> None:
    """issue #2406: BUILD clones prepare's PORTS_SHA; PORTS_REF is ls-remote only."""
    text = WORKFLOW.read_text(encoding="utf-8")
    step = _build_and_verify_step(text)
    build_leg = _build_leg_invocation(step)

    _assert_build_leg_pins_prepare_sha(build_leg)
    assert 'if [ "$ACTUAL_PORTS_SHA" != "$PORTS_SHA" ]; then' in step

    prepare_start = text.index("      - name: Resolve pinned source, Ports, and live matrices")
    prepare_end = text.index("\n      - name: Expose pinned plan", prepare_start)
    prepare = text[prepare_start:prepare_end]
    assert prepare.count('git ls-remote "$PORTS_URL"') == 1
    assert "refs/heads/${PORTS_REF}" in prepare
    assert 'echo "ports_sha=$PORTS_SHA"' in prepare


def test_build_leg_ports_ref_pin_rejects_moving_branch() -> None:
    """issue #2406: swapping SHA for REF on the build-leg line is RED."""
    text = WORKFLOW.read_text(encoding="utf-8")
    build_leg = _build_leg_invocation(_build_and_verify_step(text))
    mutated = build_leg.replace('--ports-ref "$PORTS_SHA"', '--ports-ref "$PORTS_REF"', 1)
    with pytest.raises(AssertionError):
        _assert_build_leg_pins_prepare_sha(mutated)


_ORIGIN_COUNT_COMPARE = 'if [ "$DEP_COPIED" -ne "$ORIGIN_COUNT" ]; then'
_DEP_PKG_GLOB = 'for DEP_PKG in "$DEP_PKG_DIR"/*.pkg;'


def _assert_build_step_compares_dep_pkg_count(step: str) -> None:
    """issue #2405: after the glob, ORIGIN_COUNT == copied dep *.pkg count."""
    assert _DEP_PKG_GLOB in step
    assert _ORIGIN_COUNT_COMPARE in step
    assert step.index(_DEP_PKG_GLOB) < step.index(_ORIGIN_COUNT_COMPARE)
    compare_tail = step[step.index(_ORIGIN_COUNT_COMPARE) :]
    assert 'echo "::error::' in compare_tail
    assert "exit 1" in compare_tail


def test_build_step_compares_origin_count_to_copied_dep_pkgs() -> None:
    """issue #2405: BUILD step compares ORIGIN_COUNT to copied dep *.pkg files."""
    step = _build_and_verify_step(WORKFLOW.read_text(encoding="utf-8"))
    _assert_build_step_compares_dep_pkg_count(step)
    assert "result/*.pkg" in step


def test_dropping_origin_count_compare_leaves_glob_and_goes_red() -> None:
    """issue #2405: deleting the ORIGIN_COUNT compare, leaving the glob, is RED."""
    step = _build_and_verify_step(WORKFLOW.read_text(encoding="utf-8"))
    _assert_build_step_compares_dep_pkg_count(step)
    mutated = step.replace(_ORIGIN_COUNT_COMPARE, "", 1)
    assert _DEP_PKG_GLOB in mutated
    with pytest.raises(AssertionError):
        _assert_build_step_compares_dep_pkg_count(mutated)


def test_build_step_builds_and_hands_off_dependency_packages() -> None:
    """issue #2146 S1: the BUILD leg also builds this leg's extra_pkgs dep
    .pkgs (issue #1806), with NO tagged-style rename, and folds them into
    result.json's dep_artifacts."""
    text = WORKFLOW.read_text(encoding="utf-8")
    start = text.index("      - name: Build and verify package")
    end = text.index("\n      - name: Upload verified build", start)
    step = text[start:end]

    # W1: build-dep-pkg-portable.py invoked with the full flag set.
    assert "build-dep-pkg-portable.py" in step
    assert "--ports" in step
    assert "--port" in step
    assert "--py-flavor" in step
    assert "--freebsd-major" in step
    assert "--ports-sha" in step
    assert "--source-date-epoch" in step
    assert '"$DEP_PYTHON"' in step
    assert "--dependency-builder dependency-builder.json" in step
    assert "--out-dir" in step

    # W2: loop driven by the matrix row's extra_pkgs, sparse-checkout add per origin.
    assert ".extra_pkgs" in step
    assert 'git -C "$PORTS_DIR" sparse-checkout add "$ORIGIN"' in step

    # W3: no rename -- nightly dep .pkgs keep their canonical filename.
    assert "-${VARIANT}-${PFSENSE_VERSION}.pkg" not in step
    assert "RENAMED_DEP" not in step

    # W4: result.json construction includes dep_artifacts.
    assert "dep_artifacts" in step
    assert "DEP_ARTIFACTS_JSON" in step


def _continued_command_ending_with(script: str, suffix: str) -> str:
    lines = script.splitlines()
    end = next(index for index, line in enumerate(lines) if suffix in line)
    start = end
    while start > 0 and lines[start - 1].rstrip().endswith("\\"):
        start -= 1
    return "\n".join(lines[start : end + 1])


@pytest.mark.parametrize(
    "origins",
    [
        ["textproc/py-charset-normalizer"],
        ["textproc/py-charset-normalizer", "devel/py-demo"],
    ],
)
def test_build_step_executes_every_dependency_with_locked_python(tmp_path: Path, origins: list[str]) -> None:
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    step = next(item for item in workflow["jobs"]["build"]["steps"] if item.get("name") == "Build and verify package")
    lines = step["run"].splitlines()
    start = next(index for index, line in enumerate(lines) if line.strip().startswith("EXTRA_PKGS="))
    end = next(index for index, line in enumerate(lines[start:], start) if line.strip() == "done")
    command = "\n".join([*lines[start : end + 1], "fi"])
    trusted = tmp_path / "trusted"
    locked_python = trusted / ".venv/bin/python"
    locked_python.parent.mkdir(parents=True)
    locked_log = tmp_path / "locked-argv"
    locked_python.write_text('#!/bin/sh\nprintf \'%s\\0\' "$@" >> "$LOCKED_LOG"\n', encoding="utf-8")
    locked_python.chmod(0o755)
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    ambient_log = tmp_path / "ambient-argv"
    ambient_python = fake_bin / "python3"
    ambient_python.write_text('#!/bin/sh\nprintf \'%s\\0\' "$@" >> "$AMBIENT_LOG"\n', encoding="utf-8")
    ambient_python.chmod(0o755)
    fake_git = fake_bin / "git"
    fake_git.write_text('#!/bin/sh\nprintf \'%s\\n\' "$*" >> "$GIT_LOG"\n', encoding="utf-8")
    fake_git.chmod(0o755)
    (tmp_path / "row.json").write_text(
        json.dumps({"extra_pkgs": origins}),
        encoding="utf-8",
    )
    env = os.environ | {
        "DEP_PYTHON": str(locked_python),
        "TRUSTED_DIR": str(trusted),
        "RUN_ROOT": str(tmp_path / "run"),
        "RUN_ID": "nightly-test",
        "PORTS_DIR": str(tmp_path / "ports"),
        "PORTS_SHA": "a" * 40,
        "PY_FLAVOR": "py311",
        "FREEBSD_MAJOR": "15",
        "SOURCE_DATE_EPOCH": "1700000000",
        "LOCKED_LOG": str(locked_log),
        "AMBIENT_LOG": str(ambient_log),
        "GIT_LOG": str(tmp_path / "git.log"),
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
    }

    completed = subprocess.run(
        ["dash", "-c", command],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert not ambient_log.exists()
    argv = locked_log.read_bytes().split(b"\0")[:-1]
    assert argv.count(str(trusted / "scripts/build-dep-pkg-portable.py").encode()) == len(origins)
    for origin in origins:
        assert argv.count(origin.encode()) == 1
    assert (tmp_path / "git.log").read_text(encoding="utf-8").count("sparse-checkout add") == len(origins)


def test_prepare_executes_exact_pinned_toolchain_generation(tmp_path: Path) -> None:
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    step = next(
        item
        for item in workflow["jobs"]["prepare"]["steps"]
        if item.get("name") == "Resolve pinned source, Ports, and live matrices"
    )
    command = _continued_command_ending_with(step["run"], "> plan/dependency-builder.json")
    trusted = tmp_path / "trusted"
    trusted.mkdir()
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    toolchain_log = tmp_path / "toolchain-argv"
    python = fake_bin / "python3"
    python.write_text(
        '#!/bin/sh\nprintf \'%s\\0\' "$@" > "$TOOLCHAIN_LOG"\nprintf \'{"locked":true}\\n\'\n',
        encoding="utf-8",
    )
    python.chmod(0o755)
    (tmp_path / "plan").mkdir()
    env = os.environ | {
        "TRUSTED_DIR": str(trusted),
        "TOOLCHAIN_LOG": str(toolchain_log),
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
    }

    completed = subprocess.run(["dash", "-c", command], cwd=tmp_path, env=env, capture_output=True, text=True)

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert toolchain_log.read_bytes().split(b"\0")[:-1] == [
        str(trusted / "scripts/build-dep-pkg-portable.py").encode(),
        b"--print-toolchain",
    ]
    assert (tmp_path / "plan/dependency-builder.json").read_text(encoding="utf-8") == '{"locked":true}\n'


def test_dependency_builder_toolchain_epoch_and_handoff_are_structurally_locked() -> None:
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    prepare_steps = workflow["jobs"]["prepare"]["steps"]
    build_steps = workflow["jobs"]["build"]["steps"]
    handoff_steps = workflow["jobs"]["handoff"]["steps"]

    setup = next(step for step in build_steps if step.get("name") == "Set up the pinned dependency-package toolchain")
    sync = next(step for step in build_steps if step.get("name") == "Sync the locked dependency-package toolchain")
    prepare = next(
        step for step in prepare_steps if step.get("name") == "Resolve pinned source, Ports, and live matrices"
    )
    handoff = next(step for step in handoff_steps if step.get("name") == "Create verified publisher handoff")

    assert setup["with"]["version"] == "0.12.6"
    assert sync["run"] == "uv sync --project trusted --locked --only-group dep-pkg-build"
    assert "> plan/dependency-builder.json" in prepare["run"]
    assert "> plan/source-date-epoch" in prepare["run"]
    assert "--dependency-builder plan/dependency-builder.json" in handoff["run"]
    assert handoff["env"]["SOURCE_DATE_EPOCH"] == "${{ needs.prepare.outputs.source_date_epoch }}"
    assert '--source-date-epoch "$SOURCE_DATE_EPOCH"' in handoff["run"]
    build = next(step for step in build_steps if step.get("name") == "Build and verify package")
    assert '[ "$ORIGIN_COUNT" -gt 0 ]' in build["run"]


def test_handoff_step_has_no_durable_completion() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    start = text.index("      - name: Create verified publisher handoff")
    end = text.index("\n      - name: Upload verified publisher handoff", start)
    step = text[start:end]

    assert "--pkg-version" in step
    assert "complete" not in step
    assert "state" not in step


def test_build_run_id_carries_full_runtime_tuple() -> None:
    """issue #2926: the per-leg RUN_ID keys on the exact runtime tuple
    (freebsd_major, php_version, py_flavor) — never the major alone."""
    text = WORKFLOW.read_text(encoding="utf-8")
    run_id = next(line.strip() for line in text.splitlines() if "RUN_ID: nightly-" in line)
    expected = (
        "RUN_ID: nightly-${{ github.run_id }}-${{ matrix.freebsd_major }}"
        "-php${{ matrix.php_version }}-${{ matrix.py_flavor }}"
    )
    assert expected == run_id, f"RUN_ID must match nightly-<run_id>-<major>-php<php>-<py_flavor>; got {run_id!r}"


def test_build_upload_artifact_name_carries_full_runtime_tuple() -> None:
    """issue #2926: the BUILD upload artifact name matches the pkg consumer's
    leg-directory layout: nightly-result-<major>-php<php>-<py_flavor>."""
    text = WORKFLOW.read_text(encoding="utf-8")
    assert (
        "name: nightly-result-${{ matrix.freebsd_major }}-php${{ matrix.php_version }}-${{ matrix.py_flavor }}" in text
    ), "upload artifact name must be nightly-result-<major>-php<php>-<py_flavor>"
    assert "name: nightly-result-${{ matrix.freebsd_major }}\n" not in text, (
        "major-only artifact name must be gone (issue #2926)"
    )


def test_download_layouts_use_tuple_leg_pattern() -> None:
    """issue #2926: both handoff and OCI jobs download every per-tuple leg
    directory via the nightly-result-* pattern (now tuple-suffixed)."""
    text = WORKFLOW.read_text(encoding="utf-8")
    assert text.count("pattern: nightly-result-*") == 2, (
        "handoff and OCI handoff jobs must both download every tuple leg"
    )
