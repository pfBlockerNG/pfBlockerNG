"""version-tracker.yml reconcile-job contracts (issue #1823).

Extracts the REAL step scripts from the workflow YAML and executes them with
fake `gh`/`git`/`oras`/`box-facts.sh` binaries, pinning:

  - the gather step boots the newest non-beta image per channel plus every
    published beta entry — never an unpublished beta tag;
  - the plan step feeds only status=ok facts to scripts/reconcile-plan.py (the
    REAL planner runs) and writes one plan per channel;
  - the dispatch step turns republish/publish_new actions into fully-specified
    image-refresh direct legs (force only when from == target) and honours
    DRY_RUN;
  - the matrix-PR step turns matrix_pr_add/ga_flip actions into tracker/* PRs
    against ci-metadata with sibling field carry-over, dedups against existing
    entries, and honours DRY_RUN.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

from tests._workflow_steps import extract_after, extract_between, extract_job, extract_step

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "version-tracker.yml"

GATHER_STEP = "Gather box facts (boot newest images)"
PLAN_STEP = "Plan reconciliation"
DISPATCH_STEP = "Dispatch planned image legs"
MATRIX_PR_STEP = "Open matrix PRs for planned actions"

BUILD_MATRIX = [
    {
        "pfsense_version": "2.8",
        "channel": "CE",
        "freebsd_version": "15.0-RELEASE",
        "freebsd_major": "15",
        "php_version": "8.3",
        "py_flavor": "py311",
        "variant": "CE",
        "status": "active",
        "ci": True,
    },
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
        "pfsense_version": "26.03",
        "channel": "Plus",
        "freebsd_version": "16.0-RELEASE",
        "freebsd_major": "16",
        "php_version": "8.5",
        "py_flavor": "py311",
        "variant": "Plus",
        "status": "active",
        "ci": False,
        "arch": "aarch64",
        "image_name": "pfsense-plus",
    },
]

BETA_2607 = {
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
}


def _step_script(step_name: str) -> str:
    source = WORKFLOW.read_text(encoding="utf-8")
    step = extract_step(source, step_name)
    body: list[str] = []
    for line in extract_after(step, "        run: |\n").splitlines():
        if not line.strip():
            body.append("")
        elif line.startswith("          "):
            body.append(line[10:])
        else:
            break
    return "\n".join(body)


FAKE_GH = """#!/bin/sh
case "$*" in
  "pr list "*)
    if [ -f "$GH_STATE_DIR/pr-created" ]; then printf '77\\n'; fi
    ;;
  "pr create "*) printf 'pr create %s\\n' "$*" >> "$GH_LOG"; true > "$GH_STATE_DIR/pr-created" ;;
  "workflow run "*)
    printf 'workflow run %s\\n' "$*" >> "$GH_LOG"
    _prev=""
    for _a in "$@"; do
      case "$_prev" in -f) printf '%s\\n' "$_a" >> "$GH_FIELDS" ;; esac
      _prev="$_a"
    done
    ;;
esac
exit 0
"""

FAKE_GIT = """#!/bin/sh
printf 'git %s\\n' "$*" >> "$GIT_LOG"
case "$1" in
  show) cat "$FAKE_MATRIX" ;;
esac
exit 0
"""

# oras: `manifest fetch REF` succeeds iff REF is listed in $ORAS_EXISTING.
FAKE_ORAS = """#!/bin/sh
case "$1" in
  login) cat >/dev/null; exit 0 ;;
  manifest)
    case " ${ORAS_EXISTING:-} " in
      *" $3 "*) printf '{}\\n'; exit 0 ;;
    esac
    exit 1
    ;;
esac
exit 0
"""


def _write_fakes(tmp_path: Path) -> dict[str, str]:
    for name, content in (
        ("gh", FAKE_GH),
        ("git", FAKE_GIT),
        ("oras", FAKE_ORAS),
        ("sudo", '#!/bin/sh\ncase "$1" in tee) cat >/dev/null ;; esac\nexit 0\n'),
    ):
        fake = tmp_path / name
        fake.write_text(content, encoding="utf-8")
        fake.chmod(0o755)
    (tmp_path / "gh-state").mkdir(exist_ok=True)
    return {
        "PATH": f"{tmp_path}:{os.environ['PATH']}",
        "GH_LOG": str(tmp_path / "gh.log"),
        "GH_FIELDS": str(tmp_path / "gh-fields.log"),
        "GIT_LOG": str(tmp_path / "git.log"),
        "GH_STATE_DIR": str(tmp_path / "gh-state"),
        "REPO": "owner/repo",
        "REF": "devel",
    }


def _log(tmp_path: Path, name: str) -> str:
    log = tmp_path / name
    return log.read_text(encoding="utf-8") if log.exists() else ""


def _run_step(
    tmp_path: Path, step_name: str, extra_env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    env = os.environ | _write_fakes(tmp_path) | (extra_env or {})
    return subprocess.run(
        ["bash", "-c", _step_script(step_name)],
        cwd=tmp_path,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )


class TestGatherBootSet:
    """Scenario: which images the daily reconcile boots."""

    def _run(self, tmp_path: Path, matrix: list[dict[str, Any]], existing_refs: str) -> tuple[str, str]:
        # Fake box-facts.sh: record argv, emit ok + canned facts.
        scripts_dir = tmp_path / "scripts"
        scripts_dir.mkdir()
        (scripts_dir / "box-facts.sh").write_text(
            """#!/bin/sh
printf '%s\\n' "$*" >> "$FACTS_LOG"
while [ "$#" -gt 0 ]; do [ "$1" = "--out-dir" ] && OUT="$2"; shift; done
mkdir -p "$OUT"
printf 'ok\\n' > "$OUT/status"
printf '26.03.1-RELEASE\\n' > "$OUT/etc-version"
true > "$OUT/repoc.txt"
true > "$OUT/upgrade-check.txt"
exit 0
""",
            encoding="utf-8",
        )
        proc = _run_step(
            tmp_path,
            GATHER_STEP,
            {
                "ROUTE_MATRIX": json.dumps(matrix),
                "SMOKE_SSH_PRIV_KEY": "dummy-key",
                "SMOKE_GHCR_USER": "u",
                "SMOKE_GHCR_TOKEN": "t",
                "SMOKE_IMAGE_REPO": "ghcr.io/pfblockerng",
                "GITHUB_REPOSITORY_OWNER": "pfBlockerNG",
                "ORAS_EXISTING": existing_refs,
                "FACTS_LOG": str(tmp_path / "facts.log"),
            },
        )
        return _log(tmp_path, "facts.log"), proc.stdout + proc.stderr

    def test_boots_newest_stable_per_channel(self, tmp_path: Path) -> None:
        facts_log, _ = self._run(
            tmp_path,
            BUILD_MATRIX,
            "ghcr.io/pfblockerng/pfsense-ce:2.8 ghcr.io/pfblockerng/pfsense-plus:26.03",
        )
        assert "--tag 2.8" in facts_log
        assert "--tag 26.03" in facts_log
        pub = json.loads((tmp_path / "facts" / "Plus-published.json").read_text(encoding="utf-8"))
        assert pub == {"26.03": True}

    def test_unpublished_beta_entry_is_not_booted(self, tmp_path: Path) -> None:
        facts_log, _ = self._run(
            tmp_path,
            BUILD_MATRIX + [BETA_2607],
            "ghcr.io/pfblockerng/pfsense-ce:2.8 ghcr.io/pfblockerng/pfsense-plus:26.03",
        )
        assert "--tag 26.07" not in facts_log

    def test_published_beta_entry_is_booted_too(self, tmp_path: Path) -> None:
        facts_log, _ = self._run(
            tmp_path,
            BUILD_MATRIX + [BETA_2607],
            "ghcr.io/pfblockerng/pfsense-ce:2.8 ghcr.io/pfblockerng/pfsense-plus:26.03"
            " ghcr.io/pfblockerng/pfsense-plus:26.07",
        )
        assert "--tag 26.03" in facts_log
        assert "--tag 26.07" in facts_log

    def test_unpublished_newest_stable_does_not_shadow_the_published_one(self, tmp_path: Path) -> None:
        # Review F1: a freshly-merged NEWER stable entry with no image yet must
        # not become the boot source — booting only the nonexistent tag would
        # blind the whole channel (no facts → no publish_new branch → deadlock)
        newer_stable = dict(BUILD_MATRIX[1], pfsense_version="26.05")
        facts_log, _ = self._run(
            tmp_path,
            BUILD_MATRIX + [newer_stable],
            "ghcr.io/pfblockerng/pfsense-ce:2.8 ghcr.io/pfblockerng/pfsense-plus:26.03",
        )
        assert "--tag 26.03" in facts_log
        assert "--tag 26.05" not in facts_log

    def test_reconcile_job_has_a_hard_timeout(self) -> None:
        # Review F2: a wedged guest command must not hold a runner for the
        # 360-minute default
        source = WORKFLOW.read_text(encoding="utf-8")
        job = extract_between(source, "\n  reconcile:\n", "\n    steps:")
        assert "timeout-minutes:" in job


class TestPlanStep:
    """Scenario: the REAL planner runs over gathered facts, ok-status only."""

    def _facts(self, tmp_path: Path, channel: str, family: str, status: str, repoc: str, etc: str) -> None:
        d = tmp_path / "facts" / channel / family
        d.mkdir(parents=True, exist_ok=True)
        (d / "status").write_text(status + "\n", encoding="utf-8")
        (d / "etc-version").write_text(etc + "\n", encoding="utf-8")
        (d / "repoc.txt").write_text(repoc, encoding="utf-8")
        (d / "upgrade-check.txt").write_text("Your system is up to date\n", encoding="utf-8")

    def test_plans_matrix_pr_add_from_real_planner(self, tmp_path: Path) -> None:
        (tmp_path / "scripts").mkdir()
        (tmp_path / "scripts" / "reconcile-plan.py").write_text(
            (ROOT / "scripts" / "reconcile-plan.py").read_text(encoding="utf-8"), encoding="utf-8"
        )
        (tmp_path / "facts").mkdir(exist_ok=True)
        (tmp_path / "facts" / "Plus-published.json").write_text('{"26.03": true}', encoding="utf-8")
        self._facts(
            tmp_path,
            "Plus",
            "26.03",
            "ok",
            "26.07\t\tBeta Version (26.07)\n26_03_1 (release) (default)\t\tCurrent Stable Version (26.03.1)\n",
            "26.03.1-RELEASE",
        )
        # An unavailable boot must be EXCLUDED from the planner's input
        self._facts(tmp_path, "Plus", "26.09", "unavailable", "junk\t\tJunk (26.99)\n", "26.09-BETA")
        _run_step(tmp_path, PLAN_STEP, {"ROUTE_MATRIX": json.dumps(BUILD_MATRIX)})
        plan = json.loads((tmp_path / "facts" / "plan-Plus.json").read_text(encoding="utf-8"))
        assert {"type": "matrix_pr_add", "family": "26.07", "branch": "26.07", "status": "beta"} in plan["actions"]
        assert all(a.get("family") != "26.99" for a in plan["actions"])


class TestDispatchStep:
    """Scenario: planned image actions become image-refresh direct legs."""

    def _run(self, tmp_path: Path, actions: list[dict[str, str]], *, dry_run: str = "false") -> tuple[str, str]:
        (tmp_path / "facts").mkdir()
        (tmp_path / "facts" / "plan-Plus.json").write_text(json.dumps({"actions": actions}), encoding="utf-8")
        _run_step(
            tmp_path,
            DISPATCH_STEP,
            {"ROUTE_MATRIX": json.dumps(BUILD_MATRIX + [BETA_2607]), "DRY_RUN": dry_run},
        )
        return _log(tmp_path, "gh.log"), _log(tmp_path, "gh-fields.log")

    def test_republish_becomes_forced_direct_leg(self, tmp_path: Path) -> None:
        gh_log, fields = self._run(
            tmp_path, [{"type": "republish", "family": "26.03", "branch": "26_03_1", "reason": "newer-branch"}]
        )
        assert "workflow run image-refresh.yml" in gh_log
        leg = json.loads(next(line for line in fields.splitlines() if line.startswith("direct_leg=")).split("=", 1)[1])
        assert leg["pfsense_version"] == "26.03"
        assert leg["from"] == "26.03"
        assert leg["target"] == "26.03"
        assert leg["branch"] == "26_03_1"
        assert leg["force_flag"] == "--force"
        assert leg["image_name"] == "pfsense-plus"

    def test_publish_new_leg_builds_from_stable_without_force(self, tmp_path: Path) -> None:
        _, fields = self._run(
            tmp_path, [{"type": "publish_new", "family": "26.07", "branch": "26.07", "from": "26.03"}]
        )
        leg = json.loads(next(line for line in fields.splitlines() if line.startswith("direct_leg=")).split("=", 1)[1])
        assert leg["from"] == "26.03"
        assert leg["target"] == "26.07"
        assert leg["branch"] == "26.07"
        assert leg["force_flag"] == ""

    def test_matrix_pr_actions_dispatch_nothing(self, tmp_path: Path) -> None:
        gh_log, _ = self._run(
            tmp_path, [{"type": "matrix_pr_add", "family": "26.09", "branch": "26.09", "status": "beta"}]
        )
        assert "workflow run" not in gh_log

    def test_error_action_renders_error_annotation_and_dispatches_nothing(self, tmp_path: Path) -> None:
        # issue #1857: a mislabeled image surfaces as a loud ::error:: fact
        (tmp_path / "facts").mkdir()
        (tmp_path / "facts" / "plan-Plus.json").write_text(
            json.dumps({"actions": [{"type": "error", "family": "26.07", "message": "mislabeled image"}]}),
            encoding="utf-8",
        )
        proc = _run_step(
            tmp_path, DISPATCH_STEP, {"ROUTE_MATRIX": json.dumps(BUILD_MATRIX + [BETA_2607]), "DRY_RUN": "false"}
        )
        assert "::error::26.07: mislabeled image" in proc.stdout
        assert "workflow run" not in _log(tmp_path, "gh.log")

    def test_dry_run_dispatches_nothing(self, tmp_path: Path) -> None:
        gh_log, _ = self._run(
            tmp_path,
            [{"type": "republish", "family": "26.03", "branch": "26_03_1", "reason": "newer-branch"}],
            dry_run="true",
        )
        assert "workflow run" not in gh_log


class TestMatrixPrStep:
    """Scenario: planned matrix actions become one tracker/* PR each."""

    def _run(
        self,
        tmp_path: Path,
        actions: list[dict[str, str]],
        *,
        matrix_versions: list[dict[str, Any]] | None = None,
        dry_run: str = "false",
    ) -> tuple[str, str, Path]:
        (tmp_path / "facts").mkdir()
        (tmp_path / "facts" / "plan-Plus.json").write_text(json.dumps({"actions": actions}), encoding="utf-8")
        matrix_file = tmp_path / "fake-matrix.json"
        matrix_file.write_text(json.dumps({"versions": matrix_versions or BUILD_MATRIX}), encoding="utf-8")
        _run_step(tmp_path, MATRIX_PR_STEP, {"FAKE_MATRIX": str(matrix_file), "DRY_RUN": dry_run})
        return _log(tmp_path, "git.log"), _log(tmp_path, "gh.log"), tmp_path

    ADD_2607 = [{"type": "matrix_pr_add", "family": "26.07", "branch": "26.07", "status": "beta"}]

    def test_add_action_builds_entry_and_opens_pr(self, tmp_path: Path) -> None:
        git_log, gh_log, cwd = self._run(tmp_path, self.ADD_2607)
        assert "git push --force origin tracker/matrix-plus-26.07" in git_log
        assert "pr create" in gh_log
        new_matrix = json.loads((cwd / "supported-versions.json").read_text(encoding="utf-8"))
        entry = next(e for e in new_matrix["versions"] if e["pfsense_version"] == "26.07")
        assert entry["channel"] == "Plus"
        assert entry["status"] == "beta"
        assert entry["ci"] is False
        # carried from the newest same-channel amd64 sibling
        assert entry["php_version"] == "8.5"
        assert entry["image_name"] == "pfsense-plus"
        assert "arch" not in entry

    def test_existing_matrix_entry_skips_pr(self, tmp_path: Path) -> None:
        git_log, gh_log, _ = self._run(tmp_path, self.ADD_2607, matrix_versions=BUILD_MATRIX + [BETA_2607])
        assert "push" not in git_log
        assert "pr create" not in gh_log

    def test_ga_flip_rewrites_status(self, tmp_path: Path) -> None:
        git_log, gh_log, cwd = self._run(
            tmp_path,
            [{"type": "matrix_pr_ga_flip", "family": "26.07"}],
            matrix_versions=BUILD_MATRIX + [BETA_2607],
        )
        assert "git push --force origin tracker/matrix-plus-26.07-ga" in git_log
        assert "pr create" in gh_log
        new_matrix = json.loads((cwd / "supported-versions.json").read_text(encoding="utf-8"))
        entry = next(e for e in new_matrix["versions"] if e["pfsense_version"] == "26.07")
        assert entry["status"] == "active"

    def test_ga_flip_for_non_beta_entry_is_skipped(self, tmp_path: Path) -> None:
        git_log, gh_log, _ = self._run(tmp_path, [{"type": "matrix_pr_ga_flip", "family": "26.03"}])
        assert "push" not in git_log
        assert "pr create" not in gh_log

    def test_image_actions_touch_nothing(self, tmp_path: Path) -> None:
        git_log, gh_log, _ = self._run(
            tmp_path, [{"type": "republish", "family": "26.03", "branch": "", "reason": "upgrade-check"}]
        )
        assert git_log == ""
        assert "pr create" not in gh_log

    def test_dry_run_pushes_nothing(self, tmp_path: Path) -> None:
        git_log, gh_log, _ = self._run(tmp_path, self.ADD_2607, dry_run="true")
        assert "push" not in git_log
        assert "pr create" not in gh_log


class TestReconcileMatrixSource:
    """Scenario (issue #1839): the reconcile must see EVERY version, one row per
    family. `build_matrix` is deduped to one row per freebsd_major (issue #1806),
    which hid Plus 26.03 the moment 26.07 (same major 16) joined the matrix —
    the boot source vanished and the planner could not resolve the new family's
    branch. The route matrix is the never-deduped view."""

    SAME_MAJOR_MATRIX = {
        "versions": [
            {
                "pfsense_version": "2.8",
                "channel": "CE",
                "freebsd_version": "15.0-RELEASE",
                "freebsd_major": "15",
                "php_version": "8.3",
                "py_flavor": "py311",
                "variant": "CE",
                "status": "active",
                "ci": True,
            },
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

    def _reader(self, tmp_path: Path, mode: str) -> list[dict[str, Any]]:
        """Run the REAL reader against the fixture matrix."""
        matrix_file = tmp_path / "matrix.json"
        matrix_file.write_text(json.dumps(self.SAME_MAJOR_MATRIX), encoding="utf-8")
        fake_git = tmp_path / "git"
        fake_git.write_text(
            '#!/bin/sh\ncase "$1" in\n  fetch) exit 0 ;;\n  show) cat "$FAKE_MATRIX" ;;\nesac\n',
            encoding="utf-8",
        )
        fake_git.chmod(0o755)
        proc = subprocess.run(
            ["sh", str(ROOT / "scripts" / "read-version-matrix.sh"), "--ref", "origin/ci-metadata", mode],
            cwd=tmp_path,
            env=os.environ | {"PATH": f"{tmp_path}:{os.environ['PATH']}", "FAKE_MATRIX": str(matrix_file)},
            check=True,
            capture_output=True,
            text=True,
        )
        return json.loads(proc.stdout)

    def test_build_matrix_hides_a_same_major_family(self, tmp_path: Path) -> None:
        # The documented ABI dedup — correct for .pkg builds, wrong for the
        # reconcile. Pins WHY the source had to change.
        plus = [e for e in self._reader(tmp_path, "--print-build") if e["channel"] == "Plus"]
        assert len(plus) == 1

    def test_route_matrix_keeps_every_family(self, tmp_path: Path) -> None:
        plus = sorted(e["pfsense_version"] for e in self._reader(tmp_path, "--print-route") if e["channel"] == "Plus")
        assert plus == ["26.03", "26.07"]

    def test_reconcile_steps_consume_the_route_matrix(self) -> None:
        # Wiring pin: every reconcile step reads the never-deduped view.
        source = WORKFLOW.read_text(encoding="utf-8")
        reconcile = extract_after(source, "\n  reconcile:\n")
        assert "BUILD_MATRIX" not in reconcile
        assert reconcile.count("ROUTE_MATRIX:") >= 3

    def test_resolve_step_emits_single_line_json(self, tmp_path: Path) -> None:
        # CodeRabbit: the reader pretty-prints, so a bare `printf key=%s` would
        # corrupt GITHUB_OUTPUT and hand the reconcile a truncated matrix.
        matrix_file = tmp_path / "matrix.json"
        matrix_file.write_text(json.dumps(self.SAME_MAJOR_MATRIX), encoding="utf-8")
        fake_git = tmp_path / "git"
        fake_git.write_text(
            '#!/bin/sh\ncase "$1" in\n  fetch) exit 0 ;;\n  show) cat "$FAKE_MATRIX" ;;\nesac\n',
            encoding="utf-8",
        )
        fake_git.chmod(0o755)
        (tmp_path / "scripts").mkdir(exist_ok=True)
        (tmp_path / "scripts" / "read-version-matrix.sh").write_text(
            (ROOT / "scripts" / "read-version-matrix.sh").read_text(encoding="utf-8"), encoding="utf-8"
        )
        out = tmp_path / "gh-output"
        out.write_text("", encoding="utf-8")
        subprocess.run(
            ["bash", "-c", _step_script("Resolve the route matrix (never deduped)")],
            cwd=tmp_path,
            env=os.environ
            | {
                "PATH": f"{tmp_path}:{os.environ['PATH']}",
                "FAKE_MATRIX": str(matrix_file),
                "GITHUB_OUTPUT": str(out),
            },
            check=True,
            capture_output=True,
            text=True,
        )
        lines = [ln for ln in out.read_text(encoding="utf-8").splitlines() if ln.startswith("route=")]
        assert len(lines) == 1, "the route output must be one line"
        entries = json.loads(lines[0][len("route=") :])
        assert sorted(e["pfsense_version"] for e in entries if e["channel"] == "Plus") == ["26.03", "26.07"]

    def test_reconcile_job_is_independent_and_best_effort(self) -> None:
        # Review follow-ups: the reconcile resolves its own matrix, so the
        # read-matrix dependency is dead coupling (an unrelated failure there
        # would skip this job); and the resolve step must degrade like every
        # other data step in this best-effort job.
        source = WORKFLOW.read_text(encoding="utf-8")
        reconcile = extract_job(source, "reconcile")
        assert "needs: read-matrix" not in reconcile
        resolve = extract_between(reconcile, "- name: Resolve the route matrix", "\n      - name:")
        assert "continue-on-error: true" in resolve

    def test_reconcile_uploads_the_facts_tree(self) -> None:
        # issue #1848: an intermittent boot failure is undiagnosable once the
        # runner is gone — the facts must outlive it.
        source = WORKFLOW.read_text(encoding="utf-8")
        reconcile = extract_after(source, "\n  reconcile:\n")
        assert "actions/upload-artifact" in reconcile
        upload = extract_after(reconcile, "actions/upload-artifact")[:400]
        assert "facts" in upload
        # the window an intermittent failure gets investigated in
        assert "retention-days: 14" in upload
