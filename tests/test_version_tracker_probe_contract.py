"""version-tracker.yml probe-job contracts (issue #1820).

Extracts the REAL step scripts from the workflow YAML and executes them with
fake `gh`/`git`/`oras` binaries, pinning:

  - the tracking-issue body carries the public-beta probe outcome (yes — with
    the detected repo branch and the matrix auto-PR reference — / no / unknown);
  - patch/GA drift detection compares the Netgate page's newest released build
    against the published image's pfsense-version annotation, only for the
    newest matrix version per channel, and skips annotation-less images;
  - the matrix auto-PR step builds the new beta entry by carrying the newest
    same-channel entry's fields, opens one PR per detection against
    ci-metadata, dedups against existing entries/PRs, and honours DRY_RUN.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "version-tracker.yml"

TRACKING_STEP = "Open or update tracking issues for upcoming/TBD versions"
PATCH_STEP = "Patch/GA drift detection (page vs image annotation)"
MATRIX_PR_STEP = "Open matrix PRs for detected betas and GA flips"
BETA_PROBE_STEP = "Public-beta VM probe (boot latest image per channel)"

FUTURE_2607 = {
    "version": "26.07",
    "channel": "Plus",
    "released": "TBD",
    "freebsd_major": "16",
    "freebsd_version": "16.0-CURRENT@c215eef34550",
}

MATRIX_VERSIONS = [
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
        "upgrade": {"available": False},
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
        "upgrade": {"available": False},
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
        "upgrade": {"available": False},
    },
]


def _step_script(step_name: str) -> str:
    source = WORKFLOW.read_text(encoding="utf-8")
    step = source.split(f"      - name: {step_name}\n", 1)[1].split("\n      - name:", 1)[0]
    body: list[str] = []
    for line in step.split("        run: |\n", 1)[1].splitlines():
        if not line.strip():
            body.append("")
        elif line.startswith("          "):
            body.append(line[10:])
        else:
            break
    return "\n".join(body)


FAKE_GH = """#!/bin/sh
case "$*" in
  "issue list "*) printf '%s\\n' "${GH_OPEN:-[]}" ;;
  "issue edit "*)
    printf 'edit %s\\n' "$3" >> "$GH_LOG"
    _prev=""
    for _a in "$@"; do
      [ "$_prev" = "--body-file" ] && cp "$_a" "$BODY_CAPTURE"
      _prev="$_a"
    done
    ;;
  "issue create "*)
    printf 'create\\n' >> "$GH_LOG"
    _prev=""
    for _a in "$@"; do
      [ "$_prev" = "--body-file" ] && cp "$_a" "$BODY_CAPTURE"
      _prev="$_a"
    done
    ;;
  "pr list "*)
    if [ -f "$GH_STATE_DIR/pr-created" ]; then printf '77\\n'; fi
    ;;
  "pr create "*) printf 'pr create %s\\n' "$*" >> "$GH_LOG"; : > "$GH_STATE_DIR/pr-created" ;;
  "workflow run "*) printf 'workflow run %s\\n' "$*" >> "$GH_LOG" ;;
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

FAKE_ORAS = """#!/bin/sh
case "$1" in
  login) exit 0 ;;
  manifest)
    # $3 = the image ref; serve the fixture manifest mapped for it, else fail.
    _key=$(printf '%s' "$3" | tr '/:' '__')
    if [ -f "$ORAS_DIR/$_key" ]; then cat "$ORAS_DIR/$_key"; exit 0; fi
    exit 1
    ;;
esac
exit 0
"""


def _write_fakes(tmp_path: Path) -> dict[str, str]:
    for name, content in (("gh", FAKE_GH), ("git", FAKE_GIT), ("oras", FAKE_ORAS)):
        fake = tmp_path / name
        fake.write_text(content, encoding="utf-8")
        fake.chmod(0o755)
    (tmp_path / "oras-manifests").mkdir(exist_ok=True)
    (tmp_path / "gh-state").mkdir(exist_ok=True)
    return {
        "PATH": f"{tmp_path}:{os.environ['PATH']}",
        "GH_LOG": str(tmp_path / "gh.log"),
        "GIT_LOG": str(tmp_path / "git.log"),
        "BODY_CAPTURE": str(tmp_path / "body-capture.md"),
        "ORAS_DIR": str(tmp_path / "oras-manifests"),
        "GH_STATE_DIR": str(tmp_path / "gh-state"),
        "REPO": "owner/repo",
        "REF": "devel",
    }


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


def _log(tmp_path: Path, name: str) -> str:
    log = tmp_path / name
    return log.read_text(encoding="utf-8") if log.exists() else ""


class TestTrackingIssueBody:
    """Scenario: the tracking issue surfaces the beta-probe outcome."""

    def _body(self, tmp_path: Path, *, beta: dict[str, Any] | None, prs: dict[str, str] | None = None) -> str:
        (tmp_path / "probe_result.json").write_text(json.dumps({"future": [FUTURE_2607]}), encoding="utf-8")
        if beta is not None:
            (tmp_path / "beta_result.json").write_text(json.dumps(beta), encoding="utf-8")
        if prs is not None:
            (tmp_path / "matrix_prs.json").write_text(json.dumps(prs), encoding="utf-8")
        _run_step(tmp_path, TRACKING_STEP)
        return (tmp_path / "body-capture.md").read_text(encoding="utf-8")

    def test_beta_yes_renders_branch_and_matrix_pr(self, tmp_path: Path) -> None:
        beta = {"Plus/26.07": {"variant": "plus", "expect": "26.07", "verdict": "yes", "branch": "26.07"}}
        body = self._body(tmp_path, beta=beta, prs={"Plus/26.07": "77"})
        assert "| Public beta | yes" in body
        assert "`26.07`" in body
        assert "#77" in body

    def test_beta_no_renders_not_yet(self, tmp_path: Path) -> None:
        beta = {"Plus/26.07": {"variant": "plus", "expect": "26.07", "verdict": "no", "branch": ""}}
        body = self._body(tmp_path, beta=beta)
        assert "| Public beta | not yet" in body

    def test_absent_probe_result_renders_unknown(self, tmp_path: Path) -> None:
        body = self._body(tmp_path, beta=None)
        assert "| Public beta | unknown" in body


class TestPatchDetect:
    """Scenario: page latest release vs the published image's annotation."""

    def _run(
        self, tmp_path: Path, latest_releases: list[dict[str, str]], manifests: dict[str, dict[str, Any]]
    ) -> tuple[list[dict[str, Any]], str]:
        (tmp_path / "probe_result.json").write_text(json.dumps({"latest_releases": latest_releases}), encoding="utf-8")
        env = _write_fakes(tmp_path)
        oras_dir = Path(env["ORAS_DIR"])
        for ref, manifest in manifests.items():
            (oras_dir / ref.replace("/", "_").replace(":", "_")).write_text(json.dumps(manifest), encoding="utf-8")
        proc = subprocess.run(
            ["bash", "-c", _step_script(PATCH_STEP)],
            cwd=tmp_path,
            env=os.environ
            | env
            | {
                "BUILD_MATRIX": json.dumps(MATRIX_VERSIONS),
                "SMOKE_GHCR_USER": "u",
                "SMOKE_GHCR_TOKEN": "t",
                "SMOKE_IMAGE_REPO": "ghcr.io/pfblockerng",
                "GITHUB_REPOSITORY_OWNER": "pfBlockerNG",
            },
            check=True,
            capture_output=True,
            text=True,
        )
        result = json.loads((tmp_path / "patch_result.json").read_text(encoding="utf-8"))
        return result, proc.stdout + proc.stderr

    def test_drifted_image_flags_refresh(self, tmp_path: Path) -> None:
        result, _ = self._run(
            tmp_path,
            [{"version": "26.03", "channel": "Plus", "latest_release": "26.03.1"}],
            {
                "ghcr.io/pfblockerng/pfsense-plus:26.03": {
                    "annotations": {"io.github.pfblockerng.pfsense-version": "26.03.0-RELEASE"}
                }
            },
        )
        assert result == [
            {"version": "26.03", "channel": "Plus", "page": "26.03.1", "image": "26.03.0-RELEASE", "refresh": True}
        ]

    def test_current_image_not_flagged(self, tmp_path: Path) -> None:
        result, _ = self._run(
            tmp_path,
            [{"version": "2.8", "channel": "CE", "latest_release": "2.8.1"}],
            {
                "ghcr.io/pfblockerng/pfsense-ce:2.8": {
                    "annotations": {"io.github.pfblockerng.pfsense-version": "2.8.1-RELEASE"}
                }
            },
        )
        assert result == [
            {"version": "2.8", "channel": "CE", "page": "2.8.1", "image": "2.8.1-RELEASE", "refresh": False}
        ]

    def test_annotation_less_image_is_skipped_with_warning(self, tmp_path: Path) -> None:
        result, output = self._run(
            tmp_path,
            [{"version": "2.8", "channel": "CE", "latest_release": "2.8.1"}],
            {"ghcr.io/pfblockerng/pfsense-ce:2.8": {"annotations": {}}},
        )
        assert result == []
        assert "no pfsense-version annotation" in output
        # Review F1: image-refresh cannot seed a CURRENT image (image-upgrade
        # no-op-exits before publishing), so the prescribed remediation must be
        # the manual publish path, which stamps the annotation unconditionally
        assert "image-publish.sh" in output

    def test_only_newest_version_per_channel_is_checked(self, tmp_path: Path) -> None:
        # 2.7 is in latest_releases (matrix family) but 2.8 is the channel's
        # newest — the frozen 2.7 floating tag must not be probed. Review F2:
        # the fixture carries a DRIFTED manifest for 2.7, so if the
        # newest-per-channel guard is removed the candidate gets probed,
        # flagged, and this assertion fails (not vacuous).
        result, _ = self._run(
            tmp_path,
            [{"version": "2.7", "channel": "CE", "latest_release": "2.7.2"}],
            {
                "ghcr.io/pfblockerng/pfsense-ce:2.7": {
                    "annotations": {"io.github.pfblockerng.pfsense-version": "2.7.0-RELEASE"}
                }
            },
        )
        assert result == []

    def test_beta_entry_does_not_hide_ga_family_drift(self, tmp_path: Path) -> None:
        # Final-pass F1: with a merged (unbuilt) beta entry in the matrix, the
        # channel's newest STABLE family must still be drift-checked — during
        # the whole beta window it is the image CI actually smokes.
        (tmp_path / "probe_result.json").write_text(
            json.dumps({"latest_releases": [{"version": "26.03", "channel": "Plus", "latest_release": "26.03.1"}]}),
            encoding="utf-8",
        )
        env = _write_fakes(tmp_path)
        (Path(env["ORAS_DIR"]) / "ghcr.io_pfblockerng_pfsense-plus_26.03").write_text(
            json.dumps({"annotations": {"io.github.pfblockerng.pfsense-version": "26.03.0-RELEASE"}}),
            encoding="utf-8",
        )
        build_matrix = MATRIX_VERSIONS + [dict(MATRIX_VERSIONS[1], pfsense_version="26.07", status="beta", ci=False)]
        subprocess.run(
            ["bash", "-c", _step_script(PATCH_STEP)],
            cwd=tmp_path,
            env=os.environ
            | env
            | {
                "BUILD_MATRIX": json.dumps(build_matrix),
                "SMOKE_GHCR_USER": "u",
                "SMOKE_GHCR_TOKEN": "t",
                "SMOKE_IMAGE_REPO": "ghcr.io/pfblockerng",
                "GITHUB_REPOSITORY_OWNER": "pfBlockerNG",
            },
            check=True,
            capture_output=True,
            text=True,
        )
        result = json.loads((tmp_path / "patch_result.json").read_text(encoding="utf-8"))
        assert result == [
            {"version": "26.03", "channel": "Plus", "page": "26.03.1", "image": "26.03.0-RELEASE", "refresh": True}
        ]

    def test_beta_entry_itself_is_checked_on_ga_day(self, tmp_path: Path) -> None:
        # GA day: the page lists the (still status:beta) family as released —
        # its own entry is a candidate even though it is not the newest stable
        (tmp_path / "probe_result.json").write_text(
            json.dumps({"latest_releases": [{"version": "26.07", "channel": "Plus", "latest_release": "26.07"}]}),
            encoding="utf-8",
        )
        env = _write_fakes(tmp_path)
        (Path(env["ORAS_DIR"]) / "ghcr.io_pfblockerng_pfsense-plus_26.07").write_text(
            json.dumps({"annotations": {"io.github.pfblockerng.pfsense-version": "26.07-BETA"}}),
            encoding="utf-8",
        )
        build_matrix = MATRIX_VERSIONS + [dict(MATRIX_VERSIONS[1], pfsense_version="26.07", status="beta", ci=False)]
        subprocess.run(
            ["bash", "-c", _step_script(PATCH_STEP)],
            cwd=tmp_path,
            env=os.environ
            | env
            | {
                "BUILD_MATRIX": json.dumps(build_matrix),
                "SMOKE_GHCR_USER": "u",
                "SMOKE_GHCR_TOKEN": "t",
                "SMOKE_IMAGE_REPO": "ghcr.io/pfblockerng",
                "GITHUB_REPOSITORY_OWNER": "pfBlockerNG",
            },
            check=True,
            capture_output=True,
            text=True,
        )
        result = json.loads((tmp_path / "patch_result.json").read_text(encoding="utf-8"))
        assert result == [
            {"version": "26.07", "channel": "Plus", "page": "26.07", "image": "26.07-BETA", "refresh": True}
        ]

    def test_nonfinal_annotation_flags_refresh_even_when_versions_match(self, tmp_path: Path) -> None:
        # A beta image reports /etc/version like "26.07-BETA" (live-probed on
        # the owner's Plus VM). On GA day the page's newest released build is
        # "26.07" — equal after suffix strip — yet the image still holds the
        # BETA build and MUST be refreshed to the GA final.
        result, _ = self._run(
            tmp_path,
            [{"version": "26.03", "channel": "Plus", "latest_release": "26.03"}],
            {
                "ghcr.io/pfblockerng/pfsense-plus:26.03": {
                    "annotations": {"io.github.pfblockerng.pfsense-version": "26.03-BETA"}
                }
            },
        )
        assert result == [
            {"version": "26.03", "channel": "Plus", "page": "26.03", "image": "26.03-BETA", "refresh": True}
        ]


class TestBetaProbeBootSource:
    """Scenario: the VM probe boots the newest PUBLISHED image — a merged beta
    matrix entry (ci:false, image not yet built) must not become the boot source
    (review F5: booting the nonexistent beta tag would flip the verdict to
    unknown daily until image-refresh publishes it)."""

    def test_merged_beta_entry_is_not_the_boot_source(self, tmp_path: Path) -> None:
        (tmp_path / "probe_result.json").write_text(json.dumps({"future": [FUTURE_2607]}), encoding="utf-8")
        env = _write_fakes(tmp_path)
        # sudo stub swallows the dep-install plumbing (udev, apt, tee).
        sudo = tmp_path / "sudo"
        sudo.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        sudo.chmod(0o755)
        # The step invokes the real probe script relative to the workspace.
        scripts_dir = tmp_path / "scripts"
        scripts_dir.mkdir()
        probe = ROOT / "scripts" / "beta-repo-probe.sh"
        (scripts_dir / "beta-repo-probe.sh").write_text(probe.read_text(encoding="utf-8"), encoding="utf-8")
        # Matrix already carries the merged (unbuilt) 26.07 beta entry.
        build_matrix = MATRIX_VERSIONS + [dict(MATRIX_VERSIONS[1], pfsense_version="26.07", status="beta", ci=False)]
        proc = subprocess.run(
            ["bash", "-c", _step_script(BETA_PROBE_STEP)],
            cwd=tmp_path,
            env=os.environ
            | env
            | {
                "BUILD_MATRIX": json.dumps(build_matrix),
                "SMOKE_SSH_PRIV_KEY": "dummy-key",
                "SMOKE_GHCR_USER": "u",
                "SMOKE_GHCR_TOKEN": "t",
                "SMOKE_IMAGE_REPO": "ghcr.io/pfblockerng",
                "GITHUB_REPOSITORY_OWNER": "pfBlockerNG",
            },
            check=True,
            capture_output=True,
            text=True,
        )
        out = proc.stdout + proc.stderr
        # Boot source = newest NON-beta entry (26.03), never the beta tag.
        assert "on ghcr.io/pfblockerng/pfsense-plus:26.03" in out
        assert "on ghcr.io/pfblockerng/pfsense-plus:26.07" not in out
        # The probe itself degrades to unknown here (no Plus identity in env).
        beta = json.loads((tmp_path / "beta_result.json").read_text(encoding="utf-8"))
        assert beta["Plus/26.07"]["verdict"] == "unknown"


class TestMatrixAutoPr:
    """Scenario: a detected beta / GA flip becomes one auto-PR against ci-metadata."""

    def _run(
        self,
        tmp_path: Path,
        *,
        beta: dict[str, Any] | None = None,
        ga_flips: list[dict[str, str]] | None = None,
        matrix_versions: list[dict[str, Any]] | None = None,
        future: dict[str, Any] | None = None,
        dry_run: str = "false",
    ) -> tuple[str, str, Path]:
        (tmp_path / "probe_result.json").write_text(
            json.dumps({"future": [future or FUTURE_2607], "ga_flips": ga_flips or []}), encoding="utf-8"
        )
        if beta is not None:
            (tmp_path / "beta_result.json").write_text(json.dumps(beta), encoding="utf-8")
        matrix_file = tmp_path / "fake-matrix.json"
        matrix_file.write_text(json.dumps({"versions": matrix_versions or MATRIX_VERSIONS}), encoding="utf-8")
        env = _write_fakes(tmp_path)
        subprocess.run(
            ["bash", "-c", _step_script(MATRIX_PR_STEP)],
            cwd=tmp_path,
            env=os.environ | env | {"FAKE_MATRIX": str(matrix_file), "DRY_RUN": dry_run},
            check=True,
            capture_output=True,
            text=True,
        )
        return _log(tmp_path, "git.log"), _log(tmp_path, "gh.log"), tmp_path

    BETA_YES = {"Plus/26.07": {"variant": "plus", "expect": "26.07", "verdict": "yes", "branch": "26.07"}}

    def test_beta_yes_builds_entry_and_opens_pr(self, tmp_path: Path) -> None:
        git_log, gh_log, cwd = self._run(tmp_path, beta=self.BETA_YES)
        assert "git push --force origin tracker/matrix-plus-26.07" in git_log
        assert "pr create" in gh_log
        new_matrix = json.loads((cwd / "supported-versions.json").read_text(encoding="utf-8"))
        entry = next(e for e in new_matrix["versions"] if e["pfsense_version"] == "26.07")
        assert entry["channel"] == "Plus"
        assert entry["status"] == "beta"
        assert entry["ci"] is False
        # carried from the newest same-channel amd64 sibling…
        assert entry["php_version"] == "8.5"
        assert entry["image_name"] == "pfsense-plus"
        assert "arch" not in entry
        # …page data wins for FreeBSD…
        assert entry["freebsd_version"] == "16.0-CURRENT@c215eef34550"
        assert entry["freebsd_major"] == "16"
        # …and the upgrade block wires the beta build
        assert entry["upgrade"] == {"available": True, "from": "26.03", "branch": "26.07", "target": "26.07"}
        prs = json.loads((cwd / "matrix_prs.json").read_text(encoding="utf-8"))
        assert prs["Plus/26.07"] == "77"

    def test_empty_page_freebsd_cells_fall_back_to_sibling(self, tmp_path: Path) -> None:
        # Final-pass F2: jq // treats "" as truthy — an empty/TBD FreeBSD cell
        # on the page must not overwrite the sibling's value in the proposed entry
        _, _, cwd = self._run(
            tmp_path,
            beta=self.BETA_YES,
            future=dict(FUTURE_2607, freebsd_version="", freebsd_major=""),
        )
        new_matrix = json.loads((cwd / "supported-versions.json").read_text(encoding="utf-8"))
        entry = next(e for e in new_matrix["versions"] if e["pfsense_version"] == "26.07")
        assert entry["freebsd_version"] == "16.0-RELEASE"
        assert entry["freebsd_major"] == "16"

    def test_existing_matrix_entry_skips_pr(self, tmp_path: Path) -> None:
        versions = MATRIX_VERSIONS + [dict(MATRIX_VERSIONS[1], pfsense_version="26.07", status="beta", ci=False)]
        git_log, gh_log, _ = self._run(tmp_path, beta=self.BETA_YES, matrix_versions=versions)
        assert "push" not in git_log
        assert "pr create" not in gh_log

    def test_beta_no_and_unknown_make_no_pr(self, tmp_path: Path) -> None:
        beta = {"Plus/26.07": {"variant": "plus", "expect": "26.07", "verdict": "no", "branch": ""}}
        git_log, gh_log, _ = self._run(tmp_path, beta=beta)
        assert "push" not in git_log
        assert "pr create" not in gh_log

    def test_ga_flip_rewrites_status(self, tmp_path: Path) -> None:
        git_log, gh_log, cwd = self._run(
            tmp_path,
            ga_flips=[{"version": "26.03", "channel": "Plus"}],
            matrix_versions=[dict(MATRIX_VERSIONS[1], status="beta")],
        )
        assert "git push --force origin tracker/matrix-plus-26.03-ga" in git_log
        assert "pr create" in gh_log
        new_matrix = json.loads((cwd / "supported-versions.json").read_text(encoding="utf-8"))
        assert new_matrix["versions"][0]["status"] == "active"

    def test_ga_flip_for_already_active_entry_is_skipped(self, tmp_path: Path) -> None:
        git_log, gh_log, _ = self._run(tmp_path, ga_flips=[{"version": "26.03", "channel": "Plus"}])
        assert "push" not in git_log
        assert "pr create" not in gh_log

    def test_dry_run_pushes_nothing(self, tmp_path: Path) -> None:
        git_log, gh_log, _ = self._run(tmp_path, beta=self.BETA_YES, dry_run="true")
        assert "push" not in git_log
        assert "pr create" not in gh_log
