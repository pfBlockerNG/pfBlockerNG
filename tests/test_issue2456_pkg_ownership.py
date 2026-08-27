from __future__ import annotations

import os
import subprocess
import textwrap
import unittest
from pathlib import Path

from tests._workflow_steps import extract_after, extract_before, extract_job, extract_step

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
PUBLISHED = (WORKFLOWS / "release-published.yml").read_text(encoding="utf-8")
REPUBLISH = (WORKFLOWS / "pkg-republish.yml").read_text(encoding="utf-8")
TAGGED = WORKFLOWS / "pkg-tagged-ingest.yml"
NIGHTLY = (WORKFLOWS / "nightly.yml").read_text(encoding="utf-8")
REPO_INSTALL = (WORKFLOWS / "repo-install.yml").read_text(encoding="utf-8")
README = (ROOT / "README.md").read_text(encoding="utf-8")


class SourcePublicationBoundaryTests(unittest.TestCase):
    def test_tagged_release_and_republish_call_the_same_pkg_orchestrator(self) -> None:
        tagged = TAGGED.read_text(encoding="utf-8")
        self.assertIn("workflow_call:", tagged)
        self.assertIn("scripts/dispatch-pkg-publication.sh", tagged)
        self.assertIn("operation=tagged-stage", tagged)
        self.assertIn("operation=tagged-promote", tagged)
        self.assertIn("operation=tagged-discard", tagged)
        self.assertIn("validate-live-pages-install", tagged)
        self.assertIn("smoke_repo_live_url:", tagged)
        expected_inputs = {
            "source_repository": "${{ needs.resolve.outputs.source_repository }}",
            "release_id": "${{ needs.resolve.outputs.release_id }}",
            "release_tag": "${{ needs.resolve.outputs.release_tag }}",
            "source_sha": "${{ needs.resolve.outputs.source_sha }}",
            "destinations": "${{ needs.resolve.outputs.destinations }}",
            "channel": "${{ needs.resolve.outputs.channel }}",
            "portversion": "${{ needs.resolve.outputs.portversion }}",
        }
        for caller in (PUBLISHED, REPUBLISH):
            job = extract_job(caller, "publish-pkg")
            self.assertIn("uses: ./.github/workflows/pkg-tagged-ingest.yml", job)
            for name, expression in expected_inputs.items():
                self.assertIn(f"{name}: {expression}", job)

        for workflow, jobs in (
            (TAGGED.read_text(encoding="utf-8"), ("stage-pkg", "finalize-pkg")),
            (NIGHTLY, ("ingest-pkg", "cleanup-nightly-oci")),
        ):
            for job_name in jobs:
                job = extract_job(workflow, job_name)
                self.assertIn("owner: pfBlockerNG", job)
                self.assertIn("repositories: pkg", job)
                self.assertIn("permission-actions: write", job)
                self.assertNotIn("permission-contents: write", job)
        self.assertNotIn("repository: pfBlockerNG/pkg", TAGGED.read_text(encoding="utf-8") + NIGHTLY)

    def test_nightly_pushes_digest_bound_oci_then_dispatches_and_validates_live(self) -> None:
        for needle in (
            "packages: write",
            "oras push",
            "--artifact-type application/vnd.pfblockerng.nightly.v1",
            "application/vnd.pfblockerng.nightly.handoff.v1+json",
            "application/vnd.pfblockerng.nightly.results.v1+tar+gzip",
            "artifact_ref=ghcr.io/pfblockerng/pfblockerng-nightly@sha256:",
            "operation=nightly",
            "operation=nightly-cleanup",
            "test_install_from_live_nightly_url",
        ):
            self.assertIn(needle, NIGHTLY)
        ingest = extract_job(NIGHTLY, "ingest-pkg")
        live = extract_job(NIGHTLY, "validate-live-pages-install")
        cleanup = extract_job(NIGHTLY, "cleanup-nightly-oci")
        digest = "needs.publish-nightly-oci.outputs.artifact_ref"
        self.assertIn("needs: [prepare, publish-nightly-oci]", ingest)
        self.assertIn(digest, ingest)
        self.assertIn("needs: [prepare, ingest-pkg]", live)
        publish = extract_job(NIGHTLY, "publish-nightly-oci")
        self.assertIn(
            "case \"$DIGEST_HEX\" in ''|*[!0-9a-f]*)",
            publish,
        )
        self.assertNotIn("sha256:[0-9a-f][0-9a-f]*", publish)
        self.assertIn("needs: [prepare, publish-nightly-oci, validate-live-pages-install]", cleanup)
        self.assertIn(digest, cleanup)
        self.assertNotRegex(ingest, r"artifact_ref:\s*ghcr\.io/.+:(?:latest|nightly)")
        self.assertLess(NIGHTLY.index("operation=nightly"), NIGHTLY.index("test_install_from_live_nightly_url"))
        self.assertLess(NIGHTLY.index("test_install_from_live_nightly_url"), NIGHTLY.index("operation=nightly-cleanup"))

    def test_tagged_finalize_depends_on_the_live_gate_and_discards_failure(self) -> None:
        tagged = TAGGED.read_text(encoding="utf-8")
        live = extract_job(tagged, "validate-live-pages-install")
        finalize = extract_job(tagged, "finalize-pkg")
        for contract in (
            "fail-fast: false",
            "pytest_marker: repo",
            "pytest_filter: test_install_from_live_pages_url",
            (
                "smoke_repo_live_url: https://pkg.pfblockerng.com/"
                "${{ needs.stage-pkg.outputs.staging_prefix }}/${{ matrix.channel }}"
            ),
            "smoke_repo_expected_source_sha: ${{ inputs.source_sha }}",
            "smoke_repo_expected_version: ${{ inputs.portversion }}",
            "smoke_repo_expected_channel: ${{ inputs.channel }}",
            "checkout_ref: ${{ github.workflow_sha }}",
        ):
            self.assertIn(contract, live)
        self.assertIn("needs: [stage-pkg, prepare-live-gate]", live)
        self.assertIn(
            "needs: [stage-pkg, prepare-live-gate, validate-live-pages-install]",
            finalize,
        )
        self.assertIn("needs.validate-live-pages-install.result == 'success'", finalize)
        self.assertIn("PKG_OPERATION=tagged-promote", finalize)
        self.assertIn("PKG_OPERATION=tagged-discard", finalize)
        self.assertIn("needs.stage-pkg.outputs.staging_prefix", finalize)
        self.assertIn(
            (
                "GATE_GREEN: ${{ needs.prepare-live-gate.result == 'success' && "
                "needs.validate-live-pages-install.result == 'success' }}"
            ),
            finalize,
        )
        step = extract_step(finalize, "Promote a green stage or discard every other outcome")
        script = extract_before(
            textwrap.dedent(extract_after(step, "        run: |\n")), "sh scripts/dispatch-pkg-publication.sh"
        )
        script += '\nprintf "%s\\n" "$PKG_OPERATION"\n'
        for gate_green, expected in (("true", "tagged-promote"), ("false", "tagged-discard")):
            completed = subprocess.run(
                ["sh", "-c", script],
                check=False,
                capture_output=True,
                text=True,
                env={**os.environ, "GATE_GREEN": gate_green},
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stdout.strip(), expected)

    def test_source_no_longer_owns_pkg_publisher_renderer_or_site(self) -> None:
        removed = (
            WORKFLOWS / "pkg-render-site.yml",
            ROOT / "scripts" / "publish-pkg-repo.sh",
            ROOT / "scripts" / "render-pkg-site.sh",
            ROOT / "scripts" / "gen_landing.py",
            ROOT / "pkg-site",
        )
        self.assertEqual([str(path.relative_to(ROOT)) for path in removed if path.exists()], [])
        for path in WORKFLOWS.glob("*.yml"):
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("repository: pfBlockerNG/pkg", text, path.name)
            self.assertNotIn("scripts/render-pkg-site.sh", text, path.name)
            self.assertNotIn("scripts/publish-pkg-repo.sh", text, path.name)
        all_workflows = "\n".join(path.read_text(encoding="utf-8") for path in WORKFLOWS.glob("*.yml"))
        self.assertNotIn("PUBLISH_REFRESH_LANDING", all_workflows)
        self.assertNotIn("refresh_landing", all_workflows)

    def test_scheduled_repo_install_never_uses_live_pages_urls(self) -> None:
        job = extract_job(REPO_INSTALL, "repo-install")
        self.assertNotIn("smoke_repo_live_url", job)
        self.assertNotIn("smoke_nightly_live_url", job)

    def test_source_readme_install_recipes_match_the_pkg_client_contract(self) -> None:
        for channel in ("stable", "edge"):
            self.assertIn(
                (
                    't=$(mktemp "${TMPDIR:-/tmp}/pfb-install.XXXXXX") && '
                    'fetch -T 60 -o "$t" https://pkg.pfblockerng.com/install.sh && '
                    '[ -s "$t" ] && '
                    f'/bin/sh "$t" --channel {channel}'
                    '; e=$?; [ -n "$t" ] && rm -f "$t"; (exit $e)'
                ),
                README,
            )

    def test_dispatch_helper_is_bounded_and_correlates_exact_run_title(self) -> None:
        helper = (ROOT / "scripts" / "dispatch-pkg-publication.sh").read_text(encoding="utf-8")
        self.assertIn("Ingest ${PKG_OPERATION} ${SOURCE_RUN_ID}", helper)
        self.assertIn("MAX_DISPATCH_ATTEMPTS", helper)
        self.assertIn("MAX_RUN_LOOKUPS", helper)
        self.assertNotIn("while " + ":; do", helper)
        self.assertIn('while [ "$attempt" -le "$MAX_DISPATCH_ATTEMPTS" ]; do', helper)
        self.assertIn("gh run watch", helper)
        self.assertIn("gh run download", helper)
        self.assertIn("publication-result", helper)
        self.assertNotIn("git push", helper)


def _run_dispatch(
    tmp_path: Path,
    *,
    dispatch_rc: int = 0,
    empty_lookup: bool = False,
    result_operation: str = "tagged-stage",
    result_run_id: str = "123:1",
    max_dispatch_attempts: str = "2",
    max_run_lookups: str = "2",
) -> tuple[subprocess.CompletedProcess[str], str, Path]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    gh_log = tmp_path / "gh.log"
    gh = bin_dir / "gh"
    gh.write_text(
        """#!/bin/sh
printf '%s\n' "$*" >> "$FAKE_GH_LOG"
case "$1 $2" in
  "workflow run") exit "$FAKE_DISPATCH_RC" ;;
  "run list")
    if [ "$FAKE_EMPTY_LOOKUP" = 1 ]; then
      printf '[]\n'
    else
      printf '[{"databaseId":40,"displayTitle":"Ingest %s %s",' \
        "$PKG_OPERATION" "$SOURCE_RUN_ID"
      printf '"createdAt":"0001-01-01T00:00:00Z"},'
      printf '{"databaseId":41,"displayTitle":"wrong title",'
      printf '"createdAt":"9999-01-01T00:00:00Z"},'
      printf '{"databaseId":42,"displayTitle":"Ingest %s %s",' \
        "$PKG_OPERATION" "$SOURCE_RUN_ID"
      printf '"createdAt":"9999-01-01T00:00:00Z"}]\n'
    fi
    ;;
  "run watch") exit 0 ;;
  "run download")
    while [ "$#" -gt 0 ]; do
      if [ "$1" = --dir ]; then shift; result_dir=$1; fi
      shift
    done
    mkdir -p "$result_dir"
    printf '{"operation":"%s","source_run_id":"%s"}\n' \
      "$FAKE_RESULT_OPERATION" "$FAKE_RESULT_RUN_ID" > "$result_dir/result.json"
    ;;
esac
""",
        encoding="utf-8",
    )
    gh.chmod(0o755)
    sleep = bin_dir / "sleep"
    sleep.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    sleep.chmod(0o755)
    result = tmp_path / "out" / "result.json"
    env = {
        **os.environ,
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "GH_TOKEN": "test-token",
        "PKG_OPERATION": "tagged-stage",
        "SOURCE_RUN_ID": "123:1",
        "SOURCE_REPOSITORY": "owner/repo",
        "RELEASE_ID": "123",
        "RELEASE_TAG": "v4.0.0",
        "SOURCE_SHA": "a" * 40,
        "DESTINATIONS": '["stable"]',
        "ARTIFACT_REF": "ghcr.io/pfblockerng/nightly@sha256:" + "b" * 64,
        "NIGHTLY_VERSION": "20260826010101.abcdef1",
        "STAGING_PREFIX": "staging/123-1",
        "RESULT_FILE": str(result),
        "MAX_DISPATCH_ATTEMPTS": max_dispatch_attempts,
        "MAX_RUN_LOOKUPS": max_run_lookups,
        "FAKE_GH_LOG": str(gh_log),
        "FAKE_DISPATCH_RC": str(dispatch_rc),
        "FAKE_EMPTY_LOOKUP": "1" if empty_lookup else "0",
        "FAKE_RESULT_RUN_ID": result_run_id,
        "FAKE_RESULT_OPERATION": result_operation,
    }
    proc = subprocess.run(
        ["sh", str(ROOT / "scripts" / "dispatch-pkg-publication.sh")],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    calls = gh_log.read_text(encoding="utf-8") if gh_log.exists() else ""
    return proc, calls, result


def test_dispatch_helper_accepts_only_the_correlated_result(tmp_path: Path) -> None:
    proc, calls, result = _run_dispatch(tmp_path)
    assert proc.returncode == 0, proc.stderr
    dispatch = next(line for line in calls.splitlines() if line.startswith("workflow run "))
    for argument in (
        "ingest.yml",
        "-R pfBlockerNG/pkg",
        "--ref main",
        "-f operation=tagged-stage",
        "-f source_repository=owner/repo",
        "-f release_id=123",
        "-f release_tag=v4.0.0",
        "-f source_sha=" + "a" * 40,
        '-f destinations=["stable"]',
        "-f source_run_id=123:1",
        "-f artifact_ref=ghcr.io/pfblockerng/nightly@sha256:" + "b" * 64,
        "-f nightly_version=20260826010101.abcdef1",
        "-f staging_prefix=staging/123-1",
    ):
        assert argument in dispatch
    assert "run watch 42" in calls
    assert "run download 42" in calls
    assert result.read_text(encoding="utf-8").strip() == ('{"operation":"tagged-stage","source_run_id":"123:1"}')


def test_dispatch_helper_stops_after_bounded_dispatch_failures(tmp_path: Path) -> None:
    proc, calls, result = _run_dispatch(tmp_path, dispatch_rc=1)
    assert proc.returncode == 1
    assert "dispatch failed after 2 attempts" in proc.stderr
    assert calls.count("workflow run ") == 2
    assert not result.exists()


def test_dispatch_helper_stops_after_bounded_run_lookups(tmp_path: Path) -> None:
    proc, calls, result = _run_dispatch(tmp_path, empty_lookup=True)
    assert proc.returncode == 1
    assert "could not correlate pkg run titled Ingest tagged-stage 123:1" in proc.stderr
    assert calls.count("run list ") == 2
    assert not result.exists()


def test_dispatch_helper_rejects_mismatched_result_identity(tmp_path: Path) -> None:
    proc, _, result = _run_dispatch(tmp_path, result_run_id="999:1")
    assert proc.returncode == 1
    assert "source_run_id mismatch" in proc.stderr
    assert not result.exists()


def test_dispatch_helper_rejects_mismatched_result_operation(tmp_path: Path) -> None:
    proc, _, result = _run_dispatch(tmp_path, result_operation="tagged-promote")
    assert proc.returncode == 1
    assert "operation mismatch" in proc.stderr
    assert not result.exists()


def test_dispatch_helper_rejects_invalid_bounds_before_gh(tmp_path: Path) -> None:
    cases: tuple[tuple[str, str, str], ...] = (
        ("zero-dispatch", "0", "2"),
        ("nonnumeric-dispatch", "x", "2"),
        ("zero-lookup", "2", "0"),
    )
    for name, max_dispatch, max_lookups in cases:
        proc, calls, result = _run_dispatch(
            tmp_path / name,
            max_dispatch_attempts=max_dispatch,
            max_run_lookups=max_lookups,
        )
        assert proc.returncode == 1
        assert "dispatch bounds must be positive integers" in proc.stderr
        assert calls == ""
        assert not result.exists()


if __name__ == "__main__":
    unittest.main()
