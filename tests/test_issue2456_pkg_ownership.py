from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
PUBLISHED = (WORKFLOWS / "release-published.yml").read_text(encoding="utf-8")
REPUBLISH = (WORKFLOWS / "pkg-republish.yml").read_text(encoding="utf-8")
TAGGED = WORKFLOWS / "pkg-tagged-ingest.yml"
NIGHTLY = (WORKFLOWS / "nightly.yml").read_text(encoding="utf-8")


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
        self.assertIn("needs.stage-pkg.outputs.staging_prefix", tagged)
        self.assertIn("needs.stage-pkg.outputs.noop != 'true'", tagged)
        for caller in (PUBLISHED, REPUBLISH):
            self.assertIn("uses: ./.github/workflows/pkg-tagged-ingest.yml", caller)

    def test_pkg_dispatch_token_cannot_write_pkg_contents(self) -> None:
        surfaces = TAGGED.read_text(encoding="utf-8") + NIGHTLY
        self.assertIn("permission-actions: write", surfaces)
        self.assertNotRegex(surfaces, r"repositories: pkg(?s:.*?)permission-contents: write")
        self.assertNotIn("repository: pfBlockerNG/pkg", surfaces)
        self.assertNotIn("persist-credentials: true # publish-pkg-repo", surfaces)

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
        self.assertLess(NIGHTLY.index("operation=nightly"), NIGHTLY.index("test_install_from_live_nightly_url"))
        self.assertLess(NIGHTLY.index("test_install_from_live_nightly_url"), NIGHTLY.index("operation=nightly-cleanup"))
        self.assertNotRegex(NIGHTLY, r"oras pull .*:(?:latest|nightly)")

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

    def test_dispatch_helper_is_bounded_and_correlates_exact_run_title(self) -> None:
        helper = (ROOT / "scripts" / "dispatch-pkg-publication.sh").read_text(encoding="utf-8")
        self.assertIn("Ingest ${PKG_OPERATION} ${SOURCE_RUN_ID}", helper)
        self.assertIn("MAX_DISPATCH_ATTEMPTS", helper)
        self.assertIn("MAX_RUN_LOOKUPS", helper)
        self.assertIn("gh run watch", helper)
        self.assertIn("gh run download", helper)
        self.assertIn("publication-result", helper)
        self.assertNotIn("git push", helper)


if __name__ == "__main__":
    unittest.main()
