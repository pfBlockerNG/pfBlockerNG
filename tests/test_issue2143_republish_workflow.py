"""Issue #2143 exact-identity republish callback reproduction."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))

from _workflow_steps import extract_job, extract_step

REPUBLISH = (ROOT / ".github/workflows/pkg-republish.yml").read_text(encoding="utf-8")
PUBLISHED = (ROOT / ".github/workflows/release-published.yml").read_text(encoding="utf-8")

# Per-workflow forwarded VALUE expressions for the pkg-catalogue-dispatch step's
# identity keys — release-published.yml resolves them from the `resolve` job's
# outputs, pkg-republish.yml from its own dispatch inputs plus the ambient
# repository. A key-name-only assertion would still pass if either were
# forwarded from the WRONG source. release-published.yml renamed its step
# "Stage the pkg catalogue" (issue #2389: gate-before-announce); pkg-republish.yml's
# is untouched and stays "Publish the pkg catalogue".
# The job each workflow runs publish-pkg-repo.sh from. release-published.yml
# also runs it from `promote-pkg-repo`, which never invokes the publisher and
# must therefore never see the signing key.
_SIGN_KEY_JOBS = {
    PUBLISHED: "publish-pkg-repo",
    REPUBLISH: "publish",
}
_STEP_NAMES = {
    PUBLISHED: "Stage the pkg catalogue",
    REPUBLISH: "Publish the pkg catalogue",
}
_IDENTITY_VALUES = {
    PUBLISHED: {
        "SOURCE_REPOSITORY": "${{ needs.resolve.outputs.source_repository }}",
        "RELEASE_ID": "${{ needs.resolve.outputs.release_id }}",
        "RELEASE_TAG": "${{ needs.resolve.outputs.release_tag }}",
    },
    REPUBLISH: {
        "SOURCE_REPOSITORY": "${{ github.repository }}",
        "RELEASE_ID": "${{ inputs.release_id }}",
        "RELEASE_TAG": "${{ inputs.release_tag }}",
    },
}
_SOURCE_RUN_ID_VALUE = "${{ github.run_id }}:${{ github.run_attempt }}"
_SOURCE_SHA_VALUES = {
    PUBLISHED: "${{ needs.resolve.outputs.source_sha }}",
    REPUBLISH: "${{ steps.resolve.outputs.source_sha }}",
}
_HANDOFF_NAME = "pfblockerng-release-handoff.json"

# issue #2675 step 1: PFB_PKG_SIGNING_KEY (the Actions secret) is materialised to
# this exact path, then handed to publish-pkg-repo.sh as PFB_SIGN_KEY — never
# echoed, never passed on a command line.
_SIGN_KEY_PATH = "${RUNNER_TEMP}/pfb-pkg-signing.key"


def test_manual_republish_requires_exact_release_identity() -> None:
    assert "release_id:" in REPUBLISH
    assert "release_tag:" in REPUBLISH
    assert "required: true" in REPUBLISH
    assert "source_repository:" not in REPUBLISH.split("on:", 1)[1].split("jobs:", 1)[0]
    assert "gh release list" not in REPUBLISH


def test_republish_and_published_callbacks_forward_exact_run_identity() -> None:
    # The retired `gh workflow run publish.yml -f <name>=<value>` dispatch was replaced
    # by an in-repo job that forwards the same identity via env vars on the
    # pkg-catalogue-dispatch step (see _STEP_NAMES).
    for workflow, expected in _IDENTITY_VALUES.items():
        step = extract_step(workflow, _STEP_NAMES[workflow])
        for key, value in expected.items():
            assert f"{key}: {value}" in step
        assert f"SOURCE_RUN_ID: {_SOURCE_RUN_ID_VALUE}" in step
        assert "gh release list" not in workflow


def test_tagged_publishers_consume_the_release_handoff_not_live_ci_metadata() -> None:
    for workflow, job_name in _SIGN_KEY_JOBS.items():
        job = extract_job(workflow, job_name)
        assert "refs/heads/ci-metadata" not in job
        assert "read-version-matrix.sh --print-route" not in job

        download = extract_step(job, "Download release assets + build the digest sidecar")
        assert f"HANDOFF_NAME: {_HANDOFF_NAME}" in download
        assert "gh release download" in download
        assert '--pattern "$HANDOFF_NAME"' in download

        publish = extract_step(job, _STEP_NAMES[workflow])
        assert f"SOURCE_SHA: {_SOURCE_SHA_VALUES[workflow]}" in publish
        assert "ROUTE_MATRIX:" not in publish
        assert f'export HANDOFF_FILE="$RUNNER_TEMP/assets/{_HANDOFF_NAME}"' in publish


def test_publish_step_wires_pfb_sign_key_from_materialised_secret() -> None:
    """issue #2675: both workflows materialise PFB_PKG_SIGNING_KEY to a file
    BEFORE the publish/stage step, and that step exports PFB_SIGN_KEY at the
    same path so publish-pkg-repo.sh signs the catalogue it (re)generates.

    Scoped to the job that runs the step, never the whole file:
    release-published.yml runs publish-pkg-repo.sh from two jobs, so a
    file-global index could pair the key with the promote job that must never
    receive it. The `umask` is asserted with the redirect because the key is a
    private half — a default-umask file would be world-readable.
    """
    for workflow, job_name in _SIGN_KEY_JOBS.items():
        step_name = _STEP_NAMES[workflow]
        job = extract_job(workflow, job_name)
        assert "secrets.PFB_PKG_SIGNING_KEY" in job
        materialise_index = job.index("secrets.PFB_PKG_SIGNING_KEY")
        assert "umask 077" in job
        assert f'> "{_SIGN_KEY_PATH}"' in job

        step = extract_step(job, step_name)
        assert f'export PFB_SIGN_KEY="{_SIGN_KEY_PATH}"' in step

        publish_step_index = job.index(f"- name: {step_name}")
        assert materialise_index < publish_step_index, (
            f"{step_name}: the signing key must be materialised before this step runs"
        )
        assert "secrets.PFB_PKG_SIGNING_KEY" not in extract_job(workflow, "render-site")


def test_manual_republish_rejects_release_selector_before_api(tmp_path: Path) -> None:
    marker = tmp_path / "gh-called"
    gh = tmp_path / "gh"
    gh.write_text(
        '#!/bin/sh\ntouch "$GH_CALLED"\nprintf \'%s\\n\' \'{"tag_name":"v4.0.0","draft":false}\'\n',
        encoding="utf-8",
    )
    gh.chmod(0o755)
    script = textwrap.dedent(REPUBLISH.split("        run: |\n", 1)[1].split("      - uses:", 1)[0])
    completed = subprocess.run(
        ["sh", "-c", script],
        cwd=ROOT,
        env=os.environ
        | {
            "PATH": f"{tmp_path}:{os.environ.get('PATH', '')}",
            "GH_CALLED": str(marker),
            "RELEASE_ID": "tags/v4.0.0",
            "RELEASE_TAG": "v4.0.0",
            "REPOSITORY": "owner/repo",
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode != 0
    assert not marker.exists()


def test_tagged_callbacks_execute_handoff_asset_checks(tmp_path: Path) -> None:
    handoff = tmp_path / _HANDOFF_NAME
    handoff.write_text('{"schema":1}\n', encoding="utf-8")
    digest = hashlib.sha256(handoff.read_bytes()).hexdigest()
    gh = tmp_path / "gh"
    gh.write_text(
        textwrap.dedent(
            """\
            #!/bin/sh
            printf '%s\n' "$*" >> "$GH_LOG"
            if [ "$1" = api ]; then
              cat "$META_FILE"
              exit
            fi
            shift 3
            pattern=
            destination=
            while [ "$#" -gt 0 ]; do
              case "$1" in
                --pattern) pattern=$2; shift 2 ;;
                --dir) destination=$2; shift 2 ;;
                *) shift ;;
              esac
            done
            mkdir -p "$destination"
            case "$pattern" in
              '*.pkg') printf pkg > "$destination/test.pkg" ;;
              *) cp "$HANDOFF_SOURCE" "$destination/$pattern" ;;
            esac
            """
        ),
        encoding="utf-8",
    )
    gh.chmod(0o755)

    for workflow, job_name in _SIGN_KEY_JOBS.items():
        script = textwrap.dedent(
            extract_step(extract_job(workflow, job_name), "Download release assets + build the digest sidecar").split(
                "run: |\n", 1
            )[1]
        )
        for handoff_assets, expected in (
            ([], 1),
            ([{"name": _HANDOFF_NAME, "digest": f"sha256:{digest}"}], 0),
            (
                [
                    {"name": _HANDOFF_NAME, "digest": f"sha256:{digest}"},
                    {"name": _HANDOFF_NAME, "digest": f"sha256:{digest}"},
                ],
                1,
            ),
            ([{"name": _HANDOFF_NAME, "digest": "sha256:" + "0" * 64}], 1),
        ):
            meta = tmp_path / "meta.json"
            meta.write_text(
                json.dumps(
                    {
                        "assets": [
                            {"name": "test.pkg", "digest": "sha256:" + "1" * 64},
                            *handoff_assets,
                        ]
                    }
                ),
                encoding="utf-8",
            )
            runner_temp = tmp_path / f"runner-{len(handoff_assets)}-{expected}"
            gh_log = tmp_path / "gh.log"
            gh_log.write_text("", encoding="utf-8")
            completed = subprocess.run(
                ["sh", "-c", script],
                cwd=ROOT,
                env=os.environ
                | {
                    "PATH": f"{tmp_path}:{os.environ.get('PATH', '')}",
                    "GH_TOKEN": "token",
                    "REPOSITORY": "pfBlockerNG/pfBlockerNG",
                    "RELEASE_ID": "1",
                    "RELEASE_TAG": "v4.0.0",
                    "HANDOFF_NAME": _HANDOFF_NAME,
                    "HANDOFF_SOURCE": str(handoff),
                    "META_FILE": str(meta),
                    "GH_LOG": str(gh_log),
                    "RUNNER_TEMP": str(runner_temp),
                },
                capture_output=True,
                text=True,
                check=False,
            )
            assert (completed.returncode == 0) == (expected == 0), completed.stdout + completed.stderr
            if expected == 0:
                calls = gh_log.read_text(encoding="utf-8")
                assert "api repos/pfBlockerNG/pfBlockerNG/releases/1" in calls
                assert "release download v4.0.0 -R pfBlockerNG/pfBlockerNG" in calls
