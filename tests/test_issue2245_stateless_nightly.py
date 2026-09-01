"""Issue #2245: every Nightly run builds a stateless timestamped snapshot."""

from pathlib import Path

import pytest
import yaml

from scripts import release_version as rv
from tests import test_issue2231_workflow_hygiene as hygiene

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "nightly.yml"
ACTIONLINT_CONFIG = ROOT / ".github" / "actionlint.yaml"
SOURCE_SHA = "a" * 40
VERSION = f"20260814153045.{SOURCE_SHA[:7]}"


def test_nightly_version_is_utc_seconds_plus_short_source_sha() -> None:
    assert rv.validate_nightly_version(VERSION, source_sha=SOURCE_SHA) == VERSION


def test_every_nightly_invocation_builds_without_durable_state() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")

    assert 'TOOLS_SHA="$(git -C "$TRUSTED_DIR" rev-parse HEAD)"' in workflow
    assert 'SOURCE_SHA="$(git -C "$SOURCE_DIR" rev-parse HEAD)"' in workflow
    assert 'PKG_VERSION="$(sh "$TRUSTED_DIR/scripts/nightly-pkgversion.sh" "$SOURCE_SHA")"' in workflow
    assert "queue: max" in workflow
    assert "nightly-state" not in workflow
    assert 'nightly_provenance.py" allocate' not in workflow
    assert 'nightly_provenance.py" complete' not in workflow
    assert "needs.prepare.outputs.outcome" not in workflow


def test_actionlint_exception_is_narrowly_scoped_to_workflows_using_queue_max() -> None:
    queue_error = 'unexpected key "queue" for "concurrency" section'
    assert yaml.safe_load(ACTIONLINT_CONFIG.read_text(encoding="utf-8")) == {
        "paths": {
            ".github/workflows/nightly.yml": {"ignore": [queue_error]},
            ".github/workflows/release-published.yml": {"ignore": [queue_error]},
            ".github/workflows/pkg-republish.yml": {"ignore": [queue_error]},
            ".github/workflows/release.yml": {"ignore": [queue_error]},
            ".github/workflows/image-refresh.yml": {"ignore": [queue_error]},
            ".github/workflows/nightly-failure-alert.yml": {"ignore": [queue_error]},
            ".github/workflows/smoke.yml": {"ignore": [queue_error]},
            ".github/workflows/ui-tests.yml": {"ignore": [queue_error]},
        }
    }


def test_workflow_hygiene_discovery_fails_closed_when_no_files_are_found(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(hygiene, "ROOT", tmp_path)
    with pytest.raises(AssertionError, match=r"no workflow files discovered under"):
        hygiene._workflow_sources()


def test_workflow_hygiene_tracks_each_reusable_call_instance() -> None:
    sources = {
        "consumer.yml": """\
on: workflow_call
inputs:
  selector: {type: string}
jobs:
  download:
    steps:
      - uses: actions/download-artifact@v8
        with: {name: "${{ inputs.selector }}"}
""",
        "root.yml": """\
name: Root
on: workflow_dispatch
jobs:
  upload:
    steps:
      - uses: actions/upload-artifact@v8
        with: {name: present}
  good:
    needs: upload
    uses: ./.github/workflows/consumer.yml
    with: {selector: present}
  bad:
    needs: upload
    uses: ./.github/workflows/consumer.yml
    with: {selector: missing}
""",
    }
    assert hygiene._artifact_chain_offences(sources) == [
        "consumer.yml:download:step-0: rule=artifact-major: no producer matches ['missing']"
    ]


def test_workflow_hygiene_parses_semver_and_rejects_unclassified_action_refs() -> None:
    sources = {
        "semver.yml": """\
on: workflow_dispatch
jobs:
  upload:
    steps:
      - uses: actions/upload-artifact@v7.1.2
        with: {name: pkg}
  download:
    needs: upload
    steps:
      - uses: actions/download-artifact@v8.0.0
        with: {name: pkg}
""",
    }
    assert hygiene._artifact_chain_offences(sources) == [
        "semver.yml:download:step-0: rule=artifact-major: download v8 mismatches producers "
        "[('semver.yml', 'upload', 7)]"
    ]
    with pytest.raises(
        AssertionError, match=r"unknown.yml:upload:step-0: rule=artifact-major: unclassified action ref"
    ):
        hygiene._artifact_chain_offences(
            {
                "unknown.yml": """\
on: workflow_dispatch
jobs:
  upload:
    steps:
      - uses: actions/upload-artifact@main
        with: {name: pkg}
"""
            }
        )


def test_workflow_hygiene_handles_docker_globals_local_values_and_image_boundary() -> None:
    sources = {
        "scripts/global.sh": """\
docker --context remote run alpine
docker run --workdir /tmp --init alpine
docker run --workdir /tmp alpine
docker run --user 1000 --init alpine
docker run --user 1000 alpine
docker run --mount type=tmpfs,dst=/tmp --init alpine
docker run --mount type=tmpfs,dst=/tmp alpine
runtime=docker
"$runtime" run alpine
""",
        "tests/smoke/local.py": """\
import subprocess

def command():
    return ["docker", "run", "alpine"]

def invoke():
    argv = ["docker", "run", "alpine"]
    subprocess.run(argv)
    subprocess.run(command())
""",
        "scripts/variable.php": """\
<?php
$cmd = "docker run alpine";
system($cmd);
""",
    }
    assert hygiene._docker_run_offences(sources) == [
        "scripts/global.sh:1: rule=docker-init: docker run must include exact token --init",
        "scripts/global.sh:3: rule=docker-init: docker run must include exact token --init",
        "scripts/global.sh:5: rule=docker-init: docker run must include exact token --init",
        "scripts/global.sh:7: rule=docker-init: docker run must include exact token --init",
        "scripts/global.sh:9: rule=docker-init: docker run must include exact token --init",
        "tests/smoke/local.py:8: rule=docker-init: docker run must include exact token --init",
        "tests/smoke/local.py:9: rule=docker-init: docker run must include exact token --init",
        "scripts/variable.php:3: rule=docker-init: docker run must include exact token --init",
    ]


def test_workflow_hygiene_rejects_derived_fake_multiline_and_readonly_sinks() -> None:
    sources = {
        "derived.yml": """\
on: workflow_dispatch
jobs:
  prepare:
    outputs:
      source_sha: ${{ steps.pin.outputs.source_sha }}
    steps:
      - id: pin
  build:
    needs: prepare
    outputs:
      sha: ${{ needs.prepare.outputs.source_sha }}
    with:
      ref: ${{ needs.prepare.outputs.source_sha || github.ref }}
""",
        "untrusted.yml": """\
on: workflow_dispatch
jobs:
  prepare:
    outputs:
      source_sha: ${{ steps.pin.outputs.source_sha }}
    steps:
      - id: pin
  build:
    needs: prepare
    with:
      ref: ${{ needs.prepare.outputs.source_sha || needs.untrusted.outputs.sha }}
""",
        "readonly.yml": """\
on: workflow_dispatch
jobs:
  prepare:
    outputs:
      ports_sha: ${{ steps.pin.outputs.ports_sha }}
    steps:
      - id: pin
  build:
    needs: prepare
    steps:
      - env:
          PORTS_SHA: ${{ needs.prepare.outputs.ports_sha }}
        run: |
          readonly PORTS_SHA=$(git ls-remote origin main)
          git checkout \"$PORTS_SHA\"
""",
        "multiline.yml": """\
on: workflow_dispatch
jobs:
  prepare:
    outputs:
      ports_sha: ${{ steps.pin.outputs.ports_sha }}
    steps:
      - id: pin
  build:
    needs: prepare
    steps:
      - env:
          PORTS_SHA: ${{ needs.prepare.outputs.ports_sha }}
        run: |
          git show \"$PORTS_SHA:Makefile\"
          FRESH=\"$(
            git ls-remote origin main
          )\"
          build-leg.sh --ports-ref \"$FRESH\"
      - env:
          PORTS_SHA: ${{ needs.prepare.outputs.ports_sha }}
        run: |
          readonly PORTS_SHA=$(git ls-remote origin main)
          git checkout \"$PORTS_SHA\"
""",
    }
    offences = hygiene._pin_offences(sources)
    assert any("derived.yml:prepare.source_sha: rule=pin-consumer: pin is not consumed" in item for item in offences)
    assert any("untrusted.yml:prepare.source_sha: rule=pin-consumer: pin is not consumed" in item for item in offences)
    assert any(
        "readonly.yml:build: rule=pin-consumer: live git ls-remote replaces prepare.ports_sha" in item
        for item in offences
    )
    assert any(
        "multiline.yml:build: rule=pin-consumer: live git ls-remote replaces prepare.ports_sha" in item
        for item in offences
    )


@pytest.mark.parametrize(
    "sink",
    (
        '${{ format("refs/heads/{0}", needs.prepare.outputs.source_sha) }}',
        "${{ needs.prepare.outputs.source_sha }}${{ '' }}",
        "${{ needs.prepare.outputs.source_sha || 'main' }}",
    ),
)
def test_workflow_hygiene_rejects_derived_pin_expressions(sink: str) -> None:
    source = """\
on: workflow_dispatch
jobs:
  prepare:
    outputs:
      source_sha: ${{ steps.pin.outputs.source_sha }}
    steps:
      - id: pin
  build:
    needs: prepare
    with:
      ref: PIN_SINK
""".replace("PIN_SINK", sink)
    assert hygiene._pin_offences({"derived.yml": source}) == [
        "derived.yml:prepare.source_sha: rule=pin-consumer: pin is not consumed by a ref/identity sink"
    ]


def test_workflow_hygiene_rejects_job_output_as_fake_identity_sink() -> None:
    source = """\
on: workflow_dispatch
jobs:
  prepare:
    outputs:
      source_sha: ${{ steps.pin.outputs.source_sha }}
    steps:
      - id: pin
  build:
    needs: prepare
    outputs:
      sha: ${{ needs.prepare.outputs.source_sha }}
"""
    assert hygiene._pin_offences({"fake-output.yml": source}) == [
        "fake-output.yml:prepare.source_sha: rule=pin-consumer: pin is not consumed by a ref/identity sink"
    ]


def test_workflow_hygiene_accepts_semver_refs_in_uncalled_reusable_workflows() -> None:
    source = """\
on: workflow_call
jobs:
  upload:
    steps:
      - uses: actions/upload-artifact@v7.1.2
        with: {name: pkg}
"""
    assert hygiene._artifact_chain_offences({"reusable.yml": source}) == []


def test_workflow_hygiene_rejects_main_refs_in_uncalled_reusable_workflows() -> None:
    source = """\
on: workflow_call
jobs:
  upload:
    steps:
      - uses: actions/upload-artifact@main
        with: {name: pkg}
"""
    with pytest.raises(
        AssertionError, match=r"reusable.yml:upload:step-0: rule=artifact-major: unclassified action ref"
    ):
        hygiene._artifact_chain_offences({"reusable.yml": source})


def test_workflow_hygiene_checks_uncalled_reusable_artifact_chains() -> None:
    source = """\
on: workflow_call
jobs:
  upload:
    steps:
      - uses: actions/upload-artifact@v7
        with: {name: pkg}
  download:
    needs: upload
    steps:
      - uses: actions/download-artifact@v8
        with: {name: pkg}
"""
    assert hygiene._artifact_chain_offences({"reusable.yml": source}) == [
        "reusable.yml:download:step-0: rule=artifact-major: "
        "download v8 mismatches producers [('reusable.yml', 'upload', 7)]"
    ]


@pytest.mark.parametrize(
    "value",
    (
        "refs/heads/${{ needs.prepare.outputs.source_sha }}",
        "${{ needs.prepare.outputs.source_sha || github.sha }}",
    ),
)
def test_workflow_hygiene_rejects_derived_and_fallback_job_env_aliases(value: str) -> None:
    source = """\
on: workflow_dispatch
jobs:
  prepare:
    outputs:
      source_sha: ${{ steps.pin.outputs.source_sha }}
    steps:
      - id: pin
  build:
    needs: prepare
    env:
      SOURCE_SHA: VALUE
    steps:
      - run: git checkout "$SOURCE_SHA"
""".replace("VALUE", value)
    assert hygiene._pin_offences({"job-env.yml": source}) == [
        "job-env.yml:prepare.source_sha: rule=pin-consumer: pin is not consumed by a ref/identity sink"
    ]


def test_workflow_hygiene_step_env_shadow_overrides_exact_job_env_alias() -> None:
    source = """\
on: workflow_dispatch
jobs:
  prepare:
    outputs:
      source_sha: ${{ steps.pin.outputs.source_sha }}
    steps:
      - id: pin
  build:
    needs: prepare
    env:
      SOURCE_SHA: ${{ needs.prepare.outputs.source_sha }}
    steps:
      - env:
          SOURCE_SHA: main
        run: git checkout "$SOURCE_SHA"
"""
    assert hygiene._pin_offences({"shadow.yml": source}) == [
        "shadow.yml:prepare.source_sha: rule=pin-consumer: pin is not consumed by a ref/identity sink"
    ]


@pytest.mark.parametrize(
    "identity_command",
    (
        'git checkout "$PORTS_SHA"',
        'git show "$PORTS_SHA:Makefile"',
        'git switch "$PORTS_SHA"',
        'git reset "$PORTS_SHA"',
    ),
)
def test_workflow_hygiene_reports_readonly_live_replacement_at_git_identity_sinks(
    identity_command: str,
) -> None:
    source = """\
on: workflow_dispatch
jobs:
  prepare:
    outputs:
      ports_sha: ${{ steps.pin.outputs.ports_sha }}
    steps:
      - id: pin
  build:
    needs: prepare
    steps:
      - env:
          PORTS_SHA: ${{ needs.prepare.outputs.ports_sha }}
        run: |
          readonly PORTS_SHA=$(git ls-remote origin main)
          IDENTITY_COMMAND
""".replace("IDENTITY_COMMAND", identity_command)
    offences = hygiene._pin_offences({"readonly.yml": source})
    command = identity_command.split()[1]
    assert (
        "readonly.yml:build: rule=pin-consumer: live git ls-remote replaces "
        f"prepare.ports_sha at identity sink git {command}"
    ) in offences


def test_workflow_hygiene_reports_readonly_live_identity_aliases() -> None:
    source = """\
on: workflow_dispatch
jobs:
  prepare:
    outputs:
      ports_sha: ${{ steps.pin.outputs.ports_sha }}
    steps:
      - id: pin
  build:
    needs: prepare
    steps:
      - env:
          PORTS_SHA: ${{ needs.prepare.outputs.ports_sha }}
        run: |
          readonly CHECKOUT_REF=$(git ls-remote origin main)
          git checkout "$CHECKOUT_REF"
"""
    offences = hygiene._pin_offences({"readonly-alias.yml": source})
    assert (
        "readonly-alias.yml:build: rule=pin-consumer: live git ls-remote replaces "
        "prepare.ports_sha at identity sink git checkout"
    ) in offences


def test_workflow_hygiene_consumes_docker_global_short_option_values_before_run() -> None:
    source = """\
docker -c remote run --init alpine
docker -c remote run alpine
docker -l debug run --init alpine
docker -l debug run alpine
"""
    assert hygiene._docker_run_offences({"scripts/global-short.sh": source}) == [
        "scripts/global-short.sh:2: rule=docker-init: docker run must include exact token --init",
        "scripts/global-short.sh:4: rule=docker-init: docker run must include exact token --init",
    ]


def test_workflow_hygiene_resolves_nested_and_chained_python_factories() -> None:
    source = """\
import subprocess

def leaf():
    return ["docker", "run", "alpine"]

def chain():
    return leaf()

def outer():
    def inner():
        return ["docker", "run", "alpine"]
    return inner()

def local():
    argv = ["docker", "run", "alpine"]
    return argv

subprocess.run(chain())
subprocess.run(outer())
subprocess.run(local())
"""
    assert hygiene._docker_run_offences({"tests/smoke/factories.py": source}) == [
        "tests/smoke/factories.py:18: rule=docker-init: docker run must include exact token --init",
        "tests/smoke/factories.py:19: rule=docker-init: docker run must include exact token --init",
        "tests/smoke/factories.py:20: rule=docker-init: docker run must include exact token --init",
    ]


def test_workflow_hygiene_duplicate_display_name_diagnostics_pin_both_producers() -> None:
    sources = {
        "one.yml": """\
name: Producer
on: workflow_dispatch
jobs:
  upload:
    steps:
      - uses: actions/upload-artifact@v7
        with: {name: pkg}
""",
        "two.yml": """\
name: Producer
on: workflow_dispatch
jobs:
  upload:
    steps:
      - uses: actions/upload-artifact@v8
        with: {name: pkg}
""",
        "callback.yml": """\
on:
  workflow_run:
    workflows: [Producer]
jobs:
  consume:
    steps:
      - uses: actions/download-artifact@v8
        with: {name: pkg}
""",
    }
    assert hygiene._artifact_chain_offences(sources) == [
        "callback.yml:consume:step-0: rule=artifact-major: ambiguous producers for 'pkg': "
        "[('one.yml', 'upload'), ('two.yml', 'upload')]",
        "callback.yml:consume:step-0: rule=artifact-major: download v8 mismatches producers [('one.yml', 'upload', 7)]",
    ]


def test_workflow_hygiene_scans_merge_group_artifact_graphs() -> None:
    source = """\
on: merge_group
jobs:
  upload:
    steps:
      - uses: actions/upload-artifact@v7
        with: {name: pkg}
  download:
    needs: upload
    steps:
      - uses: actions/download-artifact@v8
        with: {name: pkg}
"""
    assert hygiene._artifact_chain_offences({"merge.yml": source}) == [
        "merge.yml:download:step-0: rule=artifact-major: download v8 mismatches producers [('merge.yml', 'upload', 7)]"
    ]


def test_workflow_hygiene_rejects_init_after_docker_option_terminator() -> None:
    assert hygiene._docker_run_offences({"scripts/boundary.sh": "docker run -- --init\n"}) == [
        "scripts/boundary.sh:1: rule=docker-init: docker run must include exact token --init"
    ]


def test_workflow_hygiene_scans_python_subprocess_args_keywords() -> None:
    source = """\
import subprocess
from subprocess import run

subprocess.run(args=["docker", "run", "alpine"])
run(args=["docker", "run", "alpine"])
"""
    assert hygiene._docker_run_offences({"tests/smoke/keyword.py": source}) == [
        "tests/smoke/keyword.py:4: rule=docker-init: docker run must include exact token --init",
        "tests/smoke/keyword.py:5: rule=docker-init: docker run must include exact token --init",
    ]


def test_workflow_hygiene_resolves_python_argv_in_its_lexical_scope() -> None:
    source = """\
import subprocess
argv = ["docker", "run", "alpine"]
def unrelated():
    argv = ["printf", "safe"]

def invoke():
    subprocess.run(argv)
"""
    assert hygiene._docker_run_offences({"tests/smoke/lexical.py": source}) == [
        "tests/smoke/lexical.py:7: rule=docker-init: docker run must include exact token --init"
    ]


def test_workflow_hygiene_parses_git_global_options_before_identity_commands() -> None:
    source = """\
on: workflow_dispatch
jobs:
  prepare:
    outputs:
      ports_sha: ${{ steps.pin.outputs.ports_sha }}
    steps:
      - id: pin
  build:
    needs: prepare
    steps:
      - env:
          PORTS_SHA: ${{ needs.prepare.outputs.ports_sha }}
        run: |
          git show "$PORTS_SHA:Makefile"
          readonly CHECKOUT_REF=$(git ls-remote origin main)
          git -C ports checkout "$CHECKOUT_REF"
          readonly RESET_REF=$(git ls-remote origin main)
          git -Cports reset "$RESET_REF"
"""
    assert hygiene._pin_offences({"git-options.yml": source}) == [
        "git-options.yml:build: rule=pin-consumer: live git ls-remote replaces "
        "prepare.ports_sha at identity sink git checkout",
        "git-options.yml:build: rule=pin-consumer: live git ls-remote replaces "
        "prepare.ports_sha at identity sink git reset",
    ]


def test_workflow_hygiene_rejects_direct_live_git_identity_substitutions() -> None:
    source = """\
on: workflow_dispatch
jobs:
  prepare:
    outputs:
      ports_sha: ${{ steps.pin.outputs.ports_sha }}
    steps:
      - id: pin
  build:
    needs: prepare
    steps:
      - env:
          PORTS_SHA: ${{ needs.prepare.outputs.ports_sha }}
        run: |
          git show "$PORTS_SHA:Makefile"
          git checkout "$(git ls-remote origin main)"
          git -C ports reset "$(
            git ls-remote origin main
          )"
"""
    assert hygiene._pin_offences({"direct-live.yml": source}) == [
        "direct-live.yml:build: rule=pin-consumer: live git ls-remote replaces "
        "prepare.ports_sha at identity sink git checkout",
        "direct-live.yml:build: rule=pin-consumer: live git ls-remote replaces "
        "prepare.ports_sha at identity sink git reset",
    ]


def test_workflow_hygiene_rejects_invalid_pin_sink_beside_exact_sink() -> None:
    source = """\
on: workflow_dispatch
jobs:
  prepare:
    outputs:
      source_sha: ${{ steps.pin.outputs.source_sha }}
    steps:
      - id: pin
  build:
    needs: prepare
    steps:
      - uses: actions/checkout@v7
        with:
          ref: ${{ needs.prepare.outputs.source_sha }}
      - uses: actions/checkout@v7
        with:
          ref: ${{ needs.prepare.outputs.source_sha || github.ref }}
"""
    assert hygiene._pin_offences({"mixed-sinks.yml": source}) == [
        "mixed-sinks.yml:build: rule=pin-consumer: derived or untrusted ref sink references prepare.source_sha"
    ]


def test_workflow_hygiene_rejects_unrelated_sha_key_as_identity_sink() -> None:
    source = """\
on: workflow_dispatch
jobs:
  prepare:
    outputs:
      source_sha: ${{ steps.pin.outputs.source_sha }}
    steps:
      - id: pin
  build:
    needs: prepare
    steps:
      - uses: actions/github-script@v8
        with:
          script: return 0
          sha: ${{ needs.prepare.outputs.source_sha }}
"""
    assert hygiene._pin_offences({"fake-sha.yml": source}) == [
        "fake-sha.yml:prepare.source_sha: rule=pin-consumer: pin is not consumed by a ref/identity sink"
    ]


def test_workflow_hygiene_rejects_shell_operator_alias_overwrite() -> None:
    source = """\
on: workflow_dispatch
jobs:
  prepare:
    outputs:
      source_sha: ${{ steps.pin.outputs.source_sha }}
    steps:
      - id: pin
  build:
    needs: prepare
    env:
      SOURCE_SHA: ${{ needs.prepare.outputs.source_sha }}
    steps:
      - run: 'true; SOURCE_SHA=main; git checkout "$SOURCE_SHA"'
"""
    assert hygiene._pin_offences({"operator-shadow.yml": source}) == [
        "operator-shadow.yml:build: rule=pin-consumer: alias overwrites "
        "prepare.source_sha at identity sink git checkout",
        "operator-shadow.yml:prepare.source_sha: rule=pin-consumer: pin is not consumed by a ref/identity sink",
    ]


def test_workflow_hygiene_rejects_derived_env_alias_beside_exact_checkout() -> None:
    source = """\
on: workflow_dispatch
jobs:
  prepare:
    outputs:
      source_sha: ${{ steps.pin.outputs.source_sha }}
    steps:
      - id: pin
  build:
    needs: prepare
    env:
      SOURCE_SHA: ${{ needs.prepare.outputs.source_sha || github.ref }}
    steps:
      - uses: actions/checkout@v7
        with:
          ref: ${{ needs.prepare.outputs.source_sha }}
      - run: git checkout "$SOURCE_SHA"
"""
    assert hygiene._pin_offences({"mixed-env.yml": source}) == [
        "mixed-env.yml:build: rule=pin-consumer: derived or untrusted env alias SOURCE_SHA "
        "references prepare.source_sha at identity sink git checkout"
    ]


def test_workflow_hygiene_rejects_derived_env_alias_at_flag_identity_sink() -> None:
    source = """\
on: workflow_dispatch
jobs:
  prepare:
    outputs:
      ports_sha: ${{ steps.pin.outputs.ports_sha }}
    steps:
      - id: pin
  build:
    needs: prepare
    env:
      PORTS_SHA: ${{ needs.prepare.outputs.ports_sha || github.ref }}
    steps:
      - uses: actions/checkout@v7
        with:
          ref: ${{ needs.prepare.outputs.ports_sha }}
      - run: sh scripts/build-leg.sh --ports-ref "$PORTS_SHA"
"""
    assert hygiene._pin_offences({"flag-alias.yml": source}) == [
        "flag-alias.yml:build: rule=pin-consumer: derived or untrusted env alias PORTS_SHA "
        "references prepare.ports_sha at identity sink --ports-ref"
    ]


def test_workflow_hygiene_rejects_derived_env_alias_at_equals_flag_identity_sink() -> None:
    source = """\
"on": workflow_dispatch
jobs:
  prepare:
    outputs:
      ports_sha: ${{ steps.pin.outputs.ports_sha }}
    steps:
      - id: pin
  build:
    needs: prepare
    env:
      PORTS_SHA: ${{ needs.prepare.outputs.ports_sha || github.ref }}
    steps:
      - uses: actions/checkout@v7
        with:
          ref: ${{ needs.prepare.outputs.ports_sha }}
      - run: sh scripts/build-leg.sh --ports-ref=$PORTS_SHA
"""
    assert hygiene._pin_offences({"equals-flag-env-alias.yml": source}) == [
        "equals-flag-env-alias.yml:build: rule=pin-consumer: derived or untrusted env alias PORTS_SHA "
        "references prepare.ports_sha at identity sink --ports-ref"
    ]


def test_workflow_hygiene_reports_live_alias_at_equals_flag_identity_sink() -> None:
    source = """\
"on": workflow_dispatch
jobs:
  prepare:
    outputs:
      ports_sha: ${{ steps.pin.outputs.ports_sha }}
    steps:
      - id: pin
  build:
    needs: prepare
    env:
      PORTS_SHA: ${{ needs.prepare.outputs.ports_sha }}
    steps:
      - run: |
          git show "$PORTS_SHA:Makefile"
          FRESH=$(git ls-remote origin main)
          sh scripts/build-leg.sh --ports-ref=$FRESH
"""
    assert hygiene._pin_offences({"equals-flag-live-alias.yml": source}) == [
        "equals-flag-live-alias.yml:build: rule=pin-consumer: live git ls-remote replaces "
        "prepare.ports_sha at identity sink --ports-ref"
    ]


def test_workflow_hygiene_rejects_derived_shell_alias_at_flag_identity_sink() -> None:
    source = """\
"on": workflow_dispatch
jobs:
  prepare:
    outputs:
      ports_sha: ${{ steps.pin.outputs.ports_sha }}
    steps:
      - id: pin
  build:
    needs: prepare
    env:
      PORTS_SHA: ${{ needs.prepare.outputs.ports_sha }}
    steps:
      - run: |
          git show "$PORTS_SHA:Makefile"
          FRESH="${PORTS_SHA}-attacker"
          sh scripts/build-leg.sh --ports-ref "$FRESH"
"""
    assert hygiene._pin_offences({"derived-shell-alias.yml": source}) == [
        "derived-shell-alias.yml:build: rule=pin-consumer: derived shell alias FRESH references "
        "prepare.ports_sha at identity sink --ports-ref"
    ]


def test_workflow_hygiene_rejects_unknown_alias_at_flag_identity_sink() -> None:
    source = """\
"on": workflow_dispatch
jobs:
  prepare:
    outputs:
      ports_sha: ${{ steps.pin.outputs.ports_sha }}
    steps:
      - id: pin
  build:
    needs: prepare
    steps:
      - env:
          PORTS_SHA: ${{ needs.prepare.outputs.ports_sha }}
        run: |
          git show "$PORTS_SHA:Makefile"
          FRESH=main
          sh scripts/build-leg.sh --ports-ref "$FRESH"
"""
    assert hygiene._pin_offences({"unknown-flag-alias.yml": source}) == [
        "unknown-flag-alias.yml:build: rule=pin-consumer: identity flag --ports-ref uses "
        "a derived, untrusted, or unknown value instead of prepare.ports_sha"
    ]


@pytest.mark.parametrize(
    "identity_invocation",
    (
        "sh scripts/build-leg.sh --ports-ref main",
        "sh scripts/build-leg.sh --ports-ref=main",
    ),
)
def test_workflow_hygiene_rejects_direct_literal_at_flag_identity_sink(
    identity_invocation: str,
) -> None:
    source = """\
"on": workflow_dispatch
jobs:
  prepare:
    outputs:
      ports_sha: ${{ steps.pin.outputs.ports_sha }}
    steps:
      - id: pin
  build:
    needs: prepare
    steps:
      - env:
          PORTS_SHA: ${{ needs.prepare.outputs.ports_sha }}
        run: |
          git show "$PORTS_SHA:Makefile"
          IDENTITY_INVOCATION
""".replace("IDENTITY_INVOCATION", identity_invocation)
    assert hygiene._pin_offences({"direct-flag-literal.yml": source}) == [
        "direct-flag-literal.yml:build: rule=pin-consumer: identity flag --ports-ref uses "
        "a derived, untrusted, or unknown value instead of prepare.ports_sha"
    ]


@pytest.mark.parametrize(
    "identity_invocation",
    (
        'sh scripts/build-leg.sh --ports-ref "$PORTS_SHA" --ports-ref main',
        'sh scripts/build-leg.sh --ports-ref="$PORTS_SHA" --ports-ref=main',
    ),
)
def test_workflow_hygiene_validates_each_identity_flag_argument(
    identity_invocation: str,
) -> None:
    source = """\
"on": workflow_dispatch
jobs:
  prepare:
    outputs:
      ports_sha: ${{ steps.pin.outputs.ports_sha }}
    steps:
      - id: pin
  build:
    needs: prepare
    env:
      PORTS_SHA: ${{ needs.prepare.outputs.ports_sha }}
    steps:
      - run: |
          git show "$PORTS_SHA:Makefile"
          IDENTITY_INVOCATION
""".replace("IDENTITY_INVOCATION", identity_invocation)
    assert hygiene._pin_offences({"sibling-identity-flags.yml": source}) == [
        "sibling-identity-flags.yml:build: rule=pin-consumer: identity flag --ports-ref uses "
        "a derived, untrusted, or unknown value instead of prepare.ports_sha"
    ]


@pytest.mark.parametrize(
    "declaration",
    (
        "export OTHER=1 PORTS_SHA=main",
        "readonly OTHER=1 PORTS_SHA=main",
    ),
)
def test_workflow_hygiene_tracks_every_exported_pin_alias(declaration: str) -> None:
    source = """\
"on": workflow_dispatch
jobs:
  prepare:
    outputs:
      ports_sha: ${{ steps.pin.outputs.ports_sha }}
    steps:
      - id: pin
  build:
    needs: prepare
    env:
      PORTS_SHA: ${{ needs.prepare.outputs.ports_sha }}
    steps:
      - run: |
          sh scripts/build-leg.sh --ports-ref "$PORTS_SHA"
          DECLARATION
          sh scripts/build-leg.sh --ports-ref "$PORTS_SHA"
""".replace("DECLARATION", declaration)
    assert hygiene._pin_offences({"multi-assignment.yml": source}) == [
        "multi-assignment.yml:build: rule=pin-consumer: alias overwrites prepare.ports_sha at identity sink --ports-ref"
    ]


@pytest.mark.parametrize(
    "declaration",
    (
        "export OTHER=1 EXTRA=main",
        "readonly OTHER=1 EXTRA=main",
    ),
)
def test_workflow_hygiene_keeps_exact_pin_after_unrelated_exported_assignments(declaration: str) -> None:
    source = """\
"on": workflow_dispatch
jobs:
  prepare:
    outputs:
      ports_sha: ${{ steps.pin.outputs.ports_sha }}
    steps:
      - id: pin
  build:
    needs: prepare
    env:
      PORTS_SHA: ${{ needs.prepare.outputs.ports_sha }}
    steps:
      - run: |
          DECLARATION
          sh scripts/build-leg.sh --ports-ref "$PORTS_SHA"
""".replace("DECLARATION", declaration)
    assert hygiene._pin_offences({"unrelated-multi-assignment.yml": source}) == []


def test_workflow_hygiene_scopes_flag_identity_sinks_to_matching_prepared_pins() -> None:
    sources = {
        "exact-and-unrelated.yml": """\
"on": workflow_dispatch
jobs:
  prepare:
    outputs:
      ports_sha: ${{ steps.pin.outputs.ports_sha }}
    steps:
      - id: pin
  build:
    needs: prepare
    steps:
      - env:
          PORTS_SHA: ${{ needs.prepare.outputs.ports_sha }}
        run: |
          git show "$PORTS_SHA:Makefile"
          sh scripts/build-leg.sh --ports-ref "$PORTS_SHA"
          sh scripts/build-leg.sh --ports-sha "${{ needs.prepare.outputs.ports_sha }}"
          sh scripts/build-leg.sh --ports-sha "$PORTS_SHA" --ports-ref main
          sh scripts/build-leg.sh --cache-ref main
""",
        "no-prepared-pin.yml": """\
"on": workflow_dispatch
jobs:
  build:
    steps:
      - run: sh scripts/build-leg.sh --ports-ref main
""",
    }
    assert hygiene._pin_offences(sources) == []


def test_workflow_hygiene_reports_semicolon_live_replacement_beside_exact_sink() -> None:
    source = """\
on: workflow_dispatch
jobs:
  prepare:
    outputs:
      ports_sha: ${{ steps.pin.outputs.ports_sha }}
    steps:
      - id: pin
  build:
    needs: prepare
    env:
      PORTS_SHA: ${{ needs.prepare.outputs.ports_sha }}
    steps:
      - run: |
          git show "$PORTS_SHA:Makefile"
          true; FRESH=$(git ls-remote origin main)
          FRESH=${FRESH%%[[:space:]]*}
          git checkout "$FRESH"
"""
    assert hygiene._pin_offences({"valid-live.yml": source}) == [
        "valid-live.yml:build: rule=pin-consumer: live git ls-remote replaces "
        "prepare.ports_sha at identity sink git checkout"
    ]


def test_workflow_hygiene_resolves_function_local_subprocess_import() -> None:
    source = """\
def invoke():
    import subprocess
    subprocess.run(["docker", "run", "alpine"], check=True)
invoke()
"""
    assert hygiene._docker_run_offences({"tests/smoke/nested_import.py": source}) == [
        "tests/smoke/nested_import.py:3: rule=docker-init: docker run must include exact token --init"
    ]


def test_workflow_hygiene_resolves_static_shell_and_php_docker_aliases() -> None:
    sources = {
        "scripts/command-v.sh": 'runtime="$(command -v docker)"\n"$runtime" run alpine\n',
        "scripts/concat.php": '<?php\n$cmd = "docker " . "run alpine";\nsystem($cmd);\n',
    }
    assert hygiene._docker_run_offences(sources) == [
        "scripts/command-v.sh:2: rule=docker-init: docker run must include exact token --init",
        "scripts/concat.php:3: rule=docker-init: docker run must include exact token --init",
    ]


@pytest.mark.parametrize(
    ("workflow", "prefix"),
    (("smoke.yml", "smoke-"), ("ui-tests.yml", "ui-tests-")),
)
def test_reusable_release_gates_have_distinct_lossless_concurrency(workflow: str, prefix: str) -> None:
    source = (ROOT / ".github" / "workflows" / workflow).read_text(encoding="utf-8")
    document = hygiene._workflow_document(source, workflow)
    concurrency = document["concurrency"]
    assert isinstance(concurrency, dict)
    group = concurrency.get("group")
    assert isinstance(group, str) and group.startswith(prefix)
    assert concurrency.get("queue") == "max"
    assert concurrency.get("cancel-in-progress") is False
