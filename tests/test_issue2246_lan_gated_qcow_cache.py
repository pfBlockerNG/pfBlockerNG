"""Self-hosted actions/cache qcow2 steps stay LAN-gated (issue #2246).

Uses the same narrow text parser as tests/test_issue2231_workflow_hygiene.py
and tests/test_issue2230_lan_registry.py.

The self-hosted `smoke` job (smoke-single.yml) and `ui` job (ui-tests.yml)
cache their pfSense/civm qcow2 pulls via `actions/cache` restore+save pairs.
Those pairs exist solely as the GitHub-hosted fallback (for when the
self-hosted fleet is unavailable) — on the self-hosted fleet the LAN zot
cache already serves the same bytes at LAN speed, so the GitHub-backend
cache on top would only add a slower, strictly worse WAN round-trip. Every
such cache step must therefore carry `vars.PFB_LAN_REGISTRY == ''` in its
`if:` — an unset repo variable compares equal to `''`, so the cache
defaults ON for a plain GitHub-hosted run and OFF on the self-hosted fleet
(var set). A cache step that loses its gate silently reintroduces the WAN
round-trip on the very fleet the LAN cache exists to serve; a cache step
that disappears entirely breaks the hosted fallback — both directions are
pinned here.

It also guards the job-level `PFB_LAN_REGISTRY` env forwarding the pulls (and
this gate) depend on: host env does not reach a GHA container job, so the
repo variable must be threaded in via the job's own `env:` or every pull (and
every cache step's gate) on that job silently reverts to the GitHub-hosted
default.
"""

from __future__ import annotations

import re
from pathlib import Path

from tests.test_issue2230_lan_registry import _SELF_HOSTED, _job_blocks

ROOT = Path(__file__).resolve().parents[1]

_TARGET_WORKFLOWS = ("smoke-single.yml", "ui-tests.yml")
_LAN_REGISTRY_ENV_LINE = "PFB_LAN_REGISTRY: ${{ vars.PFB_LAN_REGISTRY }}"
_LAN_GATE = "vars.PFB_LAN_REGISTRY == ''"

# The actual step usage, e.g. `uses: actions/cache/restore@v5` — NOT a bare
# substring match, which would also trip on this module's own prose (and any
# future explanatory comment naming the action it discusses).
_CACHE_STEP_USE = re.compile(r"^\s*uses:\s*actions/cache\b", re.MULTILINE)
_STEPS_KEY = re.compile(r"^(\s*)steps:\s*$", re.MULTILINE)
_STEP_NAME = re.compile(r"^\s*-?\s*name:\s*(\S.*)$", re.MULTILINE)


def _self_hosted_blocks() -> dict[str, str]:
    """(file::job) -> block text, for every self-hosted job in the two
    workflows this issue touches (smoke-single.yml's `smoke`, ui-tests.yml's
    `ui`) — NOT a whole-repo scan; other self-hosted jobs elsewhere (e.g.
    build-image.yml) are out of scope for this issue."""
    found: dict[str, str] = {}
    for name in _TARGET_WORKFLOWS:
        path = ROOT / ".github/workflows" / name
        assert path.is_file(), f"expected workflow file missing: {path}"
        text = path.read_text(encoding="utf-8")
        for job_name, block in _job_blocks(text):
            if _SELF_HOSTED.search(block):
                found[f"{name}::{job_name}"] = block
    return found


def _step_blocks(job_block: str) -> list[str]:
    """Split a job block's `steps:` list into individual step texts.

    Steps are `- ` list items at a fixed indent under `steps:`; the indent of
    the FIRST list item found there is taken as that column (checkout is
    always the first step in both target jobs, so this is stable), then every
    line at that same indent starts a new step."""
    m = _STEPS_KEY.search(job_block)
    if not m:
        return []
    body = job_block[m.end() :]
    first = re.search(r"^(?P<indent>[ \t]+)-\s", body, re.MULTILINE)
    if not first:
        return []
    indent = first.group("indent")
    boundary = re.compile(rf"^{re.escape(indent)}-\s", re.MULTILINE)
    starts = [mm.start() for mm in boundary.finditer(body)]
    ends = starts[1:] + [len(body)]
    return [body[s:e] for s, e in zip(starts, ends)]


def _step_name(step: str) -> str:
    m = _STEP_NAME.search(step)
    return m.group(1).strip() if m else step.strip().splitlines()[0]


_IF_LINE = re.compile(r"^\s*if:\s*(\S.*)$", re.MULTILINE)


def _is_unguarded_cache_step(step: str) -> bool:
    """True when `step` uses actions/cache but no `if:` LINE carries the
    LAN-registry gate — a gate merely quoted in a comment must not count."""
    if not _CACHE_STEP_USE.search(step):
        return False
    return not any(_LAN_GATE in m.group(1) for m in _IF_LINE.finditer(step))


def test_self_hosted_cache_steps_are_lan_gated() -> None:
    """Every actions/cache step inside a self-hosted job must be gated off
    when the LAN zot cache is active (the pairs stay as the GitHub-hosted
    fallback), and every expected fallback pair must still EXIST — a deleted
    pair breaks the hosted fallback as surely as a lost gate breaks the
    self-hosted path."""
    blocks = _self_hosted_blocks()
    assert len(blocks) >= 2, (
        f"expected at least 2 self-hosted job blocks (smoke-single.yml's smoke + "
        f"ui-tests.yml's ui), found {len(blocks)} — job-block scanner regressed or "
        "the workflows changed shape"
    )
    per_job_cache_steps: dict[str, int] = {}
    offenders: list[str] = []
    for job_name, block in blocks.items():
        for step in _step_blocks(block):
            if not _CACHE_STEP_USE.search(step):
                continue
            per_job_cache_steps[job_name] = per_job_cache_steps.get(job_name, 0) + 1
            if _is_unguarded_cache_step(step):
                offenders.append(f"{job_name} ({_step_name(step)})")
    expected_cache_steps = {
        "smoke-single.yml::smoke": 4,  # pfSense + civm restore/save pairs
        "ui-tests.yml::ui": 2,  # pfSense restore/save pair
    }
    assert per_job_cache_steps == expected_cache_steps, (
        f"actions/cache fallback steps changed: expected {expected_cache_steps}, "
        f"found {per_job_cache_steps} — a removed pair breaks the GitHub-hosted "
        "fallback; an added one needs its LAN gate and a row here"
    )
    assert not offenders, (
        "self-hosted actions/cache step(s) are missing the LAN-registry gate "
        f"({_LAN_GATE!r} in `if:`) — they would also run on the self-hosted fleet, "
        "adding a WAN round-trip on top of the LAN zot cache (issue #2246):\n  " + "\n  ".join(sorted(offenders))
    )


def test_self_hosted_jobs_forward_the_lan_registry_job_env() -> None:
    """Both self-hosted jobs must forward the PFB_LAN_REGISTRY repo variable
    into the job's own env (host env does not reach a GHA container job; the
    repo variable is the only channel) — without it, resolve-legs.sh sees an
    unset PFB_LAN_REGISTRY and every pull silently reverts to ghcr.io, AND
    every cache step's `if:` gate silently reads as GitHub-hosted-default
    even on the self-hosted fleet."""
    blocks = _self_hosted_blocks()
    assert len(blocks) >= 2, (
        f"expected at least 2 self-hosted job blocks, found {len(blocks)} — "
        "job-block scanner regressed or the workflows changed shape"
    )
    offenders = sorted(name for name, block in blocks.items() if _LAN_REGISTRY_ENV_LINE not in block)
    assert not offenders, (
        f"self-hosted job(s) missing job-level env {_LAN_REGISTRY_ENV_LINE!r} "
        "(issue #2246):\n  " + "\n  ".join(offenders)
    )


def test_scanner_flags_a_planted_cache_step_but_not_a_bare_mention() -> None:
    """The `_CACHE_STEP_USE` regex must match a real `uses: actions/cache...`
    step, not merely the string appearing somewhere in the block (e.g. in a
    comment) — a bare-substring check would false-positive on this very
    module's own docstring/comments once they mention the action by name."""
    real_step = (
        "  offender:\n"
        "    runs-on: [self-hosted, Linux, X64]\n"
        "    steps:\n"
        "      - name: Restore cached pfSense image\n"
        "        uses: actions/cache/restore@v5\n"
        "        with:\n"
        "          path: image\n"
    )
    only_a_comment = (
        "  clean:\n"
        "    runs-on: [self-hosted, Linux, X64]\n"
        "    steps:\n"
        "      # issue #2246: actions/cache is LAN-gated below.\n"
        "      - name: Pull pfSense image (by digest)\n"
        '        run: sh scripts/resolve-legs.sh pull "$IMAGE_REF" "$DIGEST" image\n'
    )
    assert _CACHE_STEP_USE.search(real_step)
    assert not _CACHE_STEP_USE.search(only_a_comment)


def test_scanner_flags_unguarded_cache_step_but_passes_a_lan_gated_one() -> None:
    """`_is_unguarded_cache_step` must flag an `actions/cache` step with no
    `if:` gate, and must NOT flag one carrying `vars.PFB_LAN_REGISTRY == ''`
    (either alone or AND'd with a `cache-hit` clause, as the save steps do)."""
    unguarded = (
        "      - name: Restore cached pfSense image\n"
        "        id: pfcache\n"
        "        uses: actions/cache/restore@v5\n"
        "        with:\n"
        "          path: image\n"
        "          key: pfsense-img-abc\n"
    )
    guarded_restore = (
        "      - name: Restore cached pfSense image\n"
        "        id: pfcache\n"
        "        if: ${{ vars.PFB_LAN_REGISTRY == '' }}\n"
        "        uses: actions/cache/restore@v5\n"
        "        with:\n"
        "          path: image\n"
        "          key: pfsense-img-abc\n"
    )
    guarded_save = (
        "      - name: Save pfSense image to cache\n"
        "        if: ${{ vars.PFB_LAN_REGISTRY == '' && steps.pfcache.outputs.cache-hit != 'true' }}\n"
        "        uses: actions/cache/save@v5\n"
        "        with:\n"
        "          path: image\n"
        "          key: pfsense-img-abc\n"
    )
    gate_only_in_comment = (
        "      - name: Restore cached pfSense image\n"
        "        # skipped when the LAN cache serves (vars.PFB_LAN_REGISTRY == '')\n"
        "        uses: actions/cache/restore@v5\n"
        "        with:\n"
        "          path: image\n"
        "          key: pfsense-img-abc\n"
    )
    assert _is_unguarded_cache_step(unguarded)
    assert not _is_unguarded_cache_step(guarded_restore)
    assert not _is_unguarded_cache_step(guarded_save)
    assert _is_unguarded_cache_step(gate_only_in_comment), (
        "a gate quoted in a comment, with no if: line, must still be flagged"
    )


def test_step_blocks_splits_a_steps_list_into_individual_steps() -> None:
    """`_step_blocks` must isolate each step's own text (so a step's `if:`
    is never conflated with a NEIGHBOURING step's `if:`, which would make the
    gate check pass by reading the wrong step)."""
    job_block = (
        "  smoke:\n"
        "    runs-on: [self-hosted, Linux, X64]\n"
        "    steps:\n"
        "      - name: Checkout\n"
        "        uses: actions/checkout@v6\n"
        "      - name: Restore cached pfSense image\n"
        "        if: ${{ vars.PFB_LAN_REGISTRY == '' }}\n"
        "        uses: actions/cache/restore@v5\n"
        "      - name: Pull pfSense image (by digest)\n"
        "        run: echo pull\n"
    )
    steps = _step_blocks(job_block)
    assert len(steps) == 3, steps
    assert _step_name(steps[0]) == "Checkout"
    assert _step_name(steps[1]) == "Restore cached pfSense image"
    assert _LAN_GATE in steps[1]
    assert _LAN_GATE not in steps[2]
