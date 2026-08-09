"""No actions/cache qcow2 pairs on the self-hosted runner-side jobs (issue #2246).

Deliberately stdlib-only, mirroring tests/test_issue2231_workflow_hygiene.py and
tests/test_issue2230_lan_registry.py: the CI pytest leg runs inside ci-runner,
which bakes no PyYAML.

The self-hosted `smoke` job (smoke-single.yml) and `ui` job (ui-tests.yml) used
to cache their pfSense/civm qcow2 pulls via `actions/cache` restore+save pairs.
Since issue #2246 those pulls route through the LAN zot cache instead (LAN
speed, no WAN round-trip to GitHub's cache backend) via
`scripts/resolve-legs.sh pull`, and the actions/cache steps were deleted
outright — the LAN cache already serves the same bytes at LAN speed, so a
GitHub-backend cache on top is strictly worse, never faster. This is a
regression guard: a re-added actions/cache step on either self-hosted job
silently reintroduces the WAN round-trip.

It also guards the job-level `PFB_LAN_REGISTRY` env forwarding those pulls
depend on: host env does not reach a GHA container job, so the repo variable
must be threaded in via the job's own `env:` or every pull on that job
silently reverts to the public ghcr.io path.
"""

from __future__ import annotations

import re
from pathlib import Path

from tests.test_issue2230_lan_registry import _SELF_HOSTED, _job_blocks

ROOT = Path(__file__).resolve().parents[1]

_TARGET_WORKFLOWS = ("smoke-single.yml", "ui-tests.yml")
_LAN_REGISTRY_ENV_LINE = "PFB_LAN_REGISTRY: ${{ vars.PFB_LAN_REGISTRY }}"
# The actual step usage, e.g. `uses: actions/cache/restore@v5` — NOT a bare
# substring match, which would also trip on this module's own prose (and any
# future explanatory comment naming the action it forbids).
_CACHE_STEP_USE = re.compile(r"^\s*uses:\s*actions/cache\b", re.MULTILINE)


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


def test_self_hosted_jobs_carry_no_actions_cache_step() -> None:
    """The self-hosted smoke/ui jobs must not reintroduce an actions/cache
    qcow2 pair; pulls route through the LAN zot cache unconditionally instead
    (scripts/resolve-legs.sh pull)."""
    blocks = _self_hosted_blocks()
    assert len(blocks) >= 2, (
        f"expected at least 2 self-hosted job blocks (smoke-single.yml's smoke + "
        f"ui-tests.yml's ui), found {len(blocks)} — job-block scanner regressed or "
        "the workflows changed shape"
    )
    offenders = sorted(name for name, block in blocks.items() if _CACHE_STEP_USE.search(block))
    assert not offenders, (
        "self-hosted job(s) still carry an actions/cache step (issue #2246 removed "
        "the qcow2 cache pairs in favour of the LAN zot cache, which is strictly "
        "faster for the self-hosted fleet):\n  " + "\n  ".join(offenders)
    )


def test_self_hosted_jobs_forward_the_lan_registry_job_env() -> None:
    """Both self-hosted jobs must forward the PFB_LAN_REGISTRY repo variable
    into the job's own env (host env does not reach a GHA container job; the
    repo variable is the only channel) — without it, resolve-legs.sh sees an
    unset PFB_LAN_REGISTRY and every pull silently reverts to ghcr.io."""
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
        "      # issue #2246: no actions/cache restore/save pair here anymore.\n"
        "      - name: Pull pfSense image (by digest)\n"
        '        run: sh scripts/resolve-legs.sh pull "$IMAGE_REF" "$DIGEST" image\n'
    )
    assert _CACHE_STEP_USE.search(real_step)
    assert not _CACHE_STEP_USE.search(only_a_comment)
