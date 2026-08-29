"""Tests for scripts/reconcile-plan.py (issue #1823).

Scenario: the daily image-reconcile plan for one channel
  Given the box facts from the booted smoke image(s) — /etc/version,
        `pfSense-repoc -p`, `pfSense-upgrade -c` — and the matrix
  Then the plan proposes exactly the actions the owner's reconcile rules
       demand, with the box as the sole source of truth.

Repoc fixtures are the LIVE outputs probed on the owner's CE 2.8.1 and
Plus 26.03.1 test VMs (2026-07-28), tab-delimited exactly as emitted.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "reconcile-plan.py"
_spec = importlib.util.spec_from_file_location("reconcile_plan", _SCRIPT)
assert _spec is not None and _spec.loader is not None
rp = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = rp
_spec.loader.exec_module(rp)

# ── Live-probed fixtures ──────────────────────────────────────────────────────

REPOC_PLUS = "26.07\t\tBeta Version (26.07)\n26_03_1 (release) (default)\t\tCurrent Stable Version (26.03.1)\n"
REPOC_CE = "2_8_1 (release) (default)\t\tCurrent Stable Version (2.8.1)\n"
UPGRADE_AVAILABLE = (
    ">>> Updating repositories metadata...done.\n26.07.b.20260727.1443 version of pfSense is available\n"
)
UPGRADE_CURRENT = ">>> Updating repositories metadata...done.\nYour system is up to date\n"

PLUS_2603 = {
    "pfsense_version": "26.03",
    "channel": "Plus",
    "status": "active",
    "ci": True,
    "image_name": "pfsense-plus",
}
PLUS_2607_BETA = {
    "pfsense_version": "26.07",
    "channel": "Plus",
    "status": "beta",
    "ci": False,
    "image_name": "pfsense-plus",
}
PLUS_2603_AARCH64 = dict(PLUS_2603, ci=False, arch="aarch64")


def _boot(family: str, etc: str, repoc: str, check: str = UPGRADE_CURRENT) -> dict[str, str]:
    return {"family": family, "etc_version": etc, "repoc": repoc, "upgrade_check": check}


def _plan(
    matrix: list[dict[str, Any]],
    published: dict[str, bool],
    boots: list[dict[str, str]],
    channel: str = "Plus",
) -> list[dict[str, str]]:
    return rp.plan(channel, matrix, published, boots)


# ── Repoc parsing ─────────────────────────────────────────────────────────────


class TestParseRepoc:
    def test_live_plus_output_parses_both_rows(self) -> None:
        branches = rp.parse_repoc(REPOC_PLUS)
        assert branches == [
            {"name": "26.07", "version": "26.07", "family": "26.07", "kind": "beta"},
            {"name": "26_03_1", "version": "26.03.1", "family": "26.03", "kind": "stable"},
        ]

    def test_annotations_stripped_from_name(self) -> None:
        branches = rp.parse_repoc(REPOC_CE)
        assert branches[0]["name"] == "2_8_1"

    def test_hostile_rows_are_dropped(self) -> None:
        hostile = '26.09"x};$(touch pwn)\t\tBad (26.09"x)\nno-tabs-here\n\t\tDescription without version\n'
        assert rp.parse_repoc(hostile) == []

    def test_version_taken_from_description_not_name(self) -> None:
        # The name column can be decorated ('26_03_1 (release) (default)');
        # the trailing parenthesized token in the DESCRIPTION is the version
        branches = rp.parse_repoc("weird_name\t\tSomething Version (26.05.2)\n")
        assert branches == [{"name": "weird_name", "version": "26.05.2", "family": "26.05", "kind": "stable"}]


# ── Rule: -c second source ────────────────────────────────────────────────────


class TestUpgradeCheckSecondSource:
    def test_available_update_fires_republish_even_without_branch_signal(self) -> None:
        # repoc shows nothing new (only the current stable) but -c says newer:
        # the second source alone must act (owner rule, 2026-07-28)
        actions = _plan(
            [PLUS_2603],
            {"26.03": True},
            [
                _boot(
                    "26.03",
                    "26.03.1-RELEASE",
                    REPOC_CE.replace("2.8.1", "26.03.1").replace("2_8_1", "26_03_1"),
                    UPGRADE_AVAILABLE,
                )
            ],
        )
        assert {"type": "republish", "family": "26.03", "branch": "", "reason": "upgrade-check"} in actions

    def test_up_to_date_fires_nothing(self) -> None:
        actions = _plan(
            [PLUS_2603],
            {"26.03": True},
            [_boot("26.03", "26.03.1-RELEASE", "26_03_1 (release) (default)\t\tCurrent Stable Version (26.03.1)\n")],
        )
        assert actions == []


# ── Rule: new family → matrix PR (the only human gate) ────────────────────────


class TestMatrixPrAdd:
    def test_beta_branch_absent_from_matrix_proposes_beta_entry(self) -> None:
        actions = _plan([PLUS_2603], {"26.03": True}, [_boot("26.03", "26.03.1-RELEASE", REPOC_PLUS)])
        assert {"type": "matrix_pr_add", "family": "26.07", "branch": "26.07", "status": "beta"} in actions

    def test_untracked_stable_branch_proposes_active_entry(self) -> None:
        # CR7: no beta row in the fixture — the stable row alone must yield
        # an ACTIVE proposal
        repoc = "26_07\t\tCurrent Stable Version (26.07)\n"
        actions = _plan(
            [PLUS_2603],
            {"26.03": True},
            [
                _boot(
                    "26.03", "26.03.1-RELEASE", REPOC_CE.replace("2.8.1", "26.03.1").replace("2_8_1", "26_03_1") + repoc
                )
            ],
        )
        assert {"type": "matrix_pr_add", "family": "26.07", "branch": "26_07", "status": "active"} in actions

    def test_same_family_beta_and_stable_rows_dedup_to_one_proposal(self) -> None:
        repoc = REPOC_PLUS + "26_07\t\tCurrent Stable Version (26.07)\n"
        actions = _plan([PLUS_2603], {"26.03": True}, [_boot("26.03", "26.03.1-RELEASE", repoc)])
        adds = [a for a in actions if a["type"] == "matrix_pr_add" and a["family"] == "26.07"]
        # beta + stable rows for the same family dedup to ONE proposal (first wins)
        assert len(adds) == 1

    def test_family_already_in_matrix_proposes_nothing(self) -> None:
        actions = _plan(
            [PLUS_2603, PLUS_2607_BETA],
            {"26.03": True, "26.07": True},
            [_boot("26.03", "26.03.1-RELEASE", REPOC_PLUS)],
        )
        assert all(a["type"] != "matrix_pr_add" for a in actions)


# ── Rule: merged entry, unpublished tag → first build ─────────────────────────


class TestPublishNew:
    def test_unpublished_beta_entry_builds_from_newest_stable(self) -> None:
        actions = _plan(
            [PLUS_2603, PLUS_2607_BETA],
            {"26.03": True, "26.07": False},
            [_boot("26.03", "26.03.1-RELEASE", REPOC_PLUS)],
        )
        assert {"type": "publish_new", "family": "26.07", "branch": "26.07", "from": "26.03"} in actions

    def test_branchless_unpublished_entry_warns_instead(self) -> None:
        # Matrix says 26.07 but the box no longer lists any such branch
        actions = _plan(
            [PLUS_2603, PLUS_2607_BETA],
            {"26.03": True, "26.07": False},
            [_boot("26.03", "26.03.1-RELEASE", "26_03_1 (release) (default)\t\tCurrent Stable Version (26.03.1)\n")],
        )
        warns = [a for a in actions if a["type"] == "warn" and a["family"] == "26.07"]
        assert len(warns) == 1
        assert all(a["type"] != "publish_new" for a in actions)

    def test_aarch64_entries_never_planned(self) -> None:
        actions = _plan(
            [PLUS_2603, PLUS_2603_AARCH64],
            {"26.03": False},
            [],
        )
        # the amd64 entry may warn (nothing published at all) but the aarch64
        # sibling must not produce its own duplicate action set
        assert len([a for a in actions if a.get("family") == "26.03"]) <= 1


# ── Rule: newer stable branch for the booted family → republish ───────────────


class TestRepublishNewerBranch:
    def test_new_patch_branch_fires_branch_switch_republish(self) -> None:
        # Booted 26.03.0; the box lists the 26_03_1 pinned branch (patches ARE
        # branch switches — probed live, -c stays silent about them)
        actions = _plan(
            [PLUS_2603],
            {"26.03": True},
            [_boot("26.03", "26.03-RELEASE", REPOC_PLUS)],
        )
        assert {"type": "republish", "family": "26.03", "branch": "26_03_1", "reason": "newer-branch"} in actions

    def test_empty_etc_version_never_fires_republish(self) -> None:
        # CodeRabbit CR5: version_key("") == (0,) would make EVERY stable
        # branch look newer — an unestablished box version must fire nothing
        actions = _plan([PLUS_2603], {"26.03": True}, [_boot("26.03", "", REPOC_PLUS)])
        assert all(a["type"] != "republish" for a in actions)

    def test_current_patch_level_fires_nothing(self) -> None:
        actions = _plan([PLUS_2603], {"26.03": True}, [_boot("26.03", "26.03.1-RELEASE", REPOC_PLUS)])
        assert all(a["type"] != "republish" for a in actions)

    def test_beta_branch_never_counts_as_newer_for_a_stable_family(self) -> None:
        # 26.07 beta is numerically newer than 26.03.1 but a DIFFERENT family —
        # and beta rows must never drive a stable family's republish
        actions = _plan(
            [PLUS_2603, PLUS_2607_BETA], {"26.03": True, "26.07": True}, [_boot("26.03", "26.03.1-RELEASE", REPOC_PLUS)]
        )
        republishes = [a for a in actions if a["type"] == "republish"]
        assert republishes == []


# ── Rule: GA detection for beta entries ───────────────────────────────────────


class TestGaFlip:
    def test_booted_beta_image_with_final_version_flips(self) -> None:
        actions = _plan(
            [PLUS_2603, PLUS_2607_BETA],
            {"26.03": True, "26.07": True},
            [_boot("26.07", "26.07-RELEASE", "26_07 (release) (default)\t\tCurrent Stable Version (26.07)\n")],
        )
        assert {"type": "matrix_pr_ga_flip", "family": "26.07"} in actions

    def test_booted_beta_image_still_prerelease_does_not_flip(self) -> None:
        actions = _plan(
            [PLUS_2603, PLUS_2607_BETA],
            {"26.03": True, "26.07": True},
            [_boot("26.07", "26.07-BETA", "26.07\t\tBeta Version (26.07)\n")],
        )
        assert all(a["type"] != "matrix_pr_ga_flip" for a in actions)

    def test_unpublished_beta_family_gone_ga_builds_from_stable_branch(self) -> None:
        # Review F3: GA lands BEFORE the merged beta entry's first build. The
        # family must be built once via publish_new from the STABLE branch (not
        # the leftover beta branch), and no dead republish leg may target the
        # nonexistent tag.
        repoc = REPOC_PLUS + "26_07 (release)\t\tCurrent Stable Version (26.07)\n"
        actions = _plan(
            [PLUS_2603, PLUS_2607_BETA],
            {"26.03": True, "26.07": False},
            [_boot("26.03", "26.03.1-RELEASE", repoc)],
        )
        assert {"type": "publish_new", "family": "26.07", "branch": "26_07", "from": "26.03"} in actions
        assert all(not (a["type"] == "republish" and a["family"] == "26.07") for a in actions)
        # the status flip is still proposed — the built image IS the GA build
        assert {"type": "matrix_pr_ga_flip", "family": "26.07"} in actions

    def test_stable_branch_for_beta_family_republishes_and_flips(self) -> None:
        # GA lands as a NEW stable pinned branch while the matrix still says
        # beta: refresh the beta image from it AND flip the status
        repoc = "26_07 (release) (default)\t\tCurrent Stable Version (26.07)\n"
        actions = _plan(
            [PLUS_2603, PLUS_2607_BETA],
            {"26.03": True, "26.07": True},
            [_boot("26.03", "26.03.1-RELEASE", REPOC_PLUS + repoc)],
        )
        assert {"type": "republish", "family": "26.07", "branch": "26_07", "reason": "ga-final"} in actions
        assert {"type": "matrix_pr_ga_flip", "family": "26.07"} in actions


# ── Steady state ──────────────────────────────────────────────────────────────


class TestSteadyState:
    def test_consistent_box_and_matrix_plan_nothing(self) -> None:
        actions = _plan(
            [PLUS_2603],
            {"26.03": True},
            [_boot("26.03", "26.03.1-RELEASE", "26_03_1 (release) (default)\t\tCurrent Stable Version (26.03.1)\n")],
        )
        assert actions == []

    def test_ce_steady_state_with_live_fixture(self) -> None:
        ce = {"pfsense_version": "2.8", "channel": "CE", "status": "active", "ci": True}
        actions = _plan([ce], {"2.8": True}, [_boot("2.8", "2.8.1-RELEASE", REPOC_CE)], channel="CE")
        assert actions == []


class TestBootedFamilyMismatch:
    """Scenario (issue #1857): the 26.07-tagged image booted 26.03.1-RELEASE.
    A mislabeled image must surface an error and drive NO rule, instead of
    flipping the beta entry to GA and republishing off the wrong box."""

    MISLABELED = _boot("26.07", "26.03.1-RELEASE", REPOC_PLUS, UPGRADE_AVAILABLE)

    def test_wrong_family_boot_surfaces_error_and_plans_nothing_else(self) -> None:
        # incident shape: -c said update available AND the final-looking
        # version matched no prerelease marker — both rules must stay silent
        actions = _plan([PLUS_2603, PLUS_2607_BETA], {"26.03": True, "26.07": True}, [self.MISLABELED])
        errors = [a for a in actions if a["type"] == "error"]
        assert len(errors) == 1
        assert errors[0]["family"] == "26.07"
        assert "26.03.1-RELEASE" in errors[0]["message"]
        assert [a for a in actions if a["type"] != "error"] == []

    def test_wrong_family_branches_never_drive_matrix_prs(self) -> None:
        # the tainted boot's repoc lists an unknown family — an untrusted box
        # must not open the human-gate PR either
        boot = _boot("26.07", "26.03.1-RELEASE", REPOC_PLUS + "26_09\t\tBeta Version (26.09)\n")
        actions = _plan([PLUS_2603, PLUS_2607_BETA], {"26.03": True, "26.07": True}, [boot])
        assert actions != []
        assert all(a["type"] == "error" for a in actions)

    def test_healthy_sibling_boot_still_drives_its_own_rules(self) -> None:
        # the healthy 26.03 box keeps working while the mislabeled 26.07 one
        # is quarantined
        healthy = _boot("26.03", "26.03-RELEASE", REPOC_PLUS)
        actions = _plan([PLUS_2603, PLUS_2607_BETA], {"26.03": True, "26.07": True}, [healthy, self.MISLABELED])
        assert {"type": "republish", "family": "26.03", "branch": "26_03_1", "reason": "newer-branch"} in actions
        assert all(a["type"] != "matrix_pr_ga_flip" for a in actions)

    def test_missing_etc_version_is_not_a_mismatch(self) -> None:
        # a lost etc-version fact stays a degraded fact (issue #1848), not a
        # mislabeled-image error
        actions = _plan([PLUS_2603], {"26.03": True}, [_boot("26.03", "", REPOC_PLUS)])
        assert all(a["type"] != "error" for a in actions)


class TestMissingSecondSource:
    """Scenario (issue #1848): the -c fact is optional. A boot that gathered its
    branch list but lost the upgrade check must still drive branch-based rules."""

    def test_branches_still_drive_rules_without_upgrade_check(self) -> None:
        actions = _plan(
            [PLUS_2603, PLUS_2607_BETA],
            {"26.03": True, "26.07": False},
            [_boot("26.03", "26.03.1-RELEASE", REPOC_PLUS, check="")],
        )
        assert {"type": "publish_new", "family": "26.07", "branch": "26.07", "from": "26.03"} in actions
