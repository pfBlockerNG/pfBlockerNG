"""Issue #3720: the live-VM pytest step receives the webConfigurator admin credentials.

Smoke modules log in through ``tests/smoke/ui/credgate.py:admin_password_decision``, which
fails the test when ``SMOKE_ADMIN_PASSWORD`` is unset. A runner only sees what the step's
``env`` hands it, so the step that runs ``scripts/run-smoke.sh`` must pass both values, the
way ``ui-tests.yml`` does for the UI tiers.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

WORKFLOW = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "smoke-single.yml"


def _pytest_step_env() -> dict[str, Any]:
    steps = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]["smoke"]["steps"]
    matching = [s for s in steps if "scripts/run-smoke.sh" in str(s.get("run", ""))]
    assert len(matching) == 1, f"steps running run-smoke.sh: {[s.get('name') for s in matching]}"
    env: dict[str, Any] = matching[0]["env"]
    return env


def test_the_live_vm_step_receives_the_admin_password_secret() -> None:
    env = _pytest_step_env()

    assert env.get("SMOKE_ADMIN_PASSWORD") == "${{ secrets.SMOKE_ADMIN_PASSWORD }}", (
        f"expected SMOKE_ADMIN_PASSWORD from the secret, got {env.get('SMOKE_ADMIN_PASSWORD')!r}"
    )


def test_the_live_vm_step_receives_the_admin_user_variable() -> None:
    env = _pytest_step_env()

    assert env.get("SMOKE_ADMIN_USER") == "${{ vars.SMOKE_ADMIN_USER }}", (
        f"expected SMOKE_ADMIN_USER from the repo variable, got {env.get('SMOKE_ADMIN_USER')!r}"
    )
