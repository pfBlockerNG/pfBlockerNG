"""Hermetic environment for scratch-repo `git` calls in the unit suite.

A test that builds a throwaway repository and commits into it must not inherit the
developer's global/system Git configuration: `commit.gpgsign=true` makes the synthetic
`user.name=t` identity attempt a signed commit it has no key for, and git exits 128 with
`fatal: failed to write commit object` before the tool under test ever runs (issue #1967).
The same class covers `init.defaultBranch`, `init.templateDir`, `core.hooksPath` and any
`include.path` a developer has set — none of which the scratch repo asked for.

Pointing both config scopes at `os.devnull` is the repo's established fix
(`tests/test_agent_roles_check.py` shipped it first); this module is the single
definition every scratch-git helper reuses so the scopes cannot drift apart.

Deliberately NOT applied session-wide via a conftest fixture: that would also scrub the
environment of the CHECKERS these suites run as subprocesses, and several of them exist
precisely to prove a hostile Git configuration cannot blind the gate
(`test_cli_hostile_git_configs_cannot_bypass_the_gate`). The scrub belongs to repo SETUP,
not to the tool under test.
"""

from __future__ import annotations

import os


def scrubbed_git_env(**overrides: str) -> dict[str, str]:
    """The process environment with both Git config scopes neutralised.

    ``overrides`` are applied last, for a caller that needs an extra variable
    (e.g. a fake ``PATH``) in the same environment.
    """
    return {
        **os.environ,
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull,
        **overrides,
    }
