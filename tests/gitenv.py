"""Config-neutral environment for scratch-repo `git` calls in the unit suite.

A test that builds a throwaway repository and commits into it must not inherit the
developer's global/system Git configuration: `commit.gpgsign=true` makes the synthetic
`user.name=t` identity attempt a signed commit it has no key for, and git exits 128 with
`fatal: failed to write commit object` before the tool under test ever runs (issue #1967).
`core.hooksPath` pointing at a real hook set is the same class — the scratch repo then
runs hooks it never asked for. (Probed: a NONEXISTENT hooksPath/templateDir/excludesFile
is ignored by git and harmless; it is a hooksPath that actually resolves that bites.)

Pointing both config scopes at `os.devnull` is the repo's established fix
(`tests/test_agent_roles_check.py` shipped it first); this module is the single definition
every PYTEST scratch-git helper reuses so the two scopes cannot drift apart. The shellspec
suite under `tests/shell/` has the same defect and its own mechanism — tracked separately,
not covered here.

Scope note: this neutralises CONFIG, not the whole Git environment. `GIT_DIR`,
`GIT_WORK_TREE`, `GIT_INDEX_FILE` and `GIT_PREFIX` are still inherited and would override
`cwd`; a caller that runs under a Git hook wants ``drop_git_vars=True`` as well.

Deliberately NOT applied session-wide via a conftest fixture. The scrub is a property of
repository SETUP, and a session fixture would silently change the environment the
CHECKER-under-test observes — several of these suites run that checker as a subprocess and
assert on what it sees. (It would also miss the call sites that build their env from
scratch rather than from ``os.environ``, so it is not even a complete substitute.)
"""

from __future__ import annotations

import os


def scrubbed_git_env(*, drop_git_vars: bool = False) -> dict[str, str]:
    """The process environment with both Git config scopes neutralised.

    ``drop_git_vars`` additionally strips every inherited ``GIT_*`` variable. Needed when
    the suite may run under a Git hook, which exports ``GIT_DIR``/``GIT_INDEX_FILE``/
    ``GIT_WORK_TREE``/``GIT_PREFIX`` — those override ``cwd`` and would point every
    invocation at the REAL repository instead of the throwaway one.
    """
    base = {k: v for k, v in os.environ.items() if not (drop_git_vars and k.startswith("GIT_"))}
    # After the strip, never before: these two ARE GIT_* variables and must survive it.
    base["GIT_CONFIG_GLOBAL"] = os.devnull
    base["GIT_CONFIG_SYSTEM"] = os.devnull
    return base
