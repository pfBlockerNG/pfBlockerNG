"""Bound a workflow YAML "- name: <step>" block to that step's own body.

Test-only helper shared by tests/test_issue2143_*.py: those suites assert
against one named step's env/run text inside a `.github/workflows/*.yml` file.
A plain ``str.split(marker, 1)[1]`` slices to end-of-file, so an assertion
against the slice can accidentally match a LATER, unrelated step once anything
is appended after the one under test. ``extract_step`` stops at the next
sibling list item (`- ...`) at the SAME indentation instead.
"""

from __future__ import annotations

import re


def extract_step(workflow: str, step_name: str) -> str:
    """Return the body of the ``- name: <step_name>`` step in ``workflow``,
    bounded to the next sibling step at the same indentation (or end-of-file
    when it is the last step in its job).

    Raises ``ValueError`` naming the missing marker if the step is absent — a
    silent empty-string slice would let every ``in`` assertion against it pass
    vacuously instead of failing for the right reason.
    """
    marker = re.compile(rf"^( *)- name: {re.escape(step_name)}\n", re.MULTILINE)
    match = marker.search(workflow)
    if match is None:
        raise ValueError(f"step {step_name!r} not found in workflow")
    indent = match.group(1)
    start = match.end()
    sibling = re.compile(rf"^{re.escape(indent)}- ", re.MULTILINE)
    next_match = sibling.search(workflow, start)
    end = next_match.start() if next_match else len(workflow)
    return workflow[start:end]
