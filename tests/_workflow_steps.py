"""Bound a document slice to its landmark, so a reworded landmark FAILS the test.

Test-only helpers for the contract suites that assert against one region of a
`.github/workflows/*.yml`, a policy/skill Markdown file, or a `src/` source file.
A plain ``str.split(marker, 1)[1]`` slices to end-of-file, so an assertion against
the slice can accidentally match a LATER, unrelated step; and ``[0]`` on an absent
terminator returns the WHOLE string, so the slice silently stops bounding anything
the moment an ordinary documentation edit rewords the landmark (issue #2669; it hit
PR #2663 for real). Every helper here makes the landmark load-bearing: a missing one
raises ``ValueError`` naming it instead of quietly widening the region.

``extract_after``/``extract_before``/``extract_between`` bound an arbitrary landmark
pair; ``extract_step``/``extract_job`` know the workflow-YAML shapes and stop at the
next sibling at the same indentation.
"""

from __future__ import annotations

import re


def extract_step(workflow: str, step_name: str) -> str:
    """Return the body of the ``- name: <step_name>`` step in ``workflow``,
    bounded to the next list item at the same indentation — which may be one in a
    LATER job — or end-of-file when no such item follows.

    Raises ``ValueError`` naming the missing marker if the step is absent — a
    silent empty-string slice would let every ``in`` assertion against it pass
    vacuously instead of failing for the right reason.
    """
    _reject_empty(step_name)
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


def extract_job(workflow: str, job_name: str) -> str:
    """Return the body of a top-level ``  <job_name>:`` job block, bounded to the
    next sibling job at the same (2-space) indentation, or end-of-file.

    ``extract_step``'s sibling-boundary idea, one indentation level up (job keys,
    not ``- name:`` step items). A workflow with more than one job that runs the
    same script needs this: a file-global index comparison can otherwise pair a
    step in one job with a step in another.
    """
    _reject_empty(job_name)
    marker = re.compile(rf"^  {re.escape(job_name)}:\n", re.MULTILINE)
    match = marker.search(workflow)
    if match is None:
        raise ValueError(f"job {job_name!r} not found in workflow")
    start = match.end()
    sibling = re.compile(r"^  [A-Za-z0-9_-]+:\n", re.MULTILINE)
    next_match = sibling.search(workflow, start)
    end = next_match.start() if next_match else len(workflow)
    return workflow[start:end]


def extract_after(text: str, marker: str) -> str:
    """``text`` after the first ``marker``. An absent ``marker`` raises ``ValueError``
    naming it, where ``split(marker, 1)[1]`` raised a bare ``IndexError``."""
    _reject_empty(marker)
    start = text.find(marker)
    if start < 0:
        raise ValueError(f"marker {marker!r} not found in text")
    return text[start + len(marker) :]


def extract_before(text: str, marker: str) -> str:
    """``text`` before the first ``marker``. An absent ``marker`` raises ``ValueError``
    naming it — the silent case ``split(marker, 1)[0]`` hid by returning everything."""
    _reject_empty(marker)
    end = text.find(marker)
    if end < 0:
        raise ValueError(f"marker {marker!r} not found in text")
    return text[:end]


def extract_between(text: str, start_marker: str, end_marker: str) -> str:
    """``text`` between ``start_marker`` and the FIRST ``end_marker`` after it; either
    one absent raises ``ValueError`` naming it."""
    return extract_before(extract_after(text, start_marker), end_marker)


def _reject_empty(marker: str) -> None:
    # "" matches at index 0 of every string, and an empty step/job name matches a bare
    # `- name:` line vacuously, so an empty bound is no bound — the shape these helpers
    # exist to remove. `str.split("", 1)` raised too; keep that floor across the family.
    if not marker:
        raise ValueError(f"marker {marker!r} must not be empty")
