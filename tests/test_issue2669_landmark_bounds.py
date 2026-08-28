"""Issue #2669: a landmark that bounds a contract-test slice must be load-bearing.

``text.split(marker, 1)[0]`` returns the WHOLE string when ``marker`` is absent, so a
slice bounded that way silently stops bounding anything the moment a documentation or
workflow edit rewords the landmark: the slice grows to end-of-file and every assertion
against it keeps passing.

These tests pin the replacement contract for the whole class: the landmark is
load-bearing, an absent one raises ``ValueError`` naming it, and a present one yields
byte-identically the same region the ``split`` form yielded, bounding on the FIRST
occurrence exactly as ``split(marker, 1)`` did.
"""

from __future__ import annotations

import pathlib

import pytest

from tests._workflow_steps import extract_after, extract_before, extract_between, extract_job, extract_step

ROOT = pathlib.Path(__file__).resolve().parents[1]

DOCUMENT = "alpha START body-of-interest END omega"

# One row per document flavour a converted call site slices, so the contract is pinned
# against the real markers those sites use, not only against a synthetic fixture.
REAL_DOCUMENTS = [
    pytest.param(".github/workflows/release-published.yml", "\non:\n", "\npermissions:\n", id="workflow-yaml"),
    pytest.param(".agents/policy/landing.md", "## Merge step", "## Post-merge", id="markdown-policy"),
    pytest.param(
        "src/usr/local/www/pfblockerng/pfblockerng_dnsbl.php",
        "// A usable validator always runs",
        "// Validate DNSBL VIP address",
        id="php-source",
    ),
]


def test_extract_after_returns_the_region_the_split_form_returned() -> None:
    """The conversion must not move the region: same marker in, same bytes out."""
    assert extract_after(DOCUMENT, "START") == DOCUMENT.split("START", 1)[1]


def test_extract_after_raises_naming_the_absent_marker() -> None:
    with pytest.raises(ValueError) as excinfo:
        extract_after(DOCUMENT, "MISSING-OPENER")
    assert repr("MISSING-OPENER") in str(excinfo.value)


def test_extract_before_returns_the_region_the_split_form_returned() -> None:
    assert extract_before(DOCUMENT, "END") == DOCUMENT.split("END", 1)[0]


def test_extract_before_raises_instead_of_widening_to_the_whole_string() -> None:
    """Given a terminator that is gone, the ``split`` form widens silently; ``extract_before``
    must raise instead. The before-state assertion is what makes green prove the flip."""
    assert DOCUMENT.split("MISSING-TERMINATOR", 1)[0] == DOCUMENT  # the defect, unbounded
    with pytest.raises(ValueError) as excinfo:
        extract_before(DOCUMENT, "MISSING-TERMINATOR")
    assert repr("MISSING-TERMINATOR") in str(excinfo.value)


def test_extract_between_returns_the_region_the_chained_split_form_returned() -> None:
    assert extract_between(DOCUMENT, "START", "END") == DOCUMENT.split("START", 1)[1].split("END", 1)[0]


def test_extract_between_raises_naming_the_absent_start_marker() -> None:
    with pytest.raises(ValueError) as excinfo:
        extract_between(DOCUMENT, "MISSING-OPENER", "END")
    assert repr("MISSING-OPENER") in str(excinfo.value)


def test_extract_between_raises_naming_the_absent_terminator() -> None:
    with pytest.raises(ValueError) as excinfo:
        extract_between(DOCUMENT, "START", "MISSING-TERMINATOR")
    assert repr("MISSING-TERMINATOR") in str(excinfo.value)


def test_the_helpers_bound_on_the_first_occurrence_of_each_marker() -> None:
    """Both markers repeat, and a terminator also sits BEFORE the start marker. Only
    first-occurrence semantics — what ``split(marker, 1)`` gave — yields this region;
    last-occurrence bounding widens it, which is the whole defect class."""
    text = "END alpha START body END omega START again END tail"
    assert extract_after(text, "START") == " body END omega START again END tail"
    assert extract_before(text, "END") == ""
    assert extract_between(text, "START", "END") == " body "


def test_an_empty_bound_raises_across_the_whole_family() -> None:
    """``"" in text`` is true at index 0, and an empty step or job name matches a bare
    ``- name:``/``  :`` line vacuously, so an empty bound is no bound at all — the shape
    these helpers exist to remove. ``split("", 1)`` raised too. Every member owes it, or
    the floor is only nearly total."""
    vacuous = "jobs:\n  :\n    steps:\n      - name: \n        run: echo hi\n"
    for helper, text in (
        (extract_after, DOCUMENT),
        (extract_before, DOCUMENT),
        (extract_step, vacuous),
        (extract_job, vacuous),
    ):
        with pytest.raises(ValueError, match="must not be empty"):
            helper(text, "")
    for markers in (("", "END"), ("START", "")):
        with pytest.raises(ValueError, match="must not be empty"):
            extract_between(DOCUMENT, *markers)


def test_extract_step_raises_naming_the_absent_step() -> None:
    """The workflow-shape siblings owe the same named-`ValueError` contract: converted
    sites bound a step or a job through them, so a silent miss there widens too."""
    workflow = "jobs:\n  build:\n    steps:\n      - name: Present step\n        run: echo hi\n"
    with pytest.raises(ValueError) as excinfo:
        extract_step(workflow, "Absent step")
    assert repr("Absent step") in str(excinfo.value)


def test_extract_job_raises_naming_the_absent_job() -> None:
    workflow = "jobs:\n  build:\n    steps:\n      - name: Present step\n        run: echo hi\n"
    with pytest.raises(ValueError) as excinfo:
        extract_job(workflow, "absent-job")
    assert repr("absent-job") in str(excinfo.value)


@pytest.mark.parametrize(("relative_path", "start_marker", "terminator"), REAL_DOCUMENTS)
def test_reworded_landmark_in_a_real_document_raises_instead_of_widening(
    relative_path: str, start_marker: str, terminator: str
) -> None:
    """Scenario: a real repository document whose landmark a future edit rewords.

    Given the document as committed, when the terminator is case-flipped the way PR #2663's
    reword flipped one, then the ``split`` form widens the slice and stays quiet while
    ``extract_between`` raises naming the terminator that vanished.
    """
    document = (ROOT / relative_path).read_text(encoding="utf-8")
    bounded = extract_between(document, start_marker, terminator)
    assert bounded == document.split(start_marker, 1)[1].split(terminator, 1)[0]

    reworded = document.replace(terminator, terminator.swapcase())
    assert terminator not in reworded, f"reword did not remove {terminator!r}"

    widened = reworded.split(start_marker, 1)[1].split(terminator, 1)[0]
    assert len(widened) > len(bounded), "the split form must be shown widening, or this proves nothing"

    with pytest.raises(ValueError) as excinfo:
        extract_between(reworded, start_marker, terminator)
    assert repr(terminator) in str(excinfo.value)
