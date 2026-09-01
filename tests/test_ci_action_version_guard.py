from pathlib import Path

import tests.test_ci_checkout_persist_credentials as guard


def _workflow(path: Path, uses: str) -> Path:
    path.write_text(f"jobs:\n  demo:\n    steps:\n      {uses}\n", encoding="utf-8")
    return path


def test_version_guard_rejects_each_hostile_pin_shape(tmp_path: Path) -> None:
    scan = guard.__dict__["_action_version_offenders"]
    cases = (
        ("- uses: actions/checkout@v6", "actions/checkout", "actions/checkout@v6"),
        ('- uses: "actions/checkout@v6"', "actions/checkout", "actions/checkout@v6"),
        ("- uses : actions/checkout@v6", "actions/checkout", "actions/checkout@v6"),
        ("- uses: actions/checkout@v7#junk", "actions/checkout", "actions/checkout@v7#junk"),
        ("- uses: 'astral-sh/setup-uv@v7\"'", "astral-sh/setup-uv", 'astral-sh/setup-uv@v7"'),
        ("- uses: actions/checkout@v7 junk", "actions/checkout", "actions/checkout@v7 junk"),
        ("- uses: actions/checkout@ v6", "actions/checkout", "actions/checkout@ v6"),
    )
    for index, (uses, action, value) in enumerate(cases):
        seen, offenders = scan([_workflow(tmp_path / f"bad-{index}.yml", uses)])
        assert seen == {action}, f"scanner skipped target action: {uses}"
        assert len(offenders) == 1, f"scanner accepted hostile pin: {uses}"
        assert value in offenders[0]


def test_version_guard_accepts_valid_yaml_scalar_shapes(tmp_path: Path) -> None:
    scan = guard.__dict__["_action_version_offenders"]
    cases = (
        ("- uses: actions/checkout@v7", "actions/checkout"),
        ("- uses : actions/checkout@v7", "actions/checkout"),
        ('- uses: "actions/checkout@v7" # comment', "actions/checkout"),
        ("- uses: 'astral-sh/setup-uv@v10.0.1' # comment", "astral-sh/setup-uv"),
    )
    for index, (uses, action) in enumerate(cases):
        seen, offenders = scan([_workflow(tmp_path / f"good-{index}.yml", uses)])
        assert seen == {action}, f"scanner skipped valid pin: {uses}"
        assert not offenders, f"scanner rejected valid pin: {uses}"
