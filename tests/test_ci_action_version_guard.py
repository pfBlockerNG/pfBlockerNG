from pathlib import Path

import tests.test_ci_checkout_persist_credentials as guard


def test_version_guard_rejects_inline_quoted_and_hash_suffix_pins(tmp_path: Path) -> None:
    module = guard.__dict__
    original = module["WORKFLOWS_DIR"]
    module["WORKFLOWS_DIR"] = tmp_path
    try:
        (tmp_path / "inline.yml").write_text(
            "jobs:\n"
            "  demo:\n"
            "    steps:\n"
            "      - uses: actions/checkout@v6\n"
            '      - uses: "actions/checkout@v6"\n'
            "      - uses: actions/checkout@v7#junk\n"
            "      - uses: astral-sh/setup-uv@v7\n",
            encoding="utf-8",
        )

        seen, offenders = module["_action_version_offenders"]()
        assert seen == {"actions/checkout", "astral-sh/setup-uv"}
        report = "\n".join(offenders)
        assert "checkout@v6" in report
        assert "checkout@v7#junk" in report
        assert "setup-uv@v7" in report
    finally:
        module["WORKFLOWS_DIR"] = original
