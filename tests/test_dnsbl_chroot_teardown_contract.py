"""DNSBL chroot teardown keeps each consumer and the shell source of truth wired."""

from __future__ import annotations

import re
from pathlib import Path

PKG_DIR = Path(__file__).resolve().parent.parent / "src/usr/local/pkg/pfblockerng"
INC = PKG_DIR / "pfblockerng.inc"
SHELL = PKG_DIR / "pfblockerng.sh"
TEARDOWN_EXEC = "exec('/usr/local/pkg/pfblockerng/pfblockerng.sh dnsbl_cache teardown >/dev/null 2>&1');"
STAGE_EXEC = "exec('/usr/local/pkg/pfblockerng/pfblockerng.sh dnsbl_cache stage >/dev/null 2>&1');"
STATIC_CHROOT_FILES = (
    "pfb_dnsbl_regex_rules.py",
    "pfb_unbound.py",
    "pfb_unbound_include.inc",
    "pfb_py_hsts.txt",
    "pfb_python.sh",
    "dnsbl_psl",
)


def _php_function_body(source: str, name: str) -> str:
    """Extract one top-level function from the PHP source."""
    matches = list(
        re.finditer(
            rf"^function {re.escape(name)}\([^\n]*\)\s*\{{",
            source,
            re.MULTILINE,
        )
    )
    assert len(matches) == 1, f"expected one {name}() declaration"
    start = matches[0].end()
    following = re.search(r"^function\s+", source[start:], re.MULTILINE)
    end = start + following.start() if following else len(source)
    return source[start:end]


def _shell_teardown_body(source: str) -> str:
    match = re.search(
        r"dnsbl_cache_teardown\(\) \{\n(?P<body>.*?)\n\t\}\n\n\tcase \"\$\{1\}\" in",
        source,
        re.DOTALL,
    )
    assert match is not None, "dnsbl_cache_teardown() dispatch boundary not found"
    return match.group("body")


def _shipped_files(source: str) -> list[str]:
    assignments = re.findall(r"^\s*PFB_PY_SHIPPED='([^']*)'", source, re.MULTILINE)
    assert len(assignments) == 1, "PFB_PY_SHIPPED must have one declaration"
    files = assignments[0].split()
    assert files, "PFB_PY_SHIPPED must not be empty"
    return files


def test_each_php_consumer_has_one_scoped_teardown_call() -> None:
    source = INC.read_text()
    for name in ("pfb_unbound_dnsbl", "pfblockerng_php_pre_deinstall_command"):
        body = _php_function_body(source, name)
        assert body.count(TEARDOWN_EXEC) == 1
        for call in re.finditer(r"unlink_if_exists\s*\((?P<argument>.*?)\)", body, re.DOTALL):
            argument = call.group("argument")
            assert "unbound_chroot_path" not in argument, argument
            assert not any(file_name in argument for file_name in STATIC_CHROOT_FILES), argument

        if name == "pfb_unbound_dnsbl":
            branches = [
                match
                for match in re.finditer(
                    r"^[ \t]*if \(\$mode == 'enabled'\) \{\n"
                    r"(?P<enabled>.*?)[ \t]*\} else \{\n"
                    r"(?P<disabled>.*?)\n[ \t]*\}",
                    body,
                    re.MULTILINE | re.DOTALL,
                )
                if STAGE_EXEC in match.group("enabled")
            ]
            assert len(branches) == 1, "enabled stage branch not uniquely scoped"
            enabled, disabled = branches[0].group("enabled", "disabled")
            assert TEARDOWN_EXEC not in enabled
            assert disabled.count(TEARDOWN_EXEC) == 1


def test_shell_teardown_derives_shipped_files_including_psl_authority() -> None:
    source = SHELL.read_text()
    body = _shell_teardown_body(source)
    shipped = _shipped_files(source)

    assert body.count("for _f in ${PFB_PY_SHIPPED}; do") == 1
    assert body.count('rm -f "${pfbchroot}/${_f}"') == 1
    assert "dnsbl_psl" in shipped
    assert 'rm -f "${pfbchroot}/pfb_py_tld.txt"' not in body
    assert all(file_name not in body for file_name in shipped)
