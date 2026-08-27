"""Smoke diag bundle must capture pkg ABI/repos with URL redaction (issue #2754).

A #2242 drift (guest pkg ABI FreeBSD:16 vs expected 15) produced 155 setup
errors. The collector had no pkg config ABI, no pkg -vv, no repo confs, so
the forced-ABI path stayed unproven after the guest was torn down.

pkg -vv and repo confs can carry credentials. Redact userinfo and token-shaped
query parameters at capture time.
"""

from __future__ import annotations

import inspect

from tests.smoke import helpers


def test_collect_host_diagnostics_captures_pkg_abi_and_uname() -> None:
    """Given collect_host_diagnostics
    When it builds the guest snapshot script
    Then it records pkg ABI, ALTABI, and uname -mr.
    """
    src = inspect.getsource(helpers.collect_host_diagnostics)
    assert "pkg config ABI" in src
    assert "pkg config ALTABI" in src
    assert "uname -mr" in src


def test_collect_host_diagnostics_captures_pkg_vv_and_repo_confs() -> None:
    """Given collect_host_diagnostics
    When it snapshots pkg configuration
    Then pkg -vv and /usr/local/etc/pkg/repos are in the bundle.
    """
    src = inspect.getsource(helpers.collect_host_diagnostics)
    assert "pkg -vv" in src
    assert "/usr/local/etc/pkg/repos" in src


def test_redact_pkg_urls_strips_userinfo() -> None:
    """Given a repo URL with user:pass@
    When capture-time redaction runs
    Then the userinfo is gone and the rest of the URL remains.
    """
    raw = "url: https://ci-token:s3cret@pkg.example.com/nightly/ce-2.8\n"
    out = helpers.redact_pkg_urls(raw)
    assert "s3cret" not in out
    assert "ci-token" not in out
    assert "pkg.example.com/nightly/ce-2.8" in out
    assert "REDACTED@" in out


def test_redact_pkg_urls_strips_token_query() -> None:
    """Given a URL with a token-shaped query parameter
    When capture-time redaction runs
    Then the parameter value is REDACTED and neighbouring params remain.
    """
    raw = "https://pkg.example.com/repo?token=ghp_abc123&abi=FreeBSD:15:amd64\n"
    out = helpers.redact_pkg_urls(raw)
    assert "ghp_abc123" not in out
    assert "token=REDACTED" in out
    assert "abi=FreeBSD:15:amd64" in out


def test_redact_pkg_urls_leaves_clean_urls_intact() -> None:
    """Given a URL with no userinfo and no token query
    When capture-time redaction runs
    Then the text is unchanged.
    """
    raw = "url: http://pkg.pfblockerng.com/nightly/ce-2.8/\nABI: FreeBSD:15:amd64\n"
    assert helpers.redact_pkg_urls(raw) == raw


def test_collect_host_diagnostics_redacts_pkg_urls_at_capture() -> None:
    """Given the guest snapshot script
    When it captures pkg -vv and repo confs
    Then it redacts URLs before the tarball is built.
    """
    src = inspect.getsource(helpers.collect_host_diagnostics)
    assert "redact_pkg_urls" in src or "REDACTED@" in src
