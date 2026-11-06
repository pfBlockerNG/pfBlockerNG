"""Issue #3728: the filter-reload smoke settles an alias only after the blocking filter sync builds its table.

``reload()`` launches ``/etc/rc.filter_configure_sync`` detached, so right after it the pf table may not exist
yet. The live module's ``_settle_alias`` must not read that table before ``apply_filter_sync`` (the blocking
reload, #3436) has created it. The fake guest below models exactly that: the table appears only when the
blocking sync runs, and a read before that reports ``Table does not exist`` like pfctl does.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from tests.smoke import helpers as h
from tests.smoke import test_smoke_filter_reload_bound as frb

INERT_IP = "203.0.113.50"  # RFC 5737 TEST-NET-3
ALIAS = "smokefrbsettle"


class _DetachedReloadGuest:
    """A pf host whose alias table exists only after the blocking filter sync has run."""

    def __init__(self) -> None:
        self.table_built = False
        self.table_reads_before_build = 0
        self.synced = False

    def ssh(self, *remote: str, timeout: float = 60.0) -> SimpleNamespace:
        if remote == ("/etc/rc.filter_configure_sync",):
            self.synced = True
            self.table_built = True
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        if remote[0] == h.PFCTL and remote[3:5] == ("-T", "show"):
            if not self.table_built:
                self.table_reads_before_build += 1
                return SimpleNamespace(returncode=255, stdout="", stderr="pfctl: Table does not exist")
            return SimpleNamespace(returncode=0, stdout=f"{INERT_IP}\n", stderr="")
        raise AssertionError(f"unexpected guest command: {remote!r}")


@pytest.fixture
def guest(monkeypatch: pytest.MonkeyPatch) -> _DetachedReloadGuest:
    vm = _DetachedReloadGuest()
    monkeypatch.setattr(h, "write_local_feed", lambda _vm, name, _contents, **_kw: f"/var/db/pfblockerng/{name}")
    monkeypatch.setattr(h, "inject", lambda _vm, _spec, **_kw: None)
    # The detached launch returns before the table exists, so the non-blocking reload builds nothing here.
    monkeypatch.setattr(h, "reload", lambda _vm, _scope="update", **_kw: None)
    return vm


def test_settle_alias_reads_the_table_only_after_the_blocking_filter_sync_builds_it(
    guest: _DetachedReloadGuest,
) -> None:
    spec = frb._settle_alias(guest, ALIAS, INERT_IP)  # type: ignore[arg-type]

    assert guest.synced, "the blocking filter sync must run before the table is read"
    assert guest.table_reads_before_build == 0, (
        f"{guest.table_reads_before_build} table read(s) landed before the filter sync built {spec.alias}"
    )
    assert spec.aliasname == ALIAS
