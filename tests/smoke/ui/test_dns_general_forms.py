"""Tier B (``ui_e2e``): on DNS General each form's button saves only its own form (issue #3771).

DNS General holds the pfB-DNS form (button ``save_pfb_dns``) and its own form (button ``save``). A post that carries the
fields of both forms, as the page's whole-page scrape does, must still run only the handler its button names. The
oracle is the effective config.xml read back over SSH, never the HTTP body: the keys each save writes, the keys it must
leave alone, and the description of the last write_config() (which handler ran).
"""

from __future__ import annotations

import contextlib
import json
from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .render_oracle import NO_INPUT_ERRORS
from .test_dnsbl_follows_pfb_dns import PFB_DNS_SIBLINGS, _errors_text
from .test_render_smoke import _read_config_paths, _write_config_paths

if TYPE_CHECKING:
    from collections.abc import Iterator

    from ..conftest import SmokeVM
    from .webui import WebUI

pytestmark = pytest.mark.ui_e2e

DNS_GENERAL_PAGE = "/pfblockerng/pfblockerng_dns_general.php"
SAVE_PFB_DNS = ("save_pfb_dns", "Save pfB-DNS settings")
SAVE_TIMEOUT = 300.0
LAST_WRITE = "revision/description"

PFB_DNS_ENABLE = helpers.dns_config_path("pfb_dns")
PFB_DNS_DOT_PORT = helpers.dns_config_path("pfb_dns_dot_port")
REPLY_LOGGING = f"{helpers.CFG_DNSBL_SETTINGS}/pfb_py_reply"
# The pfB-DNS form's stored settings: valid (every interface list Localhost, every transport off), enable Off.
PFB_DNS_SEED = {
    **{helpers.dns_config_path(key): value for key, value in PFB_DNS_SIBLINGS.items()},
    PFB_DNS_ENABLE: "",
}
# The DNS General form's stored settings: reply logging On, Resolver addresses and VIP-only Off (its save adds no VIP).
GENERAL_SEED = {
    REPLY_LOGGING: "on",
    **{
        f"{helpers.CFG_GLOBAL}/{key}": value
        for key, value in {
            "pfb_dns_listen_vip": "",
            "pfb_dns_listen_vip_only": "",
            "pfb_dns_listen_vip4": "",
            "pfb_dns_listen_vip6": "",
            "pfb_dns_listen_interface": "lo0",
        }.items()
    },
}


def _stored(vm: SmokeVM, paths: list[str]) -> dict[str, str]:
    """The stored value of each path, an absent one as the empty string, in one round trip."""
    items = ", ".join(
        f"{helpers._php_str(path)} => (string) config_get_path({helpers._php_str(path)}, '')" for path in paths
    )
    return json.loads(helpers._php_read_scalar(vm, "", f"json_encode(array({items}))"))


@contextlib.contextmanager
def _both_forms_seeded(vm: SmokeVM) -> Iterator[None]:
    """Store both forms' settings directly (the before-state must not depend on the saves under test); restore after."""
    seeds = {**PFB_DNS_SEED, **GENERAL_SEED}
    priors = _read_config_paths(vm, list(seeds))
    try:
        _write_config_paths(vm, seeds)
        assert _stored(vm, list(seeds)) == seeds, "the seed of both forms did not take"
        yield
    finally:
        _write_config_paths(vm, priors)


def test_save_pfb_dns_button_writes_the_pfb_dns_keys_and_leaves_the_dns_general_keys_unchanged(
    webui: WebUI, smoke_vm: SmokeVM
) -> None:
    """Given both forms stored, When the page posts a changed pfB-DNS enable and DoT port beside a changed reply logging
    with the pfB-DNS button, Then the two pfB-DNS keys are written and every DNS General key keeps its stored value.
    """
    vm = smoke_vm
    with _both_forms_seeded(vm):
        before = _stored(vm, [PFB_DNS_ENABLE, PFB_DNS_DOT_PORT, *GENERAL_SEED])
        assert (before[PFB_DNS_ENABLE], before[PFB_DNS_DOT_PORT], before[REPLY_LOGGING]) == ("", "853", "on"), (
            f"before-state: expected pfB-DNS Off, DoT port 853 and reply logging On, got {before}"
        )

        saved = webui.post(
            DNS_GENERAL_PAGE,
            {"pfb_dns": "on", "pfb_dns_dot_port": "8853", "pfb_py_reply": ""},
            submit=SAVE_PFB_DNS,
            timeout=SAVE_TIMEOUT,
        )

        assert _errors_text(saved.text) == NO_INPUT_ERRORS, f"the pfB-DNS save was refused: {_errors_text(saved.text)}"
        after = _stored(vm, list(before))
        changed = {path: (before[path], after[path]) for path in before if before[path] != after[path]}
        assert changed == {PFB_DNS_ENABLE: ("", "on"), PFB_DNS_DOT_PORT: ("853", "8853")}, (
            f"expected only the pfB-DNS enable and DoT port to change, got {changed}"
        )
        last = _stored(vm, [LAST_WRITE])[LAST_WRITE]
        assert "save pfB-DNS settings" in last, f"expected the pfB-DNS handler's write to be the last, got {last!r}"


def test_save_dns_general_button_writes_a_dns_general_key_and_leaves_the_pfb_dns_keys_unchanged(
    webui: WebUI, smoke_vm: SmokeVM
) -> None:
    """Given both forms stored, When the page posts a changed reply logging beside a changed pfB-DNS enable and DoT port
    with the DNS General button, Then the reply logging is written and every pfB-DNS key keeps its stored value.
    """
    vm = smoke_vm
    with _both_forms_seeded(vm):
        before = _stored(vm, [*PFB_DNS_SEED, REPLY_LOGGING])
        assert (before[PFB_DNS_ENABLE], before[PFB_DNS_DOT_PORT], before[REPLY_LOGGING]) == ("", "853", "on"), (
            f"before-state: expected pfB-DNS Off, DoT port 853 and reply logging On, got {before}"
        )

        saved = webui.post(
            DNS_GENERAL_PAGE,
            {"pfb_py_reply": "", "pfb_dns": "on", "pfb_dns_dot_port": "8853"},
            timeout=SAVE_TIMEOUT,
        )

        assert _errors_text(saved.text) == NO_INPUT_ERRORS, (
            f"the DNS General save was refused: {_errors_text(saved.text)}"
        )
        after = _stored(vm, list(before))
        changed = {path: (before[path], after[path]) for path in before if before[path] != after[path]}
        assert changed == {REPLY_LOGGING: ("on", "")}, f"expected only the reply logging to change, got {changed}"
        last = _stored(vm, [LAST_WRITE])[LAST_WRITE]
        assert "save DNS General settings" in last, f"expected the DNS General handler's last write, got {last!r}"
