"""Tier B (``ui_e2e``): on DNS General one form and one Save button save both parts together (issue #3856).

DNS General is one form (button ``save``, "Save DNS settings") holding the pfB-DNS settings and the DNS General ones
(reply logging, Resolver addresses). One post, as the page's whole-form scrape sends it, saves every changed field in
one write, and a post with an invalid field in either part changes neither part. The oracle is the effective config.xml
read back over SSH, never the HTTP body: the keys that change and the description of the last write_config().
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
def _both_parts_seeded(vm: SmokeVM) -> Iterator[None]:
    """Store both parts' settings directly (the before-state must not depend on the saves under test); restore after."""
    seeds = {**PFB_DNS_SEED, **GENERAL_SEED}
    priors = _read_config_paths(vm, list(seeds))
    try:
        _write_config_paths(vm, seeds)
        assert _stored(vm, list(seeds)) == seeds, "the seed of both forms did not take"
        yield
    finally:
        _write_config_paths(vm, priors)


def test_one_post_with_a_changed_pfb_dns_field_and_a_changed_reply_logging_saves_both(
    webui: WebUI, smoke_vm: SmokeVM
) -> None:
    """Given both parts stored, When one post carries a changed pfB-DNS enable and DoT port beside a changed reply
    logging, Then all three keys are written and the last write is the one "save DNS settings" write.
    """
    vm = smoke_vm
    with _both_parts_seeded(vm):
        before = _stored(vm, [*PFB_DNS_SEED, *GENERAL_SEED])
        assert (before[PFB_DNS_ENABLE], before[PFB_DNS_DOT_PORT], before[REPLY_LOGGING]) == ("", "853", "on"), (
            f"before-state: expected pfB-DNS Off, DoT port 853 and reply logging On, got {before}"
        )

        saved = webui.post(
            DNS_GENERAL_PAGE,
            {"pfb_dns": "on", "pfb_dns_dot_port": "8853", "pfb_py_reply": ""},
            timeout=SAVE_TIMEOUT,
        )

        assert _errors_text(saved.text) == NO_INPUT_ERRORS, f"the save was refused: {_errors_text(saved.text)}"
        after = _stored(vm, list(before))
        changed = {path: (before[path], after[path]) for path in before if before[path] != after[path]}
        assert changed == {
            PFB_DNS_ENABLE: ("", "on"),
            PFB_DNS_DOT_PORT: ("853", "8853"),
            REPLY_LOGGING: ("on", ""),
        }, f"expected the pfB-DNS enable, the DoT port and the reply logging to change, got {changed}"
        last = _stored(vm, [LAST_WRITE])[LAST_WRITE]
        assert "save DNS settings" in last, f"expected the one save's write to be the last, got {last!r}"


@pytest.mark.parametrize(
    ("invalid", "valid_change"),
    [
        pytest.param(
            {"pfb_dns_dot_port": "70000"}, {"pfb_py_reply": ""}, id="invalid_pfb_dns_dot_port_beside_reply_logging"
        ),
        pytest.param(
            {"pfb_dns_listen_interface": "nosuchif"},
            {"pfb_dns": "on", "pfb_dns_dot_port": "8853"},
            id="invalid_listen_interface_beside_pfb_dns_fields",
        ),
    ],
)
def test_one_post_with_an_invalid_field_in_either_part_changes_neither_part(
    webui: WebUI, smoke_vm: SmokeVM, invalid: dict[str, str], valid_change: dict[str, str]
) -> None:
    """Given both parts stored, When one post carries an invalid field in one part beside changed fields in the other,
    Then the page answers with the input errors and no key of either part changes.
    """
    vm = smoke_vm
    with _both_parts_seeded(vm):
        before = _stored(vm, [*PFB_DNS_SEED, *GENERAL_SEED])
        assert (before[PFB_DNS_ENABLE], before[PFB_DNS_DOT_PORT], before[REPLY_LOGGING]) == ("", "853", "on"), (
            f"before-state: expected pfB-DNS Off, DoT port 853 and reply logging On, got {before}"
        )

        refused = webui.post(DNS_GENERAL_PAGE, {**invalid, **valid_change}, timeout=SAVE_TIMEOUT)

        assert _errors_text(refused.text) != NO_INPUT_ERRORS, f"the page accepted the invalid post {invalid}"
        after = _stored(vm, list(before))
        changed = {path: (before[path], after[path]) for path in before if before[path] != after[path]}
        assert changed == {}, f"expected no key of either part to change, got {changed}"
