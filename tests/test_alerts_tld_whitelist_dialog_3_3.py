"""release/3.3 Reports > Alerts whitelist dialog for TLD-blocked domains (issue #3647).

The whitelist icon on a TLD-blocked row opened a dialog whose button text was never assigned (a
ReferenceError on a fresh page, or the label of whichever dialog ran last) and whose prompt named a
"TLD Whitelist" that does not exist: the domain goes to the DNSBL Whitelist.

release/3.3 has no browser tier, so the JS rows run the PRODUCTION click handler under node with a
recording jQuery double (tests/js/run_alerts_whitelist_dialog_3_3.js); the prompt rows eval the PRODUCTION
PHP. NOT covered: real jQuery UI rendering of the dialog.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

TESTS = Path(__file__).parent
ALERTS = TESTS.parent / "src/usr/local/www/pfblockerng/pfblockerng_alerts.php"

TLD_ICON = "DNSBLWT|tld|bad.example|www.bad.example"
ADD_ICON = "DNSBLWT|add|bad.example|FeedA|DNSBL"
DNSBL_ADD_ICON = "DNSBLWT|dnsbl_add|bad.example|ListA|ListB"

WHITELIST_BUTTONS = ["1. Wildcard Whitelist", "2. Whitelist", "Cancel"]
BLOCK_BUTTONS = ["1. Wildcard Block", "2. Block", "Cancel"]


def run_page(steps: list[dict[str, str]]) -> list[dict]:
    """Drive one fresh page through `steps` and return the state recorded after each step."""
    node = shutil.which("node")
    assert node, "node is required to execute the Alerts page JS (ubuntu-latest ships it)"
    result = subprocess.run(
        [node, str(TESTS / "js/run_alerts_whitelist_dialog_3_3.js"), str(ALERTS)],
        input=json.dumps(steps),
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return json.loads(result.stdout)["steps"]


def test_prompt_names_the_dnsbl_whitelist_not_a_tld_whitelist() -> None:
    runner = TESTS / "php/assert_alerts_tld_whitelist_prompt_3_3.php"
    result = subprocess.run(["php", str(runner)], check=False, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "ALL PASS" in result.stdout


def test_tld_dialog_on_a_fresh_page_is_labelled_and_whitelists_into_the_dnsbl_whitelist() -> None:
    opened, described, confirmed = run_page(
        [{"click": TLD_ICON}, {"press": "2. Whitelist"}, {"press": "No"}]
    )

    assert opened["dialog"]["buttons"] == WHITELIST_BUTTONS
    assert opened["dialog"]["title"] == "Domain Whitelisting:"
    assert opened["submits"] == []  # nothing is submitted until the description step is answered
    assert described["dialog"]["title"] == "Whitelist description:"
    assert len(confirmed["submits"]) == 1
    form = confirmed["submits"][0]
    assert form["#addwhitelistdom"] == "true"
    assert form["#domain"] == "bad.example"
    assert form["#table"] == "www.bad.example"
    assert form.get("#dnsbl_exclude", "") == ""
    assert form.get("#dnsbl_wildcard", "") in ("", "false")
    assert "#dnsbl_add" not in form
    assert "#ip_white" not in form


def test_tld_wildcard_button_whitelists_the_wildcard_into_the_dnsbl_whitelist() -> None:
    *_, confirmed = run_page([{"click": TLD_ICON}, {"press": "1. Wildcard Whitelist"}, {"press": "No"}])

    form = confirmed["submits"][0]
    assert form["#dnsbl_wildcard"] == "true"
    assert form["#addwhitelistdom"] == "true"
    assert form["#domain"] == "bad.example"
    assert form["#table"] == "www.bad.example"
    assert form.get("#dnsbl_exclude", "") == ""


def test_dnsbl_add_dialog_keeps_its_block_labels_and_customlist_target() -> None:
    opened, picked = run_page([{"click": DNSBL_ADD_ICON}, {"press": "2. Block"}])

    assert opened["dialog"]["buttons"] == BLOCK_BUTTONS
    assert opened["dialog"]["title"] == "Domain Blocking:"
    assert picked["selectWhitelist"] == [{"mode": "dns_reply", "list": ["ListA", "ListB"]}]
    assert picked["submits"] == []


def test_add_dialog_keeps_its_whitelist_labels_and_feed_target() -> None:
    opened, described, confirmed = run_page([{"click": ADD_ICON}, {"press": "2. Whitelist"}, {"press": "No"}])

    assert opened["dialog"]["buttons"] == WHITELIST_BUTTONS
    assert opened["dialog"]["title"] == "Domain Whitelisting:"
    assert described["dialog"]["title"] == "Whitelist description:"
    form = confirmed["submits"][0]
    assert form["#addwhitelistdom"] == "true"
    assert form["#table"] == "FeedA"


@pytest.mark.parametrize(
    ("earlier_icon", "earlier_title"),
    [(ADD_ICON, "Domain Whitelisting:"), (DNSBL_ADD_ICON, "Domain Blocking:")],
    ids=["after-add", "after-dnsbl_add"],
)
def test_tld_dialog_keeps_its_own_label_after_another_dialog_ran(earlier_icon: str, earlier_title: str) -> None:
    earlier, tld = run_page([{"click": earlier_icon}, {"click": TLD_ICON}])

    assert earlier["dialog"]["title"] == earlier_title  # before-state: the earlier dialog really ran
    assert tld["dialog"]["buttons"] == WHITELIST_BUTTONS
    assert tld["dialog"]["title"] == "Domain Whitelisting:"
