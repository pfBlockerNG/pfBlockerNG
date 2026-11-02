"""Issue #3648: TOP1M filters only the DNSBL Groups whose "TOP1M Whitelist" box is ticked.

The per-Group checkbox (``filter_top1m``, 3.3's ``filter_alexa``) is the scope of the TOP1M list:
a domain the TOP1M list names is not blocked by a Group that ticks the box, and stays blocked by
every other Group -- including the Custom List of a Group with the box cleared (the DNSBL tab's
documented recipe) and the built-in TLD Blacklist. The user's DNSBL Whitelist still beats every
block. With the global TOP1M switch off the box has no effect.

Every scenario runs the real decision path: manifest + raw feeds + TOP1M sidecar on disk ->
``_build_swap_snapshot()`` (the production reload builder) -> ``dnsbl_query_answer()`` (the same
evaluation operate() runs per query), on both the fast path and the numeric 6-band path (an
unrelated feed ``@@`` allow engages the latter). The upgrade scenario drives the PHP side too:
a 3.3 config is migrated and its Groups are written into the manifest by the production row
builder and manifest writer.
"""

from __future__ import annotations

import json
import os
import subprocess
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

import pytest

import pfb_unbound as P

REPO_ROOT = Path(__file__).resolve().parents[1]

TICKED = "DNSBL_Phish"  # a Group with "TOP1M Whitelist" ticked
CLEARED = "DNSBL_Ads"  # a Group with the box cleared (the default for every new Group)
TOP1M_LIST = ("popular.example", "cdn.shared.example", "popular.zip")

# How a Group lists a domain: an exact entry (plain line) or a wildcard zone (``||domain^``).
SHAPES = {"exact": "{}", "wildcard": "||{}^"}


def _feed(feed: str, group: str, *lines: str, ticked: bool, user: bool = False) -> dict[str, Any]:
    return {"feed": feed, "group": group, "lines": lines, "ticked": ticked, "user": user}


Publish = Callable[..., None]


@pytest.fixture(params=["fast", "numeric"])
def publish(request: pytest.FixtureRequest, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Publish:
    """Write one DNSBL generation and make the snapshot built from it live."""
    numeric = request.param == "numeric"
    generation = 0

    def _publish(
        feeds: Sequence[dict[str, Any]],
        *,
        top1m_enabled: bool = True,
        user_whitelist: Sequence[str] = (),
        tld_blacklist: Sequence[str] = (),
    ) -> None:
        nonlocal generation
        generation += 1
        base = tmp_path / f"gen{generation}"
        base.mkdir()
        if numeric:
            feeds = [*feeds, _feed("AllowFeed", "DNSBL_Allow", "@@||unrelated-allow.example^", ticked=False)]
        rows = []
        for index, feed in enumerate(feeds):
            raw = f"{index}_{feed['feed']}.raw"
            (base / raw).write_text("".join(f"{line}\n" for line in feed["lines"]), encoding="utf-8")
            row: dict[str, Any] = {
                "raw": raw,
                "feed": feed["feed"],
                "group": feed["group"],
                "log_flag": "1",
                "provenance": "user" if feed["user"] else "feed",
            }
            if feed["ticked"]:
                row["top1m"] = True
            rows.append(row)
        (base / "pfb_py_top1m.txt").write_text("".join(f"{name}\n" for name in TOP1M_LIST), encoding="utf-8")
        manifest = {
            "version": 1,
            "config": {
                "top1m_enabled": top1m_enabled,
                "user_whitelist": list(user_whitelist),
                "tld_wildcard_blacklist": list(tld_blacklist),
            },
            "feeds": rows,
        }
        (base / "pfb_py_sources.json").write_text(json.dumps(manifest), encoding="utf-8")

        P.pfb["pfb_py_sources"] = str(base / "pfb_py_sources.json")
        P.pfb["pfb_unbound.ini"] = str(base / "absent.ini")
        P.pfb["python_blocking"] = True
        snap = P._build_swap_snapshot()
        assert snap is not None, "the DNSBL generation failed to build"
        assert snap.important_rules is numeric, f"expected the {request.param} resolution path"
        monkeypatch.setattr(P, "_snapshot", snap)

    return _publish


def _assert_blocked(q_name: str, group: str) -> None:
    reply = P.dnsbl_query_answer(q_name, "A")
    assert reply["blocked"] and reply["group"] == group, f"{q_name}: expected blocked by {group}, got {reply}"


def _assert_resolves(q_name: str) -> None:
    reply = P.dnsbl_query_answer(q_name, "A")
    assert not reply["blocked"], f"{q_name}: expected to resolve, got {reply}"


@pytest.mark.parametrize("shape", SHAPES)
def test_the_box_decides_whether_a_group_blocks_a_top1m_domain(publish: Publish, shape: str) -> None:
    """R1/R2. Given TOP1M lists popular.example and one Group lists it,
    when the Group's box is ticked the domain resolves (its other entries still block),
    and when the box is cleared the same Group blocks it again."""
    entry = SHAPES[shape].format("popular.example")

    publish([_feed("PhishFeed", TICKED, entry, "evil.example", ticked=True)])
    _assert_resolves("popular.example")
    _assert_blocked("evil.example", TICKED)

    publish([_feed("PhishFeed", TICKED, entry, "evil.example", ticked=False)])
    _assert_blocked("popular.example", TICKED)
    _assert_blocked("evil.example", TICKED)


def test_a_ticked_wildcard_spares_only_the_top1m_names_under_it(publish: Publish) -> None:
    """A ticked Group's wildcard entry stops blocking exactly the names TOP1M allows (the listed
    name and its www. form); every other name under the wildcard stays blocked."""
    publish([_feed("PhishFeed", TICKED, "||shared.example^", "||popular.example^", ticked=True)])

    _assert_resolves("cdn.shared.example")
    _assert_resolves("www.cdn.shared.example")
    _assert_blocked("deep.cdn.shared.example", TICKED)
    _assert_blocked("ads.shared.example", TICKED)
    _assert_blocked("shared.example", TICKED)
    _assert_resolves("popular.example")
    _assert_resolves("www.popular.example")
    _assert_blocked("deep.popular.example", TICKED)


@pytest.mark.parametrize("ticked_first", [True, False], ids=["ticked-first", "cleared-first"])
@pytest.mark.parametrize("cleared_shape", SHAPES)
@pytest.mark.parametrize("ticked_shape", SHAPES)
def test_a_cleared_group_still_blocks_what_a_ticked_group_also_lists(
    publish: Publish, ticked_shape: str, cleared_shape: str, ticked_first: bool
) -> None:
    """R3. Given a ticked and a cleared Group both list a TOP1M domain, in either order and
    either shape, the cleared Group still blocks it and the block is attributed to it."""
    ticked = _feed("PhishFeed", TICKED, SHAPES[ticked_shape].format("popular.example"), ticked=True)
    cleared = _feed("AdsFeed", CLEARED, SHAPES[cleared_shape].format("popular.example"), ticked=False)

    publish([ticked, cleared] if ticked_first else [cleared, ticked])

    _assert_blocked("popular.example", CLEARED)


def test_a_cleared_parent_wildcard_blocks_a_top1m_name_a_ticked_child_spares(publish: Publish) -> None:
    """R3 across wildcard depths: the ticked Group's own wildcard spares the TOP1M name, but the
    cleared Group's wildcard on the parent domain still covers it."""
    publish(
        [
            _feed("PhishFeed", TICKED, "||cdn.shared.example^", ticked=True),
            _feed("AdsFeed", CLEARED, "||shared.example^", ticked=False),
        ]
    )

    _assert_blocked("cdn.shared.example", CLEARED)


@pytest.mark.parametrize("shape", SHAPES)
def test_the_box_has_no_effect_while_global_top1m_is_off(publish: Publish, shape: str) -> None:
    """R4. With the global TOP1M switch off, a ticked Group blocks the TOP1M domain like any other;
    switching TOP1M on is what lets the ticked Group stop blocking it."""
    ticked = _feed("PhishFeed", TICKED, SHAPES[shape].format("popular.example"), ticked=True)

    publish([ticked], top1m_enabled=False)
    _assert_blocked("popular.example", TICKED)

    publish([ticked], top1m_enabled=True)
    _assert_resolves("popular.example")


def test_the_dnsbl_whitelist_still_allows_what_a_cleared_group_blocks(publish: Publish) -> None:
    """R5. A cleared Group blocks a TOP1M domain; adding it to the user's DNSBL Whitelist lets it resolve."""
    cleared = _feed("AdsFeed", CLEARED, "||popular.example^", ticked=False)

    publish([cleared])
    _assert_blocked("popular.example", CLEARED)

    publish([cleared], user_whitelist=["popular.example"])
    _assert_resolves("popular.example")


def test_the_custom_list_of_a_cleared_group_blocks_a_top1m_domain(publish: Publish) -> None:
    """R6, the DNSBL tab's recipe. The first Group has the box cleared and lists a TOP1M domain in its
    Custom List; it blocks the domain although a later, ticked Group lists it too."""
    publish(
        [
            _feed("Ads_custom", CLEARED, "popular.example", ticked=False, user=True),
            _feed("PhishFeed", TICKED, "popular.example", ticked=True),
        ]
    )

    _assert_blocked("popular.example", CLEARED)


def test_top1m_never_overrides_the_tld_blacklist(publish: Publish) -> None:
    """The TLD Blacklist is no Group, so TOP1M cannot exempt a name from it -- even a name a ticked
    Group lists."""
    publish([_feed("PhishFeed", TICKED, "popular.zip", ticked=True)], tld_blacklist=["zip"])

    _assert_blocked("popular.zip", "DNSBL_TLD")


def test_a_non_boolean_top1m_flag_fails_the_generation(tmp_path: Path) -> None:
    """The manifest's per-feed ``top1m`` flag is a boolean; any other value fails the generation
    closed instead of guessing the Group's scope."""
    (tmp_path / "feed.raw").write_text("popular.example\n", encoding="utf-8")
    (tmp_path / "pfb_py_top1m.txt").write_text("popular.example\n", encoding="utf-8")
    manifest = tmp_path / "pfb_py_sources.json"
    row = {"raw": "feed.raw", "feed": "PhishFeed", "group": TICKED, "log_flag": "1"}

    manifest.write_text(
        json.dumps({"version": 1, "config": {"top1m_enabled": True}, "feeds": [{**row, "top1m": True}]}),
        encoding="utf-8",
    )
    assert P.dnsbl_build_from_manifest(str(manifest)) is not None

    manifest.write_text(
        json.dumps({"version": 1, "config": {"top1m_enabled": True}, "feeds": [{**row, "top1m": "on"}]}),
        encoding="utf-8",
    )
    assert P.dnsbl_build_from_manifest(str(manifest)) is None


UPGRADE_PROBE = r"""
require 'tests/php/bootstrap.php';
$root = getenv('PFB_PROBE_DIR');
$GLOBALS['pfb_test_write_config_calls'] = [];
$GLOBALS['pfb_test_file_notices'] = [];
// Two 3.3 DNSBL Groups: the box is stored under its retired 3.3 name.
$GLOBALS['config'] = ['installedpackages' => ['pfblockerngdnsbl' => ['config' => [
    ['aliasname' => 'Phish', 'action' => 'unbound', 'filter_alexa' => 'on'],
    ['aliasname' => 'Ads', 'action' => 'unbound', 'filter_alexa' => ''],
]]]];
pfb_run_migrations();

$GLOBALS['pfb'] = array_merge($GLOBALS['pfb'] ?? [], [
    'dbdir' => "{$root}/db",
    'dnsdir' => "{$root}/dnsbl",
    'dnsbl_top1m' => PfbToggle::On,
    'dnsbl_tld_wildcard' => '',
    'dnsblconfig' => ['tld_wildcard_blacklist' => '', 'tld_wildcard_exclusion' => '', 'whitelist' => ''],
    'unbound_py_rawdir' => "{$root}/pfb_py_raw",
    'unbound_py_sources' => "{$root}/pfb_py_sources.json",
    'unbound_py_top1m' => "{$root}/pfb_py_top1m.txt",
    'log' => "{$root}/pfblockerng.log",
    'errlog' => "{$root}/pfblockerng_error.log",
]);
file_put_contents("{$root}/db/pfbalexawhitelist.txt", "phish-listed.example\nads-listed.example\n");

// Each Group lists one TOP1M domain; its rows reach the manifest as the DNSBL update loop writes them.
$feeds = [];
foreach (config_get_path('installedpackages/pfblockerngdnsbl/config', []) as $list) {
    $header = "{$list['aliasname']}Feed";
    file_put_contents("{$root}/dnsbl/{$header}.txt",
        pfb_dnsbl_ndjson_emit_row(PfbDnsblRowKind::Domain, strtolower($list['aliasname']) . '-listed.example'));
    $feeds[] = pfb_feed_manifest_row($header, "DNSBL_{$list['aliasname']}", '1', 'feed', 'deny',
        $list['filter_top1m'] ?? NULL);
}
$published = pfb_unbound_python_sources($feeds, ['top1m_atomic' => [
    'chown' => static fn(string $file, string $owner): bool => TRUE,
    'chgrp' => static fn(string $file, string $group): bool => TRUE,
    'chmod' => static fn(string $file, int $mode): bool => TRUE,
]]);
echo json_encode(['published' => is_array($published)], JSON_THROW_ON_ERROR);
"""


def test_an_upgraded_33_config_keeps_each_groups_box(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """R7. A 3.3 config stores the box as ``filter_alexa``. After the upgrade migration, the Group that
    had it ticked stops blocking its TOP1M domain and the Group that had it cleared keeps blocking."""
    (tmp_path / "db").mkdir()
    (tmp_path / "dnsbl").mkdir()
    env = os.environ.copy()
    env["PFB_PROBE_DIR"] = str(tmp_path)
    proc = subprocess.run(
        ["php", "-r", UPGRADE_PROBE],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert proc.returncode == 0, f"PHP probe failed:\nstdout={proc.stdout}\nstderr={proc.stderr}"
    assert json.loads(proc.stdout) == {"published": True}

    P.pfb["pfb_py_sources"] = str(tmp_path / "pfb_py_sources.json")
    P.pfb["pfb_unbound.ini"] = str(tmp_path / "absent.ini")
    P.pfb["python_blocking"] = True
    snap = P._build_swap_snapshot()
    assert snap is not None, "the published DNSBL generation failed to build"
    monkeypatch.setattr(P, "_snapshot", snap)

    _assert_resolves("phish-listed.example")
    _assert_blocked("ads-listed.example", "DNSBL_Ads")
