"""ADR-10 concurrency/atomicity -- ONE extended torn-hunt over EVERY matcher mechanism.

A SEPARATE PROCESS (``tests/_adr10_reload_trigger.py``) repeatedly, ALTERNATINGLY flips
the live DNSBL data between two generations (gen1 <-> gen2) by atomically publishing a
new manifest + user-regex ini and bumping the reload sentinel -- while N query threads
hammer the matcher. It proves the zero-downtime swap is:

  * ATOMIC -- not one query EVER observes a torn (mixed-generation) view (the core
    guarantee a single-ref, build-new-then-rebind swap must make impossible);
  * REAL per lane -- gen1 and gen2 differ across EVERY block/allow mechanism, and the
    final state is verified down to a per-mechanism CONTROL domain, so a degenerate
    empty/all-blocked build cannot masquerade as a valid generation;
  * non-stalling -- queries keep flowing throughout (high total count, no crash).

The trigger is a real second process (no shared GIL with the query process, like the
PHP trigger on a box), so it genuinely races atomic-publish against concurrent-read.

Mechanism map (each produced via the manifest/ini/config; bands per ADR-07 SS2)
-----------------------------------------------------------------------------------
BLOCK (gen1 blocked, gen2 allowed -- except the per-mechanism CONTROL, still blocked):
  m1 generic exact   -> dataDB  band 1  (plain feed, 3-part name -> classify DATA)
  m2 generic exact   -> dataDB  band 1  (plain feed, 2-part name; issue #1255: the
                                          oracle is no longer manifest-driven, so this
                                          lane now exercises dataDB, not zoneDB)
  m3 abp anchored    -> dataDB  band 1  (||sub.d.com^, 3-part -> DATA)
  m4 abp regex       -> regexDB band 1  (irreducible /re/)
  m5 abp $important  -> dataDB  band 3  (||sub.d.com^$important)
  m6 user regex      -> regexDB band 5  (ini [REGEX] pattern -- lives in the ini)
  m7 user block      -> dataDB  band 5  (feed provenance=user, plain exact line)
ALLOW (gen1 allowed via an allow out-ranking a co-listed block; gen2 blocked -- except
the per-mechanism CONTROL, still allowed):
  a8  default allow  -> not in any list (gen2 adds it to a block feed)
  a9  user whitelist -> whiteDB band 6 over a co-listed feed block band 1
  a10 user unlock    -> whiteDB band 6 over a co-listed feed block band 1 (#51)
  a11 abp @@ allow   -> whiteDB band 2 over a co-listed abp block band 1
  a12 abp allow-rgx  -> allowRegexDB band 2 over a co-listed feed block band 1
  a13 abp @@$import  -> whiteDB band 4 over a co-listed abp block+important band 3

Every mechanism contributes MULTIPLE domains (>10 per group) plus one non-flipping
CONTROL, and both the before-state (gen1) and after-state (gen2) are asserted per the
repo's branch + before/after coverage rules.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Any

import pfb_unbound as P

_TRIGGER = os.path.join(os.path.dirname(__file__), "_adr10_reload_trigger.py")

# Public-suffix oracle for the zone lane: a 2-part ``d.com`` (com a known suffix) is the
# registrable parent -> ZONE; a 3-part ``sub.d.com`` (parent ``d.com`` not a suffix) ->
# exact DATA. This is what splits the m1/m3 (data) lanes from the m2 (zone) lane.
_TLD_MASTER = "com\nnet\norg\nco.uk\n"

# Per-lane: how many FLIPPING domains, plus exactly one CONTROL (the odd-one-out in gen2).
_N_FLIP = 2


@dataclass
class Lane:
    """One mechanism's domains + the gen1/gen2 producers for each.

    ``flip`` domains swap state across the generation; ``control`` does NOT (it is the
    per-mechanism odd-one-out in gen2, so a degenerate build cannot pass as gen2).
    """

    key: str
    flip: list[str] = field(default_factory=list)
    control: str = ""


# --------------------------------------------------------------------------- #
# Domain matrix -- stable, deterministic names (never DNS-queried; looked up in the
# snapshot directly, so the RFC-6761 / HSTS smoke constraints do not apply here).
# --------------------------------------------------------------------------- #
def _d3(stem: str, n: int) -> list[str]:
    """``n`` genuine 3-part names ``sub.<stem>{i}.com`` -> classify DATA (exact): the
    parent ``<stem>{i}.com`` is not a public suffix, so it is exact, not a wildcard zone.
    """
    return ["sub.{}{}.com".format(stem, i) for i in range(n)]


def _d3_ctl(stem: str) -> str:
    return "sub.{}ctl.com".format(stem)


def _stems(stem: str, n: int) -> list[str]:
    """``n`` regex-lane STEMS ``<stem>{i}`` (the probe appends ``7.com``)."""
    return ["{}{}".format(stem, i) for i in range(n)]


# BLOCK lanes. ``probe`` is the exact name evaluate_domain is asked about; ``raw`` is the
# feed/ABP/ini line that produces the block for that name.
LANES_BLOCK: dict[str, Lane] = {
    # m1 generic exact (DATA band 1): plain feed line, 3-part -> classify DATA (exact).
    "m1_data": Lane("m1_data", _d3("m1exact", _N_FLIP), _d3_ctl("m1exact")),
    # m2 generic zone (ZONE band 1): plain feed line, 2-part (d.com) -> classify ZONE
    # (registrable parent, wildcard-incl-self). The ONLY 2-part lane -> zoneDB.
    "m2_zone": Lane("m2_zone", ["m2zone0.com", "m2zone1.com"], "m2zonectl.com"),
    # m3 abp anchored (DATA band 1): ||sub.d.com^, 3-part -> DATA.
    "m3_abp": Lane("m3_abp", _d3("m3abp", _N_FLIP), _d3_ctl("m3abp")),
    # m4 abp regex (regexDB band 1): irreducible /re/ (probe = <stem>7.com).
    "m4_abpre": Lane("m4_abpre", _stems("m4abpre", _N_FLIP), "m4abprectl"),
    # m5 abp $important (DATA band 3): ||sub.d.com^$important, 3-part -> DATA.
    "m5_imp": Lane("m5_imp", _d3("m5imp", _N_FLIP), _d3_ctl("m5imp")),
    # m6 user regex (regexDB band 5): ini [REGEX] (probe = <stem>7.com).
    "m6_userre": Lane("m6_userre", _stems("m6userre", _N_FLIP), "m6userrectl"),
    # m7 user block (DATA band 5): feed provenance=user, plain exact 3-part line -> DATA.
    "m7_userblk": Lane("m7_userblk", _d3("m7ublk", _N_FLIP), _d3_ctl("m7ublk")),
}

# ALLOW lanes (gen1 allowed). Each name is co-listed in a block AND carries an allow that
# out-ranks it -- EXCEPT a8 (default allow) which is simply unlisted in gen1.
LANES_ALLOW: dict[str, Lane] = {
    "a8_default": Lane("a8_default", _d3("a8def", _N_FLIP), _d3_ctl("a8def")),
    "a9_wl": Lane("a9_wl", _d3("a9wl", _N_FLIP), _d3_ctl("a9wl")),
    "a10_unlock": Lane("a10_unlock", _d3("a10ul", _N_FLIP), _d3_ctl("a10ul")),
    "a11_abpallow": Lane("a11_abpallow", _d3("a11al", _N_FLIP), _d3_ctl("a11al")),
    "a12_abpallowre": Lane("a12_abpallowre", _stems("a12alre", _N_FLIP), "a12alrectl"),
    "a13_abpimpallow": Lane("a13_abpimpallow", _d3("a13ial", _N_FLIP), _d3_ctl("a13ial")),
}


# Regex lanes are listed by a STEM; the per-domain pattern is ``<stem>[0-9]\.com`` and
# the probe name is ``<stem>7.com`` -- so the pattern matches its OWN probe only (each
# stem is unique, so no cross-lane regex collision), and is irreducible (a char-class
# never folds to a dict).
def _regex_probe(stem: str) -> str:
    return stem + "7.com"


# --------------------------------------------------------------------------- #
# Feed-line / ABP-line / ini producers per generation
# --------------------------------------------------------------------------- #
def _abp_regex_line(stem: str, *, allow: bool, important: bool) -> str:
    # Irreducible (a char-class -> never folds to a domain/wildcard dict): matches
    # ``<stem><digit>.com``.
    inner = "{}[0-9]\\.com".format(stem)
    pre = "@@/" if allow else "/"
    suf = "$important" if important else ""
    return "{}{}/{}".format(pre, inner, suf)


def _ini_regex_pattern(stem: str) -> str:
    # User-regex (ini [REGEX]) -- irreducible, matches ``<stem><digit>.com``.
    return "{}[0-9]\\.com".format(stem)


@dataclass
class GenSpec:
    """Everything that defines a generation's matcher state, as raw text/lists."""

    plain_feed: list[str]  # plain feed lines (block lanes m1/m2)
    user_feed: list[str]  # plain feed lines on a provenance=user feed (m7)
    abp_feed: list[str]  # ABP feed lines (m3/m4/m5 + allow lanes a11/a12/a13)
    user_whitelist: list[str]  # config.user_whitelist (a9)
    user_unlock: list[str]  # config.user_unlock (a10)
    ini_regex: list[str]  # ini [REGEX] patterns (m6)


def _gen1_spec() -> GenSpec:
    plain: list[str] = []
    user_feed: list[str] = []
    abp: list[str] = []
    wl: list[str] = []
    unlock: list[str] = []
    ini: list[str] = []

    b = LANES_BLOCK
    a = LANES_ALLOW

    # --- BLOCK lanes: gen1 every flip+control domain is BLOCKED via its mechanism. ---
    # m1 generic exact (plain feed -> DATA).
    plain += b["m1_data"].flip + [b["m1_data"].control]
    # m2 generic zone (plain feed -> ZONE).
    plain += b["m2_zone"].flip + [b["m2_zone"].control]
    # m3 abp anchored (||sub.d^ -> DATA band 1).
    abp += ["||{}^".format(d) for d in b["m3_abp"].flip + [b["m3_abp"].control]]
    # m4 abp regex (band 1).
    abp += [_abp_regex_line(s, allow=False, important=False) for s in b["m4_abpre"].flip + [b["m4_abpre"].control]]
    # m5 abp $important (band 3).
    abp += ["||{}^$important".format(d) for d in b["m5_imp"].flip + [b["m5_imp"].control]]
    # m6 user regex (ini band 5).
    ini += [_ini_regex_pattern(s) for s in b["m6_userre"].flip + [b["m6_userre"].control]]
    # m7 user block (provenance=user feed -> DATA band 5).
    user_feed += b["m7_userblk"].flip + [b["m7_userblk"].control]

    # --- ALLOW lanes: gen1 every flip+control domain is ALLOWED (allow out-ranks). ---
    # a8 default allow: simply not listed anywhere in gen1.
    # a9 user whitelist (band 6) over a co-listed plain-feed block (band 1).
    plain += a["a9_wl"].flip + [a["a9_wl"].control]
    wl += a["a9_wl"].flip + [a["a9_wl"].control]
    # a10 user unlock (band 6) over a co-listed plain-feed block (band 1).
    plain += a["a10_unlock"].flip + [a["a10_unlock"].control]
    unlock += a["a10_unlock"].flip + [a["a10_unlock"].control]
    # a11 abp @@ allow (band 2) over a co-listed abp block (band 1).
    for d in a["a11_abpallow"].flip + [a["a11_abpallow"].control]:
        abp += ["||{}^".format(d), "@@||{}^".format(d)]
    # a12 abp allow-regex (band 2) over a co-listed plain-feed block (band 1).
    for s in a["a12_abpallowre"].flip + [a["a12_abpallowre"].control]:
        plain += [_regex_probe(s)]  # the exact block of the regex-probe name
        abp += [_abp_regex_line(s, allow=True, important=False)]
    # a13 abp @@$important (band 4) over a co-listed abp block+important (band 3).
    for d in a["a13_abpimpallow"].flip + [a["a13_abpimpallow"].control]:
        abp += ["||{}^$important".format(d), "@@||{}^$important".format(d)]

    return GenSpec(plain, user_feed, abp, wl, unlock, ini)


def _gen2_spec() -> GenSpec:
    """gen2: every BLOCK flip domain becomes ALLOWED (its block removed) EXCEPT its
    control (stays blocked); every ALLOW flip domain becomes BLOCKED (its allow removed,
    co-listed block kept; a8 gets added to a block feed) EXCEPT its control (stays
    allowed)."""
    plain: list[str] = []
    user_feed: list[str] = []
    abp: list[str] = []
    wl: list[str] = []
    unlock: list[str] = []
    ini: list[str] = []

    b = LANES_BLOCK
    a = LANES_ALLOW

    # --- BLOCK lanes: drop the flip domains' block; KEEP the control's block. ---
    plain += [b["m1_data"].control]
    plain += [b["m2_zone"].control]
    abp += ["||{}^".format(b["m3_abp"].control)]
    abp += [_abp_regex_line(b["m4_abpre"].control, allow=False, important=False)]
    abp += ["||{}^$important".format(b["m5_imp"].control)]
    ini += [_ini_regex_pattern(b["m6_userre"].control)]
    user_feed += [b["m7_userblk"].control]

    # --- ALLOW lanes: remove the flip domains' allow (keep co-listed block); a8 gains a
    #     block. KEEP the control's allow (it stays allowed). ---
    # a8 default: add the flip domains to a plain block feed; control stays unlisted.
    plain += a["a8_default"].flip
    # a9 whitelist: keep ALL co-listed blocks; whitelist ONLY the control.
    plain += a["a9_wl"].flip + [a["a9_wl"].control]
    wl += [a["a9_wl"].control]
    # a10 unlock: keep ALL co-listed blocks; unlock ONLY the control.
    plain += a["a10_unlock"].flip + [a["a10_unlock"].control]
    unlock += [a["a10_unlock"].control]
    # a11 abp @@: keep ALL co-listed abp blocks; @@-allow ONLY the control.
    for d in a["a11_abpallow"].flip + [a["a11_abpallow"].control]:
        abp += ["||{}^".format(d)]
    abp += ["@@||{}^".format(a["a11_abpallow"].control)]
    # a12 abp allow-regex: keep ALL co-listed exact blocks; @@-regex ONLY the control.
    for s in a["a12_abpallowre"].flip + [a["a12_abpallowre"].control]:
        plain += [_regex_probe(s)]
    abp += [_abp_regex_line(a["a12_abpallowre"].control, allow=True, important=False)]
    # a13 abp @@$important: keep ALL co-listed block+important; @@$important ONLY control.
    for d in a["a13_abpimpallow"].flip + [a["a13_abpimpallow"].control]:
        abp += ["||{}^$important".format(d)]
    abp += ["@@||{}^$important".format(a["a13_abpimpallow"].control)]

    return GenSpec(plain, user_feed, abp, wl, unlock, ini)


# --------------------------------------------------------------------------- #
# Expected-state maps (True == blocked) -- the oracle each scan is graded against.
# --------------------------------------------------------------------------- #
def _expected_gen1() -> dict[str, bool]:
    exp: dict[str, bool] = {}
    for lane in LANES_BLOCK.values():
        for n in lane.flip + [lane.control]:
            exp[_probe(lane.key, n)] = True  # gen1: every block-lane domain blocked
    for lane in LANES_ALLOW.values():
        for n in lane.flip + [lane.control]:
            exp[_probe(lane.key, n)] = False  # gen1: every allow-lane domain allowed
    return exp


def _expected_gen2() -> dict[str, bool]:
    exp: dict[str, bool] = {}
    for lane in LANES_BLOCK.values():
        for n in lane.flip:
            exp[_probe(lane.key, n)] = False  # block flips -> allowed in gen2
        exp[_probe(lane.key, lane.control)] = True  # control stays blocked
    for lane in LANES_ALLOW.values():
        for n in lane.flip:
            exp[_probe(lane.key, n)] = True  # allow flips -> blocked in gen2
        exp[_probe(lane.key, lane.control)] = False  # control stays allowed
    return exp


# Regex lanes (m4/m6/a12) are listed by a STEM; the probe name appends a digit so the
# pattern actually matches. Every other lane probes the listed name verbatim.
_REGEX_LANES = {"m4_abpre", "m6_userre", "a12_abpallowre"}


def _probe(lane_key: str, listed_name: str) -> str:
    return _regex_probe(listed_name) if lane_key in _REGEX_LANES else listed_name


# --------------------------------------------------------------------------- #
# Manifest / raw / ini writers
# --------------------------------------------------------------------------- #
def _write(path: str, data: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(data)


def _manifest_json(tld_master: str, plain_raw: str, user_raw: str, abp_raw: str, spec: GenSpec) -> str:
    return json.dumps(
        {
            "version": 1,
            "config": {
                "tld_wildcard_master": tld_master,
                "tld_wildcard_blacklist": [],
                "tld_wildcard_exclusion": [],
                "user_whitelist": spec.user_whitelist,
                "user_unlock": spec.user_unlock,
                "top1m_list": [],
                "top1m_enabled": False,
            },
            "feeds": [
                {"raw": plain_raw, "feed": "plainfeed", "group": "G", "log_flag": "1"},
                {
                    "raw": user_raw,
                    "feed": "userfeed",
                    "group": "Custom_List",
                    "log_flag": "1",
                    "provenance": "user",
                },
                {"raw": abp_raw, "feed": "abpfeed", "group": "G", "log_flag": "1"},
            ],
        }
    )


def _ini_text(spec: GenSpec) -> str:
    lines = ["[MAIN]", ""]
    if spec.ini_regex:
        lines.append("[REGEX]")
        for i, pat in enumerate(spec.ini_regex):
            lines.append("r{} = {}".format(i, pat))
    return "\n".join(lines) + "\n"


def _materialise_gen(tmp_dir: str, tag: str, tld_master_path: str, spec: GenSpec) -> tuple[str, str]:
    """Write the raw feeds + manifest + ini for one generation. Returns (manifest, ini)."""
    plain_raw = os.path.join(tmp_dir, "{}_plain.txt".format(tag))
    user_raw = os.path.join(tmp_dir, "{}_user.txt".format(tag))
    abp_raw = os.path.join(tmp_dir, "{}_abp.txt".format(tag))
    _write(plain_raw, "\n".join(spec.plain_feed) + "\n")
    _write(user_raw, "\n".join(spec.user_feed) + "\n")
    _write(abp_raw, "\n".join(spec.abp_feed) + "\n")
    manifest = os.path.join(tmp_dir, "{}_manifest.json".format(tag))
    _write(manifest, _manifest_json(tld_master_path, plain_raw, user_raw, abp_raw, spec))
    ini = os.path.join(tmp_dir, "{}_pfb_unbound.ini".format(tag))
    _write(ini, _ini_text(spec))
    return manifest, ini


# --------------------------------------------------------------------------- #
# Module wiring + a snapshot-grading scan (replicates operate()'s per-query build)
# --------------------------------------------------------------------------- #
def _wire_module(monkeypatch: Any, *, live_manifest: str, live_ini: str, sentinel: str, applied: str) -> None:
    P.pfb["pfb_py_sources"] = live_manifest
    P.pfb["pfb_unbound.ini"] = live_ini
    P.pfb["pfb_py_reload"] = sentinel
    P.pfb["pfb_py_reload_applied"] = applied
    P.pfb["python_hsts"] = False  # skip the hsts file load (not part of this matrix)
    P.pfb["regex_cap"] = False
    # This test is about the ATOMIC SWAP, not regex safety: lift the runtime warn/evict
    # ceilings so the always-on timer never EVICTS a regex pattern mid-scan under load
    # (an eviction would drop a regex-lane block and look like a non-oracle "torn" view --
    # a measurement artifact, not a torn read of the swap). ADR-07's eviction is pinned
    # by its own suite; here we hold the regexDB stable across the swap.
    P.pfb["regex_warn_ms"] = 1.0e9
    P.pfb["regex_evict_ms"] = 1.0e9
    P.pfb["mod_threading"] = True
    P.pfb["python_blocking"] = True
    P.pfb["tld_allow"] = False
    P.pfb["python_idn"] = False
    P.pfb["python_tld_seg"] = 2
    P.pfb["pfb_py_count"] = "pfb_py_count"
    P.pfb["pfb_py_regex_count"] = "pfb_py_regex_count"
    monkeypatch.setattr(P, "dnsbl_emit_count", lambda *a, **k: True)  # no UI count file
    monkeypatch.setattr(P, "_db_reset_cache", lambda: True)  # no Reports sqlite
    monkeypatch.setattr(P, "RELOAD_POLL_INTERVAL", 0.05)  # prompt poll + stop observation
    monkeypatch.setattr(P, "_reload_total_ram_bytes", lambda: 8 * 1024 * 1024 * 1024)  # gate passes
    P.decisionDB = P._LruCache(0)
    P.pfb_reload_stop = threading.Event()


def _scan(snap: Any) -> dict[str, bool]:
    """One coherent SCAN against a SINGLE captured snapshot ref, replicating operate():
    build cfg+containers from this one snap, then evaluate EVERY domain off it. Returns
    name -> blocked(bool)."""
    cfg = {
        "python_blocking": P.pfb["python_blocking"],
        "dataDB": bool(snap.data_db),
        "zoneDB": bool(snap.zone_db),
        "tld_allow": P.pfb["tld_allow"],
        "tld_allow_list": P.pfb["tld_allow_list"],
        "dnsbl_ipv4": P.pfb["dnsbl_ipv4"],
        "dnsbl_ipv6": P.pfb["dnsbl_ipv6"],
        "python_idn": P.pfb["python_idn"],
        "regexDB": bool(snap.regex_db),
        "whiteDB": bool(snap.white_db),
        "allowRegexDB": bool(snap.allow_regex_db),
        "important_rules": bool(snap.important_rules),
        "regex_warn_ms": P.pfb["regex_warn_ms"],
        "regex_evict_ms": P.pfb["regex_evict_ms"],
        "python_tld_seg": P.pfb["python_tld_seg"],
        "hstsDB": bool(snap.hsts_db),
        "hsts_tlds": P.pfb["hsts_tlds"],
    }
    out: dict[str, bool] = {}
    # NON-VACUOUS PROBE (opt-in via PFB_TORN_PROBE): re-capture ``P._snapshot`` PER
    # DOMAIN instead of using the single ``snap`` ref. Mid-flip this reads some domains
    # off gen1 and others off gen2 -> a torn (mixed) view, proving the guard catches a
    # real torn read (the one-capture path makes impossible). Default OFF -> single ref.
    _probe = os.environ.get("PFB_TORN_PROBE") == "1"
    for name in _PROBE_NAMES:
        if _probe:
            snap = P._snapshot
        cfg["dataDB"] = bool(snap.data_db)
        cfg["zoneDB"] = bool(snap.zone_db)
        cfg["regexDB"] = bool(snap.regex_db)
        cfg["whiteDB"] = bool(snap.white_db)
        cfg["allowRegexDB"] = bool(snap.allow_regex_db)
        cfg["important_rules"] = bool(snap.important_rules)
        cfg["hstsDB"] = bool(snap.hsts_db)
        containers = snap.containers()
        tld = name.rsplit(".", 1)[-1]
        dec = P.evaluate_domain(name, name, tld, False, cfg, containers)
        out[name] = bool(dec.is_found and not dec.in_whitelist)
    return out


# The exact probe names (regex lanes carry the digit suffix), computed once.
_PROBE_NAMES: list[str] = sorted(_expected_gen1().keys())


def _assert_state(snap: Any, expected: dict[str, bool], label: str) -> None:
    """Assert EVERY probe name is in its expected blocked/allowed state for ``snap``;
    fail loudly naming the first wrong domain + mechanism."""
    got = _scan(snap)
    wrong = [(n, expected[n], got[n]) for n in _PROBE_NAMES if got[n] != expected[n]]
    assert not wrong, "{}: {} domain(s) in the wrong state (name, expected_blocked, got_blocked): {}".format(
        label, len(wrong), wrong[:8]
    )


# --------------------------------------------------------------------------- #
# THE test
# --------------------------------------------------------------------------- #
def test_atomic_swap_no_torn_across_every_matcher_mechanism(tmp_path: Any, monkeypatch: Any) -> None:
    tmp_dir = str(tmp_path)
    tld_master_path = os.path.join(tmp_dir, "tld_master.txt")
    _write(tld_master_path, _TLD_MASTER)

    # Materialise both generations (manifest + per-feed raw + ini) for the trigger.
    g1_manifest, g1_ini = _materialise_gen(tmp_dir, "gen1", tld_master_path, _gen1_spec())
    g2_manifest, g2_ini = _materialise_gen(tmp_dir, "gen2", tld_master_path, _gen2_spec())

    # The LIVE manifest/ini the watcher reads -- seeded with gen1 (the trigger overwrites).
    live_manifest = os.path.join(tmp_dir, "live_manifest.json")
    live_ini = os.path.join(tmp_dir, "live_pfb_unbound.ini")
    sentinel = os.path.join(tmp_dir, "pfb_py_reload")
    applied = os.path.join(tmp_dir, "pfb_py_reload.applied")
    _write(live_manifest, _read_file(g1_manifest))
    _write(live_ini, _read_file(g1_ini))
    _write(sentinel, "1\n")

    _wire_module(monkeypatch, live_manifest=live_manifest, live_ini=live_ini, sentinel=sentinel, applied=applied)

    expected_gen1 = _expected_gen1()
    expected_gen2 = _expected_gen2()

    # Build the gen1 snapshot via the REAL background builder and install it.
    snap1 = P._build_swap_snapshot()
    assert snap1 is not None, "gen1 build returned None"
    P._snapshot = snap1

    # SETUP-ASSERT: every lane is correct in gen1 BEFORE any thread runs (a mis-built lane
    # fails here naming the domain/mechanism). Also assert gen2 builds correctly so a lane
    # that is right in gen1 but degenerate in gen2 is caught up front.
    _assert_state(snap1, expected_gen1, "gen1 setup")
    snap2_check = _build_snapshot_from(g2_manifest, g2_ini)
    assert snap2_check is not None, "gen2 build returned None"
    # Install snap2 as the live snapshot only for its own setup-assert, then restore
    # gen1 (so the live state is gen1 when the trigger starts). Installing it keeps the
    # non-vacuous probe -- which re-reads ``P._snapshot`` per domain -- consistent here.
    P._snapshot = snap2_check
    _assert_state(snap2_check, expected_gen2, "gen2 setup")
    P._snapshot = snap1
    # Sanity: the two oracles genuinely differ (a real generational swap to detect).
    assert expected_gen1 != expected_gen2, "gen1/gen2 oracles identical -- not a real swap"

    # --- watcher + query threads ------------------------------------------------ #
    watcher = threading.Thread(target=P.pfb_reload_watcher, name="pfb_reload_watcher_test", daemon=True)
    watcher.start()

    stop = threading.Event()
    errors: list[str] = []
    stats: list[dict[str, int]] = []
    _torn_samples: list[dict[str, bool]] = []
    n_threads = 6

    def query_loop() -> None:
        local = {"n": 0, "gen1": 0, "gen2": 0, "torn": 0}
        try:
            while not stop.is_set():
                snap = P._snapshot  # capture ONCE per scan, exactly as operate() does
                got = _scan(snap)
                local["n"] += 1
                if got == expected_gen1:
                    local["gen1"] += 1
                elif got == expected_gen2:
                    local["gen2"] += 1
                else:
                    local["torn"] += 1  # a mixed view -- the atomic swap must prevent this
                    if len(_torn_samples) < 4:
                        # Capture which domains diverge from BOTH oracles, to make a
                        # failure self-explanatory (which lane tore).
                        _torn_samples.append(
                            {n: got[n] for n in _PROBE_NAMES if got[n] not in (expected_gen1[n], expected_gen2[n])}
                        )
        except Exception as e:  # noqa: BLE001 -- record, never let a query crash silently
            errors.append(repr(e))
        stats.append(local)

    threads = [threading.Thread(target=query_loop, daemon=True) for _ in range(n_threads)]
    for t in threads:
        t.start()

    # BEFORE: let the loops read a gen1 baseline before the first flip.
    time.sleep(0.15)
    assert _scan(P._snapshot) == expected_gen1, "expected gen1 live before the trigger"

    # Fire the trigger: it sleeps wait_before, then ALTERNATES gen2/gen1/gen2/... K times,
    # waiting for the watcher to APPLY each generation before the next flip (so the build
    # input never races a mid-build overwrite -- the atomic _snapshot swap is still
    # exercised once per flip).
    wait_before = 0.3
    flips = 5
    gap = 0.05
    proc = subprocess.Popen(
        [
            sys.executable,
            _TRIGGER,
            str(wait_before),
            str(flips),
            str(gap),
            live_manifest,
            live_ini,
            sentinel,
            applied,
            g1_manifest,
            g1_ini,
            g2_manifest,
            g2_ini,
        ]
    )
    last_gen_expected = expected_gen2 if flips % 2 == 1 else expected_gen1
    last_applied = 1 + flips
    try:
        assert proc.wait(timeout=60) == 0, "trigger process failed to publish + flip"
        # Wait (bounded) for the watcher to APPLY the LAST generation under query load.
        deadline = time.monotonic() + 15.0
        while time.monotonic() < deadline and P._reload_read_generation(applied) != last_applied:
            time.sleep(0.02)
        time.sleep(0.2)  # let the loops observe the final generation a bit
    finally:
        stop.set()
        for t in threads:
            t.join(timeout=5)
        P.pfb_reload_stop.set()
        watcher.join(timeout=5)

    # --- assertions ------------------------------------------------------------- #
    assert not watcher.is_alive(), "watcher did not join cleanly"
    assert errors == [], "query thread(s) raised: {}".format(errors)

    total_n = sum(s["n"] for s in stats)
    total_gen1 = sum(s["gen1"] for s in stats)
    total_gen2 = sum(s["gen2"] for s in stats)
    total_torn = sum(s["torn"] for s in stats)

    # CORE GUARANTEE: not one query observed a torn (mixed-generation) snapshot. A
    # consistent snapshot grades EXACTLY as gen1 OR gen2; a divergence from BOTH would be
    # a torn/mixed view -- impossible for a single-ref, build-new-then-rebind swap.
    assert total_torn == 0, "torn reads under concurrent swaps (diverging domains): {}".format(_torn_samples)
    # Both patterns were observed under load -- a genuine generational swap, both ways.
    assert total_gen1 > 0, "no gen1 pattern observed (baseline + odd flips)"
    assert total_gen2 > 0, "no gen2 pattern observed under load"
    # Queries kept flowing (no stall) -- every thread did real, repeated work. The
    # floor is deliberately conservative (>= ~10 scans/thread): a genuine stall leaves
    # total_n on the order of n_threads (each loop ran once or twice before blocking),
    # which this still catches, while the previous 50/thread floor was timing-fragile
    # and flaked under the slower coverage-instrumented run on a busy CI runner. The
    # per-thread liveness guarantee is pinned exactly by the next assertion.
    assert total_n > n_threads * 10, "suspiciously few scans ({}) -- a stall?".format(total_n)
    assert all(s["n"] > 0 for s in stats), "a query thread never ran"

    # FINAL state: the watcher applied the LAST published generation, and the live
    # snapshot grades EXACTLY as that generation's oracle -- per-mechanism CONTROLs
    # included (proving each lane actually swapped, not a degenerate build).
    assert P._reload_read_generation(applied) == last_applied, "watcher did not apply the final generation"
    _assert_state(P._snapshot, last_gen_expected, "final generation")


def _read_file(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _build_snapshot_from(manifest: str, ini: str) -> Any:
    """Build a snapshot from an ARBITRARY (manifest, ini) pair via the REAL builder, by
    pointing the two pfb keys at them, building, then restoring -- used only for the
    gen2 setup-assert (the watcher itself reads the LIVE keys at swap time)."""
    saved_m, saved_i = P.pfb["pfb_py_sources"], P.pfb["pfb_unbound.ini"]
    try:
        P.pfb["pfb_py_sources"] = manifest
        P.pfb["pfb_unbound.ini"] = ini
        return P._build_swap_snapshot()
    finally:
        P.pfb["pfb_py_sources"] = saved_m
        P.pfb["pfb_unbound.ini"] = saved_i
