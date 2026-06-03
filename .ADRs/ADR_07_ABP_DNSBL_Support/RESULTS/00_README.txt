ADR-07 — Live smoke RESULTS (fill after a live VM run + the hand-run items)
===========================================================================

Record here, ADR-04 style (see ../../ADR_04_VM_Smoke_Tests/RESULTS/). One file
per run is fine (01_Results.txt, 02_Results.txt, ...); this README is the template.

Gate: ADR.md Status flips Implemented -> Accepted ONLY when every item below is
PASS. On any FAIL, do NOT flip — file the defect and note which decision diverged
from the unit oracle (tests/test_adr07_*).

Run metadata
------------
- Date / operator:
- VM image ref + digest (SMOKE_IMAGE_REF):
- Branch + commit (adr/07 @ <sha>):
- Built .pkg (SMOKE_PKG path / build run id):
- Commands:
    python -m pip install -r tests/smoke/requirements.txt
    python -m pytest tests/smoke -m smoke --override-ini="addopts="
  (or the gated smoke workflow dispatch — paste the run URL)

Automated (tests/smoke/test_smoke_abp.py) — paste the pytest summary
-------------------------------------------------------------------
[ ] test_abp_exception_unblocks            (@@ un-block, same feed)
[ ] test_abp_cross_feed_exception          (@@ in feed B un-blocks feed A)
[ ] test_abp_important_block_beats_feed_allow   ($important band 3 > feed @@ band 2)
[ ] test_abp_badfilter_prunes_feed_block   ($badfilter prunes the matching feed block)
[ ] test_abp_regex_block_and_allow         (/re/ block + @@/re/ allow, irreducible)
[ ] test_abp_regex_admitted_count          (DNSBL_Regex count == admitted; shrinks under cap)
[ ] test_abp_whitelist_sovereign_over_important  (whitelist band 6 beats feed $important)
[ ] test_user_regex_blocks                 (pfb_regex_list pattern blocks, VIP)
[ ] test_abp_no_regression_plain_feed      (plain feed VIP-blocks; pfb_py_count >= 1)
[ ] test_smoke_matrix.py (ADR-04)          (unchanged, still green)

Hand-run on a live box (not automated — see ADR.md "Live smoke")
----------------------------------------------------------------
[ ] Regex runtime warn -> evict: feed a deliberately slow cap-passing pattern;
    paste the resolver-log excerpt showing the
    "[pfBlockerNG]: slow ... regex" warn then "EVICTING ... regex" error, and
    confirm subsequent queries are fast (resolver recovers).
[ ] DNSBL-IP populate: a feed with ||1.2.3.4^ + a "0.0.0.0 host" line fills
    pfB_DNSBLIP_v4/_v6 with the configured action; no IP leaks into DNS blocking.
[ ] ABP x DNSBL-TLD mode: enable pfb_pytld + a TLD set with one ABP and one plain
    feed; ABP domains build via Python (no CSV-mangled garbage); plain feeds still
    TLD-analyse.
[ ] Alerts "add to whitelist" button: whitelisting via the alerts UI resolves the
    name (the non-textarea sovereignty entry point).

Flagged follow-up surfaced while wiring the smoke (record verdict)
-----------------------------------------------------------------
- User-regex band: a user regex loads as a bare compiled pattern scored at feed
  band 1 (_block_entry_band), NOT the oracle's user band 5. It is $badfilter-immune
  but NOT band-sovereign, so a feed @@...$important (band 4) would override it.
  Decide: intended (prose overreach in ADR §"User sovereignty") or a band-tagging
  bug to fix (tag user-regex provenance=USER -> band 5)?
