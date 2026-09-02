# CodeRabbit missed reviews

Append-only, newest first. One line per merged SHA whose only CodeRabbit
engagement was a quota notice (or none) and that never got a later finished
review of that SHA.

Format, one line of at most 200 bytes: ``- `SHA`  title  (#PR) — one clause``.
Two spaces separate the fields; the em-dash clause is optional. The clause is a
pointer, never a narrative: the review story — legs, findings, quota windows —
already lives in that PR's own audit comments, so record only the outcome here.
The list opens at the first line that begins with a dash and a space, and from
there the file is entries only (blank lines aside).
This header is prose and is capped at 1,200 bytes, which is the one place a
narrative could otherwise park. `scripts/check_context_budget.py` enforces both
caps, the shape, and this file's 12,288-byte policy budget; the recorded SHAs
and their order are pinned by `tests/test_context_budget.py`.

- `53f0d856b`  unbound: refuse to start a second resolver when the stop wait times out  (#3093) — finished review on the pre-fix head, quota on the landed one; four legs, one blocking fixed.
- `fa13d609`  archive: probe and list ZIP with unzip, not the host's tar flavour  (#3078) — asked once, quota (33 min); four legs, one blocking fixed.
- `f36c2a9a8`  webassets: parse ? before flag letters as quantifiers  (#3074) — asked twice, two quota notices; four legs, one blocking applied.
- `5674413a6`  tests: assert the code-graph grammar parses, not a heredoc shape  (#3071) — asked twice, two quota notices; four legs over two rounds, two blocking fixed.
- `2f17bc84c`  ci: sign workflow Git objects as project bot  (#3043) — asked twice, no engagement; four legs over three rounds, four blocking fixed.
- `6b1863cd0`  tests: recognise escaped-quote delimiters in the theme-safety vocabulary  (#3002) — never asked (orchestrator miss); four legs over two rounds, three blocking fixed.
- `1dd73d237`  tests: stop eight fixture teardowns stranding their temp directories  (#3022) — never asked, slot spent inside the window; four legs, no blocking.
- `bef489935`  tests: pin the widget shim shutdown-hook cleanup where it is load-bearing  (#3001) — never asked, slot spent inside the window; four legs, one blocking fix.
- `f7efc321d`  tests: exercise ThemeSafety's CSS scan path and pin the extension filter  (#3014) — one quota notice (38 min), owner said do not re-ask; four legs, nine findings resolved.
- `f805d7d6`  pfblockerng: align update feed statuses  (#2993) — one quota notice (41 min), owner waived retry; four legs CLEAN and exact-head CI PASS.
- `6cf8c77f`  fix(apply): honor ET reuse processet exit status  (#2980) — finished review before bot-suggested fix; two quota notices on fix heads; four carried legs + exact-head CI PASS.
- `118acc80`  fix(download): bound rsync wall time  (#2981) — two quota notices (25 min, then 36 s), no review; four carried legs CLEAN on identical content.
- `ee9490e9`  geoip: fix bare-text `<ul>` help markup and make long paths/URL wrap  (#2927) — two quota notices, no review; four exact-head legs + verifier PASS; rebase CI/gates PASS.
- `3b622554`  pfblockerng: route runtime toggles through config gateway  (#2933) — two quota notices, no review; four final exact-head legs and canonical/CI PASS.
- `4e040033`  unbound: bound daemon startup wait  (#2925) — two quota notices, no review; four exact-head legs, canonical/CI/live PASS.
- `c25135ab`  smoke: stop reading the due ledger while Run Now writes it  (#2921) — never asked; test-only, slot held for shipped code. Three legs, oracle driven against fake ledgers. CI green.
- `888ed710`  www/wizards: put the step-2 callouts in rows  (#2916) — never asked; the hourly slot went to #2917 and test-only PRs were skipped. Five legs, rounds 3-4 each blocking. CI green.
- `edeb3865`  www/wizards: stop advertising a retired sinkhole VIP range  (#2912) — asked 14:53Z, rate-limited 59 min, not retried. Four legs, mutation table re-run. CI green.
- `64623d72`  widgets: pair the jQuery-set backgrounds so the scanner sees them  (#2891) — never asked, same slot call. Four legs; helper defects split to #2866/#2892. CI green.
- `07b4894e`  pfblockerng: name the schedule-cache failure instead of asking for a bug report  (#2887) — one quota notice (999 min), no review; 4 legs over three rounds, two blockers fixed.
- `a12bae30`  test: repair the UI coverage the DNSBL/IP tab reorganisation broke  (#2885) — one quota notice (999 min), no review; 4 legs over two rounds, one blocker fixed; live-VM gate green.
- `ee6c4efe`  pfblockerng: serialize Alerts mutations  (#2883) — two quota notices, no review; 4 legs + verifier PASS; live-VM gate green.
- `e3cc14df`  pfblockerng: close the script stage when an alias is removed  (#2847) — two quota notices, no review.
- `e7d66d89`  tests: stop the lint endpoint shim leaking a PID-keyed temp dir  (#2835) — two quota notices (10 min, then 59 min), no review; 8 leg passes over two rounds.
- `d41cabc1`  extras: name the lost dispatcher lock in the Extras guard  (#2826) — two quota notices, no review; 6 leg rounds + verifier PASS.
- `38a2332c`  download: drop a refused ingest's promoted validators  (#2831) — one quota notice, no review.
- `85bb57e3`  download: sanity-scan an archive's extracted payload  (#2819) — two quota notices, no review; 4 legs + verifier PASS.
- `76b4ecc9`  download: stream the XLSX shared-strings part past the run tmpdir  (#2816) — one quota notice (999 min), no review; 4 legs over two rounds, three blockers fixed.
- `309b1902`  download: refuse an XLSX extraction that finds no address  (#2806) — two quota notices, no review; 4 legs over two rounds + verifier PASS.
- `3aa51d4d`  pfblockerng: stage the two direct-write GeoIP extractions  (#2782) — finished review at `aa696272` applied, then rebased; this SHA unreviewed.
- `4fa68d01`  tests: align the worktree-intelligence pin with the tracked root graph  (#2790) — one quota notice (999 min), no review; 4 legs, one blocking hole fixed.
- `3aab75a1`  install-pkg.sh: fail closed when pkg POST-INSTALL fails  (#2775) — one quota notice, no review; substitute review plus a correctness/test-honesty round.
- `624e9a75`  install.sh: document fetch-to-file not fetch|sh  (#2756) — two quota notices, no review; 4 legs, one blocking defect fixed.
- `f9a7e158`  pfblockerng: unlink leftover Blacklist orig/hash sidecars  (#2740) — finished review at `aa6567dc` resolved, then rebased twice; this SHA unreviewed.
- `8bb7d925`  pfblockerng: fail closed on bzip2/zip Blacklist bodies  (#2742) — never asked, never engaged; 4 legs over two rounds.
- `dc1debe1`  ci: add scripted refresh for artifact-action majors  (#2741) — never asked, never engaged; 4 legs, two blockers discharged.
- `7896e379`  pfblockerng: return from gzip Blacklist success arm  (#2737) — one quota notice (51 min); owner said no re-review; 4 legs.
- `b9cc813d`  smoke: bootstrap ports clone into an empty pre-created dir  (#2593) — two quota notices, no review; 3 legs.
- `86792fc5`  download: reject tar-bearing feeds  (#2594) — two quota notices, no review; 3 legs.
- `29c9111e`  install: fail closed when pkg reports a script failure  (#2576) — one quota notice (40 min); owner said do not re-ask; 3 legs.
- `01c6ebd6`  install.sh: refuse an empty CA hash directory  (#2536) — one quota notice (40 min), not re-asked; 3 legs off-PR; a walkthrough auto-posted despite auto_review off (also #2534/#2535).
- `1f348346b`  Consented pkg.conf PKG_ENV patch so GUI and CLI pkg operations work on Plus boxes  (#2523) — finished review at `58b25ec25` resolved; two quota notices on the fix heads; 3 legs.
- `f0dddeb6`  pfblockerng: carry the box's CA locations on the Software catalog reads  (#2520) — never asked (orchestrator miss); 3 legs, contract lens only post-merge.
- `b2df9957`  install: export SSL_CA_CERT_PATH for every pkg call  (#2515) — never asked (orchestrator miss); 3 rounds of legs, contract lens never run.
- `1e735e38`  smoke: keep polling when the post-boot metadata job has not started  (#2485) — finished review of an earlier head only; fix heads unreviewed; 4 rounds of legs.
- `de69f67b`  wait-checks.sh: resolve an abbreviated `--sha` at arm time  (#2482) — three quota notices, no review; 3 legs.
- `aaf8019d`  pkg Pages: one install-`<ch>`.sh per channel that converges the box from any starting state  (#2444) — finished review of `ed359c69` only; fix heads unreviewed; nudge already spent.
