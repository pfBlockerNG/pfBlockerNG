# Incident index

One line per incident: what shipped (or nearly shipped) and the rule it pinned, with the
file that now holds the rule. Policy text cites these inline today; going forward a new
rule cites this index instead of restating the archaeology (taxonomy #1386, anti-monolith
rules). Swept from `CLAUDE.md` and `docs/misc/workflow-reference.md` in Stage 1 (#1436).

## Evidence and briefs

- **#902** — a CI contract shipped from memory that `GITHUB_TOKEN` event suppression made
  unfulfillable → probe environmental claims in-session before writing them into artifacts
  (AGENTS.md "Working principles").
- **ADR-59** — wrong `domain_col` values shipped for feeds nobody had fetched → same rule.
- **PR #933 / #935** — a pipefail no-op gate was seeded by the planner's own brief and caught
  only at the independent gate → briefs are artifacts; embedded environmental claims carry
  probe evidence or an ASSUMED tag (AGENTS.md "Working principles").
- **#900–#909** — a one-day post-hoc audit found ten reproducible defects in work that had
  passed every prose gate → the artifact-field delegation contract
  (`.agents/policy/delegation.md`).
- **#858→#900 five-fix chain, #901, #904, PR #881** — under-enumerated sibling axes (missed
  port axis included) → the planner enumerates coverage matrices from source, never memory
  (`delegation.md`, THE BRIEF).
- **PR #937 / #941** — a checker shipped a PHP false-positive class because only the
  languages the author thought of got rows → mandatory per-file-type axis enumerated from
  `git ls-files` (`delegation.md`, THE BRIEF).
- **#903, #904, #907, #908, #920** — hostile-input misses (punycode/IDN, empty input,
  quoting/metacharacters, whitespace, encoding) → hostile-input rows are the planner's to
  supply (`delegation.md`, THE BRIEF).
- **PR #937 / #943** — the only blocking bug lived in an improvised exemption layer no brief
  had named → ESCALATE on invented mechanisms; a surprise mechanism in the diff gets
  hostile-input rows before PASS (`delegation.md`, THE BRIEF item 7 + THE GATE item 3).
- **#900** — a red run manufactured by monkeypatching a phantom `OSError` production cannot
  produce → test honesty: real failure modes through the production surface
  (`delegation.md`, THE GATE item 4).
- **#905** — an off-pattern public symbol name shipped → each new public symbol listed beside
  3 sibling symbols (`delegation.md`, THE GATE item 5; `coding.md` naming).
- **PR #937 / #941** — a fabricated "mirrors the URL-encoding checker" lineage comment →
  in-repo claims naming a sibling file or convention are verified by grep
  (`delegation.md`, THE GATE item 5).

## Testing

- **PR #933** — GitHub Actions' default `bash -e {0}` has no `pipefail`, so `| tee` masked an
  exit 1 → the in-job red canary (`testing.md`).
- **PR #937 / #943** — a newly wired blocking gate shipped green-path-only → every new gate
  demonstrates its red path once, in-session (`testing.md`).
- **issue #456** — fixed-time waits coordinating concurrency → synchronisation primitives;
  timeouts raise loudly (`.agents/context/lang-python.md`).
- **the `tick` smoke-module bug** — a module-scoped baseline masqueraded as per-test
  isolation → autouse reset fixtures that fail loudly (`testing.md`).

## Review and landing

- **#935** — a review fix pinned 2 of 4 equality clauses by trusting the reviewer's "etc." →
  re-enumerate a finding's class from the source, tree-wide
  (`.agents/policy/landing.md`, Applying fixes).
- **PR #1005 / #1008 / #1047** — a token retirement removed all 29 occurrences in one file
  and left 9 in another → a retirement's zero-hit tree grep is part of done, by hand
  (`landing.md`). The `check_retired_tokens.py` backstop built for it (#1059) never left
  warn-only and was removed on 2026-08-07 (owner call: the heuristic never earned promotion
  to blocking, and its standing findings went unactioned).
- **#941** — two real re-review bugs existed only in a session transcript until the
  post-merge audit → a downgraded-but-real finding still lands as a tracking issue before
  the merge (`landing.md`).
- **#1047 (seed)** — stale Accepted-ADR text (#1008 overturned ADR-60 §2.1/§2.4 with no
  amendment) → dated ADR amendments in the same change as the fix
  (`.agents/policy/legacy-adr-flow.md`).

## Issues, git, and process

- **issue #25** — later comments invalidated the opening text → read the whole issue,
  comments included (`.agents/policy/issues.md`).
- **#1070/#1106/#1128/#1139** — the array-`$_POST` TypeError family → per-defect sub-issues
  under tracker #1143 (`issues.md`).
- **#950** — `composer install` 403s in managed cloud sessions →
  `scripts/composer-cloud-install.sh` (`testing.md`).
- **#791, #894** — genuinely pre-existing local-only failures → file a tracking issue, never
  leave folklore (`testing.md`).
- **#1262** — an agent committed in the primary checkout → `prepare-commit-msg`
  primary-checkout block (`.agents/policy/git.md`).
- **#1307** — an agent push would have rewritten remote history it never fetched →
  `pre-push` enforces `--force-with-lease`'s check by effect (`git.md`).
- **#1388** — probe evidence for native issue-state signals replacing the `WIP`/`Waiting PR`
  labels (`issues.md`).
- **#946** — decode UTF-16 BOM first, else `nul_bytes` false-positives — the exemplar
  one-line regression breadcrumb (`coding.md`, Comments).
- **#1000** — diff-scoped `--staged`/`--diff` checker modes for ad-hoc and CI-PR invocation
  (`coding.md`, linting).
- **#1059** — the retired-token guard built as the #1047-class mechanical backstop;
  removed 2026-08-07 without ever being promoted past warn-only.
- **ADR-29 rebase incident** — a stale base re-ran already-fixed bugs into a phantom
  regression → rebase onto the latest base before every push/dispatch (`git.md`).
- **#930** — section writes bypassed normalisation → section writes are normalised too
  (`docs/misc/config-gateway.md`).
- **2026-08-27 grok-dev bus deaf (twice)** — (1) `pfb-msg serve` as background
  bash notifies only on process exit; serve never exits on a message → 8h
  silent, 10+ unread, woke when the owner typed (10 h harness cap is what
  kills the SSH). (2) Repo `.grok/rules/bus.md` is cwd-scoped; this session's
  detached tree lacked it, auto-compact does not re-fire SessionStart, and a
  long CI wait occupies the turn so monitor lines cannot start one → docs
  alone are not a backstop. Pin: monitor `persistent: true`; home
  `~/.grok/rules/bus.md` + PreToolUse deny bash-`serve` + Stop gate on
  missing monitor / unread (`GROK.md`, `.grok/rules/bus.md`,
  `.grok/hooks/`).
