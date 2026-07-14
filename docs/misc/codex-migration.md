# Claude Code → Codex migration

The repository supports both clients with one maintained policy and procedure
layer. Vendor files are discovery/runtime adapters, not independent copies.
This avoids an explicit synchronization pass after ordinary policy, skill, or
workflow edits.

## Source-of-truth layout

| Concern | Canonical source | Claude discovery/runtime | Codex discovery/runtime |
| --- | --- | --- | --- |
| Repository policy | `CLAUDE.md` plus its linked annexes | `CLAUDE.md` loads directly | `AGENTS.md` loads automatically, requires the canonical policy, and maps runtime nouns |
| Task procedures | `.claude/skills/*/SKILL.md` | Direct skill discovery | Same-name `.agents/skills/*/SKILL.md` adapter loads the detailed source |
| Workflow schemas/prompts | `.claude/workflows/*.js` | Claude `Workflow` runtime | Same-name `.agents/skills/*/SKILL.md` adapter plus Codex subagents |
| Specialist roles | Planner/implementer/verifier declarations plus `.agents/model-tiers.conf` | Claude agents using Fable/Opus/Sonnet | Codex role TOMLs using GPT-5.6-Sol/Terra/Luna |
| Lifecycle enforcement | Shared repository scripts and Git hooks | `.claude/settings.json` | `.codex/hooks.json` and `.codex/config.toml` |

`CLAUDE.md` keeps its historical filename because Claude Code discovers it.
Its opening section declares it cross-client policy. `AGENTS.md` deliberately
does not summarize that policy: summaries drift, as the July 14 session-worktree,
review-profile, delta-review, and tracked-wait changes demonstrated. It contains
only translations that are genuinely specific to Codex.

The short Codex skill files similarly contain trigger text and orchestration
translation only. Their `../../../.claude/...` references resolve from each
adapter directory to the repository source. A change to a detailed skill or
workflow is immediately used by both clients because the adapter reads the same
source.

## Automatic parity enforcement

Run:

```sh
sh scripts/agent/check-agent-config-parity.sh
```

The checker requires every canonical `.claude/skills/*/SKILL.md` and
`.claude/workflows/*.js` source to have a same-name Codex adapter whose relative
reference resolves to that exact file. It also rejects stale adapters whose
canonical source was deleted or renamed. The pre-commit hook runs it whenever
either vendor's agent configuration is staged, including deletions; the
shellspec suite also checks the real repository inventory in CI.

This is the only synchronization boundary:

- Editing canonical policy/procedure content requires no adapter change.
- Adding or renaming a skill/workflow requires one small Codex discovery adapter.
- Changing only a provider-specific runtime stays in that provider's adapter.

## Active Codex equivalents

| Claude Code surface | Codex equivalent | Notes |
| --- | --- | --- |
| `CLAUDE.md` | `AGENTS.md` adapter | Codex loads `AGENTS.md`; it routes to the canonical policy and translates only runtime surfaces. |
| `.claude/skills/*` | `.agents/skills/*` | Same trigger intent and one shared detailed procedure. |
| `.claude/workflows/*.js` | `$adr-investigate`, `$issue-triage`, `$phase-step`, `$review-single`, `$review-fanout`, `$triage-findings` | Codex has subagents rather than the Claude JavaScript `Workflow` runtime. |
| High / medium / low model tier | GPT-5.6-Sol / GPT-5.6-Terra / GPT-5.6-Luna | `.agents/model-tiers.conf` is the shared mapping; reasoning effort remains independent. |
| Planner/implementer/verifier | `planner`, `implementer`, `adversarial-reviewer` plus high/medium reviewer variants | Project-scoped custom agents pin normal delegation models. PR review launches from a detached upstream-base controller so the reviewed branch cannot replace its reviewer. |
| `PreToolUse` Git policy | `.codex/hooks.json` | Reuses the raw-payload-compatible shared Bash guard. |
| `PreToolUse` retired-token notice | `.codex/hooks.json` | Reuses `check_retired_tokens.py --claude-hook`; the compatible event JSON is accepted by Codex. |
| `SessionStart` branch synchronization | `.codex/hooks.json` | Runs on startup/resume/clear and shares the same branch script. |
| Token Savior MCP and capture hook | `.codex/config.toml` plus `.codex/hooks.json` | Uses the same pinned `andrebrait/token-savior` launcher and capture wrapper as Claude, with the client label set to `codex`; capture is limited to Bash/read/fetch tools and Playwright MCP output, never Token Savior itself or unrelated MCP servers. |
| Ponytail and Caveman | `$ponytail` and `$caveman` | Repository skills carry the behavioral constraints without a plugin dependency. |

The shared Git hooks recognize both `CLAUDECODE=1` and Codex's
`CODEX_THREAD_ID`. Primary-checkout commits and unfetched-history rewrites are
therefore blocked for either agent runtime.

Codex command-hook and MCP commands pin the SHA-256 of every repository script
they execute. Changing a target script therefore also changes the trusted hook
definition; an unreviewed branch cannot keep an already-trusted command string
while replacing its implementation. The ShellSpec configuration check prevents
legitimate edits from leaving stale pins.

PR review has a stricter trust boundary than ordinary delegation. The caller
fetches the PR base, creates a detached checkout at that upstream tip, and runs
that checkout's `scripts/agent/codex-review.sh`. The controller treats a pre-fix
SHA only as the diff boundary, loads workflow and reviewer policy from the
upstream checkout, and starts an ephemeral reviewer from an empty directory with
a read-only sandbox, scrubbed environment, and no user configuration or rules.
Consequently a PR's changes to `AGENTS.md`, `.codex/agents`, hooks, skills, or MCP
configuration are review data and cannot configure the reviewer process.

## Worktrees, shallow history, and resume

Both clients follow the canonical one-agent/one-worktree rule. A harness-made
session worktree is an orchestration home; create the work-item worktree through
`scripts/agent/work-branch.sh --worktree`, which resolves the primary checkout
through `--git-common-dir` and does not nest worktrees inside a session tree.

A shallow clone can retain an old worktree tip while a depth-limited fetch moves
`origin/devel` beyond the visible boundary. In that state Git reports no merge
base, and a plain rebase tries to replay base history. The shared session hook now
unshallows once when needed, requires a visible merge base, and otherwise leaves
the branch untouched with a recovery message.

Codex conversation persistence is separate from Git state. Before closing the
CLI, leave the dedicated worktree coherent—preferably committed. Resume with
`codex resume`, `codex resume --last`, or
`codex resume <session-id-or-name>`. The trusted startup hook checks branch
freshness on resume and never rebases a dirty tree.

## Intentionally provider-specific

- **Status line:** Codex has no equivalent to Claude Code's command status-line
  configuration. It is UI-only and does not affect repository behavior.
- **Automatic environment installation:** Codex does not copy Claude's startup
  package installation. Provision dependencies deliberately and diagnose a
  failure against the base.
- **`pyright-lsp` plugin:** Codex does not use the Claude plugin protocol. The
  repository Python gates remain authoritative.
- **Remote-control URL cloning:** `$new-terminal` can start another CLI session,
  but Codex has no equivalent for Claude's bridge URL.
- **Provider model identifiers:** procedures use high / medium / low tiers;
  `.agents/model-tiers.conf` maps them explicitly instead of treating one
  provider's model alias as portable.

## Activation and verification

1. Open the repository with a trusted Codex client and restart/reopen the session.
2. Inspect and trust project hooks with `/hooks`; changed command hooks are skipped
   until their new definitions are reviewed.
3. Use `/skills` to verify the `.agents/skills` entries are discovered.
4. Use `/mcp` to verify `token-savior-recall` is running. Its shared launcher
   installs the repository-pinned fork into the per-user cache on first start.
5. Use `/agent` or a delegation request to select project roles.
6. Run `sh scripts/agent/check-agent-config-parity.sh` for an explicit inventory
   audit; routine commits run it automatically when relevant configuration changes.

Keep personal model, provider, authentication, notification, connector, and
memory preferences in `~/.codex/config.toml`. Repository config contains only
portable team behavior.
