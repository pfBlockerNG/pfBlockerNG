# Research #1438 — Nested instruction-stub loading in linked worktrees

Wayfinder RESEARCH ticket #1438 (map #1383; feeds Stage 3 of the context-taxonomy
plan, #1439). Executed probes, not doc-trust: every verdict below is backed by a run
artifact.

**Question.** Do Claude Code and Codex reliably load nested per-directory instruction
stubs (`CLAUDE.md` / `AGENTS.md` inside subdirectories such as `tests/smoke/`, `www/`)
when the session runs (a) in the primary checkout and (b) in a linked git worktree —
including the layout where the worktree lives *inside* the primary checkout at
`.claude/worktrees/<name>`? Stage 3 drops the dir-stub backstop for any client that
fails.

**Probe environment (2026-07-17).** Claude Code 2.1.212 (`claude -p --model haiku`,
headless) · Codex CLI 0.144.5 (`codex exec`, model `gpt-5.6-sol`, read-only sandbox,
ChatGPT auth) · macOS (Darwin 25.5.0). Scratch repo `/private/tmp/stubprobe-1438/primary`
with root `CLAUDE.md` (token `ROOT-TOKEN-7391`), `sub/CLAUDE.md` (`STUB-NESTED-4242`),
root `AGENTS.md` (`ROOT-AGENTS-5150`), `sub/AGENTS.md` (`STUB-AGENTS-6060`),
`sub/data.txt`; linked worktrees at `/private/tmp/stubprobe-1438/wt-outside` and
`/private/tmp/stubprobe-1438/primary/.claude/worktrees/wt-inside` (the mirror of this
repo's session-worktree layout).

---

## 1. Verdicts — nested dir-stub loading, per client × layout

Read-probe prompt (identical everywhere): *"Read sub/data.txt and tell me its contents.
Then list every exact token your instructions tell you to include."* A layout passes when
the nested token appears after the client touched a file in the stub's subtree.

| Client | Primary checkout | Linked worktree (outside) | Nested worktree (`.claude/worktrees/`) |
| ------ | ---------------- | ------------------------- | -------------------------------------- |
| Claude Code 2.1.212 | **RELIABLE** (both tokens) | **RELIABLE** (both tokens) | **RELIABLE** (both tokens) |
| Codex CLI 0.144.5 | **UNRELIABLE** (root token only) | **UNRELIABLE** (root token only) | **UNRELIABLE** (root token only) |

Root-file loading, for contrast, is reliable for **both** clients in **all three**
layouts: every probe emitted its root token.

Codex's only path to a nested stub is starting the session *inside* the subdirectory:
with cwd `primary/sub/`, the no-read control emitted `ROOT-AGENTS-5150` **and**
`STUB-AGENTS-6060` (root→cwd chain, built at startup). A Codex session at repo root never
loads `sub/AGENTS.md`, not even after reading `sub/data.txt`.

## 2. Eager vs on-demand semantics (Stage 3's stub design depends on this)

| Finding | Client | Evidence |
| ------- | ------ | -------- |
| Root file loads eagerly at launch | both | Controls (§3 P4/C4) emit the root token with zero file reads |
| Nested stub loads **on demand**, when a file in its subtree is read | Claude only | P4 control omits `STUB-NESTED-4242`; P1 read-probe includes it |
| Nested stub **never** loads below cwd, read or no read | Codex | C1 read-probe still omits `STUB-AGENTS-6060`; chain is built once at startup, root→cwd |
| On-demand trigger is the **Read tool**, not shell reads | Claude | P7: `cat sub/data.txt` via the Bash tool returned the contents but only `ROOT-TOKEN-7391` — no stub injection |
| Worktree sessions load **only the worktree's own checkout**; no ancestor leakage from the primary | both | P6/C6: distinct tokens written into `wt-inside`'s checked-out root files; controls emit only `WT-LOCAL-8888` / `WT-AGENTS-9999`, never the primary's tokens |
| Nested stubs are not re-injected after `/compact` until the next read in that subtree | Claude (docs) | Memory-docs quote in §4; not probed |

## 3. Probe evidence (commands + decisive output)

All probes ran headless with a 5-minute cap; outputs below are verbatim tails.

**P1 — Claude, primary root, read-probe.**
`cd /private/tmp/stubprobe-1438/primary && claude -p --model haiku "Read sub/data.txt and tell me its contents. Then list every exact token your instructions tell you to include."`

```text
**Exact tokens my instructions require:**
1. ROOT-TOKEN-7391
2. STUB-NESTED-4242
```

**P2 — Claude, wt-outside, same prompt.**

```text
1. `ROOT-TOKEN-7391` (from project CLAUDE.md)
2. `STUB-NESTED-4242` (from sub/CLAUDE.md)
```

**P3 — Claude, wt-inside (`primary/.claude/worktrees/wt-inside`), same prompt.**

```text
Tokens my instructions require:
- ROOT-TOKEN-7391
- STUB-NESTED-4242
```

**P4 — Claude, primary root, startup-only control** (*"List every exact token your
instructions tell you to include. Do not read any files."*):

```text
ROOT-TOKEN-7391
```

**P5 — Claude, cwd `primary/sub/`, same control** (cwd chain loads eagerly):

```text
ROOT-TOKEN-7391
STUB-NESTED-4242
```

**P7 — Claude, primary root, Bash-read variant**
(`claude --model haiku --allowedTools "Bash(cat:*),Bash(rtk:*)" -p "Using the Bash tool only, run: cat sub/data.txt — tell me its contents. Do not use the Read tool. Then list every exact token your instructions tell you to include."`):

```text
Contents: `the quick brown fox`

Token to include: `ROOT-TOKEN-7391`
```

**C1 — Codex, primary root, read-probe**
(`cd /private/tmp/stubprobe-1438/primary && codex exec --skip-git-repo-check "Read sub/data.txt and tell me its contents. Then list every exact token your instructions tell you to include."`).
The transcript shows Codex ran `sed -n '1,240p' sub/data.txt`, i.e. it *did* touch the
subtree, and still reported only the root token:

```text
`sub/data.txt` contains:

> the quick brown fox

Required exact inclusion token:

`ROOT-AGENTS-5150`
```

**C2 — Codex, wt-outside:** final answer `Required exact token: ROOT-AGENTS-5150`
(only).
**C3 — Codex, wt-inside:** final answer `Required exact token: - ROOT-AGENTS-5150`
(only).
**C4 — Codex, primary root, control:** `ROOT-AGENTS-5150` (only).

**C5 — Codex, cwd `primary/sub/`, control** (root→cwd chain confirmed):

```text
ROOT-AGENTS-5150
STUB-AGENTS-6060
```

**P6/C6 — ancestor-leakage test.** `wt-inside`'s checked-out `CLAUDE.md` / `AGENTS.md`
rewritten to tokens `WT-LOCAL-8888` / `WT-AGENTS-9999`; controls re-run from `wt-inside`
(whose filesystem ancestors include the primary's root files):

```text
Claude: **WT-LOCAL-8888**
Codex:  WT-AGENTS-9999
```

Neither client emitted the primary's `ROOT-TOKEN-7391` / `ROOT-AGENTS-5150` — the
upward walk stops at the worktree's own project root even when the worktree sits inside
another checkout.

## 4. Primary-source documentation (Leg 1)

**Claude Code** — <https://code.claude.com/docs/en/memory> ("How Claude remembers your
project", section *How CLAUDE.md files load*):

> "CLAUDE.md and CLAUDE.local.md files in the directory hierarchy above the working
> directory are loaded in full at launch. Files in subdirectories load on demand when
> Claude reads files in those directories."
>
> "Claude also discovers `CLAUDE.md` and `CLAUDE.local.md` files in subdirectories under
> your current working directory. Instead of loading them at launch, they are included
> when Claude reads files in those subdirectories."
>
> "Project-root CLAUDE.md survives compaction: after `/compact`, Claude re-reads it from
> disk and re-injects it into the session. Nested CLAUDE.md files in subdirectories are
> not re-injected automatically; they reload the next time Claude reads a file in that
> subdirectory."

The same page documents `.claude/rules/` with `paths:` frontmatter ("Path-scoped rules
trigger when Claude reads files matching the pattern, not on every tool use") and the
`InstructionsLoaded` hook for auditing what loaded when. Note the docs' ancestor claim
("hierarchy above the working directory") is bounded by the project root in practice —
P6 shows a worktree does **not** inherit an ancestor checkout's CLAUDE.md.

**Codex** — <https://developers.openai.com/codex/guides/agents-md> (308-redirects to
<https://learn.chatgpt.com/docs/agent-configuration/agents-md>; the openai/codex repo's
`docs/agents_md.md` defers to this page), section *How Codex discovers guidance*:

> "Codex builds an instruction chain when it starts (once per run; in the TUI this
> usually means once per launched session)."
>
> "Starting at the project root (typically the Git root), Codex walks down to your
> current working directory... In each directory along the path, it checks for
> `AGENTS.override.md`, then `AGENTS.md`, then any fallback names."
>
> "Codex stops searching once it reaches your current directory, so place overrides as
> close to specialized work as possible."

No on-demand mechanism exists in the docs, and none was observed: the chain is
startup-only and never extends below cwd. The docs do not address worktrees in the
discovery section; probes C2/C3/C6 fill that gap.

## 5. Implications for Stage 3 (#1439)

1. **Drop the dir-stub backstop for Codex.** Per the ticket's own rule, Codex fails the
   probe in every layout: a nested `AGENTS.md` is invisible to any Codex session started
   at the repo root, regardless of what files it reads. Codex routing must live entirely
   in the root `AGENTS.md` chain (the routing table), or sessions must be launched with
   cwd inside the specialized directory — not a layout our workflow uses.
2. **Claude dir-stubs work in all three layouts, including the
   `.claude/worktrees/<name>` session layout** — but only as a *soft* backstop:
   - Injection triggers on the **Read tool**, not shell reads (P7). This repo's RTK
     mandate routes many reads through Bash (`rtk read`, `rtk grep`, `cat`), which
     bypasses stub injection entirely. A dir-stub therefore cannot carry a MUST
     invariant; hard invariants stay in the root chain or in hooks.
   - Nested stubs are not re-injected after `/compact` until the next Read in the
     subtree (docs, §4).
   - `.claude/rules/` with `paths:` frontmatter has the same Read-triggered semantics
     with central maintenance (single `rules/` directory, glob scoping) and is the
     Claude-idiomatic alternative to scattering per-directory `CLAUDE.md` files.
3. **Worktree isolation is clean and branch-pinned.** A session in a linked worktree —
   outside or nested inside the primary — sees only its own checkout's instruction
   files, with no double-load and no leakage from the primary (P6/C6). Corollary: a
   worktree cut from a stale base carries stale policy; the branch-freshness check at
   session start is what keeps instructions current, not filesystem position.
4. **Root files are the only surface eagerly loaded for both clients** in every layout.
   Anything both clients must always see belongs in the root `AGENTS.md` (Codex chain) /
   root `CLAUDE.md` adapter (Claude), exactly as the current bootstrap does.

## 6. ASSUMED — with discharge commands

| # | Assumption | Discharge |
| - | ---------- | --------- |
| A1 | Codex interactive TUI behaves like `codex exec` (docs say the chain is built "once per run"; only exec was probed) | Repeat C1 in an interactive session: `cd /private/tmp/stubprobe-1438/primary && codex` then paste the P1 prompt; check for `STUB-AGENTS-6060` |
| A2 | Claude verdicts are model-independent (probed with haiku only) | `cd /private/tmp/stubprobe-1438/primary && claude -p --model sonnet "<P1 prompt>"` |
| A3 | Claude's Grep/Glob tools behave like Read for stub triggering (only Read and Bash-cat probed) | `claude -p --model haiku --allowedTools "Grep" "Use the Grep tool to search for 'quick' in sub/, then list every exact token your instructions tell you to include."` |
| A4 | Codex cloud "worktrees" environments (mentioned in learn.chatgpt.com navigation, not probed locally) behave like local worktrees | Run the C2 probe in a Codex cloud environment |
| A5 | `/compact` re-injection caveat (docs-only, §4) | Long interactive session in `primary/`: Read `sub/data.txt`, `/compact`, ask for tokens before and after the next subtree Read |

The scratch repo has been deleted; the discharge commands above rebuild it with the §"Probe
environment" layout (four token files, `sub/data.txt`, two linked worktrees).
