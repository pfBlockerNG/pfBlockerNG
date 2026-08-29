# Ubiquitous Language

Domain: agent reasoning-effort and model-selection configuration (Claude Code, Codex, and GitHub Copilot in this repository).

## Effort and model selection

| Term             | Definition                                                                                                          | Aliases to avoid                  |
| ---------------- | ------------------------------------------------------------------------------------------------------------------- | --------------------------------- |
| **Effort level** | The per-request reasoning-depth knob an agent runs at (`low`–`max`; Claude `effortLevel`, Codex `model_reasoning_effort`) | Reasoning effort, effort knob     |
| **Model tier**   | The capability class (top / mid / small) that selects *which model* runs, mapped per provider in `.agents/model-tiers.conf` | Model level, reasoning tier, high/medium/low tier |

## Configuration layers

Ordered highest precedence first.

| Term                     | Definition                                                                                              | Aliases to avoid          |
| ------------------------ | -------------------------------------------------------------------------------------------------------- | ------------------------- |
| **Environment override** | A shell-exported variable (e.g. `CLAUDE_CODE_EFFORT_LEVEL`) that outranks every session and settings-file value | Env setting, shell default |
| **Session override**     | An effort chosen interactively for one session (`/effort` in Claude, `-c model_reasoning_effort=…` in Codex)   | Runtime setting           |
| **Repo default**         | The effort committed in the repository and applied to every session in it (`.claude/settings.json` `effortLevel`, `.codex/config.toml` `model_reasoning_effort`) | Project setting           |
| **User layer**           | Per-machine, cross-repo configuration outside the repository (`~/.claude/settings.json` — the directory itself is relocatable via the `CLAUDE_CONFIG_DIR` environment variable — and `~/.codex/config.toml`) | Global config             |
| **Per-agent pin**        | An effort fixed inside one subagent's own definition (`.codex/agents/*.toml`), unaffected by session-level changes | Agent default             |
| **Plan-mode effort**     | A Codex-only separate effort used while planning (`plan_mode_reasoning_effort`)                            | Planning level            |

## Relationships

- An **Environment override** outranks a **Session override**, which outranks the **Repo default**.
- A **Per-agent pin** sets the **Effort level** for exactly one subagent, regardless of the **Repo default**.
- A **Model tier** selects the model only; the **Effort level** is always set independently of it.
- The **Repo default** and a **Per-agent pin** are committed and shared; an **Environment override** and the **User layer** are machine-local.

## Example dialogue

> **Dev:** "I set `/effort` but the session ignored it — is the **Repo default** broken?"
>
> **Domain expert:** "No — an **Environment override** was active. `CLAUDE_CODE_EFFORT_LEVEL` in your shell profile outranks both the **Session override** and the **Repo default**."
>
> **Dev:** "If I delete it, do the Codex reviewer subagents drop below `xhigh`?"
>
> **Domain expert:** "No. Each reviewer carries a **Per-agent pin** in its own TOML, so it keeps its **Effort level** no matter what the session does."
>
> **Dev:** "And running the review on the high **Model tier** — does that raise the effort too?"
>
> **Domain expert:** "No. The **Model tier** only picks which model runs; its **Effort level** is set separately."

## Flagged ambiguities

- **"high"** *(resolved 2026-07-16, PR #1411)* — previously named both a **Model tier** and an **Effort level** value. The tier scale was renamed to **top / mid / small** (disjoint from the effort enum), so "high" now always means an effort value. Old forms (high/medium/low tier, "low reasoning") are aliases to avoid.
- **"settings"** was used for both shell environment and settings files ("environment and/or settings"). Use **Environment override** for exported variables and name the concrete layer (**Repo default**, **User layer**) for files.
- **"default"** is overloaded: an exported variable is often described as a "default effort" even though it has the *highest* precedence — that is an **Environment override**, not a default. Reserve "default" for the lowest-precedence fallback a layer supplies (**Repo default**).
