# Ubiquitous Language

Domains: pfBlockerNG's Core/Outpost architecture (map #3813), and agent reasoning-effort configuration (Claude Code, Codex, and GitHub Copilot in this repository).

## Core and Outpost

Owner terminology, 2026-11-17 (map #3813). Name the process that does a step; never write "Core decides" or "PHP decides" for a
step of an Update.

| Term | Definition | Aliases to avoid |
| ---- | ---------- | ---------------- |
| **Core** | The platform-neutral Go side of pfBlockerNG. It owns every business decision and stays on the Core host when Core and Outpost run on separate hosts. Today it runs co-located with the Outpost on pfSense, as the **Core API**, the **Core Updater** and **pfB-DNS** | Go side, the daemon |
| **Core API** | The `pfb-core` process that admits and schedules Updates, holds settings in memory, and serves settings and resources (generations, deltas) over the versioned API (`docs/misc/core-api-protocol.md`) | Core (when the process is meant), the server |
| **Core Updater** | The `pfb-core --update-worker` process that owns one **Update** from start to finish: work list, Extras, every download and parse, pre- and post-scripts, hooks, DNSBL, DNSBLIP, aggregation, suppression, publishing generations, then triggering the **Outpost apply** and settling. A Core API restart does not stop it | Update program, worker, FeedPhase |
| **Update** | One run of the Core Updater, admitted by the Core API (scheduled, manual, apply or retry) | Cron run, sync |
| **pfB-DNS** | The DNS engine (`pfb-dns`, `go/pfb_dns_gateway`): part of Core as a product, its own process, and a Core API client for `dnsbl/*` and `settings/dns` | DNS proxy (for the engine), the decider (for the whole process) |
| **Outpost** | The platform-specific side; on pfSense, the PHP package. It turns Core's published state into platform state (alias tables, `pfctl`, rules, filter reload, services, the Resolver move, listeners, certificates), runs the GUI, and decides nothing about an Update | PHP layer, the package (for this role) |
| **Outpost apply** | The Outpost step that applies Core's published generations to the platform and advances its cursors. While co-located, the Core Updater triggers it once at the end of an Update | Update program, sync_package (for the role) |
| **Settings backend** | Where Core's settings are stored. On pfSense it is `config.xml`, read and written through the Outpost's adapter command; Core keeps no store of its own. A standalone Core uses its own file store. This is the one concession the Outpost makes beyond applying | Core config, settings mirror |

### Relationships

- **Core** = **Core API** + **Core Updater** + **pfB-DNS**; the **Outpost** reaches Core only through the **Core API**.
- An **Update** runs entirely in the **Core Updater**; the **Outpost** takes part only through the **Settings backend** read and the **Outpost apply**.
- A download, parse or policy decision in Outpost code is a defect against map #3813, not a design choice.

## Effort

| Term             | Definition                                                                                                          | Aliases to avoid                  |
| ---------------- | ------------------------------------------------------------------------------------------------------------------- | --------------------------------- |
| **Effort level** | The per-request reasoning-depth knob an agent runs at (`low`–`max`; Claude `effortLevel`, Codex `model_reasoning_effort`) | Reasoning effort, effort knob     |

## Configuration layers

Ordered highest precedence first.

| Term                     | Definition                                                                                              | Aliases to avoid          |
| ------------------------ | -------------------------------------------------------------------------------------------------------- | ------------------------- |
| **Environment override** | A shell-exported variable (e.g. `CLAUDE_CODE_EFFORT_LEVEL`) that outranks every session and settings-file value | Env setting, shell default |
| **Session override**     | An effort chosen interactively for one session (`/effort` in Claude, `-c model_reasoning_effort=…` in Codex)   | Runtime setting           |
| **User layer**           | Per-machine, cross-repo configuration outside the repository (`~/.claude/settings.json` — the directory itself is relocatable via the `CLAUDE_CONFIG_DIR` environment variable — and `~/.codex/config.toml`) | Global config             |
| **Plan-mode effort**     | A Codex-only separate effort used while planning (`plan_mode_reasoning_effort`)                            | Planning level            |

## Relationships

- An **Environment override** outranks a **Session override**, which outranks the **User layer**.
- The repository commits no **Effort level**: effort is relative to each model, so it is chosen per session or per user,
  never pinned in agent definitions or repository settings (owner, 2026-11-17, #4051).

## Example dialogue

> **Dev:** "I set `/effort` but the session ignored it — is something in the repository overriding it?"
>
> **Domain expert:** "No — the repository pins no effort. An **Environment override** was active: `CLAUDE_CODE_EFFORT_LEVEL` in your shell profile outranks the **Session override**."

## Flagged ambiguities

- **"settings"** was used for both shell environment and settings files ("environment and/or settings"). Use **Environment override** for exported variables and name the concrete layer (the **User layer**) for files.
- **"default"** is overloaded: an exported variable is often described as a "default effort" even though it has the *highest* precedence — that is an **Environment override**, not a default. Reserve "default" for the lowest-precedence fallback, the **User layer**.
