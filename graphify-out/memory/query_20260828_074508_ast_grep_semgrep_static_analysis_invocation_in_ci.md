---
type: "query"
date: "2026-08-28T07:45:08.605157+00:00"
question: "ast-grep semgrep static analysis invocation in CI scripts hooks gates"
contributor: "graphify"
outcome: "dead_end"
correction: "ast-grep and semgrep are installed by scripts/agent/setup-agent-tools.sh:265-271 and asserted in tests/shell/agent_tools_setup_spec.sh; they are agent-host tools, not CI gates. Found by grep on .github, scripts, .githooks."
---

# Q: ast-grep semgrep static analysis invocation in CI scripts hooks gates

## Answer

Returned unrelated test nodes (test_local_hook_scope, AliasCntGrepCountGuardTest, HooksSanitizeIngestionTest).

## Outcome

- Signal: dead_end
- Correction: ast-grep and semgrep are installed by scripts/agent/setup-agent-tools.sh:265-271 and asserted in tests/shell/agent_tools_setup_spec.sh; they are agent-host tools, not CI gates. Found by grep on .github, scripts, .githooks.