---
type: "query"
date: "2026-09-28T06:13:10.816783+00:00"
question: "which scripts and tests call scripts/agent/ensure-graphify.sh and stub uv tool install"
contributor: "graphify"
outcome: "dead_end"
correction: "Shell script invocation wiring is a text-level question: grep for ensure-graphify.sh and 'tool install --upgrade' across scripts/, .github/ and tests/shell/ answered it."
---

# Q: which scripts and tests call scripts/agent/ensure-graphify.sh and stub uv tool install

## Answer

The graph returned unrelated nodes (stub(), install(), test modules). Callers are scripts/setup-hooks.sh, scripts/agent/ensure-graphify-merge-driver.sh, scripts/agent/setup-agent-tools.sh (via setup-hooks.sh) and .github/workflows/test.yml; uv stubs live in tests/shell/agent_graphify_merge_driver_spec.sh, setup_hooks_spec.sh and agent_tools_setup_spec.sh.

## Outcome

- Signal: dead_end
- Correction: Shell script invocation wiring is a text-level question: grep for ensure-graphify.sh and 'tool install --upgrade' across scripts/, .github/ and tests/shell/ answered it.