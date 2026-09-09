#!/bin/sh
# Add or refresh the curated third-party skills for every supported agent.

set -eu

command -v npx >/dev/null 2>&1 || {
	printf '%s\n' 'setup-agent-skills.sh: npx is required' >&2
	exit 1
}

npx --yes skills add addyosmani/agent-skills --global \
	--agent claude-code --agent codex --agent github-copilot --agent grok --agent pi --yes \
	--skill api-and-interface-design \
	--skill ci-cd-and-automation \
	--skill code-review-and-quality \
	--skill code-simplification \
	--skill constraint-driven-development \
	--skill context-engineering \
	--skill debugging-and-error-recovery \
	--skill deprecation-and-migration \
	--skill doubt-driven-development \
	--skill git-workflow-and-versioning \
	--skill idea-refine \
	--skill incremental-implementation \
	--skill observability-and-instrumentation \
	--skill performance-optimization \
	--skill planning-and-task-breakdown \
	--skill security-and-hardening \
	--skill shipping-and-launch \
	--skill source-driven-development \
	--skill spec-driven-development \
	--skill test-driven-development \
	--skill using-agent-skills

npx --yes skills add mattpocock/skills --global \
	--agent claude-code --agent codex --agent github-copilot --agent grok --agent pi --yes \
	--skill code-review \
	--skill codebase-design \
	--skill diagnosing-bugs \
	--skill domain-modeling \
	--skill grill-me \
	--skill grill-with-docs \
	--skill handoff \
	--skill implement \
	--skill improve-codebase-architecture \
	--skill prototype \
	--skill research \
	--skill resolving-merge-conflicts \
	--skill tdd \
	--skill teach \
	--skill to-spec \
	--skill to-tickets \
	--skill triage \
	--skill wait-what \
	--skill wayfinder \
	--skill writing-for-agents

npx --yes skills add JuliusBrussee/caveman --global \
	--agent claude-code --agent codex --agent github-copilot --agent grok --agent pi --yes \
	--skill cavecrew \
	--skill caveman \
	--skill caveman-commit \
	--skill caveman-compress \
	--skill caveman-explore \
	--skill caveman-review \
	--skill investigate-first \
	--skill migration \
	--skill surgical-patch \
	--skill verify-and-stop

npx --yes skills add DietrichGebert/ponytail --global \
	--agent claude-code --agent codex --agent github-copilot --agent grok --agent pi --yes \
	--skill ponytail \
	--skill ponytail-audit \
	--skill ponytail-review
