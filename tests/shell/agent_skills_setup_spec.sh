#shellcheck shell=sh
# Curated third-party skills are installed additively for every supported agent.

Describe 'setup-agent-skills.sh'
  project_root="${SHELLSPEC_PROJECT_ROOT:-$PWD}"
  script_abs="$project_root/scripts/agent/setup-agent-skills.sh"

  setup() {
    fixture=$(mktemp -d "${TMPDIR:-/tmp}/agent_skills_setup.XXXXXX") || return 1
    fixture=$(cd "$fixture" && pwd -P) || return 1
    bin="$fixture/bin"
    skill_log="$fixture/skills.log"
    mkdir -p "$bin"
    home="$fixture/home"
    mkdir -p "$home"
    export HOME="$home"
    export AGENT_SKILLS_HOME="$home/.agents"
    cat > "$bin/npx" <<'NPX'
#!/bin/sh
printf 'npx:%s\n' "$*" >> "$AGENT_SKILLS_LOG"
if [ "${AGENT_SKILLS_NPX_PARTIAL_FAILURE:-0}" = 1 ]; then
  printf '%s\n' 'Failed to install 1' >&2
fi
NPX
    chmod +x "$bin/npx"
    export AGENT_SKILLS_LOG="$skill_log"
    unset AGENT_SKILLS_NPX_PARTIAL_FAILURE
    node_bin=$(dirname "$(command -v node)")
    PATH="$bin:$node_bin:/usr/bin:/bin"; export PATH
  }

  cleanup() {
    rm -rf "$fixture"
  }

  BeforeEach 'setup'
  AfterEach 'cleanup'

  It 'installs only the curated skills for every project-supported agent'
    When run sh "$script_abs"
    The status should equal 0
    The contents of file "$skill_log" should equal "$(printf '%s\n' \
      'npx:--yes skills add addyosmani/agent-skills --global --agent claude-code codex github-copilot grok pi --yes --skill api-and-interface-design ci-cd-and-automation code-review-and-quality code-simplification constraint-driven-development context-engineering debugging-and-error-recovery deprecation-and-migration doubt-driven-development git-workflow-and-versioning idea-refine incremental-implementation observability-and-instrumentation performance-optimization planning-and-task-breakdown security-and-hardening shipping-and-launch source-driven-development spec-driven-development test-driven-development using-agent-skills' \
      'npx:--yes skills add mattpocock/skills --global --agent claude-code codex github-copilot grok pi --yes --skill code-review codebase-design diagnosing-bugs domain-modeling grill-me grill-with-docs handoff implement improve-codebase-architecture prototype research resolving-merge-conflicts tdd teach to-spec to-tickets triage wait-what wayfinder writing-for-agents' \
      'npx:--yes skills add JuliusBrussee/caveman --global --agent claude-code codex github-copilot grok pi --yes --skill cavecrew caveman caveman-commit caveman-compress caveman-explore caveman-review investigate-first migration surgical-patch verify-and-stop' \
      'npx:--yes skills add DietrichGebert/ponytail --global --agent claude-code codex github-copilot grok pi --yes --skill ponytail ponytail-audit ponytail-review')"
  End

  It 'refuses to overwrite a selected skill from another source'
    mkdir -p "$AGENT_SKILLS_HOME/skills/code-review"
    printf '%s\n' 'collaborator custom skill' > "$AGENT_SKILLS_HOME/skills/code-review/SKILL.md"
    When run sh "$script_abs"
    The status should not equal 0
    The stderr should include 'refusing to overwrite code-review'
    The contents of file "$AGENT_SKILLS_HOME/skills/code-review/SKILL.md" should equal 'collaborator custom skill'
    The file "$skill_log" should not be exist
  End

  It 'refuses to overwrite a selected agent-specific skill'
    mkdir -p "$AGENT_SKILLS_HOME/skills/tdd" "$HOME/.claude/skills/tdd"
    printf '%s\n' 'managed upstream skill' > "$AGENT_SKILLS_HOME/skills/tdd/SKILL.md"
    printf '%s\n' '{"version":3,"skills":{"tdd":{"source":"mattpocock/skills"}}}' > "$AGENT_SKILLS_HOME/.skill-lock.json"
    printf '%s\n' 'collaborator Claude skill' > "$HOME/.claude/skills/tdd/SKILL.md"
    When run sh "$script_abs"
    The status should not equal 0
    The stderr should include 'refusing to overwrite tdd'
    The contents of file "$HOME/.claude/skills/tdd/SKILL.md" should equal 'collaborator Claude skill'
    The file "$skill_log" should not be exist
  End

  It 'refreshes an agent-specific copy managed from the expected source'
    mkdir -p "$AGENT_SKILLS_HOME/skills/tdd" "$HOME/.claude/skills/tdd"
    printf '%s\n' 'managed upstream skill' > "$AGENT_SKILLS_HOME/skills/tdd/SKILL.md"
    printf '%s\n' 'managed upstream skill' > "$HOME/.claude/skills/tdd/SKILL.md"
    printf '%s\n' '{"version":3,"skills":{"tdd":{"source":"mattpocock/skills"}}}' > "$AGENT_SKILLS_HOME/.skill-lock.json"
    When run sh "$script_abs"
    The status should equal 0
    The contents of file "$skill_log" should include 'npx:--yes skills add mattpocock/skills'
  End

  It 'fails when the skills CLI reports a partial installation'
    export AGENT_SKILLS_NPX_PARTIAL_FAILURE=1
    When run sh "$script_abs"
    The status should not equal 0
    The stderr should include 'skills reported an installation failure'
  End

  It 'fails before installation when npx is unavailable'
    mkdir -p "$fixture/empty"
    When run /usr/bin/env PATH="$fixture/empty" /bin/sh "$script_abs"
    The status should not equal 0
    The stderr should include 'npx is required'
  End
End
