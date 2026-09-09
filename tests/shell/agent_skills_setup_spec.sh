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
    cat > "$bin/npx" <<'NPX'
#!/bin/sh
printf 'npx:%s\n' "$*" >> "$AGENT_SKILLS_LOG"
NPX
    chmod +x "$bin/npx"
    export AGENT_SKILLS_LOG="$skill_log"
    PATH="$bin:/usr/bin:/bin"; export PATH
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
      'npx:--yes skills add addyosmani/agent-skills --global --agent claude-code --agent codex --agent github-copilot --agent grok --agent pi --yes --skill api-and-interface-design --skill ci-cd-and-automation --skill code-review-and-quality --skill code-simplification --skill constraint-driven-development --skill context-engineering --skill debugging-and-error-recovery --skill deprecation-and-migration --skill doubt-driven-development --skill git-workflow-and-versioning --skill idea-refine --skill incremental-implementation --skill observability-and-instrumentation --skill performance-optimization --skill planning-and-task-breakdown --skill security-and-hardening --skill shipping-and-launch --skill source-driven-development --skill spec-driven-development --skill test-driven-development --skill using-agent-skills' \
      'npx:--yes skills add mattpocock/skills --global --agent claude-code --agent codex --agent github-copilot --agent grok --agent pi --yes --skill code-review --skill codebase-design --skill diagnosing-bugs --skill domain-modeling --skill grill-me --skill grill-with-docs --skill handoff --skill implement --skill improve-codebase-architecture --skill prototype --skill research --skill resolving-merge-conflicts --skill tdd --skill teach --skill to-spec --skill to-tickets --skill triage --skill wait-what --skill wayfinder --skill writing-for-agents' \
      'npx:--yes skills add JuliusBrussee/caveman --global --agent claude-code --agent codex --agent github-copilot --agent grok --agent pi --yes --skill cavecrew --skill caveman --skill caveman-commit --skill caveman-compress --skill caveman-explore --skill caveman-review --skill investigate-first --skill migration --skill surgical-patch --skill verify-and-stop' \
      'npx:--yes skills add DietrichGebert/ponytail --global --agent claude-code --agent codex --agent github-copilot --agent grok --agent pi --yes --skill ponytail --skill ponytail-audit --skill ponytail-review')"
  End

  It 'fails before installation when npx is unavailable'
    mkdir -p "$fixture/empty"
    When run /usr/bin/env PATH="$fixture/empty" /bin/sh "$script_abs"
    The status should not equal 0
    The stderr should include 'npx is required'
    The file "$skill_log" should not be exist
  End
End
