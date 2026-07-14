#shellcheck shell=sh
# The Claude/Codex configuration uses one detailed source plus thin discovery
# adapters. Pin inventory coverage and the source-reference contract so a new
# skill or workflow cannot silently disappear from Codex.

Describe 'check-agent-config-parity.sh'
  guard="${PFB_ROOT}/scripts/agent/check-agent-config-parity.sh"

  setup() {
    work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/agentcfg.XXXXXX")"
    mkdir -p "$work/.claude/skills/example" "$work/.claude/workflows" \
      "$work/.agents/skills/example" "$work/.agents/skills/review" \
      "$work/.codex/agents"
    printf '%s\n' 'canonical skill' > "$work/.claude/skills/example/SKILL.md"
    printf '%s\n' 'canonical workflow' > "$work/.claude/workflows/review.js"
    printf '%s\n' '---' 'name: example' 'description: fixture' '---' \
      '../../../.claude/skills/example/SKILL.md' > "$work/.agents/skills/example/SKILL.md"
    printf '%s\n' '---' 'name: review' 'description: fixture' '---' \
      '../../../.claude/workflows/review.js' > "$work/.agents/skills/review/SKILL.md"
    printf '%s\n' 'HIGH_CLAUDE=claude-fable-5' 'HIGH_CODEX=gpt-5.6-sol' \
      'MEDIUM_CLAUDE=claude-opus-4-8' 'MEDIUM_CODEX=gpt-5.6-terra' \
      'LOW_CLAUDE=claude-sonnet-5' 'LOW_CODEX=gpt-5.6-luna' > "$work/.agents/model-tiers.conf"
    for role_model in \
      'planner gpt-5.6-sol' \
      'implementer gpt-5.6-luna' \
      'analyst gpt-5.6-luna' \
      'analyst-high gpt-5.6-sol' \
      'adversarial-reviewer gpt-5.6-luna' \
      'adversarial-reviewer-high gpt-5.6-sol' \
      'adversarial-reviewer-medium gpt-5.6-terra'; do
      set -- $role_model
      printf 'model = "%s"\n' "$2" > "$work/.codex/agents/$1.toml"
    done
  }

  cleanup() {
    rm -rf "$work" || return 1
  }

  BeforeEach 'setup'
  AfterEach 'cleanup'

  It 'accepts complete adapters which reference both canonical sources'
    When run sh "$guard" --root "$work"
    The status should equal 0
    The output should equal 'agent-config-parity: 1 skills + 1 workflows mapped'
  End

  It 'rejects a canonical skill with no Codex adapter'
    rm "$work/.agents/skills/example/SKILL.md"
    When run sh "$guard" --root "$work"
    The status should equal 1
    The stderr should include 'missing Codex adapter for skill example'
  End

  It 'rejects a canonical workflow with no Codex adapter'
    rm "$work/.agents/skills/review/SKILL.md"
    When run sh "$guard" --root "$work"
    The status should equal 1
    The stderr should include 'missing Codex adapter for workflow review'
  End

  It 'rejects an adapter which copied prose instead of referencing its source'
    printf '%s\n' '---' 'name: example' 'description: fixture' '---' \
      'copied procedure' > "$work/.agents/skills/example/SKILL.md"
    When run sh "$guard" --root "$work"
    The status should equal 1
    The stderr should include 'must reference canonical source ../../../.claude/skills/example/SKILL.md'
  End

  It 'rejects a root-relative-looking source string that does not resolve from the adapter'
    printf '%s\n' '---' 'name: example' 'description: fixture' '---' \
      '.claude/skills/example/SKILL.md' > "$work/.agents/skills/example/SKILL.md"
    When run sh "$guard" --root "$work"
    The status should equal 1
    The stderr should include 'must reference canonical source ../../../.claude/skills/example/SKILL.md'
  End

  It 'rejects a discovery name that differs from the source name'
    printf '%s\n' '---' 'name: wrong' 'description: fixture' '---' \
      '../../../.claude/skills/example/SKILL.md' > "$work/.agents/skills/example/SKILL.md"
    When run sh "$guard" --root "$work"
    The status should equal 1
    The stderr should include 'declares name wrong, expected example'
  End

  It 'rejects a stale Codex adapter after its canonical source is removed'
    mkdir -p "$work/.claude/skills/keep" "$work/.agents/skills/keep"
    printf '%s\n' 'canonical skill' > "$work/.claude/skills/keep/SKILL.md"
    printf '%s\n' '---' 'name: keep' 'description: fixture' '---' \
      '../../../.claude/skills/keep/SKILL.md' > "$work/.agents/skills/keep/SKILL.md"
    rm "$work/.claude/skills/example/SKILL.md"
    When run sh "$guard" --root "$work"
    The status should equal 1
    The stderr should include 'stale Codex adapter has no canonical source: .agents/skills/example/SKILL.md'
  End

  It 'rejects an adapter name shared by a canonical skill and workflow'
    printf '%s\n' 'canonical workflow' > "$work/.claude/workflows/example.js"
    When run sh "$guard" --root "$work"
    The status should equal 1
    The stderr should include 'Codex adapter maps ambiguously to skill and workflow: .agents/skills/example/SKILL.md'
  End

  It 'rejects a Codex role whose model drifts from the shared tier mapping'
    printf '%s\n' 'model = "gpt-5.6-terra"' > "$work/.codex/agents/planner.toml"
    When run sh "$guard" --root "$work"
    The status should equal 1
    The stderr should include '.codex/agents/planner.toml model gpt-5.6-terra, expected gpt-5.6-sol'
  End

  It 'parses model tiers as data and never executes repository-controlled text'
    marker="$work/tier-code-executed"
    printf '%s\n' 'HIGH_CLAUDE=claude-fable-5' "HIGH_CODEX=\$(touch $marker)" \
      'MEDIUM_CLAUDE=claude-opus-4-8' 'MEDIUM_CODEX=gpt-5.6-terra' \
      'LOW_CLAUDE=claude-sonnet-5' 'LOW_CODEX=gpt-5.6-luna' > "$work/.agents/model-tiers.conf"
    When run sh "$guard" --root "$work"
    The status should equal 1
    The stderr should include 'invalid model tier assignment'
    The file "$marker" should not be exist
  End

  It 'rejects duplicate model tier assignments'
    printf '%s\n' 'LOW_CODEX=gpt-5.6-luna' >> "$work/.agents/model-tiers.conf"
    When run sh "$guard" --root "$work"
    The status should equal 1
    The stderr should include 'duplicate model tier assignment: LOW_CODEX'
  End

  It 'maps every canonical source in the real repository'
    When run sh "$guard" --root "$PFB_ROOT"
    The status should equal 0
    The output should match pattern 'agent-config-parity: [0-9]* skills + [0-9]* workflows mapped'
  End

  It 'allows one nested worker below a direct Codex subagent'
    When run python3 -c 'import sys, tomllib; print(tomllib.load(open(sys.argv[1], "rb"))["agents"]["max_depth"])' "$PFB_ROOT/.codex/config.toml"
    The status should equal 0
    The output should equal '2'
  End

  It 'pins truthful Codex attribution in every public-comment adapter'
    When run python3 -c 'from pathlib import Path; import sys; root=Path(sys.argv[1]); footer="🤖 Generated by OpenAI Codex and posted on behalf of @<login>."; files=(root/"AGENTS.md", root/".agents/skills/pr-comments/SKILL.md", root/".agents/skills/pr-merge-flow/SKILL.md"); missing=[str(path.relative_to(root)) for path in files if footer not in path.read_text()]; assert not missing, missing' "$PFB_ROOT"
    The status should equal 0
  End
End
