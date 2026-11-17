#shellcheck shell=sh
# The Claude/Codex configuration uses one detailed source plus thin discovery
# adapters. Pin inventory coverage and the source-reference contract so a new
# skill or workflow cannot silently disappear from Codex.
#
# Copilot (issue #2177) needs no skill adapter — it scans .agents/skills/ itself.

Describe 'check-agent-config-parity.sh'
  guard="${PFB_ROOT}/scripts/agent/check-agent-config-parity.sh"

  setup() {
    work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/agentcfg.XXXXXX")"
    mkdir -p "$work/.claude/skills/example" "$work/.claude/workflows" \
      "$work/.agents/skills/example" "$work/.agents/skills/review"
    printf '%s\n' 'canonical skill' > "$work/.claude/skills/example/SKILL.md"
    printf '%s\n' 'canonical workflow' > "$work/.claude/workflows/review.js"
    printf '%s\n' '---' 'name: example' 'description: fixture' '---' \
      '../../../.claude/skills/example/SKILL.md' > "$work/.agents/skills/example/SKILL.md"
    printf '%s\n' '---' 'name: review' 'description: fixture' '---' \
      '../../../.claude/workflows/review.js' > "$work/.agents/skills/review/SKILL.md"
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

  It 'tolerates an absent canonical workflow inventory (issue #1431)'
    rm -rf "$work/.claude/workflows" "$work/.agents/skills/review"
    When run sh "$guard" --root "$work"
    The status should equal 0
    The output should equal 'agent-config-parity: 1 skills + 0 workflows mapped'
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

  It 'accepts a symlinked skill without a textual back-reference'
    # The vendor-agnostic layout: .agents/skills/<name> is canonical real
    # content, .claude/skills/<name> a symlink onto it. Parity is the
    # filesystem link itself -- no "must reference canonical source" text
    # required, unlike the dual-real-file adapter model above.
    mkdir -p "$work/.agents/skills/linked"
    printf '%s\n' 'canonical linked skill' > "$work/.agents/skills/linked/SKILL.md"
    ln -s '../../.agents/skills/linked' "$work/.claude/skills/linked"
    When run sh "$guard" --root "$work"
    The status should equal 0
    The output should equal 'agent-config-parity: 2 skills + 1 workflows mapped'
  End

  It 'rejects a symlinked skill that resolves to the wrong canonical target'
    mkdir -p "$work/.agents/skills/linked" "$work/.agents/skills/decoy"
    printf '%s\n' 'canonical linked skill' > "$work/.agents/skills/linked/SKILL.md"
    printf '%s\n' 'decoy' > "$work/.agents/skills/decoy/SKILL.md"
    ln -s '../../.agents/skills/decoy' "$work/.claude/skills/linked"
    When run sh "$guard" --root "$work"
    The status should equal 1
    The stderr should include '.claude/skills/linked is a symlink but does not resolve to canonical .agents/skills/linked'
  End

  It 'rejects an adapter name shared by a canonical skill and workflow'
    printf '%s\n' 'canonical workflow' > "$work/.claude/workflows/example.js"
    When run sh "$guard" --root "$work"
    The status should equal 1
    The stderr should include 'Codex adapter maps ambiguously to skill and workflow: .agents/skills/example/SKILL.md'
  End

  It 'maps every canonical source in the real repository'
    When run sh "$guard" --root "$PFB_ROOT"
    The status should equal 0
    The output should match pattern 'agent-config-parity: [0-9]* skills + [0-9]* workflows mapped'
  End

  It 'allows one nested worker below a direct Codex subagent'
    When run uv run --locked python -c 'import sys, tomllib; print(tomllib.load(open(sys.argv[1], "rb"))["agents"]["max_depth"])' "$PFB_ROOT/.codex/config.toml"
    The status should equal 0
    The output should equal '2'
  End

  It 'rejects synthetic public attribution across every former footer owner'
    When run python3 -c 'from pathlib import Path; import sys; root=Path(sys.argv[1]); top=(root/"AGENTS.md", root/"GROK.md", root/".github/copilot-instructions.md", root/".agents/policy/landing.md"); missing=[str(path.relative_to(root)) for path in top if not path.exists()]; assert not missing, missing; assert not (root/"CLAUDE.md").exists(), "CLAUDE.md must stay absent"; files=(*top, *(root/".agents/context"/f"{name}-adapter.md" for name in ("claude", "codex", "copilot", "grok", "omp")), root/".agents/skills/subsystem-sweep/SKILL.md"); forbidden=("generated by", "posted on behalf", "posted via @", "co-authored-by:", "coauthor.", "noreply@anthropic.com", "noreply@openai.com", "noreply@github.com", "noreply@x.ai", "noreply@omp.local"); found=[f"{path.relative_to(root)}: {text}" for path, content in ((path, path.read_text().lower()) for path in files) for text in forbidden if text in content]; assert not found, found' "$PFB_ROOT"
    The status should equal 0
  End
End
