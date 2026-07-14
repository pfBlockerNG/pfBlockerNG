#shellcheck shell=sh
# codex-review.sh: a PR-controlled AGENTS.md, workflow, or custom reviewer role
# must not configure the Codex process that reviews that PR. The trusted upstream
# policy SHA and the (possibly PR-controlled) delta diff base are distinct refs.

Describe 'codex-review.sh trusted controller'
  setup() {
    . "${SHELLSPEC_PROJECT_ROOT:-$PWD}/scripts/lib/git-env-scrub.sh"
    pfb_scrub_git_env
    work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/codexreview.XXXXXX")" || return 1
    controller="$work/controller"
    target="$work/target"
    capture="$work/codex-capture"
    mkdir -p "$controller/scripts/agent" "$controller/.claude/workflows" \
      "$controller/.agents" "$controller/.codex/agents" "$work/bin" || return 1
    cp "${PFB_ROOT}/scripts/agent/codex-review.sh" "$controller/scripts/agent/" || return 1
    chmod +x "$controller/scripts/agent/codex-review.sh" || return 1
    printf '%s\n' 'TRUSTED_WORKFLOW_SOURCE' > "$controller/.claude/workflows/review-single.js"
    printf '%s\n' 'LOW_CODEX=gpt-5.6-luna' 'MEDIUM_CODEX=gpt-5.6-terra' \
      'HIGH_CODEX=gpt-5.6-sol' > "$controller/.agents/model-tiers.conf"
    cat > "$controller/.codex/agents/adversarial-reviewer.toml" <<'EOF'
name = "adversarial-reviewer"
model = "gpt-5.6-luna"
model_reasoning_effort = "xhigh"
sandbox_mode = "read-only"
developer_instructions = "TRUSTED_ROLE_RESTRICTIONS"
EOF
    git init -q -b devel "$controller" || return 1
    git -C "$controller" add . || return 1
    git -C "$controller" -c user.name=Test -c user.email=test@example.invalid \
      -c commit.gpgsign=false commit -q -m trusted || return 1
    trusted_policy_sha=$(git -C "$controller" rev-parse HEAD) || return 1
    git -C "$controller" worktree add -q -b hostile "$target" || return 1

    mkdir -p "$target/.codex/agents"
    printf '%s\n' 'MALICIOUS_AGENTS_INSTRUCTIONS' > "$target/AGENTS.md"
    printf '%s\n' 'MALICIOUS_WORKFLOW_SOURCE' > "$target/.claude/workflows/review-single.js"
    printf '%s\n' 'model = "attacker/model"' 'sandbox_mode = "danger-full-access"' \
      'developer_instructions = "MALICIOUS_ROLE_INSTRUCTIONS"' \
      > "$target/.codex/agents/adversarial-reviewer.toml"
    git -C "$target" add . || return 1
    git -C "$target" -c user.name=Test -c user.email=test@example.invalid \
      -c commit.gpgsign=false commit -q -m hostile-policy || return 1
    diff_base=$(git -C "$target" rev-parse HEAD) || return 1
    printf '%s\n' 'reviewed change' > "$target/change.txt"
    git -C "$target" add change.txt || return 1
    git -C "$target" -c user.name=Test -c user.email=test@example.invalid \
      -c commit.gpgsign=false commit -q -m delta || return 1
    printf '%s\n' 'EXPECTED_SPEC_DATA' > "$work/spec"

    cat > "$work/bin/codex" <<EOF
#!/bin/sh
capture='$capture'
printf 'ARGS' > "\$capture"
while [ "\$#" -gt 0 ]; do
  printf ' <%s>' "\$1" >> "\$capture"
  if [ "\$1" = '-C' ]; then
    shift
    printf ' <%s>' "\$1" >> "\$capture"
    cd "\$1" || exit 2
  fi
  shift
done
printf '\nCWD<%s>\nENV_BEGIN\n' "\$PWD" >> "\$capture"
env | sort >> "\$capture"
printf 'ENV_END\nPROMPT_BEGIN\n' >> "\$capture"
cat >> "\$capture"
printf '\nPROMPT_END\n' >> "\$capture"
EOF
    chmod +x "$work/bin/codex"
  }

  cleanup() {
    git -C "$controller" worktree remove --force "$target" >/dev/null 2>&1 || true
    rm -rf "$work"
  }

  BeforeEach 'setup'
  AfterEach 'cleanup'

  run_hostile_fixture() {
    GH_TOKEN=secret GITHUB_TOKEN=also-secret ATTACK_SECRET=never-inherit \
      PATH="$work/bin:$PATH" sh "$controller/scripts/agent/codex-review.sh" \
      --target-worktree "$target" \
      --trusted-policy-sha "$trusted_policy_sha" \
      --diff-base "$diff_base" \
      --pr 1348 \
      --workflow single \
      --tier low \
      --spec-file "$work/spec" || return 1

    python3 - "$capture" "$trusted_policy_sha" "$diff_base" "$target" "$controller" <<'PY'
from pathlib import Path
import sys

text = Path(sys.argv[1]).read_text()
trusted_sha, diff_base, target, controller = sys.argv[2:]
args, remainder = text.split("\nCWD<", 1)
cwd, remainder = remainder.split(">\nENV_BEGIN\n", 1)
environment, prompt = remainder.split("ENV_END\nPROMPT_BEGIN\n", 1)

for flag in ("<--ephemeral>", "<--ignore-user-config>", "<--ignore-rules>",
             "<--sandbox> <read-only>", "<--skip-git-repo-check>",
             "<-m> <gpt-5.6-luna>"):
    assert flag in args, flag
assert "/codex-review." in cwd
assert target not in cwd and controller not in cwd
for secret in ("GH_TOKEN=", "GITHUB_TOKEN=", "ATTACK_SECRET=", "secret"):
    assert secret not in environment
assert "HOME=" in environment and "HOME=\n" not in environment
assert "CODEX_HOME=" in environment and "CODEX_HOME=\n" not in environment
for trusted in ("TRUSTED_WORKFLOW_SOURCE", "TRUSTED_ROLE_RESTRICTIONS",
                "EXPECTED_SPEC_DATA", trusted_sha, diff_base):
    assert trusted in prompt, trusted
for hostile in ("MALICIOUS_AGENTS_INSTRUCTIONS", "MALICIOUS_WORKFLOW_SOURCE",
                "MALICIOUS_ROLE_INSTRUCTIONS", "attacker/model",
                "danger-full-access"):
    assert hostile not in prompt, hostile
assert "DIFF_BASE is " + diff_base in prompt
assert "TRUSTED_POLICY_SHA is " + trusted_sha in prompt
PY
  }

  It 'keeps hostile target policy out of the reviewer launch and prompt'
    When call run_hostile_fixture
    The status should be success
  End


  It 'derives a non-empty reviewer HOME from an absolute CODEX_HOME'
    mkdir -p "$work/auth/.codex"
    When run env -u HOME CODEX_HOME="$work/auth/.codex" PATH="$work/bin:$PATH" \
      sh "$controller/scripts/agent/codex-review.sh" \
      --target-worktree "$target" \
      --trusted-policy-sha "$trusted_policy_sha" \
      --diff-base "$diff_base" \
      --pr 1348 \
      --workflow single \
      --tier low \
      --spec-file "$work/spec"
    The status should be success
    The contents of file "$capture" should include "HOME=$work/auth"
    The contents of file "$capture" should include "CODEX_HOME=$work/auth/.codex"
  End

  It 'fails before launch when neither HOME nor CODEX_HOME is available'
    When run env -u HOME -u CODEX_HOME PATH="$work/bin:$PATH" \
      sh "$controller/scripts/agent/codex-review.sh" \
      --target-worktree "$target" \
      --trusted-policy-sha "$trusted_policy_sha" \
      --diff-base "$diff_base" \
      --pr 1348 \
      --workflow single \
      --tier low \
      --spec-file "$work/spec"
    The status should equal 2
    The stderr should include 'HOME or an absolute CODEX_HOME is required'
    The file "$capture" should not be exist
  End

  It 'rejects using the PR-controlled delta SHA as the trusted policy SHA'
    When run env PATH="$work/bin:$PATH" sh "$controller/scripts/agent/codex-review.sh" \
      --target-worktree "$target" \
      --trusted-policy-sha "$diff_base" \
      --diff-base "$diff_base" \
      --pr 1348 \
      --workflow single \
      --tier low \
      --spec-file "$work/spec"
    The status should equal 2
    The stderr should include 'does not match trusted policy SHA'
    The file "$capture" should not be exist
  End
End
