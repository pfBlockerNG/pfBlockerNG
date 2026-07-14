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
    launch_log="$work/codex-launches"
    mkdir -p "$controller/scripts/agent" "$controller/.claude/workflows/schemas" \
      "$controller/.agents" "$controller/.codex/agents" "$work/bin" || return 1
    cp "${PFB_ROOT}/scripts/agent/codex-review.sh" "$controller/scripts/agent/" || return 1
    cp "${PFB_ROOT}/scripts/agent/codex_review_aggregate.py" "$controller/scripts/agent/" || return 1
    cp "${PFB_ROOT}/.claude/workflows/schemas/review-findings.schema.json" \
      "${PFB_ROOT}/.claude/workflows/schemas/review-verdict.schema.json" \
      "$controller/.claude/workflows/schemas/" || return 1
    chmod +x "$controller/scripts/agent/codex-review.sh" || return 1
    printf '%s\n' 'TRUSTED_WORKFLOW_SOURCE' > "$controller/.claude/workflows/review-single.js"
    printf '%s\n' 'TRUSTED_FANOUT_WORKFLOW_SOURCE' > "$controller/.claude/workflows/review-fanout.js"
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
launch_log='$launch_log'
output=''
schema=''
printf 'ARGS' > "\$capture"
while [ "\$#" -gt 0 ]; do
  arg=\$1
  printf ' <%s>' "\$arg" >> "\$capture"
  shift
  case "\$arg" in
    -C)
      printf ' <%s>' "\$1" >> "\$capture"
      cd "\$1" || exit 2
      shift
      ;;
    --output-schema)
      schema=\$1
      printf ' <%s>' "\$1" >> "\$capture"
      shift
      ;;
    --output-last-message)
      output=\$1
      printf ' <%s>' "\$1" >> "\$capture"
      shift
      ;;
  esac
done
printf '\nCWD<%s>\nENV_BEGIN\n' "\$PWD" >> "\$capture"
env | sort >> "\$capture"
printf 'ENV_END\nPROMPT_BEGIN\n' >> "\$capture"
cat >> "\$capture"
printf '\nPROMPT_END\n' >> "\$capture"
printf '%s\n' "\${schema##*/}" >> "\$launch_log"
case "\${schema##*/}" in
  review-verdict.schema.json)
    printf '%s\n' '{"holds":true,"evidence":"verified probe","revised_severity":null}' > "\$output"
    ;;
  *)
    printf '%s\n' '{"findings":[{"severity":"blocking","location":"a:1","explanation":"same defect","reproduce":"probe output","suggested_fix":"fix it"}],"per_file":[{"file":"a","verdict":"finding"}]}' > "\$output"
    ;;
esac
EOF
    chmod +x "$work/bin/codex"
    cat > "$work/bin/git" <<EOF
#!/bin/sh
printf 'hostile PATH git ran\n' > '$work/hostile-git-ran'
exit 97
EOF
    chmod +x "$work/bin/git"
  }

  cleanup() {
    git -C "$controller" worktree remove --force "$target" >/dev/null 2>&1 || true
    rm -rf "$work"
  }

  BeforeEach 'setup'
  AfterEach 'cleanup'

  run_hostile_fixture() {
    output=$(GH_TOKEN=secret GITHUB_TOKEN=also-secret ATTACK_SECRET=never-inherit \
      CODEX_REVIEW_TEST_MODE=1 CODEX_REVIEW_TEST_CODEX_BIN="$work/bin/codex" \
      PATH="$work/bin:$PATH" /bin/sh "$controller/scripts/agent/codex-review.sh" \
      --target-worktree "$target" \
      --trusted-policy-sha "$trusted_policy_sha" \
      --diff-base "$diff_base" \
      --pr 1348 \
      --workflow single \
      --tier low \
      --spec-file "$work/spec") || return 1

    python3 - "$capture" "$trusted_policy_sha" "$diff_base" "$target" "$controller" <<'PY'
from pathlib import Path
import sys

text = Path(sys.argv[1]).read_text()
trusted_sha, diff_base, target, controller = sys.argv[2:]
target = str(Path(target).resolve())
controller = str(Path(controller).resolve())
args, remainder = text.split("\nCWD<", 1)
cwd, remainder = remainder.split(">\nENV_BEGIN\n", 1)
environment, prompt = remainder.split("ENV_END\nPROMPT_BEGIN\n", 1)

for flag in ("<--ephemeral>", "<--ignore-user-config>", "<--ignore-rules>",
             "<--skip-git-repo-check>", "<--output-schema>",
             "review-findings.schema.json>", "<-m> <gpt-5.6-luna>",
             '<default_permissions="codex_review">',
             '<shell_environment_policy.inherit="none">',
             '<shell_environment_policy.set=',
             '<permissions.codex_review.extends=":read-only">',
             '<permissions.codex_review.network.enabled=false>'):
    assert flag in args, flag
assert "<--sandbox>" not in args
assert f'"{target}"="read"' in args
assert '="write"' in args
assert '="deny"' in args
assert 'GIT_CONFIG_GLOBAL="/dev/null"' in args
assert 'GIT_DIR="' in args and '/review.git"' in args
assert "/codex-review." in cwd
assert target not in cwd and controller not in cwd
for secret in ("GH_TOKEN=", "GITHUB_TOKEN=", "ATTACK_SECRET=", "secret"):
    assert secret not in environment
assert "HOME=" in environment and "HOME=\n" not in environment
assert "CODEX_HOME=" in environment and "CODEX_HOME=\n" not in environment
path = next(line for line in environment.splitlines() if line.startswith("PATH="))
assert path.endswith("/usr/bin:/bin:/usr/sbin:/sbin"), path
assert str(Path(target).parent / "bin") not in path
for trusted in ("TRUSTED_WORKFLOW_SOURCE", "TRUSTED_ROLE_RESTRICTIONS",
                "EXPECTED_SPEC_DATA", trusted_sha, diff_base):
    assert trusted in prompt, trusted
for hostile in ("MALICIOUS_AGENTS_INSTRUCTIONS", "MALICIOUS_WORKFLOW_SOURCE",
                "MALICIOUS_ROLE_INSTRUCTIONS", "attacker/model",
                "danger-full-access"):
    assert hostile not in prompt, hostile
assert "DIFF_BASE is " + diff_base in prompt
assert "TRUSTED_POLICY_SHA is " + trusted_sha in prompt
assert "END UNTRUSTED SPEC DATA" in prompt
PY
    test ! -e "$work/hostile-git-ran"
  }

  It 'keeps hostile target policy out of the reviewer launch and prompt'
    When call run_hostile_fixture
    The status should be success
  End


  It 'derives a non-empty reviewer HOME from an absolute CODEX_HOME'
    mkdir -p "$work/auth/.codex"
    When run env -u HOME CODEX_HOME="$work/auth/.codex" \
      CODEX_REVIEW_TEST_MODE=1 CODEX_REVIEW_TEST_CODEX_BIN="$work/bin/codex" \
      PATH="$work/bin:$PATH" /bin/sh "$controller/scripts/agent/codex-review.sh" \
      --target-worktree "$target" \
      --trusted-policy-sha "$trusted_policy_sha" \
      --diff-base "$diff_base" \
      --pr 1348 \
      --workflow single \
      --tier low \
      --spec-file "$work/spec"
    The status should be success
    The stdout should include '"findings"'
    The contents of file "$capture" should include "HOME=$work/auth"
    The contents of file "$capture" should include "CODEX_HOME=$work/auth/.codex"
  End

  It 'fails before launch when neither HOME nor CODEX_HOME is available'
    When run env -u HOME -u CODEX_HOME \
      CODEX_REVIEW_TEST_MODE=1 CODEX_REVIEW_TEST_CODEX_BIN="$work/bin/codex" \
      PATH="$work/bin:$PATH" /bin/sh "$controller/scripts/agent/codex-review.sh" \
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
    When run env CODEX_REVIEW_TEST_MODE=1 \
      CODEX_REVIEW_TEST_CODEX_BIN="$work/bin/codex" PATH="$work/bin:$PATH" \
      /bin/sh "$controller/scripts/agent/codex-review.sh" \
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

  It 'rejects the test binary seam unless test mode is explicit'
    When run env CODEX_REVIEW_TEST_CODEX_BIN="$work/bin/codex" \
      /bin/sh "$controller/scripts/agent/codex-review.sh" \
      --target-worktree "$target" \
      --trusted-policy-sha "$trusted_policy_sha" \
      --diff-base "$diff_base" \
      --pr 1348 \
      --workflow single \
      --tier low \
      --spec-file "$work/spec"
    The status should equal 2
    The stderr should include 'accepted only in test mode'
    The file "$capture" should not be exist
  End

  run_fanout_fixture() {
    output=$(CODEX_REVIEW_TEST_MODE=1 \
      CODEX_REVIEW_TEST_CODEX_BIN="$work/bin/codex" \
      /bin/sh "$controller/scripts/agent/codex-review.sh" \
      --target-worktree "$target" \
      --trusted-policy-sha "$trusted_policy_sha" \
      --diff-base "$diff_base" \
      --pr 1348 \
      --workflow fanout \
      --tier low \
      --spec-file "$work/spec") || return 1
    python3 - "$launch_log" "$output" <<'PY'
import json
from pathlib import Path
import sys

launches = Path(sys.argv[1]).read_text().splitlines()
result = json.loads(sys.argv[2])
assert launches.count("review-findings.schema.json") == 3, launches
assert launches.count("review-verdict.schema.json") == 1, launches
assert result["lenses_returned"] == 3
assert len(result["confirmed"]) == 1
assert result["confirmed"][0]["verified"]["holds"] is True
PY
  }

  It 'enforces findings on each fanout lens and verdict on each verifier'
    When call run_fanout_fixture
    The status should be success
  End
End
