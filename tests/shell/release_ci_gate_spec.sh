#shellcheck shell=sh
# release-ci-gate.sh — the release workflow's "Require CI green on the branch
# tip" gate (issue #1077).
#
# Two ancestor-green-lighting defects are pinned here:
#
#   1) The check-runs query used to read only the first unfiltered page, so a
#      tip whose 'All tests passed' run was crowded off page 1 by smoke/ui
#      fan-out legs read as "never ran CI" and the walk-back validated an
#      ancestor instead of the tip. The query now filters server-side on the
#      check name (+ per_page=100).
#
#   2) A PRESENT but not-yet-concluded run (conclusion null, CI still running)
#      collapsed to "" -- indistinguishable from "no such check" -- and fell
#      through to the ancestor walk. It now fails loudly ("still running").
#
# The gh(1) stub serves ${GH_MOCK_DIR}/<sha>.filtered.json when the query
# carries the check_name filter and <sha>.unfiltered.json otherwise, applying
# the real --jq expression with jq -r, so the fixtures model exactly what the
# API would return for each query shape.

Describe 'release-ci-gate.sh (issue #1077)'
  setup() {
    scrub_git_env
    work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/cigate.XXXXXX")"
    export GH_MOCK_DIR="${work}/mock"
    mkdir -p "${GH_MOCK_DIR}" "${work}/bin"

    # gh stub: only `gh api <url> --jq <expr>` is served.
    cat > "${work}/bin/gh" <<'EOF'
#!/bin/sh
[ "$1" = "api" ] || { echo "gh stub: unsupported: $*" >&2; exit 64; }
url="$2"; shift 2
jqexpr=""
while [ $# -gt 0 ]; do
	case "$1" in
		--jq) jqexpr="$2"; shift 2 ;;
		*) shift ;;
	esac
done
sha="${url##*commits/}"; sha="${sha%%/*}"
if [ -f "${GH_MOCK_DIR}/${sha}.gh-fail" ]; then
	echo "gh: HTTP 403 rate limit exceeded" >&2
	exit 1
fi
case "$url" in
	*check_name=*) f="${GH_MOCK_DIR}/${sha}.filtered.json" ;;
	*)             f="${GH_MOCK_DIR}/${sha}.unfiltered.json" ;;
esac
[ -f "$f" ] || { echo '{"check_runs":[]}' | jq -r "$jqexpr"; exit 0; }
jq -r "$jqexpr" < "$f"
EOF
    chmod +x "${work}/bin/gh"

    # A 2-commit repo: ancestor then tip (first-parent walk = tip, ancestor).
    repo="${work}/repo"
    git init -q -b main "$repo"
    ( cd "$repo" \
      && git -c user.name=t -c user.email=t@t commit -q --allow-empty -m ancestor \
      && git -c user.name=t -c user.email=t@t commit -q --allow-empty -m tip )
    ancestor="$(git -C "$repo" rev-parse HEAD~1)"
    tip="$(git -C "$repo" rev-parse HEAD)"
  }
  cleanup() { rm -rf "$work"; }
  Before 'setup'
  After 'cleanup'

  # Both query shapes (filtered + legacy unfiltered) serve the same payload
  # unless a case overrides one side explicitly.
  payload() { # $1 sha, $2 json body
    printf '%s' "$2" > "${GH_MOCK_DIR}/$1.filtered.json"
    printf '%s' "$2" > "${GH_MOCK_DIR}/$1.unfiltered.json"
  }
  commit_index_paths() { # $1 message, $2 mode, remaining args are paths
    message="$1"
    mode="$2"
    shift 2
    blob="$(printf '%s\n' "$message" | git -C "$repo" hash-object -w --stdin)"
    for path do
      printf '%s %s\t%s\0' "$mode" "$blob" "$path" |
        git -C "$repo" update-index -z --index-info
    done
    git -C "$repo" -c user.name=t -c user.email=t@t commit -q -m "$message"
    tip="$(git -C "$repo" rev-parse HEAD)"
  }
  commit_paths() {
    message="$1"
    shift
    commit_index_paths "$message" 100644 "$@"
  }
  commit_executable_paths() {
    message="$1"
    shift
    commit_index_paths "$message" 100755 "$@"
  }
  commit_empty() {
    git -C "$repo" -c user.name=t -c user.email=t@t commit -q --allow-empty -m "$1"
    tip="$(git -C "$repo" rev-parse HEAD)"
  }
  run_gate() {
    ( cd "$repo" && PATH="${work}/bin:${PATH}" REPO="own/repo" GH_TOKEN=x \
        sh "${PFB_ROOT}/scripts/release-ci-gate.sh" )
  }

  It 'passes on a green tip'
    payload "$tip" '{"check_runs":[{"name":"All tests passed","completed_at":"2026-01-01T00:00:00Z","conclusion":"success"}]}'
    When call run_gate
    The status should be success
    The output should include "CI green on ${tip}"
  End

  It 'fails loudly on a tip run that has not concluded (never walks back)'
    # issue #1077 defect 2: conclusion null used to read as "no such check",
    # falling through to the ancestor walk -- a green ancestor then passed the
    # gate while the tip's CI was still running.
    payload "$tip" '{"check_runs":[{"name":"All tests passed","completed_at":null,"conclusion":null}]}'
    payload "$ancestor" '{"check_runs":[{"name":"All tests passed","completed_at":"2026-01-01T00:00:00Z","conclusion":"success"}]}'
    When call run_gate
    The status should be failure
    The output should include 'has not concluded yet'
    The output should not include "CI green on ${ancestor}"
  End

  It 'finds the tip run via the server-side check_name filter (crowded page 1)'
    # issue #1077 defect 1: the tip run exists but only the FILTERED query
    # returns it (page 1 of the unfiltered listing is crowded out by fan-out
    # legs). The legacy unfiltered query saw nothing and green-lit the
    # ancestor; the gate must validate the TIP.
    payload "$tip" '{"check_runs":[{"name":"other","completed_at":"2026-01-01T00:00:00Z","conclusion":"success"}]}'
    printf '%s' '{"check_runs":[{"name":"All tests passed","completed_at":"2026-01-01T00:00:00Z","conclusion":"success"}]}' \
      > "${GH_MOCK_DIR}/${tip}.filtered.json"
    payload "$ancestor" '{"check_runs":[{"name":"All tests passed","completed_at":"2026-01-01T00:00:00Z","conclusion":"success"}]}'
    When call run_gate
    The status should be success
    The output should include "CI green on ${tip}"
  End

  It 'walks across every exact CI-ignored path class and an empty commit'
    commit_paths root-markdown 'README.md'
    commit_paths nested-markdown 'notes/release/details.md'
    commit_paths docs-non-markdown 'docs/release-notes.txt'
    commit_paths ponytail-license '.claude/skills/ponytail/LICENSE'
    commit_paths ponytail-upstream '.claude/skills/ponytail/UPSTREAM'
    commit_paths caveman-license '.claude/skills/caveman/LICENSE'
    commit_paths caveman-upstream '.claude/skills/caveman/UPSTREAM'
    commit_empty empty
    payload "$ancestor" '{"check_runs":[{"name":"All tests passed","completed_at":"2026-01-01T00:00:00Z","conclusion":"success"}]}'
    When call run_gate
    The status should be success
    The output should include "CI green on ${ancestor}"
  End

  It 'allows hostile and opaque names when their paths are CI-ignored'
    tab_name="$(printf 'tab\tname')"
    non_utf8="$(printf '\377')"
    long_name="$(awk 'BEGIN { for (i = 0; i < 230; i++) printf "n" }')"
    commit_paths hostile-docs \
      'docs/space name' \
      'docs/two  spaces' \
      "docs/${tab_name}" \
      'docs/quote"name' \
      'docs/glob[*?]name' \
      'docs/pünicode' \
      "docs/${long_name}" \
      "docs/non-utf8-${non_utf8}" \
      'root hostile [*?] name.md'
    payload "$ancestor" '{"check_runs":[{"name":"All tests passed","completed_at":"2026-01-01T00:00:00Z","conclusion":"success"}]}'
    When call run_gate
    The status should be success
    The output should include "CI green on ${ancestor}"
  End

  It 'rejects an unchecked ordinary code commit'
    commit_paths code 'scripts/changed.sh'
    code_sha="$tip"
    payload "$ancestor" '{"check_runs":[{"name":"All tests passed","completed_at":"2026-01-01T00:00:00Z","conclusion":"success"}]}'
    When call run_gate
    The status should be failure
    The output should include "Skipped commit ${code_sha}"
    The output should include 'changes CI-relevant paths'
    The output should not include "CI green on ${ancestor}"
  End

  It 'rejects unchecked executable hooks under vendored plugin trees'
    commit_executable_paths hooks \
      '.claude/skills/ponytail/hooks/release.js' \
      '.claude/skills/caveman/src/hooks/release.js'
    hook_sha="$tip"
    payload "$ancestor" '{"check_runs":[{"name":"All tests passed","completed_at":"2026-01-01T00:00:00Z","conclusion":"success"}]}'
    When call run_gate
    The status should be failure
    The output should include "Skipped commit ${hook_sha}"
    The output should include 'changes CI-relevant paths'
  End

  It 'rejects a near miss of an exact ignored plugin path'
    commit_paths near-miss '.claude/skills/ponytail/LICENSE.extra'
    near_miss_sha="$tip"
    payload "$ancestor" '{"check_runs":[{"name":"All tests passed","completed_at":"2026-01-01T00:00:00Z","conclusion":"success"}]}'
    When call run_gate
    The status should be failure
    The output should include "Skipped commit ${near_miss_sha}"
    The output should include 'changes CI-relevant paths'
  End

  It 'rejects hostile and opaque names when their paths are CI-relevant'
    tab_name="$(printf 'tab\tname')"
    non_utf8="$(printf '\377')"
    long_name="$(awk 'BEGIN { for (i = 0; i < 230; i++) printf "n" }')"
    commit_paths hostile-code \
      'scripts/space name' \
      'scripts/two  spaces' \
      "scripts/${tab_name}" \
      'scripts/quote"name' \
      'scripts/glob[*?]name' \
      'scripts/pünicode' \
      "scripts/${long_name}" \
      "scripts/non-utf8-${non_utf8}"
    code_sha="$tip"
    payload "$ancestor" '{"check_runs":[{"name":"All tests passed","completed_at":"2026-01-01T00:00:00Z","conclusion":"success"}]}'
    When call run_gate
    The status should be failure
    The output should include "Skipped commit ${code_sha}"
    The output should include 'changes CI-relevant paths'
  End

  It 'classifies every skipped commit before accepting a green ancestor'
    commit_paths unchecked-code 'scripts/changed.sh'
    code_sha="$tip"
    commit_paths docs-after-code 'docs/release-notes.txt'
    payload "$ancestor" '{"check_runs":[{"name":"All tests passed","completed_at":"2026-01-01T00:00:00Z","conclusion":"success"}]}'
    When call run_gate
    The status should be failure
    The output should include "Skipped commit ${code_sha}"
    The output should not include "CI green on ${ancestor}"
  End

  It 'fails closed when Git cannot classify a skipped commit'
    parent_dir="$(printf '%.2s' "$ancestor")"
    parent_file="$(printf '%s' "$ancestor" | cut -c3-)"
    rm "${repo}/.git/objects/${parent_dir}/${parent_file}"
    When call run_gate
    The status should be failure
    The output should include "Could not classify skipped commit ${tip}"
    The output should not include 'CI green on'
  End

  It 'fails when a concluded run is not success'
    payload "$tip" '{"check_runs":[{"name":"All tests passed","completed_at":"2026-01-01T00:00:00Z","conclusion":"failure"}]}'
    When call run_gate
    The status should be failure
    The output should include "is 'failure'"
  End

  It 'fails when no run exists anywhere in the walk window'
    When call run_gate
    The status should be failure
    The output should include "No 'All tests passed' check-run found"
  End

  It 'aborts loudly when the check-runs query itself fails (never walks back)'
    # A gh failure (rate limit/network/auth) used to read as "no such check",
    # falling through to a green ancestor while the tip was unverifiable.
    touch "${GH_MOCK_DIR}/${tip}.gh-fail"
    payload "$ancestor" '{"check_runs":[{"name":"All tests passed","started_at":"2026-01-01T00:00:00Z","completed_at":"2026-01-01T00:10:00Z","conclusion":"success"}]}'
    When call run_gate
    The status should be failure
    The output should include 'cannot verify CI state'
    The output should not include "CI green on ${ancestor}"
    The stderr should include 'rate limit'
  End

  It 'treats a newer in-progress rerun as pending despite an older completed success'
    # ANY unresolved run for the name must read as pending -- a recency sort on
    # completed_at let the older success shadow the null-timestamped rerun.
    payload "$tip" '{"check_runs":[{"name":"All tests passed","started_at":"2026-01-01T00:00:00Z","completed_at":"2026-01-01T00:10:00Z","conclusion":"success"},{"name":"All tests passed","started_at":"2026-01-02T00:00:00Z","completed_at":null,"conclusion":null}]}'
    When call run_gate
    The status should be failure
    The output should include 'has not concluded yet'
  End

  It 'treats a QUEUED rerun (null started_at) as pending despite an older completed success'
    # A queued-but-not-started rerun has null started_at too, so even a
    # started_at recency sort would let the completed success shadow it; only
    # the any-unresolved rule catches it.
    payload "$tip" '{"check_runs":[{"name":"All tests passed","started_at":"2026-01-01T00:00:00Z","completed_at":"2026-01-01T00:10:00Z","conclusion":"success"},{"name":"All tests passed","started_at":null,"completed_at":null,"conclusion":null}]}'
    When call run_gate
    The status should be failure
    The output should include 'has not concluded yet'
  End

  It 'reports a missing REPO env var, not a bogus no-check-run diagnostic'
    payload "$tip" '{"check_runs":[{"name":"All tests passed","started_at":"2026-01-01T00:00:00Z","completed_at":"2026-01-01T00:10:00Z","conclusion":"success"}]}'
    run_gate_no_repo() {
      ( cd "$repo" && PATH="${work}/bin:${PATH}" GH_TOKEN=x \
          sh "${PFB_ROOT}/scripts/release-ci-gate.sh" )
    }
    When call run_gate_no_repo
    The status should be failure
    The output should include 'REPO env var'
    The output should not include "No 'All tests passed'"
  End

  It 'does not walk back beyond the 20-commit window'
    # The only matching run sits on commit 21 in first-parent order; the walk
    # must exhaust at 20 and fail rather than validate an ancient ancestor.
    deep="$repo-deep"
    git init -q -b main "$deep"
    ( cd "$deep" && for i in $(seq 1 22); do
        git -c user.name=t -c user.email=t@t commit -q --allow-empty -m "c$i"
      done )
    old21="$(git -C "$deep" rev-parse HEAD~21)"
    payload "$old21" '{"check_runs":[{"name":"All tests passed","started_at":"2026-01-01T00:00:00Z","completed_at":"2026-01-01T00:10:00Z","conclusion":"success"}]}'
    run_gate_deep() {
      ( cd "$deep" && PATH="${work}/bin:${PATH}" REPO="own/repo" GH_TOKEN=x \
          sh "${PFB_ROOT}/scripts/release-ci-gate.sh" )
    }
    When call run_gate_deep
    The status should be failure
    The output should include "No 'All tests passed' check-run found"
  End
End
