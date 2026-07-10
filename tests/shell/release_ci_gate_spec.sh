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

  It 'walks back to the nearest CI-run ancestor for a docs-only tip'
    # Preserved behaviour: a tip with genuinely NO matching run (docs-only
    # commit, CI skipped) defers to the nearest ancestor that ran CI.
    payload "$tip" '{"check_runs":[]}'
    payload "$ancestor" '{"check_runs":[{"name":"All tests passed","completed_at":"2026-01-01T00:00:00Z","conclusion":"success"}]}'
    When call run_gate
    The status should be success
    The output should include "CI green on ${ancestor}"
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
    # completed_at is null on the in-progress rerun and null sorts FIRST, so a
    # completed_at sort let the older success shadow it; sorting by started_at
    # surfaces the newest attempt, which has not concluded.
    payload "$tip" '{"check_runs":[{"name":"All tests passed","started_at":"2026-01-01T00:00:00Z","completed_at":"2026-01-01T00:10:00Z","conclusion":"success"},{"name":"All tests passed","started_at":"2026-01-02T00:00:00Z","completed_at":null,"conclusion":null}]}'
    When call run_gate
    The status should be failure
    The output should include 'has not concluded yet'
  End
End
