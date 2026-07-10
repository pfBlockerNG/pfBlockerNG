#!/bin/sh
# release-ci-gate.sh — assert CI is green for the commit a release will tag.
#
# The release tags the current HEAD of the channel branch. A docs-only tip
# (e.g. a committed release-notes commit) skips CI via test.yml's paths-ignore
# and carries NO 'All tests passed' check-run, so walk back first-parent
# ancestors to the most recent commit that actually ran it and assert THAT is
# success — the docs-only commits in between change no code, so the nearest
# CI'd ancestor is authoritative.
#
# Usage: sh scripts/release-ci-gate.sh
#   env REPO      owner/repo to query (required)
#   env GH_TOKEN  token for gh api (required by gh)
#   cwd           a checkout with HEAD at the commit to be tagged
# Exit 0 iff the gate passes; 1 with a ::error:: line otherwise.
#
# issue #1077: the check-runs query filters server-side on the check name and
# reads up to 100 runs, so a tip whose page 1 is crowded out by smoke/ui
# fan-out legs cannot make the run fall off the page and green-light an
# ancestor instead; and a PRESENT but not-yet-concluded run (conclusion null,
# CI still running) fails loudly instead of reading as "no such check" and
# falling through to the ancestor walk.

set -u

CONCLUSION=""
CHECK_SHA=""
for sha in $(git rev-list --first-parent -n 20 HEAD); do
	c=$(gh api \
		"repos/${REPO}/commits/${sha}/check-runs?check_name=All%20tests%20passed&per_page=100" \
		--jq '[.check_runs[] | select(.name == "All tests passed")]
		      | sort_by(.completed_at) | last
		      | if . == null then "" elif .conclusion == null then "pending" else .conclusion end')
	if [ -n "$c" ]; then CONCLUSION="$c"; CHECK_SHA="$sha"; break; fi
done
if [ -z "$CONCLUSION" ]; then
	echo "::error::No 'All tests passed' check-run found on HEAD or its recent ancestors."
	echo "Push the commit to a branch first and wait for CI to pass before releasing."
	exit 1
fi
if [ "$CONCLUSION" = "pending" ]; then
	echo "::error::'All tests passed' for ${CHECK_SHA} has not concluded yet — tip CI is still running; wait for it."
	exit 1
fi
if [ "$CONCLUSION" != "success" ]; then
	echo "::error::'All tests passed' for ${CHECK_SHA} is '${CONCLUSION}'."
	echo "Push the commit to a branch first and wait for CI to pass before releasing."
	exit 1
fi
echo "CI green on ${CHECK_SHA} (conclusion: ${CONCLUSION})"
