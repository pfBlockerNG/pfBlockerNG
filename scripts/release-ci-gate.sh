#!/bin/sh
# release-ci-gate.sh — assert CI is green for the commit a release will tag.
#
# The release tags the current HEAD of the channel branch. A docs-only tip
# (a runbook edit, an ADR amendment) skips CI via test.yml's paths-ignore
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
# falling through to the ancestor walk. A failed query (rate limit, network,
# auth) also aborts loudly -- an unverifiable tip must never read as "never
# ran CI". ANY unresolved run for the name reads as pending: recency proxies
# (completed_at/started_at sorts) let a null-timestamped in-progress or queued
# rerun sort first and be shadowed by an older completed run.

set -u

if [ -z "${REPO:-}" ]; then
	echo "::error::REPO env var (owner/repo) is required."
	exit 1
fi

CONCLUSION=""
CHECK_SHA=""
if ! sha=$(git rev-parse --verify HEAD); then
	echo "::error::Could not resolve HEAD; cannot verify CI state."
	exit 1
fi
walked=0
while [ "$walked" -lt 20 ]; do
	if ! c=$(gh api \
		"repos/${REPO}/commits/${sha}/check-runs?check_name=All%20tests%20passed&per_page=100" \
		--jq '[.check_runs[] | select(.name == "All tests passed")]
		      | if length == 0 then ""
		        elif any(.[]; .conclusion == null) then "pending"
		        else (sort_by(.started_at) | last | .conclusion)
		        end'); then
		echo "::error::check-runs query failed for ${sha} — cannot verify CI state; aborting instead of walking back."
		exit 1
	fi
	if [ -n "$c" ]; then CONCLUSION="$c"; CHECK_SHA="$sha"; break; fi
	if ! parent=$(git rev-parse --verify "${sha}^" 2>/dev/null); then
		root=$(git rev-list --max-parents=0 -n 1 "$sha" 2>/dev/null)
		if [ "$root" = "$sha" ]; then break; fi
		echo "::error::Could not classify skipped commit ${sha}; cannot verify whether an older check-run applies."
		exit 1
	fi
	git diff --quiet "$parent" "$sha" -- '.' \
		':(top,exclude,glob)**/*.md' \
		':(top,exclude,glob)*.md' \
		':(top,exclude,glob)docs/**' \
		':(top,exclude,glob)legacy/**' 2>/dev/null
	diff_status=$?
	if [ "$diff_status" -eq 1 ]; then
		echo "::error::Skipped commit ${sha} changes CI-relevant paths; cannot rely on an older check-run."
		exit 1
	fi
	if [ "$diff_status" -ne 0 ]; then
		echo "::error::Could not classify skipped commit ${sha}; cannot verify whether an older check-run applies."
		exit 1
	fi
	sha="$parent"
	walked=$((walked + 1))
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
