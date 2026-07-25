#!/bin/sh
# wait-checks.sh -- poll a PR's checks until every non-excluded check completes.
# The single implementation of the CI wait the pr-merge skill used to inline.
#
# Usage: wait-checks.sh --repo OWNER/REPO --pr N [options]
#   --sha SHA           pin polling to this commit (default: PR's head SHA at arm time)
#   --exclude REGEX    case-insensitive check-name exclusion (default 'coderabbit|snyk' --
#                      both are advisory and must never gate a merge)
#   --interval SECONDS poll interval (default 30)
#   --max-iter N       hard iteration cap (default 80, ~40 min at 30s)
#
# The LAST stdout line is the verdict: PASS | FAIL | TIMEOUT | STALE. On PASS/FAIL the
# relevant checks JSON precedes it as detail. `bucket` semantics: skipping counts as done-
# not-failed; PASS requires at least one relevant check registered (never green-by-absence).
# Checks are read SHA-addressed (commits/<sha>/check-runs + /status) rather than via the
# PR's current head, and the head is re-verified against the pinned SHA immediately before
# any PASS/FAIL, so a force-push can never be reported PASS for a commit it didn't run on.
# Exit codes: see agent_env.sh. Self-terminating: iteration cap AND wall-clock deadline
# (max-iter x interval + 300 s slack; PFB_WAIT_DEADLINE overrides) per CLAUDE.md
# "No orphaned waits" #1.

repo='' pr='' sha='' sha_set=0 exclude='coderabbit|snyk' interval=30 max_iter=80

usage() {
	echo "usage: wait-checks.sh --repo O/R --pr N [--sha SHA] [--exclude REGEX] [--interval S] [--max-iter N]" >&2
	exit 2
}

# Reduce one checks-JSON snapshot to PASS / FAIL / PENDING / EMPTY (prints verdict).
evaluate_checks() {
	# $1 = checks JSON array of {name, bucket}
	rel=$(printf '%s' "$1" | jq -c "[.[] | select((.name|ascii_downcase|test(\"$exclude\"))|not)]")
	total=$(printf '%s' "$rel" | jq 'length')
	fail=$(printf '%s' "$rel" | jq '[.[] | select(.bucket=="fail" or .bucket=="cancel")] | length')
	pend=$(printf '%s' "$rel" | jq '[.[] | select(.bucket=="pending")] | length')
	if [ "$fail" -gt 0 ]; then
		printf 'FAIL'
	elif [ "$total" -eq 0 ]; then
		printf 'EMPTY'
	elif [ "$pend" -eq 0 ]; then
		printf 'PASS'
	else
		printf 'PENDING'
	fi
}

# Map SHA-addressed check-runs + commit-status payloads (each possibly several
# `--paginate` pages concatenated) to the {name, bucket} shape evaluate_checks() consumes.
# Unrecognised status/conclusion values fall to "pending", never "pass" -- an unmapped
# value must surface as a TIMEOUT a human looks at, not a silent green.
checks_to_buckets() {
	# $1 = check-runs payload, $2 = commit-status payload
	{ printf '%s\n' "$1"; printf '%s\n' "$2"; } | jq -s -c '
		[ .[] | (.check_runs // [])[] | {name: (.name // ""), bucket: (
			if .status != "completed" then "pending"
			elif (.conclusion == "success" or .conclusion == "neutral") then "pass"
			elif .conclusion == "skipped" then "skipping"
			elif .conclusion == "cancelled" then "cancel"
			elif (.conclusion == "failure" or .conclusion == "timed_out"
				or .conclusion == "action_required" or .conclusion == "stale"
				or .conclusion == "startup_failure") then "fail"
			else "pending" end) } ]
		+
		[ .[] | (.statuses // [])[] | {name: (.context // ""), bucket: (
			if .state == "success" then "pass"
			elif .state == "pending" then "pending"
			elif (.state == "error" or .state == "failure") then "fail"
			else "pending" end) } ]
	'
}

main() {
	# shellcheck source=scripts/agent/agent_env.sh
	. "$(dirname "$0")/agent_env.sh"
	while [ $# -gt 0 ]; do
		case "$1" in
			--repo) repo=$2; shift 2 ;;
			--pr) pr=$2; shift 2 ;;
			--sha) sha=$2; sha_set=1; shift 2 ;;
			--exclude) exclude=$2; shift 2 ;;
			--interval) interval=$2; shift 2 ;;
			--max-iter) max_iter=$2; shift 2 ;;
			*) usage ;;
		esac
	done
	{ [ -n "$repo" ] && [ -n "$pr" ]; } || usage
	[ "$sha_set" -eq 0 ] || [ -n "$sha" ] || usage
	require_gh
	require_tool timeout
	require_tool jq

	# Wall-clock deadline alongside the cap (CLAUDE.md "No orphaned waits" #1);
	# PFB_WAIT_DEADLINE (epoch seconds) overrides for tests/ops.
	deadline=${PFB_WAIT_DEADLINE:-$(( $(date +%s) + max_iter * interval + 300 ))}

	if [ "$sha_set" -eq 0 ]; then
		# A wait that cannot pin a SHA must fail loudly, never poll blind.
		if ! sha=$(gh_bounded pr view "$pr" --repo "$repo" --json headRefOid --jq .headRefOid) || [ -z "$sha" ]; then
			printf 'GH-ERROR\n%s\n' "$sha"
			exit 1
		fi
	fi

	i=0
	ghfail=0
	while [ "$i" -lt "$max_iter" ]; do
		if [ "$(date +%s)" -ge "$deadline" ]; then
			break
		fi
		ok=1 failed_output=''
		if ! cr_json=$(gh_bounded api --paginate "repos/$repo/commits/$sha/check-runs"); then
			ok=0
			failed_output=$cr_json
		elif ! status_json=$(gh_bounded api --paginate "repos/$repo/commits/$sha/status"); then
			ok=0
			failed_output=$status_json
		fi
		if [ "$ok" -eq 0 ]; then
			# 3 consecutive gh failures = a real problem (bad repo/pr, auth, outage),
			# not "no checks yet" -- fail loudly instead of polling to a blind TIMEOUT.
			ghfail=$((ghfail + 1))
			if [ "$ghfail" -ge 3 ]; then
				printf 'GH-ERROR\n%s\n' "$failed_output"
				exit 1
			fi
			i=$((i + 1))
			sleep_bounded "$interval" || break
			continue
		fi
		ghfail=0
		json=$(checks_to_buckets "$cr_json" "$status_json")
		v=$(evaluate_checks "$json")
		case "$v" in
			PASS|FAIL)
				# The pinned SHA may no longer be the PR head (fix push, force-push
				# mid-wait) -- confirm before handing out a terminal verdict.
				if ! live=$(gh_bounded pr view "$pr" --repo "$repo" --json headRefOid --jq .headRefOid); then
					printf 'GH-ERROR\n%s\n' "$live"
					exit 1
				fi
				if [ "$live" != "$sha" ]; then
					printf 'pinned=%s observed=%s\nSTALE\n' "$sha" "$live"
					exit 0
				fi
				printf '%s' "$json" | jq -c "[.[] | select((.name|ascii_downcase|test(\"$exclude\"))|not)]"
				printf '%s\n' "$v"
				exit 0
				;;
		esac
		i=$((i + 1))
		sleep_bounded "$interval" || break
	done
	printf 'TIMEOUT\n'
}

case "${AGENT_SOURCE_ONLY:-0}" in
	1) ;;
	*) main "$@" ;;
esac
