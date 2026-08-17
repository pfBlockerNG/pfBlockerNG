#!/bin/sh
# wait-checks.sh -- poll a PR's checks until every non-excluded check completes.
# The single implementation of the CI wait the pr-merge skill used to inline.
#
# Usage: wait-checks.sh --repo OWNER/REPO --pr N [options]
#   --sha SHA           pin polling to this commit (default: PR's head SHA at arm time).
#                      May be abbreviated: it is resolved to the full OID at arm time.
#   --exclude REGEX    check-name exclusion, matched against the LOWERCASED check name
#                      (so an all-lowercase pattern is effectively case-insensitive; an
#                      uppercase one matches nothing). The default is ANCHORED to the
#                      exact advisory contexts -- CodeRabbit, snyk, code/snyk,
#                      code/snyk (pfBlockerNG) -- which are advisory and must never gate a
#                      merge (#1706: an unanchored default silently dropped required checks
#                      such as `security/snyk-policy-check`). A caller-supplied REGEX
#                      stays unanchored on purpose; it reaches jq as DATA, and one
#                      Oniguruma cannot compile exits 2 rather than polling blind (#1756).
#   --interval SECONDS poll interval (default 30)
#   --max-iter N       hard iteration cap (default 80, ~40 min at 30s)
#
# The LAST stdout line is the verdict: PASS | FAIL | TIMEOUT | STALE. On PASS/FAIL a
# `pinned=<sha>` line and the relevant checks JSON precede it as detail. `bucket`
# semantics: skipping counts as done-not-failed; PASS requires at least one relevant
# check registered (never green-by-absence). Checks are read SHA-addressed
# (commits/<sha>/check-runs + /status) rather than via the PR's current head, and the
# head is re-verified against the pinned SHA (same bounded retry as arm-time; an empty
# re-read is GH-ERROR, never STALE) immediately before any PASS/FAIL, so a force-push
# can never be reported PASS for a commit it didn't run on.
# GH-ERROR (exit 1) is a mechanism failure, not a checks verdict: its FIRST line is
# GH-ERROR, diagnostic follows -- it does not participate in the last-line contract.
# Exit codes: see agent_env.sh. Self-terminating: iteration cap AND wall-clock deadline
# (max-iter x interval + 300 s slack; PFB_WAIT_DEADLINE overrides) per CLAUDE.md
# "No orphaned waits" #1.

repo='' pr='' sha='' sha_set=0 interval=30 max_iter=80
exclude='^(coderabbit|snyk|code/snyk( [(][^)]*[)])?)$'

usage() {
	echo "usage: wait-checks.sh --repo O/R --pr N [--sha SHA] [--exclude REGEX] [--interval S] [--max-iter N]" >&2
	exit 2
}

# Reduce one checks-JSON snapshot to PASS / FAIL / PENDING / EMPTY (prints verdict).
evaluate_checks() {
	# $1 = checks JSON array of {name, bucket}
	rel=$(printf '%s' "$1" | jq -c --arg ex "$exclude" '[.[] | select((.name|ascii_downcase|test($ex))|not)]')
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

# Resolve the pin to the full 40-character OID `headRefOid` always returns: a `--sha`
# ref may be abbreviated, and the pre-verdict identity check compares against that OID,
# so an unexpanded pin could only ever report STALE (#2476).
resolve_pin() {
	if [ "$sha_set" -eq 0 ]; then
		gh_bounded pr view "$pr" --repo "$repo" --json headRefOid --jq .headRefOid
	else
		gh_bounded api "repos/$repo/commits/$sha" --jq .sha
	fi
}

main() {
	# shellcheck source=scripts/agent/agent_env.sh
	. "$(dirname "$0")/agent_env.sh"
	# Every value-taking flag checks that its value is actually there before `shift 2`
	# (same guard work-branch.sh uses): a bare `shift 2` on a one-token tail is fatal
	# under dash but merely non-zero under a bash-provided /bin/sh, where `$1` never
	# advances and this loop spins forever -- a hang that never reaches the deadline.
	while [ $# -gt 0 ]; do
		case "$1" in
			--repo) [ $# -ge 2 ] || usage; repo=$2; shift 2 ;;
			--pr) [ $# -ge 2 ] || usage; pr=$2; shift 2 ;;
			--sha) [ $# -ge 2 ] || usage; sha=$2; sha_set=1; shift 2 ;;
			--exclude) [ $# -ge 2 ] || usage; exclude=$2; shift 2 ;;
			--interval) [ $# -ge 2 ] || usage; interval=$2; shift 2 ;;
			--max-iter) [ $# -ge 2 ] || usage; max_iter=$2; shift 2 ;;
			*) usage ;;
		esac
	done
	{ [ -n "$repo" ] && [ -n "$pr" ]; } || usage
	[ "$sha_set" -eq 0 ] || [ -n "$sha" ] || usage
	require_gh
	require_tool timeout
	require_tool jq

	# Two patterns must die here, at the boundary (#1756), because both end the same way
	# -- a real FAIL polled past to a blind TIMEOUT -- with exit 2 like any other
	# usage/precondition error:
	#   - one Oniguruma cannot compile: the filter yields nothing, the counts come back
	#     empty, and the verdict falls through to PENDING;
	#   - the empty one: it compiles and matches EVERY name, so every check is excluded,
	#     `total` is 0 and the verdict is EMPTY. Match nothing with `^$`, never ''.
	if [ -z "$exclude" ]; then
		echo "usage: --exclude must not be empty (it would exclude every check)" >&2
		exit 2
	fi
	if ! printf '""' | jq -e --arg ex "$exclude" 'test($ex) | true' >/dev/null 2>&1; then
		echo "usage: --exclude is not a valid regex: $exclude" >&2
		exit 2
	fi

	# Wall-clock deadline alongside the cap (CLAUDE.md "No orphaned waits" #1);
	# PFB_WAIT_DEADLINE (epoch seconds) overrides for tests/ops.
	deadline=${PFB_WAIT_DEADLINE:-$(( $(date +%s) + max_iter * interval + 300 ))}

	# Bounded retry (same 3-strike tolerance as the poll loop below) before
	# failing loud: a single transient blip on the very first call -- right
	# after a force-push, exactly when this wait is armed and the API is
	# least settled -- must not kill the whole wait. Still capped by the
	# wall-clock deadline via gh_bounded; a wait that still cannot pin a SHA
	# after that tolerance is exhausted must fail loudly, never poll blind.
	ghfail=0
	while true; do
		if resolved=$(resolve_pin) && [ -n "$resolved" ]; then
			sha=$resolved
			break
		fi
		ghfail=$((ghfail + 1))
		if [ "$ghfail" -ge 3 ]; then
			printf 'GH-ERROR\n%s\n' "$resolved"
			exit 1
		fi
		sleep_bounded "$interval" || { printf 'GH-ERROR\n%s\n' "$resolved"; exit 1; }
	done
	ghfail=0

	i=0
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
				# mid-wait) -- confirm before handing out a terminal verdict. Same
				# bounded retry as arm-time resolution: a blip here must not discard
				# an otherwise-completed wait. An empty read is a hard failure, same
				# as arm-time -- it is never proof the head moved, only that this
				# read didn't land, so it is GH-ERROR, not STALE.
				while true; do
					if live=$(gh_bounded pr view "$pr" --repo "$repo" --json headRefOid --jq .headRefOid) && [ -n "$live" ]; then
						break
					fi
					ghfail=$((ghfail + 1))
					if [ "$ghfail" -ge 3 ]; then
						printf 'GH-ERROR\n%s\n' "$live"
						exit 1
					fi
					sleep_bounded "$interval" || { printf 'GH-ERROR\n%s\n' "$live"; exit 1; }
				done
				if [ "$live" != "$sha" ]; then
					printf 'pinned=%s observed=%s\nSTALE\n' "$sha" "$live"
					exit 0
				fi
				printf 'pinned=%s\n' "$sha"
				printf '%s' "$json" | jq -c --arg ex "$exclude" '[.[] | select((.name|ascii_downcase|test($ex))|not)]'
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
