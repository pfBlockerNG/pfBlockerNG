#!/bin/sh
# wait-reviewer.sh -- poll a PR until a bot/human reviewer engages or finishes.
# The single implementation of the reviewer-wait state machine the pr-comments /
# pr-merge-flow skills used to inline (content-first FINISHED, CodeRabbit QUOTA with
# resume minutes, DECLINE/PAUSE, Snyk status handling, NOTPRESENT presence window).
#
# Usage: wait-reviewer.sh --repo OWNER/REPO --pr N --handle LOGIN [options]
#   --until ack|finished  ack = ANY message from the handle counts (default: finished)
#   --since ISO8601       only activity after this instant counts (default: the PR head
#                         commit time in finished mode; unset = all activity in ack mode)
#   --presence N          polls with zero engagement before NOTPRESENT (default 10; 0=off)
#   --interval SECONDS    poll interval (default 30)
#   --max-iter N          hard iteration cap (default: 20 ack / 60 finished)
#
# The LAST stdout line is the verdict; recent handle comments precede it as detail:
#   ACK | NOACK | FINISHED | QUOTA <mins> | DECLINE | PAUSE | NOTPRESENT | TIMEOUT
# Handle matching is a case-insensitive substring of the login, so `--handle copilot`
# matches copilot-pull-request-reviewer[bot] and `coderabbitai` matches coderabbitai[bot].
# `--handle snyk` reads the head-SHA commit status/check-runs instead of comments (Snyk
# posts no review comments); its `error` state reports QUOTA, never a clean pass.
# Exit codes: see agent_env.sh (0 verdict, 2 usage, 3 gh unavailable -> MCP fallback).
# Self-terminating by construction (CLAUDE.md "No orphaned waits" #1): the cap and the
# interval bound total wall clock; run it in the background and read the verdict.

repo='' pr='' handle='' mode='finished' since='' presence=10 interval=30 max_iter=''
inline='' review='' issuec='' sinfo=''

usage() {
	echo "usage: wait-reviewer.sh --repo O/R --pr N --handle LOGIN [--until ack|finished] [--since ISO] [--presence N] [--interval S] [--max-iter N]" >&2
	exit 2
}

# Decide the verdict from the currently fetched state; prints nothing = keep polling.
# Order is load-bearing: real review content is checked BEFORE any quota phrase, so a
# transient/stale rate-limit notice sitting beside actual comments never masks them.
classify() {
	if [ "$handle" = "snyk" ]; then
		if printf '%s' "$sinfo" | grep -Eqi 'limit reached|^(error|action_required|timed_out|cancelled|stale)'; then
			printf 'QUOTA 999'
			return 0
		fi
		if printf '%s' "$sinfo" | grep -Eqi '^(success|failure|neutral|completed)'; then
			printf 'FINISHED'
			return 0
		fi
		return 0
	fi
	if [ "$mode" = "ack" ]; then
		[ -n "${inline}${review}${issuec}" ] && printf 'ACK'
		return 0
	fi
	if [ -n "$inline" ] || [ -n "$review" ] || printf '%s' "$issuec" | grep -qiE 'actionable comments posted|no actionable comments'; then
		printf 'FINISHED'
		return 0
	fi
	if printf '%s' "$issuec" | grep -Eqi 'run out of usage credits|review limit reached|rate limited by coderabbit|reached your .*review rate limit'; then
		mins=$(printf '%s' "$issuec" | grep -oEi 'available in:.{0,10}[0-9]+ *(minute|hour)' | grep -oE '[0-9]+' | head -1)
		if printf '%s' "$issuec" | grep -oEi 'available in:.{0,10}[0-9]+ *hour' | grep -q .; then
			mins=$(( ${mins:-1} * 60 ))
		fi
		printf 'QUOTA %s' "${mins:-999}"
		return 0
	fi
	if printf '%s' "$issuec" | grep -qi 'review skipped' &&
	   printf '%s' "$issuec" | grep -Eqi 'base branch|base branches|default branch'; then
		printf 'DECLINE'
		return 0
	fi
	if printf '%s' "$issuec" | grep -Eqi 'reviews? paused|paused .*review|review.*paused'; then
		printf 'PAUSE'
		return 0
	fi
	return 0
}

# jq filter for one comment source: substring login match + optional time floor.
jq_filter() {
	# $1 = timestamp field name
	if [ -n "$since" ]; then
		printf '.[] | select((.user.login|ascii_downcase)|test("%s")) | select(.%s > "%s")' "$handle" "$1" "$since"
	else
		printf '.[] | select((.user.login|ascii_downcase)|test("%s"))' "$handle"
	fi
}

fetch_state() {
	inline=$(gh api "repos/$repo/pulls/$pr/comments" --paginate -q "$(jq_filter created_at) | .id" 2>/dev/null)
	review=$(gh api "repos/$repo/pulls/$pr/reviews" --paginate -q "$(jq_filter submitted_at) | (.body // \"x\")" 2>/dev/null)
	issuec=$(gh api "repos/$repo/issues/$pr/comments" --paginate -q "$(jq_filter updated_at) | (.body // \"\")" 2>/dev/null)
	if [ "$handle" = "snyk" ]; then
		sha=$(gh pr view "$pr" --repo "$repo" --json headRefOid -q .headRefOid 2>/dev/null)
		sinfo=$(gh api "repos/$repo/commits/$sha/status" \
			-q '.statuses[] | select((.context|ascii_downcase)|test("snyk")) | "\(.state) \(.description)"' 2>/dev/null)
		sinfo="$sinfo
$(gh api "repos/$repo/commits/$sha/check-runs" --paginate \
			-q '.check_runs[] | select((.name|ascii_downcase)|test("snyk")) | "\(.conclusion // .status) \(.output.title // "")"' 2>/dev/null)"
	fi
}

main() {
	# shellcheck source=scripts/agent/agent_env.sh
	. "$(dirname "$0")/agent_env.sh"
	while [ $# -gt 0 ]; do
		case "$1" in
			--repo) repo=$2; shift 2 ;;
			--pr) pr=$2; shift 2 ;;
			--handle) handle=$(printf '%s' "$2" | tr '[:upper:]' '[:lower:]'); shift 2 ;;
			--until) mode=$2; shift 2 ;;
			--since) since=$2; shift 2 ;;
			--presence) presence=$2; shift 2 ;;
			--interval) interval=$2; shift 2 ;;
			--max-iter) max_iter=$2; shift 2 ;;
			*) usage ;;
		esac
	done
	[ -n "$repo" ] && [ -n "$pr" ] && [ -n "$handle" ] || usage
	case "$mode" in ack|finished) ;; *) usage ;; esac
	require_gh

	if [ -z "$max_iter" ]; then
		if [ "$mode" = "ack" ]; then max_iter=20; else max_iter=60; fi
	fi
	if [ -z "$since" ] && [ "$mode" = "finished" ] && [ "$handle" != "snyk" ]; then
		since=$(gh pr view "$pr" --repo "$repo" --json commits -q '.commits[-1].committedDate' 2>/dev/null)
	fi

	i=0
	seen=0
	while [ "$i" -lt "$max_iter" ]; do
		fetch_state
		[ -n "${inline}${review}${issuec}$(printf '%s' "$sinfo" | tr -dc '[:lower:]')" ] && seen=1
		v=$(classify)
		if [ -n "$v" ]; then
			printf '%s\n' "$issuec" | head -c 3000
			printf '\n%s\n' "$v"
			exit 0
		fi
		if [ "$seen" -eq 0 ] && [ "$presence" -gt 0 ] && [ "$i" -ge "$presence" ]; then
			printf 'NOTPRESENT\n'
			exit 0
		fi
		i=$((i + 1))
		sleep "$interval"
	done
	if [ "$mode" = "ack" ]; then printf 'NOACK\n'; else printf 'TIMEOUT\n'; fi
}

case "${AGENT_SOURCE_ONLY:-0}" in
	1) ;;
	*) main "$@" ;;
esac
