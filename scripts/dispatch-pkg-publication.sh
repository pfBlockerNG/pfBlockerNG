#!/bin/sh
# Dispatch one exact immutable publication operation to pfBlockerNG/pkg and
# retrieve its correlated result artifact. This script never receives a pkg
# Contents credential; GH_TOKEN is narrowed to Actions:write by every caller.

set -eu

: "${GH_TOKEN:?GH_TOKEN is required}"
: "${PKG_OPERATION:?PKG_OPERATION is required}"
: "${SOURCE_RUN_ID:?SOURCE_RUN_ID is required}"
: "${RESULT_FILE:?RESULT_FILE is required}"

PKG_REPOSITORY="${PKG_REPOSITORY:-pfBlockerNG/pkg}"
PKG_WORKFLOW="${PKG_WORKFLOW:-ingest.yml}"
MAX_DISPATCH_ATTEMPTS="${MAX_DISPATCH_ATTEMPTS:-3}"
MAX_RUN_LOOKUPS="${MAX_RUN_LOOKUPS:-60}"

case "$MAX_DISPATCH_ATTEMPTS:$MAX_RUN_LOOKUPS" in
	*[!0-9:]*) echo "::error::dispatch bounds must be positive integers" >&2; exit 1 ;;
esac
[ "$MAX_DISPATCH_ATTEMPTS" -ge 1 ] && [ "$MAX_RUN_LOOKUPS" -ge 1 ] || {
	echo "::error::dispatch bounds must be positive integers" >&2
	exit 1
}

started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
attempt=1
while [ "$attempt" -le "$MAX_DISPATCH_ATTEMPTS" ]; do
	if gh workflow run "$PKG_WORKFLOW" -R "$PKG_REPOSITORY" --ref main \
		-f "operation=$PKG_OPERATION" \
		-f "source_repository=${SOURCE_REPOSITORY:-}" \
		-f "release_id=${RELEASE_ID:-}" \
		-f "release_tag=${RELEASE_TAG:-}" \
		-f "source_sha=${SOURCE_SHA:-}" \
		-f "destinations=${DESTINATIONS:-}" \
		-f "source_run_id=$SOURCE_RUN_ID" \
		-f "artifact_ref=${ARTIFACT_REF:-}" \
		-f "nightly_version=${NIGHTLY_VERSION:-}" \
		-f "staging_prefix=${STAGING_PREFIX:-}"
	then
		break
	fi
	[ "$attempt" -lt "$MAX_DISPATCH_ATTEMPTS" ] || {
		echo "::error::pkg workflow dispatch failed after ${attempt} attempts" >&2
		exit 1
	}
	attempt=$((attempt + 1))
	sleep 2
done

expected_title="Ingest ${PKG_OPERATION} ${SOURCE_RUN_ID}"
lookup=1
run_id=""
while [ "$lookup" -le "$MAX_RUN_LOOKUPS" ]; do
	runs=$(gh run list -R "$PKG_REPOSITORY" --workflow "$PKG_WORKFLOW" \
		--event workflow_dispatch --limit 50 --json databaseId,displayTitle,createdAt)
	run_id=$(printf '%s' "$runs" | jq -r --arg title "$expected_title" --arg started "$started_at" \
		'[.[] | select(.displayTitle == $title and .createdAt >= $started)] | sort_by(.createdAt) | last | .databaseId // empty')
	[ -z "$run_id" ] || break
	lookup=$((lookup + 1))
	sleep 5
done
[ -n "$run_id" ] || {
	echo "::error::could not correlate pkg run titled ${expected_title}" >&2
	exit 1
}

gh run watch "$run_id" -R "$PKG_REPOSITORY" --exit-status
result_dir=$(mktemp -d)
trap 'rm -rf "$result_dir"' EXIT
gh run download "$run_id" -R "$PKG_REPOSITORY" --name publication-result --dir "$result_dir"
result_path="$result_dir/result.json"
[ -f "$result_path" ] || { echo "::error::pkg run returned no publication result" >&2; exit 1; }
[ "$(jq -r '.operation' "$result_path")" = "$PKG_OPERATION" ] || {
	echo "::error::pkg result operation mismatch" >&2; exit 1; }
[ "$(jq -r '.source_run_id' "$result_path")" = "$SOURCE_RUN_ID" ] || {
	echo "::error::pkg result source_run_id mismatch" >&2; exit 1; }
mkdir -p "$(dirname "$RESULT_FILE")"
cp "$result_path" "$RESULT_FILE"
