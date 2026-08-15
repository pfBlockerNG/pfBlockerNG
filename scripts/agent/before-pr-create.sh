#!/bin/sh
# Run immediately before `gh pr create`. Prints the CodeRabbit limit picture.
# Exit 0 = opening a ready PR is affordable. Exit 3 = wait (do not create
# unless the owner overrode in this conversation). Exit 2 = usage / tool error.
# Exit 3 is also used with --json: the JSON is written to stdout; treat 3 as
# advice, not a crashed command.
#
# Usage: before-pr-create.sh [--repo OWNER/REPO] [--json]

set -u

repo=${GITHUB_REPOSITORY:-}
as_json=0
while [ $# -gt 0 ]; do
	case "$1" in
		--repo)
			[ $# -ge 2 ] || {
				echo "usage: before-pr-create.sh [--repo OWNER/REPO] [--json]" >&2
				exit 2
			}
			repo=$2
			shift 2
			;;
		--json) as_json=1; shift ;;
		*)
			echo "usage: before-pr-create.sh [--repo OWNER/REPO] [--json]" >&2
			exit 2
			;;
	esac
done

if [ -z "$repo" ]; then
	repo=$(gh repo view --json nameWithOwner --jq .nameWithOwner) || exit 2
fi

script_dir=$(CDPATH='' cd "$(dirname "$0")" && pwd -P) || exit 2
py=python3
command -v python3.11 >/dev/null 2>&1 && py=python3.11

if [ "$as_json" -eq 1 ]; then
	exec "$py" "$script_dir/coderabbit_limit.py" status --repo "$repo" --json
fi
exec "$py" "$script_dir/coderabbit_limit.py" status --repo "$repo"
