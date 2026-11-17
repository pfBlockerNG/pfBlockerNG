#!/bin/sh
# Verify that every canonical Claude skill/workflow has a Codex discovery
# adapter which points back to that exact source. Detailed procedures stay in
# one place; this guard catches only discovery/routing drift.

set -u

usage() {
	echo "usage: check-agent-config-parity.sh [--root PATH]" >&2
	exit 2
}

root=''
if [ "${1:-}" = "--root" ]; then
	[ "$#" -eq 2 ] || usage
	root=$2
elif [ "$#" -ne 0 ]; then
	usage
fi

if [ -z "$root" ]; then
	script_dir=$(CDPATH='' cd "$(dirname "$0")" && pwd -P) || exit 2
	root=$(CDPATH='' cd "$script_dir/../.." && pwd -P) || exit 2
else
	root=$(CDPATH='' cd "$root" && pwd -P) || exit 2
fi

fail=0
skills=0
workflows=0

check_adapter() {
	source_rel=$1
	adapter_rel=$2
	name=$3
	kind=$4
	adapter="$root/$adapter_rel"
	source_ref="../../../$source_rel"

	if [ ! -f "$adapter" ]; then
		printf 'agent-config-parity: missing Codex adapter for %s %s: %s\n' \
			"$kind" "$name" "$adapter_rel" >&2
		fail=1
		return
	fi
	if ! grep -Fq "$source_ref" "$adapter"; then
		printf 'agent-config-parity: %s must reference canonical source %s\n' \
			"$adapter_rel" "$source_ref" >&2
		fail=1
	fi
	if [ ! -f "$(dirname "$adapter")/$source_ref" ]; then
		printf 'agent-config-parity: %s source reference does not resolve: %s\n' \
			"$adapter_rel" "$source_ref" >&2
		fail=1
	fi
	adapter_name=$(sed -n 's/^name:[[:space:]]*//p' "$adapter" | head -n 1)
	if [ "$adapter_name" != "$name" ]; then
		printf 'agent-config-parity: %s declares name %s, expected %s\n' \
			"$adapter_rel" "${adapter_name:-<missing>}" "$name" >&2
		fail=1
	fi
}

for source_dir in "$root"/.claude/skills/*/; do
	name=$(basename "${source_dir%/}")
	link_path="$root/.claude/skills/$name"

	if [ -L "$link_path" ]; then
		# Vendor-agnostic skill: .claude/skills/$name is a symlink onto
		# canonical .agents/skills/$name (or vice versa mid-migration).
		# Filesystem identity IS the parity guarantee here — no textual
		# back-reference to check, just that the link resolves.
		resolved=$(CDPATH='' cd "$link_path" 2>/dev/null && pwd -P) || resolved=''
		canonical=$(CDPATH='' cd "$root/.agents/skills/$name" 2>/dev/null && pwd -P) || canonical=''
		if [ -z "$resolved" ] || [ -z "$canonical" ] || [ "$resolved" != "$canonical" ]; then
			printf 'agent-config-parity: .claude/skills/%s is a symlink but does not resolve to canonical .agents/skills/%s\n' \
				"$name" "$name" >&2
			fail=1
		fi
		skills=$((skills + 1))
		continue
	fi

	source="$source_dir/SKILL.md"
	[ -f "$source" ] || continue
	source_rel=".claude/skills/$name/SKILL.md"
	check_adapter "$source_rel" ".agents/skills/$name/SKILL.md" "$name" skill
	skills=$((skills + 1))
done

for source in "$root"/.claude/workflows/*.js; do
	[ -f "$source" ] || continue
	name=$(basename "$source" .js)
	source_rel=".claude/workflows/$name.js"
	check_adapter "$source_rel" ".agents/skills/$name/SKILL.md" "$name" workflow
	workflows=$((workflows + 1))
done

# Forward-only parity misses the inverse drift: a canonical source can be
# deleted or renamed while its old discovery adapter remains visible to Codex.
for adapter in "$root"/.agents/skills/*/SKILL.md; do
	[ -f "$adapter" ] || continue
	name=$(basename "$(dirname "$adapter")")
	source_count=0
	[ ! -f "$root/.claude/skills/$name/SKILL.md" ] || source_count=$((source_count + 1))
	[ ! -f "$root/.claude/workflows/$name.js" ] || source_count=$((source_count + 1))
	if [ "$source_count" -eq 0 ]; then
		printf 'agent-config-parity: stale Codex adapter has no canonical source: %s\n' \
			".agents/skills/$name/SKILL.md" >&2
		fail=1
	elif [ "$source_count" -ne 1 ]; then
		printf 'agent-config-parity: Codex adapter maps ambiguously to skill and workflow: %s\n' \
			".agents/skills/$name/SKILL.md" >&2
		fail=1
	fi
done

# issue #1431: the committed workflow inventory retired; only skills must exist.
if [ "$skills" -eq 0 ]; then
	echo 'agent-config-parity: canonical skill inventory is empty' >&2
	exit 1
fi

[ "$fail" -eq 0 ] || exit 1
printf 'agent-config-parity: %s skills + %s workflows mapped\n' "$skills" "$workflows"
