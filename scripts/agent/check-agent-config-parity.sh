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

for source in "$root"/.claude/skills/*/SKILL.md; do
	[ -f "$source" ] || continue
	name=$(basename "$(dirname "$source")")
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

tiers="$root/.agents/model-tiers.conf"
if [ ! -f "$tiers" ]; then
	echo 'agent-config-parity: missing shared model tier mapping: .agents/model-tiers.conf' >&2
	fail=1
else
	high_claude=''; high_codex=''; medium_claude=''; medium_codex=''
	low_claude=''; low_codex=''
	while IFS= read -r tier_line || [ -n "$tier_line" ]; do
		case "$tier_line" in
		''|'#'*) continue ;;
		*=*)
			tier_key=${tier_line%%=*}
			tier_value=${tier_line#*=}
			case "$tier_value" in
			''|*[!A-Za-z0-9._/-]*)
				printf 'agent-config-parity: invalid model tier assignment: %s\n' \
					"$tier_line" >&2
				fail=1
				continue
				;;
			esac
			case "$tier_key" in
			HIGH_CLAUDE) [ -z "$high_claude" ] || fail=1; high_claude=$tier_value ;;
			HIGH_CODEX) [ -z "$high_codex" ] || fail=1; high_codex=$tier_value ;;
			MEDIUM_CLAUDE) [ -z "$medium_claude" ] || fail=1; medium_claude=$tier_value ;;
			MEDIUM_CODEX) [ -z "$medium_codex" ] || fail=1; medium_codex=$tier_value ;;
			LOW_CLAUDE) [ -z "$low_claude" ] || fail=1; low_claude=$tier_value ;;
			LOW_CODEX) [ -z "$low_codex" ] || fail=1; low_codex=$tier_value ;;
			*)
				printf 'agent-config-parity: unknown model tier key: %s\n' \
					"$tier_key" >&2
				fail=1
				;;
			esac
		;;
		*)
			printf 'agent-config-parity: invalid model tier line: %s\n' \
				"$tier_line" >&2
			fail=1
			;;
		esac
	done < "$tiers"
	for tier_key in HIGH_CLAUDE HIGH_CODEX MEDIUM_CLAUDE MEDIUM_CODEX LOW_CLAUDE LOW_CODEX; do
		case "$tier_key" in
		HIGH_CLAUDE) tier_value=$high_claude ;;
		HIGH_CODEX) tier_value=$high_codex ;;
		MEDIUM_CLAUDE) tier_value=$medium_claude ;;
		MEDIUM_CODEX) tier_value=$medium_codex ;;
		LOW_CLAUDE) tier_value=$low_claude ;;
		LOW_CODEX) tier_value=$low_codex ;;
		esac
		if [ -z "$tier_value" ]; then
			printf 'agent-config-parity: missing model tier assignment: %s\n' \
				"$tier_key" >&2
			fail=1
		fi
	done
	check_role_model() {
		role=$1
		expected=$2
		file="$root/.codex/agents/$role.toml"
		if [ ! -f "$file" ]; then
			printf 'agent-config-parity: missing Codex agent role: .codex/agents/%s.toml\n' "$role" >&2
			fail=1
			return
		fi
		actual=$(sed -n 's/^model = "\([^"]*\)"$/\1/p' "$file" | head -n 1)
		if [ -z "$expected" ] || [ "$actual" != "$expected" ]; then
			printf 'agent-config-parity: .codex/agents/%s.toml model %s, expected %s\n' \
				"$role" "${actual:-<missing>}" "${expected:-<missing-tier-value>}" >&2
			fail=1
		fi
	}
	check_role_model planner "$high_codex"
	check_role_model implementer "$low_codex"
	check_role_model adversarial-reviewer "$low_codex"
	check_role_model adversarial-reviewer-high "$high_codex"
	check_role_model adversarial-reviewer-medium "$medium_codex"
fi

if [ "$skills" -eq 0 ] || [ "$workflows" -eq 0 ]; then
	echo 'agent-config-parity: canonical skill/workflow inventory is empty' >&2
	exit 1
fi

[ "$fail" -eq 0 ] || exit 1
printf 'agent-config-parity: %s skills + %s workflows mapped\n' "$skills" "$workflows"
