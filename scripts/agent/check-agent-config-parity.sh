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

tiers="$root/.agents/model-tiers.conf"
if [ ! -f "$tiers" ]; then
	echo 'agent-config-parity: missing shared model tier mapping: .agents/model-tiers.conf' >&2
	fail=1
else
	top_claude=''; top_codex=''; top_copilot=''
	mid_claude=''; mid_codex=''; mid_copilot=''
	small_claude=''; small_codex=''; small_copilot=''
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
			tier_current=''
			case "$tier_key" in
			TOP_CLAUDE) tier_current=$top_claude ;;
			TOP_CODEX) tier_current=$top_codex ;;
			MID_CLAUDE) tier_current=$mid_claude ;;
			MID_CODEX) tier_current=$mid_codex ;;
			SMALL_CLAUDE) tier_current=$small_claude ;;
			SMALL_CODEX) tier_current=$small_codex ;;
			TOP_COPILOT) tier_current=$top_copilot ;;
			MID_COPILOT) tier_current=$mid_copilot ;;
			SMALL_COPILOT) tier_current=$small_copilot ;;
			*)
				printf 'agent-config-parity: unknown model tier key: %s\n' \
					"$tier_key" >&2
				fail=1
				continue
				;;
			esac
			if [ -n "$tier_current" ]; then
				printf 'agent-config-parity: duplicate model tier assignment: %s\n' \
					"$tier_key" >&2
				fail=1
				continue
			fi
			case "$tier_key" in
			TOP_CLAUDE) top_claude=$tier_value ;;
			TOP_CODEX) top_codex=$tier_value ;;
			MID_CLAUDE) mid_claude=$tier_value ;;
			MID_CODEX) mid_codex=$tier_value ;;
			SMALL_CLAUDE) small_claude=$tier_value ;;
			SMALL_CODEX) small_codex=$tier_value ;;
			TOP_COPILOT) top_copilot=$tier_value ;;
			MID_COPILOT) mid_copilot=$tier_value ;;
			SMALL_COPILOT) small_copilot=$tier_value ;;
			esac
		;;
		*)
			printf 'agent-config-parity: invalid model tier line: %s\n' \
				"$tier_line" >&2
			fail=1
			;;
		esac
	done < "$tiers"
	for tier_key in TOP_CLAUDE TOP_CODEX TOP_COPILOT MID_CLAUDE MID_CODEX MID_COPILOT \
		SMALL_CLAUDE SMALL_CODEX SMALL_COPILOT; do
		case "$tier_key" in
		TOP_CLAUDE) tier_value=$top_claude ;;
		TOP_CODEX) tier_value=$top_codex ;;
		MID_CLAUDE) tier_value=$mid_claude ;;
		MID_CODEX) tier_value=$mid_codex ;;
		SMALL_CLAUDE) tier_value=$small_claude ;;
		SMALL_CODEX) tier_value=$small_codex ;;
		TOP_COPILOT) tier_value=$top_copilot ;;
		MID_COPILOT) tier_value=$mid_copilot ;;
		SMALL_COPILOT) tier_value=$small_copilot ;;
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
	check_copilot_role_model() {
		role=$1
		expected=$2
		file="$root/.github/agents/$role.agent.md"
		if [ ! -f "$file" ]; then
			printf 'agent-config-parity: missing Copilot agent role: .github/agents/%s.agent.md\n' "$role" >&2
			fail=1
			return
		fi
		actual=$(sed -n 's/^model: *\(.*\)$/\1/p' "$file" | head -n 1)
		if [ -z "$expected" ] || [ "$actual" != "$expected" ]; then
			printf 'agent-config-parity: .github/agents/%s.agent.md model %s, expected %s\n' \
				"$role" "${actual:-<missing>}" "${expected:-<missing-tier-value>}" >&2
			fail=1
		fi
	}
	check_role_model planner "$top_codex"
	check_role_model implementer "$small_codex"
	check_role_model analyst "$small_codex"
	check_role_model analyst-top "$top_codex"
	check_role_model adversarial-reviewer "$small_codex"
	check_role_model adversarial-reviewer-top "$top_codex"
	check_role_model adversarial-reviewer-mid "$mid_codex"
	check_copilot_role_model planner "$top_copilot"
	check_copilot_role_model implementer "$small_copilot"
	check_copilot_role_model analyst "$small_copilot"
	check_copilot_role_model analyst-top "$top_copilot"
	check_copilot_role_model adversarial-reviewer "$small_copilot"
	check_copilot_role_model adversarial-reviewer-top "$top_copilot"
	check_copilot_role_model adversarial-reviewer-mid "$mid_copilot"
fi

# issue #1431: the committed workflow inventory retired; only skills must exist.
if [ "$skills" -eq 0 ]; then
	echo 'agent-config-parity: canonical skill inventory is empty' >&2
	exit 1
fi

[ "$fail" -eq 0 ] || exit 1
printf 'agent-config-parity: %s skills + %s workflows mapped\n' "$skills" "$workflows"
