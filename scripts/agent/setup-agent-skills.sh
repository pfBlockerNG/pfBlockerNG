#!/bin/sh
# Add or refresh curated third-party skills without replacing differently sourced names.

set -eu

command -v npx >/dev/null 2>&1 || {
	printf '%s\n' 'setup-agent-skills.sh: npx is required' >&2
	exit 1
}

skill_root=${AGENT_SKILLS_HOME:-"${HOME}/.agents"}
skill_lock="$skill_root/.skill-lock.json"

preflight_source() {
	source=$1
	shift
	node -e '
const fs = require("node:fs");
const path = require("node:path");
const [root, lockPath, source, ...skills] = process.argv.slice(1);
const home = process.env.HOME;
const agentRoots = [
	path.join(process.env.CLAUDE_CONFIG_DIR || path.join(home, ".claude"), "skills"),
	path.join(process.env.GROK_HOME || path.join(home, ".grok"), "skills"),
	path.join(home, ".pi", "agent", "skills"),
];
let lock = { skills: {} };
try {
	lock = JSON.parse(fs.readFileSync(lockPath, "utf8"));
} catch (error) {
	if (error.code !== "ENOENT") throw error;
}
const exists = (candidate) => {
	try {
		fs.lstatSync(candidate);
		return true;
	} catch (error) {
		if (error.code === "ENOENT") return false;
		throw error;
	}
};
const sameTree = (left, right) => {
	const leftStat = fs.lstatSync(left);
	const rightStat = fs.lstatSync(right);
	if (leftStat.isSymbolicLink() || rightStat.isSymbolicLink()) {
		return leftStat.isSymbolicLink() && rightStat.isSymbolicLink()
			&& fs.readlinkSync(left) === fs.readlinkSync(right);
	}
	if (leftStat.isDirectory() || rightStat.isDirectory()) {
		if (!leftStat.isDirectory() || !rightStat.isDirectory()) return false;
		const leftNames = fs.readdirSync(left).sort();
		const rightNames = fs.readdirSync(right).sort();
		return leftNames.length === rightNames.length
			&& leftNames.every((name, index) =>
				name === rightNames[index] && sameTree(path.join(left, name), path.join(right, name)),
			);
	}
	return leftStat.isFile() && rightStat.isFile()
		&& fs.readFileSync(left).equals(fs.readFileSync(right));
};
const refuse = (skill) => {
	console.error(
		"setup-agent-skills.sh: refusing to overwrite " + skill + "; existing skill is not managed from " + source,
	);
	process.exitCode = 1;
};
for (const skill of skills) {
	const canonical = path.join(root, "skills", skill);
	const canonicalExists = exists(canonical);
	if (canonicalExists && lock.skills?.[skill]?.source !== source) {
		refuse(skill);
		continue;
	}
	for (const agentRoot of agentRoots) {
		const target = path.join(agentRoot, skill);
		if (!exists(target)) continue;
		try {
			if (canonicalExists && (
				fs.realpathSync(target) === fs.realpathSync(canonical) || sameTree(target, canonical)
			)) continue;
		} catch {}
		refuse(skill);
	}
}
' "$skill_root" "$skill_lock" "$source" "$@"
}

install_source() {
	source=$1
	shift
	if output=$(npx --yes skills add "$source" --global \
		--agent claude-code codex github-copilot grok pi --yes \
		--skill "$@" 2>&1)
	then
		:
	else
		status=$?
		if [ -n "$output" ]; then
			printf '%s\n' "$output" >&2
		fi
		return "$status"
	fi
	case $output in
		*'Failed to install '*)
			printf '%s\n' "$output" >&2
			printf '%s\n' 'setup-agent-skills.sh: skills reported an installation failure' >&2
			return 1
			;;
	esac
	if [ -n "$output" ]; then
		printf '%s\n' "$output"
	fi
}

addy_skills() {
	"$1" addyosmani/agent-skills \
		api-and-interface-design \
		ci-cd-and-automation \
		code-review-and-quality \
		code-simplification \
		constraint-driven-development \
		context-engineering \
		debugging-and-error-recovery \
		deprecation-and-migration \
		doubt-driven-development \
		git-workflow-and-versioning \
		idea-refine \
		incremental-implementation \
		observability-and-instrumentation \
		performance-optimization \
		planning-and-task-breakdown \
		security-and-hardening \
		shipping-and-launch \
		source-driven-development \
		spec-driven-development \
		test-driven-development \
		using-agent-skills
}

matt_skills() {
	"$1" mattpocock/skills \
		code-review \
		codebase-design \
		diagnosing-bugs \
		domain-modeling \
		grill-me \
		grill-with-docs \
		handoff \
		implement \
		improve-codebase-architecture \
		prototype \
		research \
		resolving-merge-conflicts \
		tdd \
		teach \
		to-spec \
		to-tickets \
		triage \
		wait-what \
		wayfinder \
		writing-for-agents
}

caveman_skills() {
	"$1" JuliusBrussee/caveman \
		cavecrew \
		caveman \
		caveman-commit \
		caveman-compress \
		caveman-explore \
		caveman-review \
		investigate-first \
		migration \
		surgical-patch \
		verify-and-stop
}

ponytail_skills() {
	"$1" DietrichGebert/ponytail \
		ponytail \
		ponytail-audit \
		ponytail-review
}

addy_skills preflight_source
matt_skills preflight_source
caveman_skills preflight_source
ponytail_skills preflight_source

addy_skills install_source
matt_skills install_source
caveman_skills install_source
ponytail_skills install_source
