#!/bin/sh
# git-no-docs.sh — run a read-only git command with the documentation trees
# excluded from its pathspec, so doc-heavy commits show only their code lines.
#
# Local companion to the linguist-documentation entries in .gitattributes:
# on GitHub that attribute only removes the trees from language stats (it
# never suppresses diffs), so this script provides the diff-side half for
# local history views. The excluded patterns are read from .gitattributes
# itself — single source of truth; add a tree there and this picks it up.
#
# Parsing is deliberately minimal (see tests/shell/git_no_docs_spec.sh):
# each line is matched independently, so git's "last matching line wins"
# attribute resolution is NOT honored — a later overriding line for the
# same path (e.g. `docs/** -linguist-documentation`) will not undo an
# earlier match. Quoted (space-containing) patterns that carry
# linguist-documentation are refused loudly; [attr] macro lines are skipped.
#
# Usage: scripts/git-no-docs.sh [read-only git command and args]  (default: log -p)
#   scripts/git-no-docs.sh                     # git log -p without doc lines
#   scripts/git-no-docs.sh log --stat devel..
#   scripts/git-no-docs.sh show HEAD
#
# git refuses to combine any pathspec with `log -L` or `diff --no-index`,
# so those two forms fail loudly here — unsupported.
set -eu

root=$(git rev-parse --show-toplevel)

[ "$#" -gt 0 ] || set -- log -p

# An exclude appended to a state-mutating command would silently change what
# git RECORDS (`git add -A -- ':(exclude)docs/**'` really does skip the doc
# trees) — this tool must only ever affect the view.
case "$1" in
	log | show | diff | grep | blame | shortlog) ;;
	*)
		echo "git-no-docs.sh: read-only git commands only (log, show, diff, grep, blame, shortlog); got '$1'" >&2
		exit 1
		;;
esac

set -- "$@" --

cr=$(printf '\r')

# Append one ':(top,glob,exclude)<pattern>' pathspec per
# linguist-documentation entry (bare or =true form; a pattern may carry
# several attributes). 'top' anchors the pattern at the repo root so a
# subdirectory cwd works; 'glob' pins wildmatch semantics regardless of
# ambient GIT_NOGLOB_PATHSPECS/--noglob-pathspecs; '|| [ -n ... ]' keeps a
# final line that lacks a trailing newline.
found=0
while read -r pattern attrs || [ -n "${pattern:-}" ]; do
	pattern=${pattern%"${cr}"}
	attrs=${attrs%"${cr}"}
	case "${pattern}" in
	'' | \#*) continue ;;
	\[attr\]*) continue ;; # macro definition, not a path pattern
	\"*)
		# C-quoted pattern: `read` mis-splits it into a dead exclude. Refuse
		# loudly when it affects documentation; skip when it cannot.
		case "${attrs}" in
		*linguist-documentation*)
			echo "git-no-docs.sh: quoted pattern unsupported: ${pattern} ${attrs}" >&2
			exit 1
			;;
		*) continue ;;
		esac
		;;
	esac
	case " ${attrs} " in
	*' linguist-documentation '* | *' linguist-documentation=true '*) ;;
	*) continue ;;
	esac
	# Strip a leading slash: 'top' already anchors at the repo root, and
	# ':(top)' composed with '/pattern' silently matches nothing.
	set -- "$@" ":(top,glob,exclude)${pattern#/}"
	found=1
done < "${root}/.gitattributes"

# Fail loudly rather than silently degrade into an unfiltered git command.
if [ "${found}" -eq 0 ]; then
	echo "git-no-docs.sh: no linguist-documentation patterns in ${root}/.gitattributes" >&2
	exit 1
fi

exec git "$@"
