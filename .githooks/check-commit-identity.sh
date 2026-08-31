#!/bin/sh
# Commit identity & signing prerequisite gate (issue #2982): fail-closed check of
# the identity and signing configuration Git would use for THIS commit. The hook
# (.githooks/pre-commit) resolves this file relative to its own $0 so the absolute
# shared core.hooksPath works from linked release worktrees; a missing or
# non-executable checker is a hook-level hard failure. Git's own signing remains
# the cryptographic proof -- this gate only rejects known-bad prerequisites, so a
# `key::ssh-...` literal signing key is left for Git to validate.

set -u

bad() { printf '[check-commit-identity] FAILED: %s\n' "$1" >&2; exit 1; }
cfg() { git config --get "$1" 2>/dev/null; }
have() { command -v "$1" >/dev/null 2>&1; }

# Lowercase + outer-whitespace trim, bound once: generic names and placeholder
# domains are compared case- and whitespace-insensitively (issue #2982).
norm() {
	printf '%s' "$1" \
		| tr -d '[:cntrl:]' \
		| sed 's/^[[:space:]]*//;s/[[:space:]]*$//' \
		| tr '[:upper:]' '[:lower:]'
}

# Effective identity value: the GIT_* override wins when set (even empty, which
# Git itself would reject for a name), otherwise the config key.
ident_val() { # $1=env var name  $2=config key
	_key=$2
	eval "set -- \"\${$1+set}\" \"\${$1-}\""
	if [ "$1" = set ]; then printf '%s' "$2"; else cfg "$_key"; fi
}

check_name() { # $1=role  $2=value
	case $(norm "$2") in
	'') bad "$1 name is missing or empty" ;;
	verifier|root|ci) bad "$1 name is a generic placeholder: '$2'" ;;
	esac
}

check_email() { # $1=role  $2=value
	e=$(norm "$2")
	[ -n "$e" ] || bad "$1 email is missing or empty"
	case $e in
	*@*) ;;
	*) bad "$1 email is malformed (no '@'): '$2'" ;;
	esac
	case ${e##*@} in
	''|example.invalid|example.com|localhost) bad "$1 email domain is a placeholder or empty: '$2'" ;;
	esac
}

check_name author "$(ident_val GIT_AUTHOR_NAME user.name)"
check_email author "$(ident_val GIT_AUTHOR_EMAIL user.email)"
check_name committer "$(ident_val GIT_COMMITTER_NAME user.name)"
check_email committer "$(ident_val GIT_COMMITTER_EMAIL user.email)"

[ "$(git config --get --bool commit.gpgsign 2>/dev/null)" = true ] \
	|| bad 'commit.gpgsign is not enabled (set git config commit.gpgsign true)'
signkey=$(cfg user.signingkey)
[ -n "$signkey" ] || bad 'user.signingkey is not configured'

fmt=$(cfg gpg.format)
case ${fmt:-openpgp} in
ssh)
	prog=$(cfg gpg.ssh.program)
	[ -n "$prog" ] || prog=ssh-keygen
	have "$prog" || bad "SSH signing program not found in PATH: $prog"
	case $signkey in
	key::*) ;;
	*) [ -r "$signkey" ] || bad "SSH signing key not found or unreadable: $signkey" ;;
	esac
	;;
openpgp)
	prog=$(cfg gpg.openpgp.program)
	[ -n "$prog" ] || prog=$(cfg gpg.program)
	[ -n "$prog" ] || prog=gpg
	have "$prog" || bad "OpenPGP signing program not found in PATH: $prog"
	;;
x509)
	prog=$(cfg gpg.x509.program)
	[ -n "$prog" ] || prog=gpgsm
	have "$prog" || bad "X.509 signing program not found in PATH: $prog"
	;;
*) bad "unknown gpg.format: '$fmt' (expected openpgp, x509, or ssh)" ;;
esac
