#!/bin/sh
# setup-dev-shell.sh — OPTIONAL, macOS-only contributor convenience.
#
# Makes Homebrew CLIs (node/npx for markdownlint, php, shellcheck, …) resolve in EVERY
# shell — including the non-login sub-shells that tooling/editors spawn, where ~/.zprofile
# (which runs `brew shellenv`) is NOT sourced. Also upgrades an old interactive/login
# bash (Apple's /bin/bash 3.2) to Homebrew's bash 5.x.
#
# NOTE: the pre-commit hook ALREADY self-bootstraps Homebrew on PATH, so you do NOT need
# this for the hook to work — it only improves your interactive/manual shell ergonomics
# (e.g. running `npx markdownlint-cli2` by hand). Safe to re-run: each file gets a single
# managed block, skipped if already present.
#
# What it changes in your HOME:
#   ~/.brew_path.sh   (created)  shared PATH-prepend snippet (also exports BASH_ENV/ENV)
#   ~/.zshenv         (block)    source the snippet for every zsh
#   ~/.profile        (block)    source the snippet for login sh
#   ~/.bashrc         (block)    bash<4 -> Homebrew re-exec + source the snippet
#   ~/.bash_profile   (block)    bash<4 -> Homebrew re-exec + source the snippet
# It does NOT touch /etc/shells or your login shell (it only prints the optional sudo
# commands for those).

set -u

MARK_BEGIN='# >>> pfBlockerNG dev shell (managed) >>>'
MARK_END='# <<< pfBlockerNG dev shell (managed) <<<'

log() { printf '%s\n' "$*"; }

# macOS only — the login-only brew PATH and ancient /bin/bash are macOS problems.
if [ "$(uname -s)" != Darwin ]; then
	log "Not macOS ($(uname -s)) — nothing to do (brew tools are normally already on PATH)."
	exit 0
fi

# Locate Homebrew (Apple Silicon first, then Intel).
brew_bin=''
for p in /opt/homebrew/bin/brew /usr/local/bin/brew; do
	if [ -x "$p" ]; then brew_bin=$p; break; fi
done
if [ -z "$brew_bin" ]; then
	log "Homebrew not found under /opt/homebrew or /usr/local. Install it first: https://brew.sh"
	exit 1
fi
log "Homebrew: $brew_bin"

# 1) The shared PATH snippet (overwritten — it is fully managed by this script).
snippet="$HOME/.brew_path.sh"
cat > "$snippet" <<'SNIPPET'
# Shared Homebrew PATH bootstrap — POSIX-sh compatible (works in sh, bash, zsh).
# Managed by pfBlockerNG scripts/setup-dev-shell.sh. Puts Homebrew bin/sbin on PATH so
# CLIs like node/npx resolve even in a non-login shell spawned by tooling. Idempotent +
# deduped + subprocess-free; a no-op unless Homebrew is installed.
for _bp in /opt/homebrew /usr/local; do
	if [ -x "$_bp/bin/brew" ]; then
		case ":$PATH:" in
			*":$_bp/bin:"*) ;;
			*) PATH="$_bp/bin:$_bp/sbin:$PATH"; export PATH ;;
		esac
		break
	fi
done
unset _bp

# Non-interactive bash sources $BASH_ENV; interactive sh sources $ENV. (`sh -c` reads
# nothing — it inherits the PATH set above.) This propagates the fix to child shells.
export BASH_ENV="$HOME/.brew_path.sh"
export ENV="$HOME/.brew_path.sh"
SNIPPET
log "wrote $snippet"

# Append a managed block (read from stdin) to a file unless one is already present.
# Reading from stdin avoids a here-doc inside $(...), which Apple's bash 3.2 mishandles.
ensure_block() {
	_file=$1
	if [ -f "$_file" ] && grep -qF "$MARK_BEGIN" "$_file" 2>/dev/null; then
		log "  $_file: managed block present — skipped"
		return 0
	fi
	if [ -s "$_file" ]; then printf '\n' >> "$_file"; fi
	{
		printf '%s\n' "$MARK_BEGIN"
		cat
		printf '%s\n' "$MARK_END"
	} >> "$_file"
	log "  $_file: managed block added"
}

log "wiring shell init files:"

# zsh (every invocation) + login sh: just source the snippet.
printf '%s\n' '[ -r "$HOME/.brew_path.sh" ] && . "$HOME/.brew_path.sh"' | ensure_block "$HOME/.zshenv"
printf '%s\n' '[ -r "$HOME/.brew_path.sh" ] && . "$HOME/.brew_path.sh"' | ensure_block "$HOME/.profile"

# bash: re-exec an old interactive/login bash to Homebrew's, then source the snippet.
# Build the block in a temp file so it can be fed to ensure_block twice without a
# here-doc inside $(...).
bash_block_file=$(mktemp)
cat > "$bash_block_file" <<'BASHBLOCK'
# Upgrade a REAL interactive/login bash <4 (e.g. Apple's /bin/bash 3.2) to Homebrew's,
# preserving login/interactive flags. Skips -c/script invocations (never drops a command
# or hijacks a script) and is guarded against re-exec loops.
if [ -z "${BASH_UPGRADED:-}" ] && [ "${BASH_VERSINFO:-0}" -lt 4 ] && [ -z "${BASH_EXECUTION_STRING:-}" ]; then
	for _bh in /opt/homebrew/bin/bash /usr/local/bin/bash; do
		[ -x "$_bh" ] || continue
		_login=0; shopt -q login_shell && _login=1
		case $- in *i*) _int=1 ;; *) _int=0 ;; esac
		if [ "$_int" = 1 ] || [ "$_login" = 1 ]; then
			export BASH_UPGRADED=1; _a=''
			[ "$_login" = 1 ] && _a="$_a -l"
			[ "$_int" = 1 ] && _a="$_a -i"
			exec "$_bh" $_a
		fi
		break
	done
	unset _bh _login _int _a
fi
[ -r "$HOME/.brew_path.sh" ] && . "$HOME/.brew_path.sh"
BASHBLOCK
ensure_block "$HOME/.bashrc"       < "$bash_block_file"
ensure_block "$HOME/.bash_profile" < "$bash_block_file"
rm -f "$bash_block_file"

# Optional, manual (needs sudo): register + adopt Homebrew bash as a login shell.
brew_bash="${brew_bin%/brew}/bash"
if [ -x "$brew_bash" ] && ! grep -qxF "$brew_bash" /etc/shells 2>/dev/null; then
	log ""
	log "Optional — register Homebrew bash as a sanctioned login shell (needs sudo):"
	log "  echo $brew_bash | sudo tee -a /etc/shells"
	log "  # then, only if you want bash (not zsh) as your login shell: chsh -s $brew_bash"
fi

log ""
log "Done. Open a new terminal, or run:  . ~/.brew_path.sh"
