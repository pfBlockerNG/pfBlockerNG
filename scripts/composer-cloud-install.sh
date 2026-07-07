#!/bin/sh
# composer-cloud-install.sh — composer install with fallbacks for egress-restricted
# managed cloud sessions (issue #950).
#
# In Anthropic managed cloud sessions, GitHub REST endpoints (api.github.com,
# codeload.github.com) are repo-scoped: any third-party repo returns 403, so every
# composer dist (zipball) download fails with "Could not authenticate against
# github.com". Plain git clone/fetch of public GitHub repos still works. The one
# package that cannot ride `--prefer-source` is phpstan/phpstan: it is dist-only in
# composer.lock (the phar distribution repo carries no source entry), and a full
# mirror clone of it times out (phar blobs across the whole history).
#
# Recipe (validated in issue #950):
#   1. Plain `composer install`; on success, done — no fallback needed.
#   2. Strip phpstan/phpstan from composer.json + composer.lock (composer
#      hard-errors on a json/lock mismatch, so both), then
#      `composer install --prefer-source` (git transport), then restore both files.
#   3. Shallow-fetch phpstan at the lock's pinned dist reference (single commit,
#      fast), place it under vendor/phpstan/phpstan, symlink vendor/bin/phpstan.
#
# ponytail: phpstan/phpstan is the only dist-only package in today's lock;
# generalize the strip/fetch to a package list if another one ever appears.
set -eu

REPO_ROOT="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"

# Echo phpstan/phpstan's pinned dist reference from a composer.lock ($1).
phpstan_ref_from_lock() {
	# shellcheck disable=SC2016  # the $-signs are PHP variables, not shell expansions
	php -r '
		$l = json_decode(file_get_contents($argv[1]), true);
		foreach (array_merge($l["packages"] ?? [], $l["packages-dev"] ?? []) as $p) {
			if ($p["name"] === "phpstan/phpstan") {
				echo $p["dist"]["reference"] ?? "";
				exit;
			}
		}
	' "$1"
}

# Remove phpstan/phpstan from a composer.json ($1) and composer.lock ($2), in place.
strip_phpstan() {
	# shellcheck disable=SC2016  # the $-signs are PHP variables, not shell expansions
	php -r '
		$j = json_decode(file_get_contents($argv[1]), true);
		unset($j["require-dev"]["phpstan/phpstan"]);
		file_put_contents($argv[1], json_encode($j, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");
		$l = json_decode(file_get_contents($argv[2]), true);
		foreach (["packages", "packages-dev"] as $k) {
			$l[$k] = array_values(array_filter($l[$k] ?? [], fn ($p) => $p["name"] !== "phpstan/phpstan"));
		}
		file_put_contents($argv[2], json_encode($l, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");
	' "$1" "$2"
}

main() {
	cd "$REPO_ROOT"
	# Composer refuses plugins as root without this; harmless as non-root.
	export COMPOSER_ALLOW_SUPERUSER=1

	if composer install --no-interaction; then
		exit 0
	fi

	echo "composer-cloud-install: plain install failed -- applying the cloud egress fallback (issue #950)" >&2

	# The fallback mutates composer.json/lock and restores them via git checkout;
	# refuse to run over uncommitted user edits it would clobber.
	if ! git diff --quiet -- composer.json composer.lock; then
		echo "composer-cloud-install: composer.json/composer.lock have uncommitted changes; commit or stash them first" >&2
		exit 1
	fi

	ref="$(phpstan_ref_from_lock composer.lock)"
	if [ -z "$ref" ]; then
		echo "composer-cloud-install: no phpstan/phpstan dist reference in composer.lock" >&2
		exit 1
	fi

	trap 'git -C "$REPO_ROOT" checkout -- composer.json composer.lock' EXIT
	strip_phpstan composer.json composer.lock
	composer install --no-interaction --prefer-source
	git checkout -- composer.json composer.lock
	trap - EXIT

	staging="$(mktemp -d)"
	git init -q "$staging"
	git -C "$staging" fetch -q --depth 1 https://github.com/phpstan/phpstan.git "$ref"
	git -C "$staging" checkout -q FETCH_HEAD
	rm -rf "$staging/.git" vendor/phpstan/phpstan
	mkdir -p vendor/phpstan
	mv "$staging" vendor/phpstan/phpstan
	ln -sf ../phpstan/phpstan/phpstan vendor/bin/phpstan

	echo "composer-cloud-install: fallback complete" >&2
	vendor/bin/phpstan --version
}

# Run only when executed, not when sourced by the shellspec suite.
case "${0##*/}" in
	composer-cloud-install.sh) main "$@" ;;
esac
