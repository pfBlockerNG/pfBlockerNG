#!/bin/sh
# ci-vendor.sh -- materialise the Composer vendor tree from the copy baked into the
# ci-runner image (issue #2502).
#
# CI legs used to run `composer install` per job, which resolved 27 dev packages from
# api.github.com every run; the 2026-08-17 GitHub API incident turned three PHP gates red
# on a pull request that touched no PHP. The tree is baked into the image instead, and
# this is the one path every leg uses to get it.
#
# The tree is COPIED, not symlinked: composer's generated autoloader derives $baseDir
# from its own real path, so a symlinked vendor/ would resolve autoload-dev's
# PfBlockerNG\PHPStan\ => tests/phpstan/ mapping outside the checkout (which is why
# check_composer_vendor.py rejects a symlinked vendor outright).
#
# The baked tree is pinned to the composer.lock the image was built from. If the
# checkout's lock has moved past it, that is a stale image, not a stale checkout, and the
# leg fails here naming the fix rather than analysing against the wrong tool versions.
#
# Usage: ci-vendor.sh          (PFB_BAKED_VENDOR overrides the baked location)

set -eu

baked=${PFB_BAKED_VENDOR:-/opt/pfb-composer/vendor}
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)

if [ ! -d "$baked" ]; then
	echo "ci-vendor.sh: no baked Composer tree at ${baked}" >&2
	echo "ci-vendor.sh: this script runs inside ci-runner, which bakes it (.github/docker/ci-runner.Dockerfile)" >&2
	exit 1
fi

# cp -R, never cp -a: the baked tree is root-owned and the legs run as uid 1001, so
# preserving ownership would fail for every file.
rm -rf "${root}/vendor"
cp -R "$baked" "${root}/vendor"
echo "ci-vendor.sh: vendor/ materialised from ${baked}"

if ! python3 "${root}/scripts/check_composer_vendor.py" "$root" >&2; then
	echo "ci-vendor.sh: composer.lock does not match the tree baked into this image." >&2
	echo "ci-vendor.sh: bump .github/docker/VERSION and publish a new image, then repin the workflows." >&2
	exit 1
fi
