#!/bin/sh
# install-testing.sh — put this pfSense box on the pfBlockerNG testing channel (issue #2416).
# Published at https://pfblockerng.github.io/pkg/install-testing.sh; run ON the box:
#   fetch -qo - https://pfblockerng.github.io/pkg/install-testing.sh | sh
#
# The testing channel serves prerelease builds ahead of stable — release candidates
# and betas cut from a release branch, published before they are tagged stable.
# Expect occasional regressions; report them.
set -eu
# shellcheck disable=SC2034 # used by install-common.sh, sourced below
PFB_CHANNEL="testing"
# PFB_EMBED_COMMON_BEGIN — do not edit; gen_landing.py replaces this block with install-common.sh at website-build time.
. "$(CDPATH='' cd "$(dirname "$0")" && pwd)/install-common.sh"
# PFB_EMBED_COMMON_END
pfb_channel_install "$@"
