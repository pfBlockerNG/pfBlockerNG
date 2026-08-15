#!/bin/sh
# install-edge.sh — put this pfSense box on the pfBlockerNG edge channel (issue #2416).
# Published at https://pfblockerng.github.io/pkg/install-edge.sh; run ON the box:
#   fetch -qo - https://pfblockerng.github.io/pkg/install-edge.sh | sh
#
# The edge channel serves prerelease builds cut more frequently than testing — still
# release-branch work, published earliest. Expect more churn than testing.
set -eu
# shellcheck disable=SC2034 # used by install-common.sh, sourced below
PFB_CHANNEL="edge"
# PFB_EMBED_COMMON_BEGIN — do not edit; gen_landing.py replaces this block with install-common.sh at website-build time.
. "$(CDPATH='' cd "$(dirname "$0")" && pwd)/install-common.sh"
# PFB_EMBED_COMMON_END
pfb_channel_install "$@"
