#!/bin/sh
# install-stable.sh — put this pfSense box on the pfBlockerNG stable channel (issue #2416).
# Published at https://pfblockerng.github.io/pkg/install-stable.sh; run ON the box:
#   fetch -qo - https://pfblockerng.github.io/pkg/install-stable.sh | sh
#
# The stable channel serves final tagged releases only — the same builds users get
# from the pfSense package manager, just without waiting for a Netgate sync. Safe
# for daily use.
set -eu
# shellcheck disable=SC2034 # used by install-common.sh, sourced below
PFB_CHANNEL="stable"
# PFB_EMBED_COMMON_BEGIN — do not edit; gen_landing.py replaces this block with install-common.sh at website-build time.
. "$(CDPATH='' cd "$(dirname "$0")" && pwd)/install-common.sh"
# PFB_EMBED_COMMON_END
pfb_channel_install "$@"
