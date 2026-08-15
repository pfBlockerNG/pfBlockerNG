#!/bin/sh
# install-nightly.sh — put this pfSense box on the pfBlockerNG nightly channel (issue #2416).
# Published at https://pfblockerng.github.io/pkg/install-nightly.sh; run ON the box:
#   fetch -qo - https://pfblockerng.github.io/pkg/install-nightly.sh | sh
#
# The nightly channel serves untagged, unreviewed builds straight off devel — NOT for
# daily use. Moving OFF nightly onto a slower channel is a downgrade: nightly sits
# ahead of every tagged release.
set -eu
# shellcheck disable=SC2034 # used by install-common.sh, sourced below
PFB_CHANNEL="nightly"
# PFB_EMBED_COMMON_BEGIN — do not edit; gen_landing.py replaces this block with install-common.sh at website-build time.
. "$(CDPATH='' cd "$(dirname "$0")" && pwd)/install-common.sh"
# PFB_EMBED_COMMON_END
pfb_channel_install "$@"
