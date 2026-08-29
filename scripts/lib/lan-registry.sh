#!/bin/sh
# lan-registry.sh — shared LAN OCI registry ref helpers.

# pfb_lan_registry_active — true (0) when PFB_LAN_REGISTRY is non-empty.
pfb_lan_registry_active() {
    [ -n "${PFB_LAN_REGISTRY:-}" ]
}

# pfb_rewrite_lan_registry <ref>
#
# Rewrite a leading ghcr.io/ to the configured LAN registry. PFB_LAN_REGISTRY
# is a bare host[:port] with no trailing slash. Other refs and any tag or
# @digest suffix pass through unchanged.
pfb_rewrite_lan_registry() {
    if ! pfb_lan_registry_active; then
        printf '%s\n' "$1"
        return 0
    fi
    case "$1" in
        ghcr.io/*) printf '%s/%s\n' "$PFB_LAN_REGISTRY" "${1#ghcr.io/}" ;;
        *)         printf '%s\n' "$1" ;;
    esac
}
