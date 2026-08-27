#!/bin/sh
# scripts/lib/run-id.sh — single source-of-truth run-id minter.
#
# Safe to source: no top-level side effects, no set -e, no traps set.
# Source this with: . scripts/lib/run-id.sh
#
# Format:
#   local-<boxtok>-<epoch>-<rand8hex>   (pfb_mint_run_id_local)
#   ci-<GITHUB_RUN_ID>-<GITHUB_RUN_ATTEMPT>-<LEG>  (pfb_mint_run_id_ci)
#
# No-alias guarantee: the literal "local-" vs "ci-" prefix is a hard structural
# split — no GITHUB_RUN_ID can equal the string "local", so the two id spaces
# never collide.

# pfb_mint_run_id_local <box>
# Mint a run-id for a local run on <box>.
#   <boxtok> = box with user@ stripped, non-alphanumeric chars removed, lowercased.
#   <epoch>  = date +%s
#   <rand>   = 8 bytes of /dev/urandom as lowercase hex (POSIX; no $RANDOM).
pfb_mint_run_id_local() {
    _ribox="${1##*@}"
    _ribox="$(printf '%s' "$_ribox" | tr -cd '[:alnum:]' | tr '[:upper:]' '[:lower:]')"
    _riepoch="$(date +%s)"
    _rirand="$(od -An -tx1 -N8 /dev/urandom | tr -d ' \t\n')"
    printf 'local-%s-%s-%s\n' "$_ribox" "$_riepoch" "$_rirand"
}

# pfb_mint_run_id_ci
# Mint a run-id for a CI leg. Reads GITHUB_RUN_ID, GITHUB_RUN_ATTEMPT, LEG from env.
pfb_mint_run_id_ci() {
    printf 'ci-%s-%s-%s\n' \
        "${GITHUB_RUN_ID}" \
        "${GITHUB_RUN_ATTEMPT}" \
        "${LEG:-default}"
}
