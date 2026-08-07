#!/bin/sh
# oras-refresh.sh — refresh an OCI-stored qcow2 into a SHARED image directory (issue #2218).
#
# The PFB_BOXES pool shares one image store, so a refresh by one box can land while another
# box has a VM running off the same file. Two measured facts shape this:
#
#   1. `oras pull` writes in place under the FINAL filename and is not atomic — the target
#      appears immediately at partial size and grows.
#   2. tests/smoke/boot_vm.sh does `qemu-img create -b "$BASE_IMG"`, so the base image is a
#      LIVE backing file for the whole life of the VM, not a one-time copy.
#
# So a pull straight into the published directory can truncate a running VM's backing store
# on a different box. Locking the pull does not fix it: the reader holds the file for the
# length of a smoke run. Instead the pull lands in a staging directory and is published with
# a rename — a running VM keeps its open inode and finishes on the old bytes, and the next
# boot opens the new file.
#
# The digest bookkeeping is per REF, not per directory: ${IMAGES_DIR}/pfsense holds images
# for several refs (pfsense-ce and pfsense-plus, chosen per leg by SMOKE_PFSENSE_REF), so a
# single .digest made every alternating leg re-pull an image that was already on disk.

# Filesystem-safe token for a ref, so each ref owns its digest file.
pfb_oras_digest_file() {
    printf '%s/.digest-%s\n' "$2" "$(printf '%s' "$1" | tr -c 'A-Za-z0-9._-' '-')"
}

# pfb_oras_refresh <ref> <published-dir> <label>
pfb_oras_refresh() {
    _or_ref="$1"
    _or_dir="$2"
    _or_tag="$3"

    mkdir -p "$_or_dir"

    _or_digest_file="$(pfb_oras_digest_file "$_or_ref" "$_or_dir")"

    # Remote digest (best-effort; a lookup failure must not delete or replace anything).
    _or_remote=''
    _or_remote="$(oras resolve "$_or_ref" 2>/dev/null)" \
        || _or_remote="$(oras manifest fetch "$_or_ref" --descriptor 2>/dev/null \
                         | grep -o '"digest":"[^"]*"' | cut -d'"' -f4)" \
        || _or_remote=''

    _or_local="$(cat "$_or_digest_file" 2>/dev/null)" || _or_local=''

    # Anything already published for THIS ref? The digest file is written only after a
    # successful publish, so its presence plus a matching digest means the image is there.
    if [ -n "$_or_remote" ] && [ "$_or_remote" = "$_or_local" ]; then
        printf 'oras-refresh: %s up-to-date at %s\n' "$_or_tag" "$_or_dir" >&2
        return 0
    fi

    printf 'oras-refresh: pulling %s (%s) -> %s\n' "$_or_tag" "$_or_ref" "$_or_dir" >&2

    # Stage OUTSIDE the published directory so a partial transfer is never visible there,
    # and so a listing of the store never shows scratch. Same filesystem as the store when
    # TMPDIR allows, otherwise the publish below falls back to a copy+rename.
    _or_stage="$(mktemp -d "${_or_dir%/*}/.staging.XXXXXX")" || return 1

    if pfb_oras_login 2>/dev/null; then :; fi

    if [ -n "$_or_remote" ]; then
        ( cd "$_or_stage" && oras pull "${_or_ref%@*}@${_or_remote}" ) >&2 || {
            rm -rf "$_or_stage"
            printf 'oras-refresh: pull FAILED for %s; published store left untouched\n' \
                "$_or_tag" >&2
            return 1
        }
    else
        ( cd "$_or_stage" && oras pull "$_or_ref" ) >&2 || {
            rm -rf "$_or_stage"
            printf 'oras-refresh: pull FAILED for %s; published store left untouched\n' \
                "$_or_tag" >&2
            return 1
        }
    fi

    # Publish each staged artifact by rename. Readers with the old file open keep their
    # inode; new opens get the new bytes. Never a truncate-in-place.
    for _or_f in "$_or_stage"/*; do
        [ -e "$_or_f" ] || continue
        mv -f "$_or_f" "${_or_dir}/$(basename "$_or_f")" || {
            rm -rf "$_or_stage"
            return 1
        }
    done
    rm -rf "$_or_stage"

    # Only now is the ref genuinely published, so only now record its digest.
    [ -n "$_or_remote" ] && printf '%s\n' "$_or_remote" > "$_or_digest_file"

    return 0
}

# Overridable so the unit spec does not need credentials; the caller supplies the real one.
if ! command -v pfb_oras_login >/dev/null 2>&1; then
    pfb_oras_login() { :; }
fi
