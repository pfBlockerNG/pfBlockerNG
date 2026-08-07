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

# Short, collision-resistant hash of a ref. Every hash in this file goes through here:
# sha256sum failing inside a command substitution is invisible (the pipeline's status is
# not the caller's, and `set -eu` does not surface it), so an absent tool would yield an
# empty suffix and every ref would share one name.
pfb_oras_ref_hash() {
    command -v sha256sum >/dev/null 2>&1 || {
        printf 'oras-refresh: sha256sum is required to name per-ref files\n' >&2
        return 1
    }
    printf '%s' "$1" | sha256sum | cut -c1-16
}

# Filesystem-safe, COLLISION-RESISTANT token for a ref, so each ref owns its digest file.
# A plain character substitution is not enough: ':' and '/' both fold to '-', so
# ghcr.io/x/a:1 and ghcr.io/x/a-1 would share a file and one would suppress the other's
# pull. The readable part stays for debuggability; the hash of the FULL ref decides identity.
pfb_oras_digest_file() {
    # A missing sha256sum would fail INSIDE the pipe below, which neither `set -e` nor a
    # non-zero exit surfaces: the hash would silently be empty and every ref would share
    # one name again. Refuse rather than degrade.
    _od_safe="$(printf '%s' "$1" | tr -c 'A-Za-z0-9._-' '-')"
    _od_hash="$(pfb_oras_ref_hash "$1")" || return 1
    printf '%s/.digest-%s-%s\n' "$2" "$_od_safe" "$_od_hash"
}

# pfb_oras_refresh <ref> <published-dir> <label>
#
# Serialised per ref. Staging + rename already keeps the BYTES safe under concurrency, but
# two boxes racing the same ref across an upstream digest change can still interleave so
# that the recorded digest describes the other box's bytes; the store then believes it is
# current when it is not, and stops self-healing on a tag revert.
pfb_oras_refresh() {
    _orl_dir="$2"
    mkdir -p "$_orl_dir"
    if command -v flock >/dev/null 2>&1; then
        # Named OUT of the .digest-* namespace: a lock is not a digest, and anything
        # enumerating the store's digest files must not see it.
        _orl_hash="$(pfb_oras_ref_hash "$1")" || return 1
        _orl_lock="${_orl_dir}/.lock-${_orl_hash}"
        ( flock 9 || exit 1; pfb_oras_refresh_unlocked "$@" ) 9>"$_orl_lock"
        return $?
    fi
    printf 'oras-refresh: flock unavailable; refreshing %s unserialised\n' "$1" >&2
    pfb_oras_refresh_unlocked "$@"
}

pfb_oras_refresh_unlocked() {
    _or_ref="$1"
    _or_dir="$2"
    _or_tag="$3"

    mkdir -p "$_or_dir"

    _or_digest_file="$(pfb_oras_digest_file "$_or_ref" "$_or_dir")" || return 1

    # Remote digest (best-effort; a lookup failure must not delete or replace anything).
    _or_remote=''
    _or_remote="$(oras resolve "$_or_ref" 2>/dev/null)" \
        || _or_remote="$(oras manifest fetch "$_or_ref" --descriptor 2>/dev/null \
                         | grep -o '"digest":"[^"]*"' | cut -d'"' -f4)" \
        || _or_remote=''

    # Anything already published for THIS ref? The digest file is written only after a
    # successful publish, so its presence plus a matching digest means the image is there.
    # A recorded digest is not proof THIS ref's image is still there: the store holds several
    # refs' images in one directory, so "some .qcow2 exists" is satisfied by a sibling and
    # hides this ref's missing file — the boot then dies on a missing base image. The state
    # file therefore records the artifacts this ref published (line 1 digest, then one
    # filename per line) and every one of them must still be present.
    _or_local="$(sed -n 1p "$_or_digest_file" 2>/dev/null)" || _or_local=''
    _or_have_artifact=0
    if [ -s "$_or_digest_file" ] && [ "$(sed -n '2,$p' "$_or_digest_file" 2>/dev/null | wc -l)" -gt 0 ]; then
        _or_have_artifact=1
        while IFS= read -r _or_name; do
            [ -n "$_or_name" ] || continue
            [ -e "${_or_dir}/${_or_name}" ] || _or_have_artifact=0
        done <<EOF
$(sed -n '2,$p' "$_or_digest_file" 2>/dev/null)
EOF
    fi

    if [ "$_or_have_artifact" -eq 1 ] && [ -n "$_or_remote" ] && [ "$_or_remote" = "$_or_local" ]; then
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
    _or_published=''
    for _or_f in "$_or_stage"/*; do
        [ -e "$_or_f" ] || continue
        _or_published="$_or_published $(basename "$_or_f")"
        mv -f "$_or_f" "${_or_dir}/$(basename "$_or_f")" || {
            rm -rf "$_or_stage"
            return 1
        }
    done
    rm -rf "$_or_stage"

    # Only now is the ref genuinely published, so only now record its state: the digest,
    # then the artifacts this ref owns, so a later run can tell ITS image from a sibling's.
    if [ -n "$_or_remote" ]; then
        { printf '%s\n' "$_or_remote"
          for _or_p in "$_or_dir"/*.qcow2; do
              [ -e "$_or_p" ] || continue
              case " $_or_published " in *" $(basename "$_or_p") "*) basename "$_or_p" ;; esac
          done
        } > "$_or_digest_file"
    fi

    return 0
}

# Overridable so the unit spec does not need credentials; the caller supplies the real one.
if ! command -v pfb_oras_login >/dev/null 2>&1; then
    pfb_oras_login() { :; }
fi
