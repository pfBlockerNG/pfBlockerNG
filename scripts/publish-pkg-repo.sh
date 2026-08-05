#!/bin/sh
# publish-pkg-repo.sh — verify + publish a tagged release's .pkg assets into the
# pfBlockerNG/pkg catalogue tree, then commit + fast-forward-push the result.
#
# The release job's own checkout runs this — PFB_SRC/scripts/publish_release.py
# does the verify+assemble work (never runs git itself); this script owns the ONLY
# git mutation in the whole flow: syncing PKG_REPO to origin/main, staging exactly
# what publish_release.py reports touched, committing, and pushing.
#
# CONTAINMENT: a publish_release.py failure — verification, or a mid-regeneration
# write-back fault inside catalogue_assembly.py — must never reach a commit. This
# script enforces that structurally: every git mutation (add/commit/push) happens
# strictly AFTER a successful publish_release.py run, and a non-zero exit from it
# is `exit 1` on the spot, before any git add ever runs. There is no
# `git add -A` / `git add .` anywhere below — only the exact touched (channel,
# varver) directories publish_release.py reports, plus the landing page's own
# output and docs/.nojekyll.
#
# On a rejected push (another run advanced origin/main first), the ENTIRE cycle
# reruns from a fresh sync — not a rebase of the local commit — because
# publish_release.py's retention/regeneration must see the racing run's tree, not
# stale local state.
#
# Required environment:
#   PFB_SRC             pfBlockerNG source-repo checkout (this repo; also exported
#                        for publish_release.py's own engine loading)
#   PKG_REPO             pfBlockerNG/pkg checkout, already cloned with a credentialed
#                        remote (this script only fetches/checks out/pushes `main`)
#   SOURCE_REPOSITORY, RELEASE_ID, RELEASE_TAG, DESTINATIONS, SOURCE_RUN_ID
#                        the publish_release.py intake — see its --help
#   ASSETS_DIR            directory of downloaded .pkg assets + digests.json sidecar
#   ROUTE_MATRIX          the pinned ROUTE matrix, compact JSON array text
#   BASE_URL              Pages base URL passed to gen_landing.py
# Optional:
#   MAX_PUSH_ATTEMPTS     bounded retry count (default 5)

set -eu

: "${PFB_SRC:?PFB_SRC is required}"
: "${PKG_REPO:?PKG_REPO is required}"
: "${SOURCE_REPOSITORY:?SOURCE_REPOSITORY is required}"
: "${RELEASE_ID:?RELEASE_ID is required}"
: "${RELEASE_TAG:?RELEASE_TAG is required}"
: "${DESTINATIONS:?DESTINATIONS is required}"
: "${SOURCE_RUN_ID:?SOURCE_RUN_ID is required}"
: "${ASSETS_DIR:?ASSETS_DIR is required}"
: "${ROUTE_MATRIX:?ROUTE_MATRIX is required}"
: "${BASE_URL:?BASE_URL is required}"
MAX_PUSH_ATTEMPTS="${MAX_PUSH_ATTEMPTS:-5}"

export PFB_SRC

attempt=1
while [ "$attempt" -le "$MAX_PUSH_ATTEMPTS" ]; do
    echo "publish-pkg-repo: sync attempt ${attempt}/${MAX_PUSH_ATTEMPTS} — fetching origin/main"
    git -C "$PKG_REPO" fetch --quiet origin main
    git -C "$PKG_REPO" checkout --quiet -B main origin/main

    # --- verify + assemble (never runs git) --------------------------------
    # A non-zero exit here is fatal to the WHOLE run, on the spot: no git add,
    # no commit, no push follows. publish_release.py's own stderr (already
    # tagged ::error:: on failure) reaches the job log via the redirect below.
    out_file=$(mktemp)
    # Cleanup is a trap, deliberately NOT a manual `rm -f` paired with the
    # failure branch's `exit 1` below: an `rm` immediately before an `exit`
    # that later gets removed (by accident, by a future edit) would leave the
    # NEXT line — an unconditional `cat "$out_file"` on the success path —
    # tripping over a missing file and aborting via `set -e` for an unrelated
    # reason, which would make the exit-1 guard's own removal invisible to any
    # test asserting only "did it abort". The trap fires once, at actual
    # script exit, however that exit happens; nothing on the path between here
    # and there depends on `$out_file` already being gone.
    trap 'rm -f "$out_file"' EXIT
    if ! python3 "${PFB_SRC}/scripts/publish_release.py" \
        --source-repository "$SOURCE_REPOSITORY" \
        --release-id "$RELEASE_ID" \
        --release-tag "$RELEASE_TAG" \
        --destinations "$DESTINATIONS" \
        --source-run-id "$SOURCE_RUN_ID" \
        --assets-dir "$ASSETS_DIR" \
        --pkg-repo "$PKG_REPO" \
        --route-matrix "$ROUTE_MATRIX" >"$out_file" 2>&1
    then
        echo "::error::publish_release.py failed — aborting before any git mutation" >&2
        cat "$out_file" >&2
        exit 1
    fi
    cat "$out_file"
    touched=$(grep '^updated ' "$out_file" | sed 's/^updated //') || true
    trap - EXIT
    rm -f "$out_file"

    if [ -z "$touched" ]; then
        echo "publish-pkg-repo: NOOP — nothing touched, nothing to commit."
        exit 0
    fi

    # --- landing page regen — only for an actual publish -------------------
    # Skipped entirely on a no-op above: gen_landing.py embeds a generation
    # timestamp, so running it unconditionally would manufacture a diff (and
    # therefore a commit) on every run even when no catalogue changed.
    #
    # landing_matrix.json's abi expression (pinned by
    # tests/shell/publish_pkg_repo_spec.sh): freebsd_major alone feeds the
    # CPU-wildcarded ABI string. The retired `arch` matrix field is never
    # interpolated — every published .pkg is NO_ARCH, so the honest ABI is the
    # wildcard the packages themselves carry, never a per-arch value.
    landing_matrix_file=$(mktemp)
    printf '%s' "$ROUTE_MATRIX" | jq -c \
        '[.[] | {abi: "FreeBSD:\(.freebsd_major):*", pfsense_version, variant, php_version, py_flavor}]' \
        >"$landing_matrix_file"
    python3 "${PFB_SRC}/scripts/gen_landing.py" \
        "${PKG_REPO}/docs" "$BASE_URL" "${PFB_SRC}/scripts/add-repo.sh" \
        --matrix "$landing_matrix_file"
    rm -f "$landing_matrix_file"
    true >"${PKG_REPO}/docs/.nojekyll"

    # --- stage EXACTLY what changed — never -A / . --------------------------
    stage_paths="docs/.nojekyll"
    [ -f "${PKG_REPO}/docs/index.html" ] && stage_paths="${stage_paths} docs/index.html"
    [ -f "${PKG_REPO}/docs/browse.html" ] && stage_paths="${stage_paths} docs/browse.html"
    for target in $touched; do
        stage_paths="${stage_paths} docs/${target}"
    done
    # shellcheck disable=SC2086  # stage_paths is a controlled, space-separated pathspec list
    git -C "$PKG_REPO" add -- $stage_paths

    if git -C "$PKG_REPO" diff --cached --quiet; then
        echo "publish-pkg-repo: NOOP — publish_release.py reported changes but nothing is staged; discarding."
        git -C "$PKG_REPO" reset --quiet
        exit 0
    fi

    commit_message=$(printf 'publish: %s -> %s\n\npfBlockerNG-Release-Tag: %s\npfBlockerNG-Source-Run-Id: %s\n' \
        "$RELEASE_TAG" "$DESTINATIONS" "$RELEASE_TAG" "$SOURCE_RUN_ID")
    git -C "$PKG_REPO" commit --quiet -m "$commit_message"

    if git -C "$PKG_REPO" push origin HEAD:main; then
        echo "publish-pkg-repo: ADVANCE — pushed $(git -C "$PKG_REPO" rev-parse HEAD)"
        exit 0
    fi

    echo "publish-pkg-repo: push rejected (attempt ${attempt}/${MAX_PUSH_ATTEMPTS}) — another run advanced main; re-syncing and retrying" >&2
    attempt=$((attempt + 1))
done

echo "::error::push rejected ${MAX_PUSH_ATTEMPTS} times in a row; giving up" >&2
exit 1
