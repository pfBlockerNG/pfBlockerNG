#!/bin/sh
# publish-pkg-repo.sh — verify + publish a Tagged release's or a Nightly snapshot's
# .pkg assets into the pfBlockerNG/pkg catalogue tree, then commit + fast-forward-push
# the result.
#
# PUBLISH_KIND selects the mode (default "tagged" when unset):
#   tagged   PFB_SRC/scripts/publish_release.py verifies + assembles a tagged
#            Release's assets against the pinned ROUTE matrix.
#   nightly  PFB_SRC/scripts/publish_nightly.py verifies + assembles a verified
#            Nightly handoff's assets, fanned out to every ROUTE varver sharing
#            each build's FreeBSD major.
# Neither publisher ever runs git itself; this script owns the ONLY git mutation
# in the whole flow: syncing PKG_REPO to origin/main, staging exactly what the
# publisher reports touched, committing, and pushing.
#
# CONTAINMENT: a publisher failure — verification, or a mid-regeneration
# write-back fault inside catalogue_assembly.py — must never reach a commit. This
# script enforces that structurally: every git mutation (add/commit/push) happens
# strictly AFTER a successful publisher run, and a non-zero exit from it
# is `exit 1` on the spot, before any git add ever runs. There is no
# `git add -A` / `git add .` anywhere below — only the exact touched (channel,
# varver) directories the publisher reports, plus the landing page's own
# output and docs/.nojekyll.
#
# On a rejected push (another run advanced origin/main first), the ENTIRE cycle
# reruns from a fresh sync — not a rebase of the local commit — because
# the publisher's retention/regeneration must see the racing run's tree, not
# stale local state.
#
# Required environment — every mode:
#   PFB_SRC              pfBlockerNG source-repo checkout (this repo; also exported
#                        for the publisher's own engine loading)
#   PKG_REPO              pfBlockerNG/pkg checkout, already cloned with a credentialed
#                        remote (this script only fetches/checks out/pushes `main`)
#   SOURCE_RUN_ID          identifies this run to the publisher (tagged:
#                        publish_release.py intake; nightly: must equal the
#                        handoff's own run_id — see publish_nightly.py --help)
#   BASE_URL               Pages base URL passed to gen_landing.py
# Optional — every mode:
#   PUBLISH_KIND           "tagged" (default) or "nightly"; anything else is a
#                        usage error
#   MAX_PUSH_ATTEMPTS      bounded retry count (default 5)
#
# Required environment — PUBLISH_KIND=tagged only:
#   SOURCE_REPOSITORY, RELEASE_ID, RELEASE_TAG, DESTINATIONS
#                        the rest of the publish_release.py intake — see its --help
#   ASSETS_DIR             directory of downloaded .pkg assets + digests.json sidecar
#   ROUTE_MATRIX           the pinned ROUTE matrix, compact JSON array text
#
# Required environment — PUBLISH_KIND=nightly only:
#   HANDOFF_FILE            path to the verified nightly_provenance.build_handoff JSON
#   RESULTS_DIR             directory of downloaded nightly-result-<major>/ legs

set -eu

PUBLISH_KIND="${PUBLISH_KIND:-tagged}"
case "$PUBLISH_KIND" in
    tagged | nightly) ;;
    *)
        echo "::error::PUBLISH_KIND must be 'tagged' or 'nightly', got '${PUBLISH_KIND}'" >&2
        exit 1
        ;;
esac

: "${PFB_SRC:?PFB_SRC is required}"
: "${PKG_REPO:?PKG_REPO is required}"
: "${SOURCE_RUN_ID:?SOURCE_RUN_ID is required}"
: "${BASE_URL:?BASE_URL is required}"

case "$PUBLISH_KIND" in
    tagged)
        : "${SOURCE_REPOSITORY:?SOURCE_REPOSITORY is required}"
        : "${RELEASE_ID:?RELEASE_ID is required}"
        : "${RELEASE_TAG:?RELEASE_TAG is required}"
        : "${DESTINATIONS:?DESTINATIONS is required}"
        : "${ASSETS_DIR:?ASSETS_DIR is required}"
        : "${ROUTE_MATRIX:?ROUTE_MATRIX is required}"
        ;;
    nightly)
        : "${HANDOFF_FILE:?HANDOFF_FILE is required}"
        : "${RESULTS_DIR:?RESULTS_DIR is required}"
        ;;
esac
MAX_PUSH_ATTEMPTS="${MAX_PUSH_ATTEMPTS:-5}"
# A bound below 1 (or a non-numeric one) makes the retry loop body unreachable, so the
# script would report a push rejection for a push it never attempted.
case "$MAX_PUSH_ATTEMPTS" in
    '' | *[!0-9]*) MAX_PUSH_ATTEMPTS=0 ;;
esac
[ "$MAX_PUSH_ATTEMPTS" -ge 1 ] || {
    echo "::error::MAX_PUSH_ATTEMPTS must be a positive integer" >&2
    exit 1
}

export PFB_SRC

attempt=1
while [ "$attempt" -le "$MAX_PUSH_ATTEMPTS" ]; do
    echo "publish-pkg-repo: sync attempt ${attempt}/${MAX_PUSH_ATTEMPTS} — fetching origin/main"
    git -C "$PKG_REPO" fetch --quiet origin main
    git -C "$PKG_REPO" checkout --quiet -B main origin/main

    # --- verify + assemble (never runs git) --------------------------------
    # A non-zero exit here is fatal to the WHOLE run, on the spot: no git add,
    # no commit, no push follows. The publisher's own stderr (already tagged
    # ::error:: on failure) reaches the job log via the redirect below.
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
    # `cmd || publish_rc=$?` — not `if ! cmd; then` — because the command to run
    # differs per mode: the failure must be captured from inside a `case` arm,
    # and a non-final component of an OR list (the assignment is always the
    # list's own last, always-successful component) is exempt from `set -e`,
    # same idiom as `touched=$(...) || true` further down.
    publish_rc=0
    case "$PUBLISH_KIND" in
        tagged) publisher_script="publish_release.py" ;;
        nightly) publisher_script="publish_nightly.py" ;;
    esac
    case "$PUBLISH_KIND" in
        tagged)
            python3 "${PFB_SRC}/scripts/${publisher_script}" \
                --source-repository "$SOURCE_REPOSITORY" \
                --release-id "$RELEASE_ID" \
                --release-tag "$RELEASE_TAG" \
                --destinations "$DESTINATIONS" \
                --source-run-id "$SOURCE_RUN_ID" \
                --assets-dir "$ASSETS_DIR" \
                --pkg-repo "$PKG_REPO" \
                --route-matrix "$ROUTE_MATRIX" >"$out_file" 2>&1 || publish_rc=$?
            ;;
        nightly)
            python3 "${PFB_SRC}/scripts/${publisher_script}" \
                --handoff "$HANDOFF_FILE" \
                --results-dir "$RESULTS_DIR" \
                --pkg-repo "$PKG_REPO" \
                --source-run-id "$SOURCE_RUN_ID" >"$out_file" 2>&1 || publish_rc=$?
            ;;
    esac
    if [ "$publish_rc" -ne 0 ]; then
        echo "::error::${publisher_script} failed — aborting before any git mutation" >&2
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
    # wildcard the packages themselves carry, never a per-arch value. The two
    # modes share this ONE transform, differing only in the matrix array's
    # source: tagged's pinned $ROUTE_MATRIX, nightly's own handoff-carried
    # route_matrix (the handoff is what this run actually verified against —
    # never a freshly re-read live matrix, which could have moved since).
    case "$PUBLISH_KIND" in
        tagged) landing_input="$ROUTE_MATRIX" ;;
        nightly) landing_input="$(jq -ec '.route_matrix' "$HANDOFF_FILE")" ;;
    esac
    landing_matrix_file=$(mktemp)
    printf '%s' "$landing_input" | jq -c \
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
    # write_site() also publishes a self-contained add-repo.sh into the site root —
    # the landing page's bootstrap one-liner fetches it from there.
    [ -f "${PKG_REPO}/docs/add-repo.sh" ] && stage_paths="${stage_paths} docs/add-repo.sh"
    for target in $touched; do
        stage_paths="${stage_paths} docs/${target}"
    done
    # gen_landing.py's all_dirs() regenerates a per-directory autoindex at
    # EVERY existing level, not just this run's touched targets — stage every
    # directory's index.html too, matching what actually changed on disk.
    docs_root="${PKG_REPO}/docs"
    dir_indexes=$(find "$docs_root" -mindepth 1 -type d -print | while IFS= read -r d; do
        [ -f "${d}/index.html" ] && printf 'docs/%s/index.html\n' "${d#"${docs_root}/"}"
    done)
    stage_paths="${stage_paths}
${dir_indexes}"
    # shellcheck disable=SC2086  # stage_paths is a controlled, space/newline-separated pathspec list
    git -C "$PKG_REPO" add -- $stage_paths

    if git -C "$PKG_REPO" diff --cached --quiet; then
        echo "publish-pkg-repo: NOOP — the publisher reported changes but nothing is staged; discarding."
        git -C "$PKG_REPO" reset --quiet
        exit 0
    fi

    case "$PUBLISH_KIND" in
        tagged)
            commit_message=$(printf 'publish: %s -> %s\n\npfBlockerNG-Release-Tag: %s\npfBlockerNG-Source-Run-Id: %s\n' \
                "$RELEASE_TAG" "$DESTINATIONS" "$RELEASE_TAG" "$SOURCE_RUN_ID")
            ;;
        nightly)
            # jq -er: a missing/null allocation.pkg_version aborts here (via
            # set -e) before any commit — same containment rule as a non-zero
            # exit from the publisher itself further up.
            nightly_pkg_version=$(jq -er '.allocation.pkg_version' "$HANDOFF_FILE")
            commit_message=$(printf 'publish: nightly %s -> ["nightly"]\n\npfBlockerNG-Nightly-Version: %s\npfBlockerNG-Source-Run-Id: %s\n' \
                "$nightly_pkg_version" "$nightly_pkg_version" "$SOURCE_RUN_ID")
            ;;
    esac
    # Fixed bot identity via per-invocation -c flags, not repo config: a bare CI
    # checkout carries no git identity, and this script must not depend on one
    # being configured elsewhere (matches release.yml/module-durations.yml's
    # direct-to-repo commits).
    git -C "$PKG_REPO" \
        -c user.name="github-actions[bot]" \
        -c user.email="github-actions[bot]@users.noreply.github.com" \
        commit --quiet -m "$commit_message"

    if push_out=$(git -C "$PKG_REPO" push origin HEAD:main 2>&1); then
        printf '%s\n' "$push_out" >&2
        echo "publish-pkg-repo: ADVANCE — pushed $(git -C "$PKG_REPO" rev-parse HEAD)"
        exit 0
    fi
    printf '%s\n' "$push_out" >&2

    # Retry only a genuine non-fast-forward rejection (another run advanced
    # main); anything else (auth, network, protected-branch policy) is a hard
    # failure and must not be retried.
    if ! printf '%s' "$push_out" | grep -qiE 'non-fast-forward|fetch first|\[rejected\]'; then
        echo "::error::push failed for a reason other than remote contention — aborting without retry" >&2
        exit 1
    fi

    echo "publish-pkg-repo: push rejected (attempt ${attempt}/${MAX_PUSH_ATTEMPTS}) — another run advanced main; re-syncing and retrying" >&2
    attempt=$((attempt + 1))
done

echo "::error::push rejected ${MAX_PUSH_ATTEMPTS} times in a row; giving up" >&2
exit 1
