#!/bin/sh
# render-pkg-site.sh — renders the pkg website (everything under pfBlockerNG/pkg's
# docs/ EXCEPT the catalogue-owned trees) from this repo's pkg-site/ via
# gen_landing.py, then commits + pushes the result onto docs/ on `main`. Split out
# from publish-pkg-repo.sh (issue #2450 step 2): that script owns catalogue paths
# only (docs/<stable|testing|edge|nightly>/<varver>/, docs/staging/<segment>/);
# this script is the SOLE place that renders and ships the site around them —
# dispatched independently, after a publish or on its own.
#
# GUARD: a render commit may never touch a catalogue-owned path (CATALOGUE_DIRS,
# which MUST equal gen_landing.py's own constant of the same name) — enforced by
# a name-only diff right after staging, before any commit. A violation resets the
# index and exits 1, no exceptions (gen_landing.py's own sync_site() already
# refuses to write one; this is the shell-side backstop).
#
# On a rejected push, the ENTIRE cycle re-syncs + re-renders from a fresh
# origin/main checkout (never a rebase of the local commit) — same rationale as
# publish-pkg-repo.sh's own retry loop: the renderer must see the racing run's
# tree, not stale local state.
#
# Required environment:
#   PFB_SRC          pfBlockerNG source-repo checkout — provides
#                    scripts/gen_landing.py and pkg-site/
#   PKG_REPO         pfBlockerNG/pkg checkout, already cloned with a credentialed
#                    remote (this script only fetches/checks out/pushes `main`)
#   BASE_URL         Pages base URL passed to gen_landing.py
#   SOURCE_RUN_ID    provenance trailer on the render commit
#   ROUTE_MATRIX     the pinned ROUTE matrix, compact JSON array text (same shape
#                    the publisher receives) — transformed into gen_landing.py's
#                    --matrix input below
# Optional:
#   MAX_PUSH_ATTEMPTS  bounded retry count (default 5)

set -eu

# Publisher-owned top-level prefixes a render commit may never touch — MUST equal
# gen_landing.py's own CATALOGUE_DIRS constant.
CATALOGUE_DIRS="stable testing edge nightly staging"

: "${PFB_SRC:?PFB_SRC is required}"
: "${PKG_REPO:?PKG_REPO is required}"
: "${BASE_URL:?BASE_URL is required}"
: "${SOURCE_RUN_ID:?SOURCE_RUN_ID is required}"
: "${ROUTE_MATRIX:?ROUTE_MATRIX is required}"

MAX_PUSH_ATTEMPTS="${MAX_PUSH_ATTEMPTS:-5}"
# A bound below 1 (or a non-numeric one) makes the retry loop body unreachable, so
# the script would report a push rejection for a push it never attempted.
case "$MAX_PUSH_ATTEMPTS" in
    '' | *[!0-9]*) MAX_PUSH_ATTEMPTS=0 ;;
esac
[ "$MAX_PUSH_ATTEMPTS" -ge 1 ] || {
    echo "::error::MAX_PUSH_ATTEMPTS must be a positive integer" >&2
    exit 1
}

# gen_landing.py's own --matrix transform (shared with publish-pkg-repo.sh's
# publisher intake): freebsd_major alone feeds the CPU-wildcarded ABI string.
# The retired `arch` matrix field is never interpolated — every published .pkg is
# NO_ARCH, so the honest ABI is the wildcard the packages themselves carry.
# ROUTE_MATRIX is constant across retries, so this runs once, up front.
matrix_file=$(mktemp)
trap 'rm -f "$matrix_file"' EXIT
printf '%s' "$ROUTE_MATRIX" | jq -c \
    '[.[] | {abi: "FreeBSD:\(.freebsd_major):*", pfsense_version, variant, php_version, py_flavor}]' \
    >"$matrix_file"

attempt=1
while [ "$attempt" -le "$MAX_PUSH_ATTEMPTS" ]; do
    echo "render-pkg-site: sync attempt ${attempt}/${MAX_PUSH_ATTEMPTS} — fetching origin/main"
    git -C "$PKG_REPO" fetch --quiet origin main
    git -C "$PKG_REPO" checkout --quiet -B main origin/main
    # checkout -B restores tracked files; untracked leftovers from a rejected
    # push survive unless cleaned. Scope to docs/ so debris at the repo root
    # stays untracked (matches publish-pkg-repo.sh, issue #2407).
    git -C "$PKG_REPO" clean -fd -- docs

    # A non-zero exit here is fatal to the WHOLE run, on the spot: no git add, no
    # commit, no push follows (same containment idiom as publish-pkg-repo.sh's
    # own publisher call).
    render_out=$(mktemp)
    trap 'rm -f "$render_out" "$matrix_file"' EXIT
    render_rc=0
    python3 "${PFB_SRC}/scripts/gen_landing.py" \
        "${PKG_REPO}/docs" "$BASE_URL" \
        --site-tree "${PFB_SRC}/pkg-site" \
        --matrix "$matrix_file" >"$render_out" 2>&1 || render_rc=$?
    if [ "$render_rc" -ne 0 ]; then
        echo "::error::gen_landing.py failed — aborting before any git mutation" >&2
        cat "$render_out" >&2
        exit 1
    fi
    cat "$render_out"
    trap 'rm -f "$matrix_file"' EXIT
    rm -f "$render_out"

    # No `git add -A` without the guard below to back it: gen_landing.py's own
    # sync_site() already refuses to write inside a catalogue prefix, but this
    # is the independent, structural check that a broken/regressed renderer
    # cannot silently defeat.
    git -C "$PKG_REPO" add -A -- docs

    catalogue_pathspec=""
    for catalogue_dir in $CATALOGUE_DIRS; do
        catalogue_pathspec="${catalogue_pathspec} docs/${catalogue_dir}"
    done
    # shellcheck disable=SC2086  # catalogue_pathspec is a controlled, space-separated pathspec list
    touched_catalogue=$(git -C "$PKG_REPO" diff --cached --name-only -- $catalogue_pathspec)
    if [ -n "$touched_catalogue" ]; then
        echo "::error::render touched catalogue-owned path(s):" >&2
        printf '%s\n' "$touched_catalogue" >&2
        git -C "$PKG_REPO" reset --quiet
        exit 1
    fi

    if git -C "$PKG_REPO" diff --cached --quiet; then
        echo "render-pkg-site: NOOP — site already current."
        exit 0
    fi

    short_sha=$(git -C "$PFB_SRC" rev-parse --short HEAD 2>/dev/null || echo unknown)
    commit_message=$(printf 'render: pkg website (%s)\n\npfBlockerNG-Source-Run-Id: %s\n' "$short_sha" "$SOURCE_RUN_ID")

    # Fixed bot identity via per-invocation -c flags, not repo config — same
    # rationale as publish-pkg-repo.sh: a bare CI checkout carries no git
    # identity, and this script must not depend on one being configured elsewhere.
    git -C "$PKG_REPO" \
        -c user.name="github-actions[bot]" \
        -c user.email="github-actions[bot]@users.noreply.github.com" \
        commit --quiet -m "$commit_message"

    if push_out=$(git -C "$PKG_REPO" push origin HEAD:main 2>&1); then
        printf '%s\n' "$push_out" >&2
        echo "render-pkg-site: ADVANCE — pushed $(git -C "$PKG_REPO" rev-parse HEAD)"
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

    echo "render-pkg-site: push rejected (attempt ${attempt}/${MAX_PUSH_ATTEMPTS}) — another run advanced main; re-syncing and retrying" >&2
    attempt=$((attempt + 1))
done

echo "::error::push rejected ${MAX_PUSH_ATTEMPTS} times in a row; giving up" >&2
exit 1
