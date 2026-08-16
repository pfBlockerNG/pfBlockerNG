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
# output and docs/.nojekyll; on a catalogue no-op, only the regenerated
# client script (issue #2408) unless PUBLISH_REFRESH_LANDING=1 (issue #2416
# follow-up) — see below. Any retired client script still on the live site is
# swept in the same commit either way.
#
# On a rejected push (another run advanced origin/main first), the ENTIRE cycle
# reruns from a fresh sync — not a rebase of the local commit — because
# the publisher's retention/regeneration must see the racing run's tree, not
# stale local state. checkout -B restores tracked files; `git clean -fd -- docs`
# drops untracked leftovers under docs/ (issue #2407) so a dest autoindex
# without its .pkgs cannot survive into landing_regen_and_stage.
#
# PUBLISH_STAGE additionally selects WHEN a tagged catalogue commit becomes the
# live Pages site (issue #2389 — gate-before-announce). docs/ on `main` IS the
# Pages site, so a plain publish (PUBLISH_STAGE=direct, the default) commits the
# catalogue and the landing page atomically, and nothing can be live-gated before
# announce. The three extra values split that into a stage-then-promote flow:
#   stage    run the publisher exactly as "direct" does, against the real tree,
#            then relocate its output under docs/staging/<run-segment>/ instead
#            of leaving it at its real (channel, varver) location — restoring
#            the original bytes there — so a live install can be gated against
#            the staged path while nothing else on the site moves. No landing
#            regen: staging is never served as the site. The catalogue-no-op
#            path is the ONE exception — it still regenerates + pushes the
#            deterministic client script (docs/install.sh, the --channel
#            parameterized installer; issue #2408, issue #2416, shared with
#            "direct") even though nothing was staged, and reports
#            GITHUB_OUTPUT noop=true.
#   promote  move a previously staged tree (STAGING_PREFIX) into its real
#            location and run the landing regen — this is the step that
#            actually goes live. Never runs the publisher.
#   discard  drop a previously staged tree (STAGING_PREFIX) without ever going
#            live. Never runs the publisher.
# promote/discard act on STAGING_PREFIX as staged (a prior "stage" run's own
# GITHUB_OUTPUT staging_prefix). PUBLISH_STAGE values other than "direct" are a
# usage error under PUBLISH_KIND=nightly — nightly keeps today's
# publish-then-gate flow untouched.
#
# Required environment — every mode:
#   PFB_SRC              pfBlockerNG source-repo checkout (this repo; also exported
#                        for the publisher's own engine loading)
#   PKG_REPO              pfBlockerNG/pkg checkout, already cloned with a credentialed
#                        remote (this script only fetches/checks out/pushes `main`)
#   SOURCE_RUN_ID          identifies this run to the publisher (tagged:
#                        publish_release.py intake; nightly: must equal the
#                        handoff's own run_id — see publish_nightly.py --help).
#                        PUBLISH_STAGE=stage also uses it as a staging path
#                        segment: `:` is translated to `-` (the real workflows
#                        set SOURCE_RUN_ID="<run_id>:<run_attempt>"), and it must
#                        otherwise match [0-9A-Za-z_:-]+.
#   BASE_URL               Pages base URL passed to gen_landing.py
# Optional — every mode:
#   PUBLISH_KIND           "tagged" (default) or "nightly"; anything else is a
#                        usage error
#   PUBLISH_STAGE           "direct" (default), "stage", "promote", or "discard";
#                        anything else is a usage error. Only "direct" is valid
#                        when PUBLISH_KIND=nightly.
#   PUBLISH_REFRESH_LANDING "0" (default) or "1"; on an otherwise catalogue-NOOP
#                        run, "1" regenerates the FULL landing page
#                        (index.html/browse.html/every autoindex) instead of
#                        just CLIENT_SCRIPTS — for shipping a landing
#                        template/card fix via a republish of an
#                        already-published release (issue #2416 follow-up).
#                        Valid only with PUBLISH_KIND=tagged and
#                        PUBLISH_STAGE=direct; any other combination is a usage
#                        error.
#   MAX_PUSH_ATTEMPTS      bounded retry count (default 5)
# Optional — PUBLISH_STAGE=stage only, when GITHUB_ACTIONS-style outputs are
# wanted:
#   GITHUB_OUTPUT           when set and non-empty, this run appends
#                        staging_prefix=staging/<segment>,
#                        touched=<compact JSON array of "channel/varver">, and
#                        noop=true|false.
#
# Required environment — PUBLISH_KIND=tagged, PUBLISH_STAGE=direct|stage only:
#   SOURCE_REPOSITORY, RELEASE_ID, RELEASE_TAG, DESTINATIONS
#                        the rest of the publish_release.py intake — see its --help
#   ASSETS_DIR             directory of downloaded .pkg assets + digests.json sidecar
#   ROUTE_MATRIX           the pinned ROUTE matrix, compact JSON array text
#
# Required environment — PUBLISH_KIND=tagged, PUBLISH_STAGE=promote only:
#   RELEASE_TAG, DESTINATIONS  the promote commit message's own trailers
#   ROUTE_MATRIX             landing_regen_and_stage's tagged-mode matrix source
#                        Never ASSETS_DIR — promote never runs publish_release.py,
#                        and the workflow's promote-pkg-repo job does not export it
#                        (issue #2389); SOURCE_REPOSITORY/RELEASE_ID are exported
#                        there but unused by promote, so they are not required.
#
# Required environment — PUBLISH_KIND=tagged, PUBLISH_STAGE=discard only:
#   (none beyond the unconditional PFB_SRC/PKG_REPO/SOURCE_RUN_ID/BASE_URL and
#   STAGING_PREFIX below) — discard only removes a staged tree and commits the
#   removal; it never runs the publisher or the landing regen.
#
# Required environment — PUBLISH_KIND=nightly only:
#   HANDOFF_FILE            path to the verified nightly_provenance.build_handoff JSON
#   RESULTS_DIR             directory of downloaded nightly-result-<major>/ legs
#
# Required environment — PUBLISH_STAGE=promote|discard only:
#   STAGING_PREFIX          "staging/<segment>", as emitted by a prior "stage"
#                        run's GITHUB_OUTPUT staging_prefix — must match
#                        staging/[0-9A-Za-z_-]+

set -eu

# Every deterministic client script gen_landing.py publishes at the site root:
# the one --channel-parameterized installer (issue #2416 follow-up) — the SOLE
# client entry point. Single source of truth for both the catalogue-NOOP `git add`
# list and the direct/promote stage_paths list below.
CLIENT_SCRIPTS="install.sh"

# Scripts the landing generator used to publish before the issue #2416
# follow-up collapsed every client entry point down to install.sh above —
# gen_landing.py no longer writes them, but a republish of an
# already-published release must still sweep them off an already-live site.
RETIRED_CLIENT_SCRIPTS="add-repo.sh migrate-channel.sh"

PUBLISH_KIND="${PUBLISH_KIND:-tagged}"
case "$PUBLISH_KIND" in
    tagged | nightly) ;;
    *)
        echo "::error::PUBLISH_KIND must be 'tagged' or 'nightly', got '${PUBLISH_KIND}'" >&2
        exit 1
        ;;
esac

PUBLISH_STAGE="${PUBLISH_STAGE:-direct}"
case "$PUBLISH_STAGE" in
    direct | stage | promote | discard) ;;
    *)
        echo "::error::PUBLISH_STAGE must be 'direct', 'stage', 'promote', or 'discard', got '${PUBLISH_STAGE}'" >&2
        exit 1
        ;;
esac

PUBLISH_REFRESH_LANDING="${PUBLISH_REFRESH_LANDING:-0}"
case "$PUBLISH_REFRESH_LANDING" in
    0 | 1) ;;
    *)
        echo "::error::PUBLISH_REFRESH_LANDING must be '0' or '1', got '${PUBLISH_REFRESH_LANDING}'" >&2
        exit 1
        ;;
esac

: "${PFB_SRC:?PFB_SRC is required}"
: "${PKG_REPO:?PKG_REPO is required}"
: "${SOURCE_RUN_ID:?SOURCE_RUN_ID is required}"
: "${BASE_URL:?BASE_URL is required}"

case "$PUBLISH_KIND" in
    tagged)
        # Required-var set depends on PUBLISH_STAGE: direct/stage run the publisher
        # (needs the full publish_release.py intake); promote only regenerates the
        # landing page + writes a commit trailer (needs a strict subset); discard
        # needs nothing here at all (issue #2389) — the workflow's promote-pkg-repo
        # job never exports ASSETS_DIR, so requiring it unconditionally broke every
        # promote/discard; only what each mode reads is required.
        case "$PUBLISH_STAGE" in
            direct | stage)
                : "${SOURCE_REPOSITORY:?SOURCE_REPOSITORY is required}"
                : "${RELEASE_ID:?RELEASE_ID is required}"
                : "${RELEASE_TAG:?RELEASE_TAG is required}"
                : "${DESTINATIONS:?DESTINATIONS is required}"
                : "${ASSETS_DIR:?ASSETS_DIR is required}"
                : "${ROUTE_MATRIX:?ROUTE_MATRIX is required}"
                ;;
            promote)
                : "${RELEASE_TAG:?RELEASE_TAG is required}"
                : "${DESTINATIONS:?DESTINATIONS is required}"
                : "${ROUTE_MATRIX:?ROUTE_MATRIX is required}"
                ;;
            discard) ;;
        esac
        ;;
    nightly)
        : "${HANDOFF_FILE:?HANDOFF_FILE is required}"
        : "${RESULTS_DIR:?RESULTS_DIR is required}"
        ;;
esac

# nightly keeps today's publish-then-gate flow untouched — staging a Nightly
# snapshot is out of scope here (see the header docblock).
if [ "$PUBLISH_KIND" = nightly ] && [ "$PUBLISH_STAGE" != direct ]; then
    echo "::error::PUBLISH_STAGE must be 'direct' when PUBLISH_KIND=nightly, got '${PUBLISH_STAGE}'" >&2
    exit 1
fi

# PUBLISH_REFRESH_LANDING=1 only makes sense on the real single-push publish
# flow — stage/promote/discard and nightly keep their own flows untouched.
if [ "$PUBLISH_REFRESH_LANDING" = 1 ] && { [ "$PUBLISH_KIND" != tagged ] || [ "$PUBLISH_STAGE" != direct ]; }; then
    echo "::error::PUBLISH_REFRESH_LANDING=1 requires PUBLISH_KIND=tagged and PUBLISH_STAGE=direct, got PUBLISH_KIND='${PUBLISH_KIND}' PUBLISH_STAGE='${PUBLISH_STAGE}'" >&2
    exit 1
fi

# --- PUBLISH_STAGE=stage: derive the staging path segment ------------------
# The real workflows set SOURCE_RUN_ID="<run_id>:<run_attempt>" (a colon), but a
# staging path is a single filesystem/git path segment — `:` is translated to
# `-` up front, and anything else outside [0-9A-Za-z_:-] (space, `/`, `.` — which
# also rules out `..`) is rejected before any git call.
if [ "$PUBLISH_STAGE" = stage ]; then
    case "$SOURCE_RUN_ID" in
        '' | *[!0-9A-Za-z_:-]*)
            echo "::error::SOURCE_RUN_ID must match [0-9A-Za-z_:-]+ when PUBLISH_STAGE=stage (used as a staging path segment), got '${SOURCE_RUN_ID}'" >&2
            exit 1
            ;;
    esac
    STAGING_SEGMENT=$(printf '%s' "$SOURCE_RUN_ID" | tr ':' '-')
    stage_prefix="staging/${STAGING_SEGMENT}"
fi

# --- PUBLISH_STAGE=promote|discard: validate the caller-supplied prefix ----
case "$PUBLISH_STAGE" in
    promote | discard)
        if [ -z "${STAGING_PREFIX:-}" ]; then
            echo "::error::STAGING_PREFIX is required when PUBLISH_STAGE=${PUBLISH_STAGE}" >&2
            exit 1
        fi
        case "$STAGING_PREFIX" in
            staging/*)
                staging_prefix_rest="${STAGING_PREFIX#staging/}"
                case "$staging_prefix_rest" in
                    '' | *[!0-9A-Za-z_-]*)
                        echo "::error::STAGING_PREFIX must match staging/[0-9A-Za-z_-]+, got '${STAGING_PREFIX}'" >&2
                        exit 1
                        ;;
                esac
                ;;
            *)
                echo "::error::STAGING_PREFIX must match staging/[0-9A-Za-z_-]+, got '${STAGING_PREFIX}'" >&2
                exit 1
                ;;
        esac
        ;;
esac

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

export PFB_SRC

# --- shell helpers (PUBLISH_STAGE stage/promote/discard) --------------------

# Removes any docs/staging tree entirely — used both to sweep a stale tree left
# by an earlier crashed "stage" run (before laying down a fresh one) and, on
# "promote", to drop the whole staging area once its content has been moved out.
remove_docs_staging_tree() {
    [ -d "${PKG_REPO}/docs/staging" ] || return 0
    if git -C "$PKG_REPO" ls-files --error-unmatch docs/staging >/dev/null 2>&1; then
        git -C "$PKG_REPO" rm -r --quiet docs/staging
    fi
    rm -rf "${PKG_REPO}/docs/staging"
}

# Stages the removal of every RETIRED_CLIENT_SCRIPTS entry still present on the
# live site, so the deletion rides the same commit as whatever else this run is
# already about to commit (NOOP script/landing refresh, or a real publish).
# --ignore-unmatch is a no-op once a script is already gone.
remove_retired_client_scripts() {
    for retired in $RETIRED_CLIENT_SCRIPTS; do
        git -C "$PKG_REPO" rm -q --ignore-unmatch -- "docs/${retired}"
    done
}

# Relocates every $touched (channel, varver) target under
# docs/staging/<segment>/ and restores the original committed bytes at its real
# location. A brand-new target has nothing tracked to restore — `git ls-files
# --error-unmatch` decides, never a blind `checkout --` that would abort under
# `set -e` for a path git has never seen.
stage_touched() {
    remove_docs_staging_tree
    for target in $touched; do
        ch="${target%%/*}"
        mkdir -p "${PKG_REPO}/docs/staging/${STAGING_SEGMENT}/${ch}"
        mv "${PKG_REPO}/docs/${target}" "${PKG_REPO}/docs/staging/${STAGING_SEGMENT}/${target}"
        if git -C "$PKG_REPO" ls-files --error-unmatch "docs/${target}" >/dev/null 2>&1; then
            git -C "$PKG_REPO" checkout --quiet -- "docs/${target}"
        fi
    done
    git -C "$PKG_REPO" add -- "docs/staging/${STAGING_SEGMENT}"
}

# Moves every (channel, varver) directory found under docs/$STAGING_PREFIX/ back
# to its real location, replacing whatever is there today, and sets $touched to
# the list of targets moved. Then drops docs/staging entirely.
promote_from_staging() {
    staging_root="${PKG_REPO}/docs/${STAGING_PREFIX}"
    if [ ! -d "$staging_root" ]; then
        echo "::error::PUBLISH_STAGE=promote: no staged tree at docs/${STAGING_PREFIX} — nothing to promote" >&2
        exit 1
    fi
    touched=""
    for ch_path in "$staging_root"/*/; do
        [ -d "$ch_path" ] || continue
        ch="${ch_path%/}"
        ch="${ch##*/}"
        for varver_path in "$ch_path"*/; do
            [ -d "$varver_path" ] || continue
            varver="${varver_path%/}"
            varver="${varver##*/}"
            target="${ch}/${varver}"
            if git -C "$PKG_REPO" ls-files --error-unmatch "docs/${target}" >/dev/null 2>&1; then
                git -C "$PKG_REPO" rm -r --quiet "docs/${target}"
            else
                rm -rf "${PKG_REPO}/docs/${target}"
            fi
            mkdir -p "${PKG_REPO}/docs/${ch}"
            git -C "$PKG_REPO" mv "docs/${STAGING_PREFIX}/${target}" "docs/${target}"
            touched="${touched}${touched:+"
"}${target}"
        done
    done
    remove_docs_staging_tree
}

# Shared by "direct" (non-noop) and "promote": regenerate the landing page and
# stage the landing output, every $touched target's directory, that dest's
# channel-level autoindex, and already-tracked dest/channel autoindexes
# gen_landing rewrote. Never a site-wide find of every docs/**/index.html —
# an untracked leftover dest from a rejected push is not this run's
# (issue #2407).
landing_regen_and_stage() {
    case "$PUBLISH_KIND" in
        tagged) landing_input="$ROUTE_MATRIX" ;;
        nightly) landing_input="$(jq -ec '.route_matrix' "$HANDOFF_FILE")" ;;
    esac
    landing_matrix_file=$(mktemp)
    printf '%s' "$landing_input" | jq -c \
        '[.[] | {abi: "FreeBSD:\(.freebsd_major):*", pfsense_version, variant, php_version, py_flavor}]' \
        >"$landing_matrix_file"
    python3 "${PFB_SRC}/scripts/gen_landing.py" \
        "${PKG_REPO}/docs" "$BASE_URL" \
        --matrix "$landing_matrix_file"
    rm -f "$landing_matrix_file"
    true >"${PKG_REPO}/docs/.nojekyll"

    stage_paths="docs/.nojekyll"
    [ -f "${PKG_REPO}/docs/index.html" ] && stage_paths="${stage_paths} docs/index.html"
    [ -f "${PKG_REPO}/docs/browse.html" ] && stage_paths="${stage_paths} docs/browse.html"
    for client_script in $CLIENT_SCRIPTS; do
        if [ ! -f "${PKG_REPO}/docs/${client_script}" ]; then
            echo "::error::gen_landing.py did not write docs/${client_script} (CLIENT_SCRIPTS/generator drift)" >&2
            exit 1
        fi
        stage_paths="${stage_paths} docs/${client_script}"
    done
    for target in $touched; do
        stage_paths="${stage_paths} docs/${target}"
        ch="${target%%/*}"
        [ -f "${PKG_REPO}/docs/${ch}/index.html" ] && stage_paths="${stage_paths} docs/${ch}/index.html"
    done
    # Already-tracked dest/channel autoindexes only. ls-files cannot name a
    # dest that is not in the index, so a leftover dest autoindex cannot
    # appear here (issue #2407).
    tracked_indexes=$(git -C "$PKG_REPO" ls-files -- 'docs/*/index.html' 'docs/*/*/index.html')
    if [ -n "$tracked_indexes" ]; then
        stage_paths="${stage_paths}
${tracked_indexes}"
    fi
    # shellcheck disable=SC2086  # stage_paths is a controlled, space/newline-separated pathspec list
    git -C "$PKG_REPO" add -- $stage_paths
}

# GITHUB_OUTPUT for PUBLISH_STAGE=stage only ($1 = noop true|false). $touched is
# newline-separated "channel/varver" tokens, possibly empty.
emit_stage_outputs() {
    [ -n "${GITHUB_OUTPUT:-}" ] || return 0
    if [ -z "$touched" ]; then
        touched_json='[]'
    else
        touched_json=$(printf '%s\n' "$touched" | jq -Rc . | jq -sc .)
    fi
    {
        printf 'staging_prefix=%s\n' "$stage_prefix"
        printf 'touched=%s\n' "$touched_json"
        printf 'noop=%s\n' "$1"
    } >>"$GITHUB_OUTPUT"
}

attempt=1
while [ "$attempt" -le "$MAX_PUSH_ATTEMPTS" ]; do
    echo "publish-pkg-repo: sync attempt ${attempt}/${MAX_PUSH_ATTEMPTS} — fetching origin/main"
    git -C "$PKG_REPO" fetch --quiet origin main
    git -C "$PKG_REPO" checkout --quiet -B main origin/main
    # checkout -B restores tracked files. Untracked leftovers from a rejected
    # push (dest autoindex without its .pkgs) survive unless cleaned. Scope
    # to docs/ so G1 debris at the repo root stays untracked (issue #2407).
    git -C "$PKG_REPO" clean -fd -- docs

    stage_commit=0

    case "$PUBLISH_STAGE" in
        promote)
            # --- promote: move a staged tree live; never runs the publisher ---
            promote_from_staging
            # A staged prefix carrying no (channel, varver) directory at all (a
            # stray file, an empty tree) is not a valid promote — regenerating the
            # landing page and committing would announce nothing while still
            # advancing main, silently.
            [ -n "$touched" ] || {
                echo "::error::PUBLISH_STAGE=promote: no <channel>/<varver> under docs/${STAGING_PREFIX}" >&2
                exit 1
            }
            landing_regen_and_stage
            commit_message=$(printf 'publish: %s -> %s\n\npfBlockerNG-Release-Tag: %s\npfBlockerNG-Source-Run-Id: %s\npfBlockerNG-Promoted-From: %s\n' \
                "$RELEASE_TAG" "$DESTINATIONS" "$RELEASE_TAG" "$SOURCE_RUN_ID" "$STAGING_PREFIX")
            ;;
        discard)
            # --- discard: drop a staged tree; never runs the publisher ---------
            staging_dir="${PKG_REPO}/docs/${STAGING_PREFIX}"
            if [ ! -d "$staging_dir" ]; then
                # A discard after a failed/already-discarded stage must be safe.
                echo "publish-pkg-repo: DISCARD NOOP — nothing staged at docs/${STAGING_PREFIX}."
                exit 0
            fi
            if git -C "$PKG_REPO" ls-files --error-unmatch "docs/${STAGING_PREFIX}" >/dev/null 2>&1; then
                git -C "$PKG_REPO" rm -r --quiet "docs/${STAGING_PREFIX}"
            else
                rm -rf "$staging_dir"
            fi
            parent_staging="${PKG_REPO}/docs/staging"
            if [ -d "$parent_staging" ] && [ -z "$(find "$parent_staging" -mindepth 1 -print -quit)" ]; then
                rmdir "$parent_staging"
            fi
            commit_message=$(printf 'publish: discard %s\n\npfBlockerNG-Source-Run-Id: %s\n' "$STAGING_PREFIX" "$SOURCE_RUN_ID")
            ;;
        direct | stage)
            # --- verify + assemble (never runs git) ----------------------------
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

            # --- stage: drop a phantom-touched target BEFORE it can be staged -----
            # The publisher's own "updated <target>" report and the tree's real
            # state can, in principle, disagree (a write that resolves to
            # byte-identical content, a mid-fix regression). Filtering here, before
            # stage_touched's own mv, means the empty-touched branch just below
            # (unconditional for every mode) already handles "all dropped" as the
            # ordinary STAGE NOOP case — no separate code path needed.
            if [ "$PUBLISH_STAGE" = stage ] && [ -n "$touched" ]; then
                real_touched=""
                for target in $touched; do
                    if [ -n "$(git -C "$PKG_REPO" status --porcelain -- "docs/${target}")" ]; then
                        real_touched="${real_touched}${real_touched:+"
"}${target}"
                    else
                        echo "publish-pkg-repo: stage — ${target} reported updated but unchanged; not staged"
                    fi
                done
                touched="$real_touched"
            fi

            script_refresh=0
            if [ -z "$touched" ]; then
                # --- catalogue unchanged: the client scripts (or, with
                # PUBLISH_REFRESH_LANDING=1, the whole landing page) may still have
                # drifted --------------------------------------------------------
                # Every client script (CLIENT_SCRIPTS) is generated from the PFB_SRC
                # checkout, not from the release assets, so a script-only fix must ship
                # even when every destination already matches (issue #2408, issue #2416).
                # By default only the deterministic script set is regenerated here —
                # the landing/browse/autoindex pages embed a generation timestamp, and
                # writing them on every no-op would manufacture a commit on every run.
                # PUBLISH_REFRESH_LANDING=1 (validated tagged+direct-only above) opts
                # into the full regen instead, for a landing-only fix (issue #2416
                # follow-up).
                if [ "$PUBLISH_REFRESH_LANDING" = 1 ]; then
                    landing_regen_and_stage
                else
                    python3 "${PFB_SRC}/scripts/gen_landing.py" \
                        "${PKG_REPO}/docs" "$BASE_URL" \
                        --client-scripts-only
                    client_script_paths=""
                    for client_script in $CLIENT_SCRIPTS; do
                        client_script_paths="${client_script_paths} docs/${client_script}"
                    done
                    # shellcheck disable=SC2086  # client_script_paths is a controlled, space-separated pathspec list
                    git -C "$PKG_REPO" add -- $client_script_paths
                fi
                remove_retired_client_scripts
                if git -C "$PKG_REPO" diff --cached --quiet; then
                    if [ "$PUBLISH_STAGE" = stage ]; then
                        emit_stage_outputs true
                        echo "publish-pkg-repo: STAGE NOOP — nothing to gate."
                    fi
                    echo "publish-pkg-repo: NOOP — nothing touched, nothing to commit."
                    exit 0
                fi
                if [ "$PUBLISH_REFRESH_LANDING" = 1 ]; then
                    echo "publish-pkg-repo: catalogue unchanged — PUBLISH_REFRESH_LANDING=1; committing a landing refresh."
                else
                    echo "publish-pkg-repo: catalogue unchanged — client script(s) drifted; committing a script refresh."
                fi
                script_refresh=1
            elif [ "$PUBLISH_STAGE" = stage ]; then
                # --- stage: relocate the publisher's output, never serve it --------
                stage_touched
                stage_commit=1
            else
                # --- landing page regen — only for an actual publish ---------------
                # Never on the catalogue-NOOP path above: gen_landing.py's page output
                # embeds a generation timestamp, so running it there would manufacture
                # a diff (and therefore a commit) on every run even when no catalogue
                # changed.
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
                landing_regen_and_stage
                remove_retired_client_scripts

                # --- stage EXACTLY what changed — never -A / . ----------------------
                if git -C "$PKG_REPO" diff --cached --quiet; then
                    echo "publish-pkg-repo: NOOP — the publisher reported changes but nothing is staged; discarding."
                    git -C "$PKG_REPO" reset --quiet
                    exit 0
                fi
            fi

            if [ "$script_refresh" -eq 1 ]; then
                # Mode-independent: the refresh carries no release/nightly identity —
                # its content comes from PFB_SRC, so the run id is the whole provenance.
                if [ "$PUBLISH_REFRESH_LANDING" = 1 ]; then
                    commit_message=$(printf 'publish: refresh landing page\n\npfBlockerNG-Source-Run-Id: %s\n' \
                        "$SOURCE_RUN_ID")
                else
                    commit_message=$(printf 'publish: refresh client scripts\n\npfBlockerNG-Source-Run-Id: %s\n' \
                        "$SOURCE_RUN_ID")
                fi
            elif [ "$PUBLISH_STAGE" = stage ]; then
                commit_message=$(printf 'publish: stage %s -> %s\n\npfBlockerNG-Release-Tag: %s\npfBlockerNG-Source-Run-Id: %s\npfBlockerNG-Staging-Prefix: %s\n' \
                    "$RELEASE_TAG" "$DESTINATIONS" "$RELEASE_TAG" "$SOURCE_RUN_ID" "$stage_prefix")
            else
                case "$PUBLISH_KIND" in
                    tagged)
                        commit_message=$(printf 'publish: %s -> %s\n\npfBlockerNG-Release-Tag: %s\npfBlockerNG-Source-Run-Id: %s\n' \
                            "$RELEASE_TAG" "$DESTINATIONS" "$RELEASE_TAG" "$SOURCE_RUN_ID")
                        ;;
                    nightly)
                        # jq -er: a missing/null pkg_version aborts here (via
                        # set -e) before any commit — same containment rule as a non-zero
                        # exit from the publisher itself further up.
                        nightly_pkg_version=$(jq -er '.pkg_version' "$HANDOFF_FILE")
                        commit_message=$(printf 'publish: nightly %s -> ["nightly"]\n\npfBlockerNG-Nightly-Version: %s\npfBlockerNG-Source-Run-Id: %s\n' \
                            "$nightly_pkg_version" "$nightly_pkg_version" "$SOURCE_RUN_ID")
                        ;;
                esac
            fi
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
        if [ "$PUBLISH_STAGE" = stage ]; then
            # stage_commit=0 here means the ADVANCE was a script-only refresh
            # (script_refresh=1: touched was empty, but the client scripts had
            # drifted) — there is nothing to gate, so this is a noop from the
            # caller's point of view even though a commit landed.
            if [ "$stage_commit" -eq 1 ]; then
                emit_stage_outputs false
            else
                emit_stage_outputs true
            fi
        fi
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
