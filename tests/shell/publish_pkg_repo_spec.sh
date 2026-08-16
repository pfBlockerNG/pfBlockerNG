#shellcheck shell=sh
# publish_pkg_repo_spec.sh — scripts/publish-pkg-repo.sh.
#
# publish_release.py and publish_nightly.py are stubbed (a fake PFB_SRC checkout,
# see setup()): git mutation is the ONLY thing this script owns, and it is exactly
# what this spec exercises — network/engine verification is each publisher's own,
# already-covered PFB_SRC=... python3 -m unittest suite (pkg repo). Site rendering
# is NOT this script's job (issue #2450 step 2) — render-pkg-site.sh's own spec
# (render_pkg_site_spec.sh) covers that. Fixture: a bare "remote" origin plus a
# working PKG_REPO clone already carrying one committed catalogue directory
# (docs/edge/ce-2.8), mirroring what the release job's checkout looks like before
# this script runs.
#
# CONTAINMENT: two independent guards are exercised here. The publisher
# fault-injection case (a mid-regeneration write-back fault: wipe the catalog
# descriptor files, leave an orphaned .pkg, THEN exit non-zero) asserts the
# damaged working tree never reaches a commit and the bare origin never moves.
# The catalogue-only-staged guard (g1/g1b) asserts a hostile or drifted "updated
# <path>" report that reaches outside docs/<stable|testing|edge|nightly|staging>/
# is rejected before any commit, even though the per-target `git add` alone would
# otherwise trust the report blindly.

Describe 'publish-pkg-repo.sh'
  script="${PFB_ROOT}/scripts/publish-pkg-repo.sh"

  setup() {
    scrub_git_env
    base="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pubpkgrepo.XXXXXX")"

    # --- bare origin + a working PKG_REPO clone with one committed catalogue ---
    git_fixture init -q --bare "${base}/remote.git"
    git_fixture clone -q "${base}/remote.git" "${base}/pkg-repo" 2>/dev/null
    git_fixture -C "${base}/pkg-repo" config user.email pub@example.com
    git_fixture -C "${base}/pkg-repo" config user.name pub
    git_fixture -C "${base}/pkg-repo" config commit.gpgsign false
    mkdir -p "${base}/pkg-repo/docs/edge/ce-2.8"
    echo seed > "${base}/pkg-repo/docs/edge/ce-2.8/meta.conf"
    echo seed > "${base}/pkg-repo/docs/edge/ce-2.8/data.pkg"
    echo seed > "${base}/pkg-repo/docs/edge/ce-2.8/packagesite.pkg"
    # An unrelated tracked file, outside docs/ entirely: one example dirties it
    # (never a member of any (channel, varver) target) to prove the explicit
    # pathspec, not `git add -A`, is what actually runs.
    echo seed > "${base}/pkg-repo/README.txt"
    ( cd "${base}/pkg-repo" && git_fixture checkout -q -b main \
        && git_fixture add docs README.txt && git_fixture commit -q -m seed \
        && git_fixture push -q origin main )
    original_head="$(git_fixture -C "${base}/pkg-repo" rev-parse main)"
    original_remote_head="$(git_fixture -C "${base}/remote.git" rev-parse refs/heads/main)"

    # --- fake PFB_SRC: stub publish_release.py + publish_nightly.py ---------
    # Real network/engine verification is each publisher's own unit suite
    # (pkg repo); this script's OWN job is the git mutation around it, so the
    # python calls are doubled here rather than re-verified.
    mkdir -p "${base}/fake-src/scripts"
    cat >"${base}/fake-src/scripts/publish_release.py" <<'PY'
import os
import sys


def _arg(name, argv):
    return argv[argv.index(name) + 1]


def main():
    argv = sys.argv[1:]
    pkg_repo = _arg("--pkg-repo", argv)
    mode = os.environ.get("FAKE_MODE", "success")

    if mode == "fail":
        # Mirrors catalogue_assembly.py's own documented third outcome (a
        # write-back fault after the wipe): wipe the catalog descriptors and
        # leave an orphaned .pkg, THEN report failure. The wrapper script must
        # never stage or commit this damage.
        damaged = os.path.join(pkg_repo, "docs", "edge", "ce-2.8")
        os.makedirs(damaged, exist_ok=True)
        for name in ("meta.conf", "data.pkg", "packagesite.pkg"):
            path = os.path.join(damaged, name)
            if os.path.exists(path):
                os.remove(path)
        with open(os.path.join(damaged, "orphan.pkg"), "w") as fh:
            fh.write("damaged")
        print("::error::simulated mid-regeneration fault", file=sys.stderr)
        return 1

    if mode == "noop":
        print("NOOP: every destination already matches this run's verified assets")
        return 0

    if mode == "phantom":
        # Reports a target touched WITHOUT writing anything under docs/ — the
        # wrapper's own "reported changes but nothing is actually staged"
        # discard path exists for exactly this: publish_release.py's own
        # touched-report and the tree's real state can, in principle, disagree.
        for target in os.environ.get("FAKE_TOUCHED", "").split(","):
            target = target.strip()
            if target:
                print(f"updated {target}")
        return 0

    if mode == "rename_fold":
        # g1c (hostile): a rename-SHAPED diff. docs/index.html (non-catalogue,
        # already tracked) is deleted, and a NEW catalogue-owned file is added
        # carrying its exact bytes -- git's own default rename detection pairs
        # a genuine delete with a genuine add of near-identical content, so
        # `git diff --cached --name-only` (no --no-renames) shows ONLY the
        # catalogue-side name, hiding the non-catalogue deletion entirely. The
        # wrapper's guard must not depend on that git default.
        docs_dir = os.path.join(pkg_repo, "docs")
        with open(os.path.join(docs_dir, "index.html"), "rb") as fh:
            index_bytes = fh.read()
        target_dir = os.path.join(docs_dir, "edge", "ce-2.8")
        os.makedirs(target_dir, exist_ok=True)
        with open(os.path.join(target_dir, "data.pkg"), "wb") as fh:
            fh.write(index_bytes)
        os.remove(os.path.join(docs_dir, "index.html"))
        print("updated index.html")
        print("updated edge/ce-2.8")
        return 0

    for target in os.environ.get("FAKE_TOUCHED", "").split(","):
        target = target.strip()
        if not target:
            continue
        # Hostile/drifted report (g1/g1b): a `..`-bearing target resolves
        # OUTSIDE docs/ entirely — the wrapper's own containment guard (never
        # this stub) is what must catch it, so this writes directly to the
        # resolved path instead of assuming target is always a fresh directory.
        if ".." in target.split("/"):
            resolved = os.path.normpath(os.path.join(pkg_repo, "docs", target))
            with open(resolved, "a") as fh:
                fh.write("\ntraversal\n")
        else:
            target_dir = os.path.join(pkg_repo, "docs", target)
            os.makedirs(target_dir, exist_ok=True)
            with open(os.path.join(target_dir, "marker.pkg"), "w") as fh:
                fh.write(target)
        print(f"updated {target}")
    return 0


sys.exit(main())
PY

    # --- fake publish_nightly.py — the Nightly-mode counterpart to the
    # publish_release.py stub above. Same doubling rationale: real handoff/asset
    # verification is publish_nightly.py's own unit suite
    # (tests/test_publish_nightly.py); this script's OWN job — the git mutation
    # and mode-routing around it — is what this spec exercises. Always reads the
    # handoff JSON (mirrors the real module's own read+parse-first behaviour) so
    # an invalid HANDOFF_FILE fails here, before any git mutation, exactly like a
    # real verification failure would.
    cat >"${base}/fake-src/scripts/publish_nightly.py" <<'PY'
import json
import os
import sys


def _arg(name, argv):
    return argv[argv.index(name) + 1]


def main():
    argv = sys.argv[1:]
    pkg_repo = _arg("--pkg-repo", argv)
    handoff_path = _arg("--handoff", argv)
    mode = os.environ.get("FAKE_MODE", "success")

    # Records the exact argv this invocation received, for the spec's own
    # assertions -- proves the wrapper forwards all four flags with the right
    # values, not just that SOME python3 call happened.
    record_path = os.environ.get("FAKE_INVOCATION_RECORD")
    if record_path:
        with open(record_path, "w") as fh:
            fh.write("\n".join(argv))

    try:
        with open(handoff_path, encoding="utf-8") as fh:
            json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"::error::simulated handoff read/parse failure: {exc}", file=sys.stderr)
        return 1

    if mode == "fail":
        print("::error::simulated nightly publish fault", file=sys.stderr)
        return 1

    if mode == "noop":
        print("NOOP: every destination already matches this run's verified assets")
        return 0

    for target in os.environ.get("FAKE_TOUCHED", "").split(","):
        target = target.strip()
        if not target:
            continue
        target_dir = os.path.join(pkg_repo, "docs", target)
        os.makedirs(target_dir, exist_ok=True)
        with open(os.path.join(target_dir, "marker.pkg"), "w") as fh:
            fh.write(target)
        print(f"updated {target}")
    return 0


sys.exit(main())
PY

    common_env() {
        PFB_SRC="${base}/fake-src"
        PKG_REPO="${base}/pkg-repo"
        SOURCE_REPOSITORY=pfBlockerNG/pfBlockerNG
        RELEASE_ID=1
        RELEASE_TAG=v4.0.0.b1
        DESTINATIONS='["edge"]'
        SOURCE_RUN_ID=10:1
        ASSETS_DIR="${base}/assets"
        ROUTE_MATRIX='[{"freebsd_major":"15","pfsense_version":"2.8","variant":"CE","php_version":"8.3","py_flavor":"py311"}]'
        export PFB_SRC PKG_REPO SOURCE_REPOSITORY RELEASE_ID RELEASE_TAG DESTINATIONS SOURCE_RUN_ID ASSETS_DIR ROUTE_MATRIX
    }
    common_env
    mkdir -p "${base}/assets"
  }

  cleanup() {
    rm -rf "$base"
  }

  BeforeEach 'setup'
  AfterEach 'cleanup'

  remote_head_now() {
    git_fixture -C "${base}/remote.git" rev-parse refs/heads/main
  }
  local_head_now() {
    # A failed resolution reports a sentinel, never $original_head: the containment
    # example asserts the head still EQUALS $original_head, so substituting it on
    # failure would let an unreadable repository (deleted ref, broken .git, detached
    # HEAD after a failed checkout -B) pass as "HEAD did not move".
    git_fixture -C "${base}/pkg-repo" rev-parse main 2>/dev/null || echo "UNRESOLVABLE-main"
  }

  # --- PUBLISH_KIND=nightly fixture ------------------------------------------
  # Layered on top of common_env (already exported by setup()): keeps the shared
  # vars (PFB_SRC/PKG_REPO/SOURCE_RUN_ID) and adds the nightly-only ones.
  # Tagged-only vars are deliberately left exported by common_env in most nightly
  # examples -- proving they are IGNORED, not merely absent (see the "does not
  # leak a tagged trailer" example) -- except where a test explicitly unsets them.
  nightly_env() {
    PUBLISH_KIND=nightly
    HANDOFF_FILE="${base}/nightly-handoff.json"
    RESULTS_DIR="${base}/results"
    export PUBLISH_KIND HANDOFF_FILE RESULTS_DIR
    mkdir -p "$RESULTS_DIR"
    cat > "$HANDOFF_FILE" <<'JSON'
{"run_id":"10:1","pkg_version":"20260804153045.aaaaaaa","route_matrix":[{"freebsd_major":"16","pfsense_version":"2.9","variant":"Plus","php_version":"8.4","py_flavor":"py312"}]}
JSON
  }

  # --- g1/g1b: the catalogue-only-staged guard (issue #2450 step 2) ----------
  # A hostile or drifted "updated <path>" report is the load-bearing red canary:
  # the per-target `git add -- docs/<target>` alone would stage whatever git
  # resolves that pathspec to, however it escapes docs/ — this guard is the
  # only thing that catches it, on every mode, right before every commit.

  It 'g1 (hostile): refuses to commit when the staged diff reaches outside the catalogue trees'
    export FAKE_MODE=success
    export FAKE_TOUCHED='../README.txt'
    When run script "$script"
    The status should equal 1
    The stderr should include '::error::publisher commit touched non-catalogue path(s):'
    The stderr should include 'README.txt'
    The result of function local_head_now should equal "$original_head"
    The result of function remote_head_now should equal "$original_remote_head"
    staged="$(git_fixture -C "${base}/pkg-repo" diff --cached --name-only)"
    The variable staged should equal ''
  End

  It 'g1b (hostile): refuses a traversal target that resolves outside docs/ but still inside the repo'
    export FAKE_MODE=success
    export FAKE_TOUCHED='stable/../../x'
    When run script "$script"
    The status should equal 1
    The stderr should include '::error::publisher commit touched non-catalogue path(s):'
    The result of function local_head_now should equal "$original_head"
    The result of function remote_head_now should equal "$original_remote_head"
    staged="$(git_fixture -C "${base}/pkg-repo" diff --cached --name-only)"
    The variable staged should equal ''
  End

  It 'g1c: a rename-shaped diff (non-catalogue file deleted, similar bytes added under a catalogue path) is still rejected'
    # Fixture: seed a tracked docs/index.html (>=200 bytes -- past git's default
    # rename-similarity threshold) and drop the pre-existing docs/edge/ce-2.8/data.pkg
    # from HEAD, so the stub's own recreation of data.pkg below is a genuine ADD, not
    # a MODIFY -- required for git's default rename detection to even consider pairing
    # it with the deletion of docs/index.html (a same-path modify can never become R).
    content=""
    i=0
    while [ "$i" -lt 200 ]; do
        content="${content}x"
        i=$((i + 1))
    done
    printf '%s\n' "$content" > "${base}/pkg-repo/docs/index.html"
    git_fixture -C "${base}/pkg-repo" add docs/index.html
    git_fixture -C "${base}/pkg-repo" rm -q docs/edge/ce-2.8/data.pkg
    git_fixture -C "${base}/pkg-repo" commit -q -m 'g1c fixture: seed docs/index.html, drop data.pkg'
    git_fixture -C "${base}/pkg-repo" push -q origin main
    pretest_head="$(git_fixture -C "${base}/pkg-repo" rev-parse main)"
    pretest_remote_head="$(git_fixture -C "${base}/remote.git" rev-parse refs/heads/main)"
    export FAKE_MODE=rename_fold
    When run script "$script"
    The status should equal 1
    The stderr should include '::error::publisher commit touched non-catalogue path(s):'
    The stderr should include 'docs/index.html'
    The result of function local_head_now should equal "$pretest_head"
    The result of function remote_head_now should equal "$pretest_remote_head"
    staged="$(git_fixture -C "${base}/pkg-repo" diff --cached --name-only)"
    The variable staged should equal ''
  End

  It 'g2: a direct publish commits ONLY docs/<channel>/<varver> paths'
    export FAKE_MODE=success
    export FAKE_TOUCHED=edge/ce-2.8
    When run script "$script"
    The status should equal 0
    The output should include 'ADVANCE'
    The stderr should include 'main'
    committed="$(git_fixture -C "${base}/pkg-repo" show --name-only --format= HEAD | sort | xargs)"
    The variable committed should equal 'docs/edge/ce-2.8/marker.pkg'
  End

  # --- success path ----------------------------------------------------------

  It 'never sweeps a stray untracked file or an unrelated dirty tracked file into the commit'
    # Proves the explicit pathspec, not `git add -A`/`.`, is what runs —
    # debris.txt is untracked, README.txt is tracked but outside every
    # (channel, varver) target.
    export FAKE_MODE=success
    export FAKE_TOUCHED=edge/ce-2.8
    echo dirty >> "${base}/pkg-repo/README.txt"
    echo stray > "${base}/pkg-repo/debris.txt"
    When run script "$script"
    The status should equal 0
    The output should include 'ADVANCE'
    The stderr should include 'main'
    committed="$(git_fixture -C "${base}/pkg-repo" show --stat --format= HEAD | tr -s ' ' | sed 's/^ *//;s/ .*//')"
    The variable committed should not include 'README.txt'
    The variable committed should not include 'debris.txt'
    porcelain="$(git_fixture -C "${base}/pkg-repo" status --porcelain)"
    The variable porcelain should include 'README.txt'
    The variable porcelain should include 'debris.txt'
  End

  # --- leftover dest autoindex from a rejected push (issue #2407) -----------
  # Dual defense: `git clean -fd -- docs` after checkout -B, and the explicit
  # per-target pathspec, never a site-wide add. Each pin below is independent —
  # dropping only one defense must turn that pin RED.

  It 'cleans an untracked leftover dest autoindex off disk after checkout -B'
    # Clean pin: leftover must not exist on disk after ADVANCE. Dropping
    # `git clean -fd -- docs` leaves the untracked dest and this example goes
    # RED. G1 debris/README stay uncommitted.
    mkdir -p "${base}/pkg-repo/docs/nightly/ce-2.8"
    printf 'orphan autoindex\n' > "${base}/pkg-repo/docs/nightly/ce-2.8/index.html"
    echo dirty >> "${base}/pkg-repo/README.txt"
    echo stray > "${base}/pkg-repo/debris.txt"
    export FAKE_MODE=success
    export FAKE_TOUCHED=edge/ce-2.8
    When run script "$script"
    The status should equal 0
    The output should include 'ADVANCE'
    The stderr should include 'main'
    The path "${base}/pkg-repo/docs/nightly/ce-2.8/index.html" should not be exist
    committed="$(git_fixture -C "${base}/pkg-repo" show --name-only --format= HEAD)"
    The variable committed should not include 'docs/nightly/ce-2.8/index.html'
    The variable committed should include 'docs/edge/ce-2.8/marker.pkg'
    The variable committed should not include 'README.txt'
    The variable committed should not include 'debris.txt'
    tracked_leftover="$(git_fixture -C "${base}/pkg-repo" ls-files -- docs/nightly/ce-2.8/index.html)"
    The variable tracked_leftover should equal ''
    porcelain="$(git_fixture -C "${base}/pkg-repo" status --porcelain)"
    The variable porcelain should include 'README.txt'
    The variable porcelain should include 'debris.txt'
  End

  It 'cleans leftover dest payload next to an orphan autoindex and never tracks it'
    # Clean pin for the leftover .pkg as well: both paths gone from disk.
    # marker.pkg must also stay out of the commit and the index.
    mkdir -p "${base}/pkg-repo/docs/nightly/ce-2.8"
    printf 'orphan autoindex\n' > "${base}/pkg-repo/docs/nightly/ce-2.8/index.html"
    printf 'leftover\n' > "${base}/pkg-repo/docs/nightly/ce-2.8/marker.pkg"
    export FAKE_MODE=success
    export FAKE_TOUCHED=edge/ce-2.8
    When run script "$script"
    The status should equal 0
    The output should include 'ADVANCE'
    The stderr should include 'main'
    The path "${base}/pkg-repo/docs/nightly/ce-2.8/index.html" should not be exist
    The path "${base}/pkg-repo/docs/nightly/ce-2.8/marker.pkg" should not be exist
    committed="$(git_fixture -C "${base}/pkg-repo" show --name-only --format= HEAD)"
    The variable committed should not include 'docs/nightly/ce-2.8/index.html'
    The variable committed should not include 'docs/nightly/ce-2.8/marker.pkg'
    tracked_leftover="$(git_fixture -C "${base}/pkg-repo" ls-files -- docs/nightly/ce-2.8)"
    The variable tracked_leftover should equal ''
  End

  # --- the script must be self-sufficient for git identity -----------------

  It 'commits with a fixed bot identity even when no git identity is configured anywhere'
    # Reproduces the GitHub-hosted-runner state: no user.name/user.email in the
    # fixture repo, no global/system config, no GIT_AUTHOR_*/GIT_COMMITTER_* env
    # — a bare environment falls back to auto-detecting SOME identity from the
    # OS account/hostname (which is itself the failure mode: real GitHub-hosted
    # runners auto-detect an unusable one and die outright), so the assertion
    # that matters is that the LANDED identity is the fixed bot one, never
    # whatever the ambient environment happened to guess.
    git_fixture -C "${base}/pkg-repo" config --unset user.email
    git_fixture -C "${base}/pkg-repo" config --unset user.name
    export GIT_CONFIG_GLOBAL=/dev/null
    export GIT_CONFIG_SYSTEM=/dev/null
    unset GIT_AUTHOR_NAME GIT_AUTHOR_EMAIL GIT_COMMITTER_NAME GIT_COMMITTER_EMAIL
    export FAKE_MODE=success
    export FAKE_TOUCHED=edge/ce-2.8
    When run script "$script"
    The status should equal 0
    The output should include 'ADVANCE'
    The stderr should include 'main'
    author="$(git_fixture -C "${base}/pkg-repo" log -1 --format='%an <%ae>')"
    committer="$(git_fixture -C "${base}/pkg-repo" log -1 --format='%cn <%ce>')"
    The variable author should equal 'github-actions[bot] <github-actions[bot]@users.noreply.github.com>'
    The variable committer should equal 'github-actions[bot] <github-actions[bot]@users.noreply.github.com>'
  End

  It 'the commit message carries the release tag and source_run_id as trailers'
    export FAKE_MODE=success
    export FAKE_TOUCHED=edge/ce-2.8
    When run script "$script"
    The status should equal 0
    The output should include 'ADVANCE'
    The stderr should include 'main'
    msg="$(git_fixture -C "${base}/pkg-repo" log -1 --format=%B)"
    The variable msg should include 'pfBlockerNG-Release-Tag: v4.0.0.b1'
    The variable msg should include 'pfBlockerNG-Source-Run-Id: 10:1'
  End

  # --- no-op path --------------------------------------------------------

  It 'commits nothing on a no-op run'
    export FAKE_MODE=noop
    When run script "$script"
    The status should equal 0
    The output should include 'NOOP'
    The result of function local_head_now should equal "$original_head"
    The result of function remote_head_now should equal "$original_remote_head"
  End

  It 'commits nothing when a reported touched target leaves the tree unchanged'
    # publish_release.py reports "updated edge/ce-2.8" but writes nothing
    # under docs/ — the tree itself never changed, so `git diff --cached
    # --quiet` after staging must find nothing to commit — the discard path,
    # not the guard, is what this reaches.
    export FAKE_MODE=phantom
    export FAKE_TOUCHED=edge/ce-2.8
    When run script "$script"
    The status should equal 0
    The output should include 'NOOP'
    The result of function local_head_now should equal "$original_head"
    The result of function remote_head_now should equal "$original_remote_head"
  End

  # --- a damaged working tree must never reach a commit --------------------

  It 'never commits or pushes a mid-regeneration fault, even though the working tree is left damaged'
    export FAKE_MODE=fail
    When run script "$script"
    The status should equal 1
    The stderr should include 'simulated mid-regeneration fault'
    The result of function local_head_now should equal "$original_head"
    The result of function remote_head_now should equal "$original_remote_head"
    The path "${base}/pkg-repo/docs/edge/ce-2.8/orphan.pkg" should be exist
    The path "${base}/pkg-repo/docs/edge/ce-2.8/meta.conf" should not be exist
  End

  # --- the push resync-retry loop -------------------------------------------
  # A pre-receive hook in the bare origin drives deterministic rejections
  # (a counter file rejects the first N attempts, or all of them). Its own
  # message carries a non-fast-forward-shaped phrase ("fetch first") so the
  # rejection is classified as remote contention, matching what a real
  # racing push looks like from the client's side.

  It 're-syncs and republishes after a rejected push, without rebasing the local commit'
    reject_count_file="${base}/reject_count"
    printf '2\n' > "$reject_count_file"
    cat > "${base}/remote.git/hooks/pre-receive" <<HOOK
#!/bin/sh
n=\$(cat "$reject_count_file" 2>/dev/null || echo 0)
if [ "\$n" -gt 0 ]; then
    echo \$((n - 1)) > "$reject_count_file"
    echo "simulated contention — fetch first" >&2
    exit 1
fi
exit 0
HOOK
    chmod +x "${base}/remote.git/hooks/pre-receive"
    export FAKE_MODE=success
    export FAKE_TOUCHED=edge/ce-2.8
    When run script "$script"
    The status should equal 0
    The output should include 'ADVANCE'
    The stderr should include 'push rejected (attempt 1/5)'
    The stderr should include 'push rejected (attempt 2/5)'
    The output should include 'sync attempt 3/5'
    The result of function local_head_now should not equal "$original_head"
    The result of function remote_head_now should not equal "$original_remote_head"
    # Never a rebase of the original local commit: each retry fully re-syncs
    # from origin/main (checkout -B), so only ONE publish commit ever lands on
    # top of the seed commit, however many attempts it took.
    commit_count="$(git_fixture -C "${base}/pkg-repo" rev-list --count main)"
    The variable commit_count should equal 2
  End

  It 'gives up after MAX_PUSH_ATTEMPTS rejections, exits 1, and leaves the remote unmoved'
    cat > "${base}/remote.git/hooks/pre-receive" <<'HOOK'
#!/bin/sh
echo "simulated contention — fetch first" >&2
exit 1
HOOK
    chmod +x "${base}/remote.git/hooks/pre-receive"
    export FAKE_MODE=success
    export FAKE_TOUCHED=edge/ce-2.8
    export MAX_PUSH_ATTEMPTS=2
    When run script "$script"
    The status should equal 1
    The stderr should include '::error::push rejected 2 times in a row; giving up'
    The result of function remote_head_now should equal "$original_remote_head"
  End

  It 'refuses a MAX_PUSH_ATTEMPTS that cannot produce a single attempt'
    # A bound of 0 (or a non-numeric value) makes the loop body unreachable, so
    # the script would fall straight through to the give-up branch and report a
    # push rejection for a push it never attempted.
    export FAKE_MODE=success
    export FAKE_TOUCHED=edge/ce-2.8
    export MAX_PUSH_ATTEMPTS=0
    When run script "$script"
    The status should equal 1
    The stderr should include '::error::MAX_PUSH_ATTEMPTS must be a positive integer'
    The stderr should not include 'push rejected'
    The result of function remote_head_now should equal "$original_remote_head"
  End

  It 'refuses a non-numeric MAX_PUSH_ATTEMPTS'
    export FAKE_MODE=success
    export FAKE_TOUCHED=edge/ce-2.8
    export MAX_PUSH_ATTEMPTS=many
    When run script "$script"
    The status should equal 1
    The stderr should include '::error::MAX_PUSH_ATTEMPTS must be a positive integer'
    The result of function remote_head_now should equal "$original_remote_head"
  End

  # --- a hard push failure is not remote contention -------------------------

  It 'a push that fails for an authentication-shaped reason makes exactly one attempt and does not retry'
    # A client-side pre-push hook stands in for an expired token / network
    # fault / protected-branch rejection: none of those are "another run
    # advanced main", so the failure must be reported once, distinctly, and
    # never retried.
    export FAKE_MODE=success
    export FAKE_TOUCHED=edge/ce-2.8
    cat > "${base}/pkg-repo/.git/hooks/pre-push" <<'HOOK'
#!/bin/sh
echo "fatal: Authentication failed for the requested URL" >&2
exit 1
HOOK
    chmod +x "${base}/pkg-repo/.git/hooks/pre-push"
    When run script "$script"
    The status should equal 1
    The stderr should include 'Authentication failed'
    The stderr should include 'aborting without retry'
    The stderr should not include 'push rejected'
    The output should not include 'sync attempt 2/'
    The result of function remote_head_now should equal "$original_remote_head"
  End

  # --- PUBLISH_KIND=nightly (issue #2146 S3) --------------------------------

  It 'n1: nightly mode invokes publish_nightly.py with the four required flags and publishes on updated output'
    nightly_env
    export FAKE_MODE=success
    export FAKE_TOUCHED=nightly/ce-2.8
    export FAKE_INVOCATION_RECORD="${base}/nightly-invocation.txt"
    When run script "$script"
    The status should equal 0
    The output should include 'ADVANCE'
    The stderr should include 'main'
    invocation="$(cat "${base}/nightly-invocation.txt")"
    The variable invocation should include '--handoff'
    The variable invocation should include "$HANDOFF_FILE"
    The variable invocation should include '--results-dir'
    The variable invocation should include "$RESULTS_DIR"
    The variable invocation should include '--pkg-repo'
    The variable invocation should include "${base}/pkg-repo"
    The variable invocation should include '--source-run-id'
    The variable invocation should include '10:1'
  End

  It 'n2a: nightly mode fails before any git call when HANDOFF_FILE is missing'
    nightly_env
    unset HANDOFF_FILE
    export FAKE_MODE=success
    export FAKE_TOUCHED=nightly/ce-2.8
    When run script "$script"
    The status should not equal 0
    The stderr should include 'HANDOFF_FILE is required'
    The result of function local_head_now should equal "$original_head"
    The result of function remote_head_now should equal "$original_remote_head"
  End

  It 'n2b: nightly mode fails before any git call when RESULTS_DIR is missing'
    nightly_env
    unset RESULTS_DIR
    export FAKE_MODE=success
    export FAKE_TOUCHED=nightly/ce-2.8
    When run script "$script"
    The status should not equal 0
    The stderr should include 'RESULTS_DIR is required'
    The result of function local_head_now should equal "$original_head"
    The result of function remote_head_now should equal "$original_remote_head"
  End

  It 'n2c: nightly mode fails before any git call when SOURCE_RUN_ID is missing'
    nightly_env
    unset SOURCE_RUN_ID
    export FAKE_MODE=success
    export FAKE_TOUCHED=nightly/ce-2.8
    When run script "$script"
    The status should not equal 0
    The stderr should include 'SOURCE_RUN_ID is required'
    The result of function local_head_now should equal "$original_head"
    The result of function remote_head_now should equal "$original_remote_head"
  End

  It 'n3: nightly mode does not require any tagged-only env var'
    nightly_env
    unset SOURCE_REPOSITORY RELEASE_ID RELEASE_TAG DESTINATIONS ASSETS_DIR ROUTE_MATRIX
    export FAKE_MODE=success
    export FAKE_TOUCHED=nightly/ce-2.8
    When run script "$script"
    The status should equal 0
    The output should include 'ADVANCE'
    The stderr should include 'main'
  End

  It 'n4a: nightly mode publisher failure aborts before any git mutation'
    nightly_env
    export FAKE_MODE=fail
    When run script "$script"
    The status should equal 1
    The stderr should include 'simulated nightly publish fault'
    The result of function local_head_now should equal "$original_head"
    The result of function remote_head_now should equal "$original_remote_head"
  End

  It 'n4b: nightly mode invalid handoff JSON fails via the publisher before any git mutation'
    nightly_env
    printf 'not json' > "$HANDOFF_FILE"
    export FAKE_MODE=success
    export FAKE_TOUCHED=nightly/ce-2.8
    When run script "$script"
    The status should equal 1
    The stderr should include 'simulated handoff read/parse failure'
    The result of function local_head_now should equal "$original_head"
    The result of function remote_head_now should equal "$original_remote_head"
  End

  It 'n4c: nightly mode missing pkg_version aborts before any commit, even after staging'
    # jq -er '.pkg_version' HANDOFF_FILE builds the commit message --
    # this handoff is otherwise valid (the stubbed publisher succeeds and
    # reports an "updated" target, so staging has ALREADY happened by the time
    # this read runs) but the handoff carries no pkg_version key, so jq -er sees
    # a null result and aborts (set -e) before the commit
    # that would otherwise follow. Same containment guarantee as a non-zero
    # publisher exit (n4a/n4b): a damaged/incomplete run must never reach a
    # commit, however late in the pipeline the fault is discovered.
    nightly_env
    printf '%s' '{"run_id":"10:1","route_matrix":[{"freebsd_major":"16","pfsense_version":"2.9","variant":"Plus","php_version":"8.4","py_flavor":"py312"}]}' > "$HANDOFF_FILE"
    export FAKE_MODE=success
    export FAKE_TOUCHED=nightly/ce-2.8
    When run script "$script"
    The status should equal 1
    The result of function local_head_now should equal "$original_head"
    The result of function remote_head_now should equal "$original_remote_head"
  End

  It 'n5: nightly mode NOOP output commits nothing'
    nightly_env
    export FAKE_MODE=noop
    When run script "$script"
    The status should equal 0
    The output should include 'NOOP'
    The result of function local_head_now should equal "$original_head"
    The result of function remote_head_now should equal "$original_remote_head"
  End

  It 'n6: nightly mode commit message carries the nightly version subject and trailers, ignoring tagged vars'
    nightly_env
    # Tagged vars (RELEASE_TAG=v4.0.0.b1 etc.) remain exported by common_env --
    # proves PUBLISH_KIND=nightly ignores them rather than leaking a tagged
    # trailer into the nightly commit message.
    export FAKE_MODE=success
    export FAKE_TOUCHED=nightly/ce-2.8
    When run script "$script"
    The status should equal 0
    The output should include 'ADVANCE'
    The stderr should include 'main'
    msg="$(git_fixture -C "${base}/pkg-repo" log -1 --format=%B)"
    The variable msg should include 'publish: nightly 20260804153045.aaaaaaa -> ["nightly"]'
    The variable msg should include 'pfBlockerNG-Nightly-Version: 20260804153045.aaaaaaa'
    The variable msg should include 'pfBlockerNG-Source-Run-Id: 10:1'
    The variable msg should not include 'pfBlockerNG-Release-Tag'
    The variable msg should not include 'v4.0.0.b1'
  End

  It 'n7: rejects an invalid PUBLISH_KIND value before any git call'
    export PUBLISH_KIND=bogus
    When run script "$script"
    The status should equal 1
    The stderr should include "::error::PUBLISH_KIND must be 'tagged' or 'nightly', got 'bogus'"
    The result of function local_head_now should equal "$original_head"
    The result of function remote_head_now should equal "$original_remote_head"
  End

  It 'n8: PUBLISH_KIND unset still defaults to the tagged behaviour'
    unset PUBLISH_KIND
    export FAKE_MODE=success
    export FAKE_TOUCHED=edge/ce-2.8
    When run script "$script"
    The status should equal 0
    The output should include 'ADVANCE'
    The stderr should include 'main'
    msg="$(git_fixture -C "${base}/pkg-repo" log -1 --format=%B)"
    The variable msg should include 'pfBlockerNG-Release-Tag: v4.0.0.b1'
  End

  # --- PUBLISH_STAGE=stage|promote|discard (issue #2389 S1, gate-before-announce) --
  # docs/ on `main` IS the Pages site, so a plain tagged publish commits the
  # catalogue atomically and nothing can be live-gated before announce.
  # common_env's SOURCE_RUN_ID is "10:1" (colon, matching the real
  # release-published.yml workflow) -- PUBLISH_STAGE=stage translates it to the
  # dash-form staging segment "10-1" throughout these examples.

  It 's1: stage relocates a touched target under docs/staging/<segment>, restoring the original at its real location'
    export PUBLISH_STAGE=stage
    export FAKE_MODE=success
    export FAKE_TOUCHED=edge/ce-2.8
    When run script "$script"
    The status should equal 0
    The output should include 'ADVANCE'
    The stderr should include 'main'
    The path "${base}/pkg-repo/docs/staging/10-1/edge/ce-2.8/marker.pkg" should be exist
    marker="$(cat "${base}/pkg-repo/docs/staging/10-1/edge/ce-2.8/marker.pkg")"
    The variable marker should equal 'edge/ce-2.8'
    The path "${base}/pkg-repo/docs/edge/ce-2.8/marker.pkg" should not be exist
    original="$(cat "${base}/pkg-repo/docs/edge/ce-2.8/meta.conf")"
    The variable original should equal 'seed'
    committed="$(git_fixture -C "${base}/pkg-repo" show --stat --format= HEAD | tr -s ' ' | sed 's/^ *//;s/ .*//')"
    The variable committed should include 'docs/staging/10-1/edge/ce-2.8/marker.pkg'
    msg="$(git_fixture -C "${base}/pkg-repo" log -1 --format=%B)"
    The variable msg should include 'publish: stage v4.0.0.b1 -> ["edge"]'
    The variable msg should include 'pfBlockerNG-Release-Tag: v4.0.0.b1'
    The variable msg should include 'pfBlockerNG-Source-Run-Id: 10:1'
    The variable msg should include 'pfBlockerNG-Staging-Prefix: staging/10-1'
  End

  It 's2: stage lands a brand-new target only under staging, with no real docs/<channel> created'
    export PUBLISH_STAGE=stage
    export FAKE_MODE=success
    export FAKE_TOUCHED=stable/ce-2.8
    When run script "$script"
    The status should equal 0
    The output should include 'ADVANCE'
    The stderr should include 'main'
    The path "${base}/pkg-repo/docs/staging/10-1/stable/ce-2.8/marker.pkg" should be exist
    # "does not exist in the COMMITTED tree" (git never tracks empty directories,
    # so an incidental empty docs/stable/ leftover on the filesystem, from the
    # publisher's own os.makedirs before the mv, is not itself a defect).
    committed="$(git_fixture -C "${base}/pkg-repo" show --name-only --format= HEAD | sort | xargs)"
    The variable committed should not include 'docs/stable/'
    tree_entries="$(git_fixture -C "${base}/pkg-repo" ls-tree -r --name-only HEAD)"
    The variable tree_entries should not include 'docs/stable/'
  End

  It 's3: stage GITHUB_OUTPUT carries staging_prefix, touched, and noop=false'
    export PUBLISH_STAGE=stage
    export FAKE_MODE=success
    export FAKE_TOUCHED=edge/ce-2.8
    export GITHUB_OUTPUT="${base}/github_output.txt"
    true >"$GITHUB_OUTPUT"
    When run script "$script"
    The status should equal 0
    The output should include 'ADVANCE'
    The stderr should include 'main'
    out="$(cat "$GITHUB_OUTPUT")"
    The variable out should include 'staging_prefix=staging/10-1'
    The variable out should include 'touched=["edge/ce-2.8"]'
    The variable out should include 'noop=false'
  End

  It 's4: stage full no-op (nothing touched) writes noop=true and prints STAGE NOOP'
    export PUBLISH_STAGE=stage
    export FAKE_MODE=noop
    export GITHUB_OUTPUT="${base}/github_output.txt"
    true >"$GITHUB_OUTPUT"
    When run script "$script"
    The status should equal 0
    The output should include 'NOOP'
    The output should include 'STAGE NOOP'
    The result of function local_head_now should equal "$original_head"
    The result of function remote_head_now should equal "$original_remote_head"
    out="$(cat "$GITHUB_OUTPUT")"
    The variable out should include 'noop=true'
  End

  It 's5: stage removes a stale docs/staging tree from an earlier crashed run in the same commit as the new one'
    export PUBLISH_STAGE=stage
    mkdir -p "${base}/pkg-repo/docs/staging/OLD/edge/ce-2.8"
    echo stale >"${base}/pkg-repo/docs/staging/OLD/edge/ce-2.8/old.pkg"
    (cd "${base}/pkg-repo" && git_fixture add docs/staging \
        && git_fixture commit -q -m preseed-stale-staging && git_fixture push -q origin main)
    export FAKE_MODE=success
    export FAKE_TOUCHED=edge/ce-2.8
    When run script "$script"
    The status should equal 0
    The output should include 'ADVANCE'
    The stderr should include 'main'
    The path "${base}/pkg-repo/docs/staging/OLD" should not be exist
    The path "${base}/pkg-repo/docs/staging/10-1/edge/ce-2.8/marker.pkg" should be exist
    changed="$(git_fixture -C "${base}/pkg-repo" show --name-status --format= HEAD)"
    The variable changed should include 'docs/staging/OLD/edge/ce-2.8/old.pkg'
    The variable changed should include 'docs/staging/10-1/edge/ce-2.8/marker.pkg'
    commit_count="$(git_fixture -C "${base}/pkg-repo" rev-list --count main)"
    The variable commit_count should equal 3
  End

  It 's6: stage translates a colon-bearing SOURCE_RUN_ID into a dash-form staging segment'
    export PUBLISH_STAGE=stage
    export SOURCE_RUN_ID='20:3'
    export FAKE_MODE=success
    export FAKE_TOUCHED=edge/ce-2.8
    export GITHUB_OUTPUT="${base}/github_output.txt"
    true >"$GITHUB_OUTPUT"
    When run script "$script"
    The status should equal 0
    The output should include 'ADVANCE'
    The stderr should include 'main'
    The path "${base}/pkg-repo/docs/staging/20-3/edge/ce-2.8/marker.pkg" should be exist
    The path "${base}/pkg-repo/docs/staging/20:3" should not be exist
    out="$(cat "$GITHUB_OUTPUT")"
    The variable out should include 'staging_prefix=staging/20-3'
    msg="$(git_fixture -C "${base}/pkg-repo" log -1 --format=%B)"
    The variable msg should include 'pfBlockerNG-Staging-Prefix: staging/20-3'
    The variable msg should include 'pfBlockerNG-Source-Run-Id: 20:3'
  End

  It 's7 (hostile): stage rejects a SOURCE_RUN_ID that is not a safe path segment, before any git call'
    export PUBLISH_STAGE=stage
    export SOURCE_RUN_ID='../evil run'
    When run script "$script"
    The status should equal 1
    The stderr should include '::error::SOURCE_RUN_ID must match'
    The result of function local_head_now should equal "$original_head"
    The result of function remote_head_now should equal "$original_remote_head"
  End

  It 's9: stage drops a phantom-touched target (publisher reported it, the tree never changed) instead of staging it'
    # publish_release.py's own touched-report and the tree's real state can, in
    # principle, disagree (the "phantom" FAKE_MODE above exists for exactly this).
    # Blindly relocating a phantom target under docs/staging would gate + eventually
    # promote a "change" that never happened. edge/ce-2.8 already carries the seed
    # bytes untouched, so `git status --porcelain -- docs/edge/ce-2.8` is empty --
    # the target must be dropped before stage_touched's own mv, never staged.
    export PUBLISH_STAGE=stage
    export FAKE_MODE=phantom
    export FAKE_TOUCHED=edge/ce-2.8
    export GITHUB_OUTPUT="${base}/github_output.txt"
    true >"$GITHUB_OUTPUT"
    When run script "$script"
    The status should equal 0
    The output should include 'publish-pkg-repo: stage — edge/ce-2.8 reported updated but unchanged; not staged'
    The output should include 'NOOP'
    The result of function local_head_now should equal "$original_head"
    The result of function remote_head_now should equal "$original_remote_head"
    The path "${base}/pkg-repo/docs/staging" should not be exist
    original="$(cat "${base}/pkg-repo/docs/edge/ce-2.8/meta.conf")"
    The variable original should equal 'seed'
    out="$(cat "$GITHUB_OUTPUT")"
    The variable out should include 'touched=[]'
    The variable out should include 'noop=true'
  End

  seed_staged_tree() {
    mkdir -p "${base}/pkg-repo/docs/staging/10-1/edge/ce-2.8"
    printf 'edge/ce-2.8' >"${base}/pkg-repo/docs/staging/10-1/edge/ce-2.8/marker.pkg"
    (cd "${base}/pkg-repo" && git_fixture add docs/staging \
        && git_fixture commit -q -m preseed-staged && git_fixture push -q origin main)
  }

  It 'p1: promote moves a staged tree live and never sweeps unrelated dirty/untracked files'
    seed_staged_tree
    echo dirty >>"${base}/pkg-repo/README.txt"
    echo stray >"${base}/pkg-repo/debris.txt"
    export PUBLISH_STAGE=promote
    export STAGING_PREFIX=staging/10-1
    When run script "$script"
    The status should equal 0
    The output should include 'ADVANCE'
    The stderr should include 'main'
    The path "${base}/pkg-repo/docs/edge/ce-2.8/marker.pkg" should be exist
    marker="$(cat "${base}/pkg-repo/docs/edge/ce-2.8/marker.pkg")"
    The variable marker should equal 'edge/ce-2.8'
    The path "${base}/pkg-repo/docs/staging" should not be exist
    msg="$(git_fixture -C "${base}/pkg-repo" log -1 --format=%B)"
    The variable msg should include 'publish: v4.0.0.b1 -> ["edge"]'
    The variable msg should include 'pfBlockerNG-Promoted-From: staging/10-1'
    committed="$(git_fixture -C "${base}/pkg-repo" show --name-only --format= HEAD | sort | xargs)"
    The variable committed should not include 'README.txt'
    The variable committed should not include 'debris.txt'
    porcelain="$(git_fixture -C "${base}/pkg-repo" status --porcelain)"
    The variable porcelain should include 'README.txt'
    The variable porcelain should include 'debris.txt'
  End

  It 'g3: promote commits only catalogue paths'
    # edge/ce-2.8 already exists (from the base fixture's own seed commit), so
    # promote_from_staging's own `git rm -r` + `git mv` legitimately touches
    # every file at that location (the 3 pre-existing ones plus the promoted
    # marker.pkg), not just one — the invariant this pins is that EVERY touched
    # path is catalogue-owned, never an exact single-file count.
    seed_staged_tree
    export PUBLISH_STAGE=promote
    export STAGING_PREFIX=staging/10-1
    When run script "$script"
    The status should equal 0
    The output should include 'ADVANCE'
    The stderr should include 'main'
    committed="$(git_fixture -C "${base}/pkg-repo" show --name-only --format= HEAD)"
    non_catalogue="$(printf '%s\n' "$committed" | grep -vE '^docs/(stable|testing|edge|nightly|staging)/' || true)"
    The variable non_catalogue should equal ''
  End

  It 'p2: promote never invokes the publisher'
    seed_staged_tree
    cat >"${base}/fake-src/scripts/publish_release.py" <<'PY'
import sys
with open(sys.argv[sys.argv.index("--pkg-repo") + 1] + "/PUBLISHER_WAS_CALLED", "w") as fh:
    fh.write("called")
sys.exit(1)
PY
    export PUBLISH_STAGE=promote
    export STAGING_PREFIX=staging/10-1
    When run script "$script"
    The status should equal 0
    The output should include 'ADVANCE'
    The stderr should include 'main'
    The path "${base}/pkg-repo/PUBLISHER_WAS_CALLED" should not be exist
  End

  It 'p3: promote refuses when STAGING_PREFIX is unset, before any git call'
    export PUBLISH_STAGE=promote
    When run script "$script"
    The status should equal 1
    The stderr should include '::error::STAGING_PREFIX is required'
    The result of function local_head_now should equal "$original_head"
    The result of function remote_head_now should equal "$original_remote_head"
  End

  It 'p4: promote fails with ::error:: when STAGING_PREFIX points at nothing staged'
    export PUBLISH_STAGE=promote
    export STAGING_PREFIX=staging/nope
    When run script "$script"
    The status should equal 1
    The stderr should include '::error::'
    The stderr should include 'nothing to promote'
    The result of function remote_head_now should equal "$original_remote_head"
  End

  It 'p5 (hostile): promote rejects a STAGING_PREFIX that is not a bare staging/<segment>, before any git call'
    export PUBLISH_STAGE=promote
    export STAGING_PREFIX='staging/../evil'
    When run script "$script"
    The status should equal 1
    The stderr should include '::error::STAGING_PREFIX must match staging/'
    The result of function local_head_now should equal "$original_head"
    The result of function remote_head_now should equal "$original_remote_head"
  End

  It 'p6: promote creates a brand-new channel directory absent from the seed tree'
    mkdir -p "${base}/pkg-repo/docs/staging/10-1/stable/ce-2.8"
    printf 'stable/ce-2.8' >"${base}/pkg-repo/docs/staging/10-1/stable/ce-2.8/marker.pkg"
    (cd "${base}/pkg-repo" && git_fixture add docs/staging \
        && git_fixture commit -q -m preseed-staged-new-channel && git_fixture push -q origin main)
    export PUBLISH_STAGE=promote
    export STAGING_PREFIX=staging/10-1
    When run script "$script"
    The status should equal 0
    The output should include 'ADVANCE'
    The stderr should include 'main'
    The path "${base}/pkg-repo/docs/stable/ce-2.8/marker.pkg" should be exist
    marker="$(cat "${base}/pkg-repo/docs/stable/ce-2.8/marker.pkg")"
    The variable marker should equal 'stable/ce-2.8'
    The path "${base}/pkg-repo/docs/staging" should not be exist
    commit_count="$(git_fixture -C "${base}/pkg-repo" rev-list --count main)"
    The variable commit_count should equal 3
    msg="$(git_fixture -C "${base}/pkg-repo" log -1 --format=%B)"
    The variable msg should include 'pfBlockerNG-Promoted-From: staging/10-1'
  End

  It 'p7: promote succeeds without ASSETS_DIR — the workflow promote-pkg-repo job never sets it'
    seed_staged_tree
    unset ASSETS_DIR
    export PUBLISH_STAGE=promote
    export STAGING_PREFIX=staging/10-1
    When run script "$script"
    The status should equal 0
    The output should include 'ADVANCE'
    The stderr should include 'main'
    The path "${base}/pkg-repo/docs/edge/ce-2.8/marker.pkg" should be exist
  End

  It 'p8: promote fails with ::error:: when the staged prefix holds only a stray file — no channel/varver to promote'
    mkdir -p "${base}/pkg-repo/docs/staging/10-1"
    echo stray >"${base}/pkg-repo/docs/staging/10-1/stray.txt"
    (cd "${base}/pkg-repo" && git_fixture add docs/staging \
        && git_fixture commit -q -m preseed-empty-staged && git_fixture push -q origin main)
    original_remote_head="$(git_fixture -C "${base}/remote.git" rev-parse refs/heads/main)"
    export PUBLISH_STAGE=promote
    export STAGING_PREFIX=staging/10-1
    When run script "$script"
    The status should equal 1
    The stderr should include '::error::PUBLISH_STAGE=promote: no <channel>/<varver> under docs/staging/10-1'
    The result of function remote_head_now should equal "$original_remote_head"
  End

  It 'd1: discard drops a staged tree, commits the removal, and leaves the real target untouched'
    seed_staged_tree
    export PUBLISH_STAGE=discard
    export STAGING_PREFIX=staging/10-1
    When run script "$script"
    The status should equal 0
    The output should include 'ADVANCE'
    The output should not include 'DISCARD NOOP'
    The stderr should include 'main'
    The path "${base}/pkg-repo/docs/staging" should not be exist
    original="$(cat "${base}/pkg-repo/docs/edge/ce-2.8/meta.conf")"
    The variable original should equal 'seed'
    msg="$(git_fixture -C "${base}/pkg-repo" log -1 --format=%B)"
    The variable msg should include 'publish: discard staging/10-1'
    The variable msg should include 'pfBlockerNG-Source-Run-Id: 10:1'
    commit_count="$(git_fixture -C "${base}/pkg-repo" rev-list --count main)"
    The variable commit_count should equal 3
  End

  It 'd2: discard with nothing staged is a safe no-op'
    export PUBLISH_STAGE=discard
    export STAGING_PREFIX=staging/nope
    When run script "$script"
    The status should equal 0
    The output should include 'DISCARD NOOP'
    The result of function local_head_now should equal "$original_head"
    The result of function remote_head_now should equal "$original_remote_head"
  End

  It 'd3: discard succeeds with none of the tagged-only vars set — discard needs only STAGING_PREFIX + SOURCE_RUN_ID'
    seed_staged_tree
    unset ASSETS_DIR SOURCE_REPOSITORY RELEASE_ID RELEASE_TAG DESTINATIONS ROUTE_MATRIX
    export PUBLISH_STAGE=discard
    export STAGING_PREFIX=staging/10-1
    When run script "$script"
    The status should equal 0
    The output should include 'ADVANCE'
    The stderr should include 'main'
    The path "${base}/pkg-repo/docs/staging" should not be exist
  End

  It 'k1: rejects PUBLISH_STAGE other than direct under PUBLISH_KIND=nightly, before any git call'
    nightly_env
    export PUBLISH_STAGE=stage
    When run script "$script"
    The status should equal 1
    The stderr should include "::error::PUBLISH_STAGE must be 'direct' when PUBLISH_KIND=nightly"
    The result of function local_head_now should equal "$original_head"
    The result of function remote_head_now should equal "$original_remote_head"
  End

  It 'k2: rejects an invalid PUBLISH_STAGE value before any git call'
    export PUBLISH_STAGE=bogus
    When run script "$script"
    The status should equal 1
    The stderr should include "::error::PUBLISH_STAGE must be 'direct', 'stage', 'promote', or 'discard', got 'bogus'"
    The result of function local_head_now should equal "$original_head"
    The result of function remote_head_now should equal "$original_remote_head"
  End

  It 'k3: PUBLISH_STAGE unset still defaults to direct behaviour'
    export FAKE_MODE=success
    export FAKE_TOUCHED=edge/ce-2.8
    When run script "$script"
    The status should equal 0
    The output should include 'ADVANCE'
    The stderr should include 'main'
    msg="$(git_fixture -C "${base}/pkg-repo" log -1 --format=%B)"
    The variable msg should include 'pfBlockerNG-Release-Tag: v4.0.0.b1'
    The variable msg should not include 'pfBlockerNG-Staging-Prefix'
  End
End
