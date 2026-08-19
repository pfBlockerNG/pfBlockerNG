#shellcheck shell=sh
# render_pkg_site_spec.sh — scripts/render-pkg-site.sh.
#
# gen_landing.py is stubbed (a fake PFB_SRC checkout, see setup()): this script's
# own job is the git sync/guard/commit/push mechanics AROUND the renderer, which
# is exactly what this spec exercises. The real renderer's own byte-for-byte
# output (site-tree rendering, packages table, browse pages) is pinned by
# tests/test_gen_landing.py — never re-verified here. Fixture: a bare "remote"
# origin plus a working PKG_REPO clone already carrying one committed catalogue
# directory (docs/edge/ce-2.8) with a legacy in-tree autoindex (issue #2450
# ruling: never swept by this script or gen_landing.py — a one-time operator
# cleanup, never script logic), a retired docs/add-repo.sh, and stale
# docs/index.html content, mirroring what a first run of this script sees on an
# already-published site.
#
# GUARD: the catalogue-containment case is the load-bearing one — the stub can
# simulate a renderer that (mistakenly or maliciously) rewrites a file inside a
# catalogue-owned tree, and this spec asserts that commit never happens and the
# bare origin never moves.

Describe 'render-pkg-site.sh'
  script="${PFB_ROOT}/scripts/render-pkg-site.sh"

  setup() {
    scrub_git_env
    base="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/renderpkgsite.XXXXXX")"

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
    # Legacy in-tree autoindex under a catalogue dir, from the generator this
    # replaces — issue #2450 ruling: this script (and gen_landing.py) must never
    # touch it; sweeping it is a one-time operator cleanup, never script logic.
    printf 'legacy autoindex\n' > "${base}/pkg-repo/docs/edge/ce-2.8/index.html"
    printf '#!/bin/sh\n# old add-repo\n' > "${base}/pkg-repo/docs/add-repo.sh"
    printf 'old index\n' > "${base}/pkg-repo/docs/index.html"
    echo seed > "${base}/pkg-repo/README.txt"
    ( cd "${base}/pkg-repo" && git_fixture checkout -q -b main \
        && git_fixture add docs README.txt && git_fixture commit -q -m seed \
        && git_fixture push -q origin main )
    original_head="$(git_fixture -C "${base}/pkg-repo" rev-parse main)"
    original_remote_head="$(git_fixture -C "${base}/remote.git" rev-parse refs/heads/main)"
    legacy_index_before="$(cat "${base}/pkg-repo/docs/edge/ce-2.8/index.html")"

    # --- fake PFB_SRC: a real (tiny) git checkout, so the render commit's own
    # "render: pkg website (<short sha>)" subject is deterministically pinnable,
    # plus a stubbed gen_landing.py + an (unused by the stub, present for
    # realism) pkg-site/ tree ------------------------------------------------
    mkdir -p "${base}/fake-src/scripts" "${base}/fake-src/pkg-site"
    cat >"${base}/fake-src/scripts/gen_landing.py" <<'PY'
import os
import subprocess
import sys

argv = sys.argv[1:]
mode = os.environ.get("FAKE_RENDER_MODE", "default")

# Pins the WRAPPER's own invocation shape: <docs> <base> --site-tree <dir>
# --matrix <file>. The real generator's own argparse contract (and its
# rendered byte content) is pinned by tests/test_gen_landing.py -- never
# re-verified here.
if len(argv) != 6 or argv[2] != "--site-tree" or argv[4] != "--matrix":
    print("::error::unexpected gen_landing.py argv shape", file=sys.stderr)
    sys.exit(2)

docs = argv[0]
base_url = argv[1]
matrix_file = argv[argv.index("--matrix") + 1]

record_path = os.environ.get("FAKE_MATRIX_DUMP")
if record_path:
    with open(matrix_file, encoding="utf-8") as src, open(record_path, "w", encoding="utf-8") as dst:
        dst.write(src.read())

# r6: simulates another run advancing origin/main WHILE this run renders --
# a real competing commit, pushed from a second clone, so the retried run's
# final tree provably contains both changes (not just a rejected-push message).
compete_remote = os.environ.get("FAKE_COMPETE_REMOTE")
compete_marker = os.environ.get("FAKE_COMPETE_MARKER")
if compete_remote and compete_marker and not os.path.exists(compete_marker):
    compete_clone = os.environ["FAKE_COMPETE_CLONE"]
    git_env = dict(os.environ, GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_SYSTEM="/dev/null")
    subprocess.run(["git", "clone", "-q", compete_remote, compete_clone], check=True, env=git_env)
    # The bare origin's own HEAD symref was never repointed at "main" (only
    # refs/heads/main was ever pushed to it), so a plain clone leaves no local
    # branch checked out -- an explicit checkout -B is what the real scripts
    # themselves do, and what makes `git commit`/`push origin main` below valid.
    subprocess.run(["git", "-C", compete_clone, "checkout", "-q", "-B", "main", "origin/main"], check=True, env=git_env)
    with open(os.path.join(compete_clone, "COMPETING.txt"), "w") as fh:
        fh.write("race")
    subprocess.run(["git", "-C", compete_clone, "add", "COMPETING.txt"], check=True, env=git_env)
    subprocess.run(
        ["git", "-C", compete_clone, "-c", "user.email=c@c.com", "-c", "user.name=competitor",
         "commit", "-q", "-m", "competing change"],
        check=True, env=git_env,
    )
    subprocess.run(["git", "-C", compete_clone, "push", "-q", "origin", "main"], check=True, env=git_env)
    with open(compete_marker, "w") as fh:
        fh.write("done")

if mode == "fail":
    with open(os.path.join(docs, "junk.html"), "w") as fh:
        fh.write("junk")
    print("::error::simulated renderer failure", file=sys.stderr)
    sys.exit(1)

if mode == "noop":
    # Writes nothing -- the committed state (from a prior "default" run) is
    # already current.
    print("pkg-site: 0 file(s) written, 0 removed; 0 pfBlockerNG package(s) indexed")
    sys.exit(0)

if mode == "touch-catalogue":
    with open(os.path.join(docs, "edge", "ce-2.8", "meta.conf"), "w") as fh:
        fh.write("tampered")

os.makedirs(os.path.join(docs, "browse", "edge", "ce-2.8"), exist_ok=True)
with open(os.path.join(docs, "index.html"), "w") as fh:
    fh.write(f"rendered {base_url}")
with open(os.path.join(docs, ".nojekyll"), "w") as fh:
    fh.write("")
with open(os.path.join(docs, "browse", "edge", "ce-2.8", "index.html"), "w") as fh:
    fh.write("browse stub")
add_repo = os.path.join(docs, "add-repo.sh")
if os.path.exists(add_repo):
    os.remove(add_repo)
print("pkg-site: 3 file(s) written, 1 removed; 1 pfBlockerNG package(s) indexed")
PY
    ( cd "${base}/fake-src" && git_fixture init -q . \
        && git_fixture config user.email src@example.com && git_fixture config user.name src \
        && git_fixture config commit.gpgsign false \
        && git_fixture add -A && git_fixture commit -q -m fake-src-seed )
    fake_src_sha="$(git_fixture -C "${base}/fake-src" rev-parse --short HEAD)"

    common_env() {
        PFB_SRC="${base}/fake-src"
        PKG_REPO="${base}/pkg-repo"
        BASE_URL=https://pkg.pfblockerng.com
        SOURCE_RUN_ID=10:1
        ROUTE_MATRIX='[{"freebsd_major":"15","pfsense_version":"2.8","variant":"ce","php_version":"8.3","py_flavor":"py311","arch":"amd64"}]'
        export PFB_SRC PKG_REPO BASE_URL SOURCE_RUN_ID ROUTE_MATRIX
    }
    common_env
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
    git_fixture -C "${base}/pkg-repo" rev-parse main 2>/dev/null || echo "UNRESOLVABLE-main"
  }

  # --- r1: success path -------------------------------------------------------

  It 'r1: renders and pushes ONE commit touching exactly the renderer output, deleting the retired script'
    echo dirty >> "${base}/pkg-repo/README.txt"
    export FAKE_MATRIX_DUMP="${base}/matrix-seen.json"
    When run script "$script"
    The status should equal 0
    The output should include 'ADVANCE'
    The stderr should include 'main'
    commit_count="$(git_fixture -C "${base}/pkg-repo" rev-list --count main)"
    The variable commit_count should equal 2
    committed="$(git_fixture -C "${base}/pkg-repo" show --name-only --format= HEAD | sort | xargs)"
    The variable committed should equal 'docs/.nojekyll docs/add-repo.sh docs/browse/edge/ce-2.8/index.html docs/index.html'
    msg="$(git_fixture -C "${base}/pkg-repo" log -1 --format=%B)"
    The variable msg should include "render: pkg website (${fake_src_sha})"
    The variable msg should include 'pfBlockerNG-Source-Run-Id: 10:1'
    # README.txt (dirtied above, at the repo root) is never swept -- only
    # `git add -A -- docs` runs, never a repo-wide add.
    porcelain="$(git_fixture -C "${base}/pkg-repo" status --porcelain)"
    The variable porcelain should include 'README.txt'
    # The legacy in-tree autoindex under the catalogue dir is untouched, in the
    # working tree AND in the pushed commit.
    legacy_after="$(cat "${base}/pkg-repo/docs/edge/ce-2.8/index.html")"
    The variable legacy_after should equal "$legacy_index_before"
    tracked_legacy="$(git_fixture -C "${base}/pkg-repo" show HEAD:docs/edge/ce-2.8/index.html)"
    The variable tracked_legacy should equal "$legacy_index_before"
  End

  # --- r2: NOOP ----------------------------------------------------------------

  It 'r2: a second run over already-rendered content is a NOOP'
    seed_rc=0
    sh "$script" >/dev/null 2>&1 || seed_rc=$?
    [ "$seed_rc" -eq 0 ] || { echo "seed render failed with ${seed_rc}" >&2; return 1; }
    original_remote_head="$(git_fixture -C "${base}/remote.git" rev-parse refs/heads/main)"
    original_head="$(git_fixture -C "${base}/pkg-repo" rev-parse main)"
    When run script "$script"
    The status should equal 0
    The output should include 'NOOP'
    The result of function local_head_now should equal "$original_head"
    The result of function remote_head_now should equal "$original_remote_head"
  End

  # --- r3: GUARD red canary ------------------------------------------------

  It 'r3 (hostile): a renderer that rewrites a catalogue-owned path is rejected before any commit'
    export FAKE_RENDER_MODE=touch-catalogue
    When run script "$script"
    The status should equal 1
    The stderr should include '::error::render touched catalogue-owned path(s):'
    The stderr should include 'docs/edge/ce-2.8/meta.conf'
    The result of function local_head_now should equal "$original_head"
    The result of function remote_head_now should equal "$original_remote_head"
    staged="$(git_fixture -C "${base}/pkg-repo" diff --cached --name-only)"
    The variable staged should equal ''
  End

  # --- r4: renderer failure -------------------------------------------------

  It 'r4: a renderer failure aborts before any git mutation'
    export FAKE_RENDER_MODE=fail
    When run script "$script"
    The status should equal 1
    The stderr should include '::error::gen_landing.py failed — aborting before any git mutation'
    The stderr should include 'simulated renderer failure'
    The result of function local_head_now should equal "$original_head"
    The result of function remote_head_now should equal "$original_remote_head"
  End

  # --- r5: matrix transform --------------------------------------------------

  It 'r5: feeds gen_landing.py the same abi transform the publisher used to, never interpolating arch'
    export ROUTE_MATRIX='[{"freebsd_major":"15","pfsense_version":"2.8","variant":"ce","php_version":"8.3","py_flavor":"py311","arch":"amd64"}]'
    export FAKE_MATRIX_DUMP="${base}/matrix-seen.json"
    When run script "$script"
    The status should equal 0
    The output should include 'ADVANCE'
    The stderr should include 'main'
    seen="$(cat "${base}/matrix-seen.json")"
    The variable seen should equal '[{"abi":"FreeBSD:15:*","pfsense_version":"2.8","variant":"ce","php_version":"8.3","py_flavor":"py311"}]'
  End

  # --- r6: the push resync-retry loop, with a REAL competing commit ----------

  It 'r6: a rejected push (a competing commit lands mid-render) re-syncs, re-renders, and pushes on the next attempt'
    export FAKE_COMPETE_REMOTE="${base}/remote.git"
    export FAKE_COMPETE_CLONE="${base}/compete-clone"
    export FAKE_COMPETE_MARKER="${base}/compete-marker"
    When run script "$script"
    The status should equal 0
    The output should include 'ADVANCE'
    The output should include 'sync attempt 2'
    The stderr should include 'push rejected (attempt 1'
    tree_entries="$(git_fixture -C "${base}/pkg-repo" ls-tree -r --name-only HEAD)"
    The variable tree_entries should include 'COMPETING.txt'
    The variable tree_entries should include 'docs/index.html'
    commit_count="$(git_fixture -C "${base}/pkg-repo" rev-list --count main)"
    The variable commit_count should equal 3
  End

  # --- r7: MAX_PUSH_ATTEMPTS validation ---------------------------------------

  It 'r7a: refuses a MAX_PUSH_ATTEMPTS that cannot produce a single attempt, before any git call'
    export MAX_PUSH_ATTEMPTS=0
    When run script "$script"
    The status should equal 1
    The stderr should include '::error::MAX_PUSH_ATTEMPTS must be a positive integer'
    The result of function remote_head_now should equal "$original_remote_head"
  End

  It 'r7b: refuses a non-numeric MAX_PUSH_ATTEMPTS, before any git call'
    export MAX_PUSH_ATTEMPTS=many
    When run script "$script"
    The status should equal 1
    The stderr should include '::error::MAX_PUSH_ATTEMPTS must be a positive integer'
    The result of function remote_head_now should equal "$original_remote_head"
  End

  # --- r8: missing required env -----------------------------------------------

  It 'r8a: fails before any git call when PFB_SRC is missing'
    unset PFB_SRC
    When run script "$script"
    The status should not equal 0
    The stderr should include 'PFB_SRC is required'
    The result of function remote_head_now should equal "$original_remote_head"
  End

  It 'r8b: fails before any git call when PKG_REPO is missing'
    unset PKG_REPO
    When run script "$script"
    The status should not equal 0
    The stderr should include 'PKG_REPO is required'
    The result of function remote_head_now should equal "$original_remote_head"
  End

  It 'r8c: fails before any git call when BASE_URL is missing'
    unset BASE_URL
    When run script "$script"
    The status should not equal 0
    The stderr should include 'BASE_URL is required'
    The result of function local_head_now should equal "$original_head"
    The result of function remote_head_now should equal "$original_remote_head"
  End

  It 'r8d: fails before any git call when SOURCE_RUN_ID is missing'
    unset SOURCE_RUN_ID
    When run script "$script"
    The status should not equal 0
    The stderr should include 'SOURCE_RUN_ID is required'
    The result of function local_head_now should equal "$original_head"
    The result of function remote_head_now should equal "$original_remote_head"
  End

  It 'r8e: fails before any git call when ROUTE_MATRIX is missing'
    unset ROUTE_MATRIX
    When run script "$script"
    The status should not equal 0
    The stderr should include 'ROUTE_MATRIX is required'
    The result of function local_head_now should equal "$original_head"
    The result of function remote_head_now should equal "$original_remote_head"
  End

  # --- r9: fixed bot identity --------------------------------------------------

  It 'r9: commits with a fixed bot identity even when no git identity is configured anywhere'
    git_fixture -C "${base}/pkg-repo" config --unset user.email
    git_fixture -C "${base}/pkg-repo" config --unset user.name
    export GIT_CONFIG_GLOBAL=/dev/null
    export GIT_CONFIG_SYSTEM=/dev/null
    unset GIT_AUTHOR_NAME GIT_AUTHOR_EMAIL GIT_COMMITTER_NAME GIT_COMMITTER_EMAIL
    When run script "$script"
    The status should equal 0
    The output should include 'ADVANCE'
    The stderr should include 'main'
    author="$(git_fixture -C "${base}/pkg-repo" log -1 --format='%an <%ae>')"
    committer="$(git_fixture -C "${base}/pkg-repo" log -1 --format='%cn <%ce>')"
    The variable author should equal 'github-actions[bot] <github-actions[bot]@users.noreply.github.com>'
    The variable committer should equal 'github-actions[bot] <github-actions[bot]@users.noreply.github.com>'
  End

  # --- r10: a hard push failure is not remote contention ----------------------

  It 'r10: an authentication-shaped push failure makes exactly one attempt and does not retry'
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

  # --- hostile: SOURCE_RUN_ID is never evaluated ------------------------------

  It 'hostile: a SOURCE_RUN_ID with spaces and quotes lands verbatim in the commit trailer only'
    export SOURCE_RUN_ID='10:1 with spaces and "quotes"'
    When run script "$script"
    The status should equal 0
    The output should include 'ADVANCE'
    The stderr should include 'main'
    msg="$(git_fixture -C "${base}/pkg-repo" log -1 --format=%B)"
    The variable msg should include 'pfBlockerNG-Source-Run-Id: 10:1 with spaces and "quotes"'
  End
End
