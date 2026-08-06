#shellcheck shell=sh
# publish_pkg_repo_spec.sh — scripts/publish-pkg-repo.sh.
#
# publish_release.py and gen_landing.py are stubbed (a fake PFB_SRC checkout, see
# setup()): git mutation is the ONLY thing this script owns, and it is exactly what
# this spec exercises — network/engine verification is publish_release.py's own,
# already-covered PFB_SRC=... python3 -m unittest suite (pkg repo). Fixture: a bare
# "remote" origin plus a working PKG_REPO clone already carrying one committed
# catalogue directory (docs/edge/ce-2.8), mirroring what the release job's checkout
# looks like before this script runs.
#
# CONTAINMENT: the fault-injection case is the load-bearing one —
# the stub simulates catalogue_assembly.py's own documented failure mode (a
# mid-regeneration write-back fault: wipe the catalog descriptor files, leave an
# orphaned .pkg, THEN exit non-zero) and this spec asserts the damaged working tree
# never reaches a commit, and the bare origin never moves.

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

    # --- fake PFB_SRC: stub publish_release.py + gen_landing.py -------------
    # Real network/engine verification is publish_release.py's own unit suite
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
    cat >"${base}/fake-src/scripts/gen_landing.py" <<'PY'
import os
import sys

site = sys.argv[1]
with open(os.path.join(site, "index.html"), "w") as fh:
    fh.write("landing stub\n")
with open(os.path.join(site, "browse.html"), "w") as fh:
    fh.write("browse stub\n")
# Mirrors the real generator's all_dirs()/write_site(): a per-directory
# autoindex at EVERY existing level, not just this run's touched targets. The
# site-wide walk is the property being pinned, so the stub must walk it too.
for dirpath, _dirs, _files in os.walk(site):
    rel = os.path.relpath(dirpath, site)
    if rel == ".":
        continue
    with open(os.path.join(dirpath, "index.html"), "w") as fh:
        fh.write(f"autoindex stub: {rel}\n")
# write_site() also publishes a self-contained add-repo.sh into the site root.
with open(os.path.join(site, "add-repo.sh"), "w") as fh:
    fh.write("#!/bin/sh\n# add-repo stub\n")
print("landing stub written")
PY
    echo '#!/bin/sh' > "${base}/fake-src/scripts/add-repo.sh"

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
        BASE_URL=https://pfblockerng.github.io/pkg
        export PFB_SRC PKG_REPO SOURCE_REPOSITORY RELEASE_ID RELEASE_TAG DESTINATIONS SOURCE_RUN_ID ASSETS_DIR ROUTE_MATRIX BASE_URL
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

  # --- landing_matrix ABI expression pins: the transform lives in this script,
  # so the properties pfBlockerNG/pkg's own retired test pinned live here now ---

  It 'never interpolates the retired arch matrix field'
    When run sh -c "! grep -Fq '\\(.arch)' '${script}'"
    The status should equal 0
  End

  It 'contains exactly one abi FreeBSD wildcard expression'
    When run sh -c "grep -o 'abi: \"FreeBSD:[^\"]*\"' '${script}' | wc -l | tr -d ' '"
    The output should equal 1
  End

  It 'the abi expression as written emits the NO_ARCH wildcard for freebsd_major'
    abi_expr="$(grep -o 'abi: "FreeBSD:[^"]*"' "$script" | head -1)"
    When run sh -c "printf '%s' '{\"freebsd_major\":\"15\"}' | jq -c '{ ${abi_expr} }'"
    The output should equal '{"abi":"FreeBSD:15:*"}'
  End

  # --- success path ----------------------------------------------------------

  It 'commits and pushes exactly the touched directory plus the landing page'
    export FAKE_MODE=success
    export FAKE_TOUCHED=edge/ce-2.8
    When run script "$script"
    The status should equal 0
    The output should include 'ADVANCE'
    The result of function local_head_now should not equal "$original_head"
    The result of function remote_head_now should not equal "$original_remote_head"
    The path "${base}/pkg-repo/docs/edge/ce-2.8/marker.pkg" should be exist
    The path "${base}/pkg-repo/docs/index.html" should be exist
  End

  It 'stages nothing outside the touched target and the landing page'
    export FAKE_MODE=success
    export FAKE_TOUCHED=edge/ce-2.8
    When run script "$script"
    The status should equal 0
    The output should include 'ADVANCE'
    The stderr should include 'main'
    committed="$(git_fixture -C "${base}/pkg-repo" show --stat --format= HEAD | tr -s ' ' | sed 's/^ *//;s/ .*//')"
    The variable committed should include 'docs/edge/ce-2.8/marker.pkg'
    The variable committed should include 'docs/index.html'
    The variable committed should include 'docs/.nojekyll'
  End

  It 'stages the channel-level autoindex gen_landing.py regenerates for every existing directory'
    # gen_landing.py's all_dirs() walks the WHOLE docs/ tree on every run,
    # regenerating a per-directory autoindex at every level — not just the
    # (channel, varver) directory this run touched. docs/edge/index.html sits
    # one level ABOVE docs/edge/ce-2.8 (the touched target), so it is never
    # swept in by the touched-target pathspec and must be staged separately.
    export FAKE_MODE=success
    export FAKE_TOUCHED=edge/ce-2.8
    When run script "$script"
    The status should equal 0
    The output should include 'ADVANCE'
    The stderr should include 'main'
    The path "${base}/pkg-repo/docs/edge/index.html" should be exist
    committed="$(git_fixture -C "${base}/pkg-repo" show --stat --format= HEAD | tr -s ' ' | sed 's/^ *//;s/ .*//')"
    The variable committed should include 'docs/edge/index.html'
    # write_site() publishes add-repo.sh into the site root on the same walk;
    # the bootstrap one-liner on the landing page fetches it from there, so an
    # unstaged copy means the published site serves a 404 for it.
    The variable committed should include 'docs/add-repo.sh'
  End

  It 'never sweeps a stray untracked file or an unrelated dirty tracked file into the commit'
    # Proves the explicit pathspec, not `git add -A`/`.`, is what runs —
    # debris.txt is untracked, README.txt is tracked but outside every
    # (channel, varver) target and outside the landing page's own output.
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
    # --quiet` after staging must find nothing to commit. Pre-seeds
    # docs/index.html with byte-identical content to what the (also stubbed)
    # gen_landing.py would regenerate, so the landing-page step contributes no
    # diff either — the discard path is reached honestly, not bypassed by an
    # incidental landing-page change.
    git_fixture -C "${base}/pkg-repo" fetch -q origin
    git_fixture -C "${base}/pkg-repo" checkout -q main
    printf 'landing stub\n' > "${base}/pkg-repo/docs/index.html"
    # The stub gen_landing.py also regenerates browse.html and a per-directory
    # autoindex at every existing level (edge/ and edge/ce-2.8/, mirroring the
    # real generator) — pre-seed those identically too, or their own
    # first-ever creation would be a genuine diff and mask the branch this
    # test means to reach.
    printf 'browse stub\n' > "${base}/pkg-repo/docs/browse.html"
    printf 'autoindex stub: edge\n' > "${base}/pkg-repo/docs/edge/index.html"
    printf 'autoindex stub: edge/ce-2.8\n' > "${base}/pkg-repo/docs/edge/ce-2.8/index.html"
    printf '#!/bin/sh\n# add-repo stub\n' > "${base}/pkg-repo/docs/add-repo.sh"
    # docs/.nojekyll is truncate-and-recreated unconditionally whenever the
    # script has any touched target (regardless of whether the target itself
    # changed) — pre-seed it too, or its own first-ever creation would be a
    # genuine diff and mask the branch this test means to reach.
    true > "${base}/pkg-repo/docs/.nojekyll"
    ( cd "${base}/pkg-repo" && git_fixture add docs/index.html docs/browse.html \
        docs/edge/index.html docs/edge/ce-2.8/index.html docs/.nojekyll docs/add-repo.sh \
        && git_fixture commit -q -m preseed-landing \
        && git_fixture push -q origin main )
    original_head="$(git_fixture -C "${base}/pkg-repo" rev-parse main)"
    original_remote_head="$(git_fixture -C "${base}/remote.git" rev-parse refs/heads/main)"

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
End
