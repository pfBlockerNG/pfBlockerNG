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
argv = sys.argv[1:]
# ONE deterministic client script since issue #2416 follow-up: install.sh,
# --channel parameterized, is the SOLE client entry point. Stub body text is the
# script's own base name (sans .sh) so existing pre-seeded fixture bytes below
# ("# install stub\n") keep matching byte-for-byte.
CLIENT_SCRIPTS = ("install.sh",)


def _write_client_scripts(site):
    # FAKE_OMIT_CLIENT_SCRIPT simulates a generator that silently produced fewer
    # scripts than CLIENT_SCRIPTS names (a drifted generator/wrapper pairing) —
    # the wrapper's own fail-closed guard is what this exercises, never gen_landing.py.
    omit = os.environ.get("FAKE_OMIT_CLIENT_SCRIPT", "")
    for name in CLIENT_SCRIPTS:
        if name == omit:
            continue
        with open(os.path.join(site, name), "w") as fh:
            fh.write(f"#!/bin/sh\n# {name[:-len('.sh')]} stub\n")


if "--client-scripts-only" in argv:
    # Mirrors the real generator's script-only mode (issue #2408): ONLY the
    # deterministic client scripts are written — no landing/browse/autoindex output.
    _write_client_scripts(site)
    print("client scripts stub written")
    sys.exit(0)
# Records the exact --matrix file this run was fed, byte for byte, when
# FAKE_LANDING_MATRIX_RECORD is set — publish-pkg-repo.sh's own job (not
# gen_landing.py's) is choosing that file's SOURCE (tagged: $ROUTE_MATRIX;
# nightly: the handoff's own route_matrix), so the nightly-mode spec examples
# assert against this record rather than re-deriving the transform themselves.
if "--matrix" in argv:
    matrix_path = argv[argv.index("--matrix") + 1]
    record_path = os.environ.get("FAKE_LANDING_MATRIX_RECORD")
    if record_path:
        with open(matrix_path, encoding="utf-8") as src, open(record_path, "w", encoding="utf-8") as dst:
            dst.write(src.read())
with open(os.path.join(site, "index.html"), "w") as fh:
    fh.write("landing stub\n")
with open(os.path.join(site, "browse.html"), "w") as fh:
    fh.write("browse stub\n")
# Mirrors the real generator's all_dirs()/write_site(): a per-directory
# autoindex at EVERY existing level, not just this run's touched targets. The
# site-wide walk is the property being pinned, so the stub must walk it too.
# Skips docs/staging (issue #2389: gen_landing.py never indexes it) so the
# spec examples can exercise a real index-less directory under docs/.
for dirpath, _dirs, _files in os.walk(site):
    rel = os.path.relpath(dirpath, site)
    if rel == "." or rel == "staging" or rel.startswith("staging" + os.sep):
        continue
    with open(os.path.join(dirpath, "index.html"), "w") as fh:
        fh.write(f"autoindex stub: {rel}\n")
# write_site() also publishes every client script into the site root.
_write_client_scripts(site)
print("landing stub written")
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

  # The one deterministic client script (issue #2416 follow-up: install.sh,
  # --channel parameterized, is the SOLE client entry point), and its docs/-relative
  # path — shared by every preseed/assertion below so a future addition only needs
  # bumping in one place.
  CLIENT_SCRIPT_NAMES="install.sh"
  CLIENT_SCRIPT_PATHS="docs/install.sh"
  SORTED_CLIENT_SCRIPT_PATHS="docs/install.sh"

  # Writes every client-script stub, byte-identical to the fake gen_landing.py's
  # own output, into docs/ — used to preseed a "current scripts" state.
  write_client_script_stubs() {
    for _name in ${CLIENT_SCRIPT_NAMES}; do
        _base="${_name%.sh}"
        printf '#!/bin/sh\n# %s stub\n' "${_base}" > "${base}/pkg-repo/docs/${_name}"
    done
  }

  # --- PUBLISH_KIND=nightly fixture ------------------------------------------
  # Layered on top of common_env (already exported by setup()): keeps the shared
  # vars (PFB_SRC/PKG_REPO/SOURCE_RUN_ID/BASE_URL) and adds the nightly-only ones.
  # Tagged-only vars are deliberately left exported by common_env in most nightly
  # examples -- proving they are IGNORED, not merely absent (see the "does not
  # leak a tagged trailer" example) -- except where a test explicitly unsets them.
  nightly_env() {
    PUBLISH_KIND=nightly
    HANDOFF_FILE="${base}/nightly-handoff.json"
    RESULTS_DIR="${base}/results"
    export PUBLISH_KIND HANDOFF_FILE RESULTS_DIR
    mkdir -p "$RESULTS_DIR"
    # DELIBERATELY a different row than common_env's own $ROUTE_MATRIX (freebsd
    # 15/2.8/CE/8.3/py311) -- n9 stages the landing matrix on this handoff row
    # and asserts against ITS values; if the nightly arm ever regressed to
    # reading $ROUTE_MATRIX instead, the assertion must fail on a value
    # mismatch, not pass on accidental byte-identity between the two fixtures.
    cat > "$HANDOFF_FILE" <<'JSON'
{"run_id":"10:1","pkg_version":"20260804153045.aaaaaaa","route_matrix":[{"freebsd_major":"16","pfsense_version":"2.9","variant":"Plus","php_version":"8.4","py_flavor":"py312"}]}
JSON
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

  It 'fails closed when the generator silently omits a client script'
    # CodeRabbit finding: landing_regen_and_stage's `[ -f ... ] && stage_paths=...`
    # SKIPS a missing client script instead of failing — a drifted generator/wrapper
    # pairing (CLIENT_SCRIPTS names a script the generator no longer writes) would
    # silently ship no script at all, never caught. The wrapper must die instead,
    # naming the missing file, and commit nothing.
    export FAKE_MODE=success
    export FAKE_TOUCHED=edge/ce-2.8
    export FAKE_OMIT_CLIENT_SCRIPT=install.sh
    When run script "$script"
    The status should not equal 0
    The stderr should include 'install.sh'
    The result of function local_head_now should equal "$original_head"
    The result of function remote_head_now should equal "$original_remote_head"
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
    # write_site() publishes the client script into the site root on the same
    # walk; the landing page's install one-liner fetches it from there, so an
    # unstaged copy means the published site serves a 404 into `sh` (issue #2416).
    The variable committed should include 'docs/install.sh'
  End

  It 'a stray index-less docs/staging dir (leftover from a crashed stage run) never aborts the dir_indexes collector'
    # gen_landing.py never writes an index.html under docs/staging (issue #2389)
    # -- reachable here because a `direct` publish (this script's default mode,
    # used by nightly.yml/pkg-republish.yml) can run while a stray docs/staging
    # tree is still sitting on disk from an earlier crashed "stage" run.
    # docs/staging/10-1/stable/ce-2.8 is the DEEPEST, alphabetically LAST entry
    # `find -type d` enumerates under docs/ in this fixture, so `[ -f "$d/index.html"
    # ] && printf ...` (no `if`/`fi`) makes the while loop's own exit status 1 on
    # its last iteration -- `dir_indexes=$(...)` then aborts the whole script under
    # `set -e`, after the publisher already ran, before any git add/commit.
    mkdir -p "${base}/pkg-repo/docs/staging/10-1/stable/ce-2.8"
    echo stray >"${base}/pkg-repo/docs/staging/10-1/stable/ce-2.8/stray.pkg"
    export FAKE_MODE=success
    export FAKE_TOUCHED=edge/ce-2.8
    When run script "$script"
    The status should equal 0
    The output should include 'ADVANCE'
    The stderr should include 'main'
    committed="$(git_fixture -C "${base}/pkg-repo" show --stat --format= HEAD | tr -s ' ' | sed 's/^ *//;s/ .*//')"
    The variable committed should not include 'docs/staging'
    The path "${base}/pkg-repo/docs/staging/10-1/stable/ce-2.8/index.html" should not be exist
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

  # --- leftover dest autoindex from a rejected push (issue #2407) -----------
  # Dual defense: `git clean -fd -- docs` after checkout -B, and dest
  # autoindex staging via `git ls-files` (already-tracked only), never a
  # site-wide find. Each pin below is independent — dropping only one
  # defense must turn that pin RED.

  It 'cleans an untracked leftover dest autoindex off disk after checkout -B'
    # Clean pin: leftover must not exist on disk after ADVANCE. Dropping
    # `git clean -fd -- docs` leaves the untracked dest (ls-files will not
    # stage it) and this example goes RED. G1 debris/README stay uncommitted.
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

  It 'stages a rewrite of an already-tracked dest autoindex that this run did not touch'
    # ls-files dest-level pin: origin already tracks docs/nightly/ce-2.8/index.html
    # and this run only touches edge/ce-2.8. gen_landing rewrites every existing
    # dest autoindex; only the ls-files dest-index stage picks this one up.
    # Dropping that stage leaves the rewrite unstaged and this example goes RED,
    # even if git clean remains (the file is tracked, so clean cannot remove it).
    # Distinct from the touched-channel docs/edge/index.html rewrite below.
    mkdir -p "${base}/pkg-repo/docs/nightly/ce-2.8"
    printf 'old dest index\n' > "${base}/pkg-repo/docs/nightly/ce-2.8/index.html"
    ( cd "${base}/pkg-repo" && git_fixture add docs/nightly/ce-2.8/index.html \
        && git_fixture commit -q -m preseed-nightly-dest-index \
        && git_fixture push -q origin main )
    export FAKE_MODE=success
    export FAKE_TOUCHED=edge/ce-2.8
    When run script "$script"
    The status should equal 0
    The output should include 'ADVANCE'
    The stderr should include 'main'
    committed="$(git_fixture -C "${base}/pkg-repo" show --name-only --format= HEAD)"
    The variable committed should include 'docs/nightly/ce-2.8/index.html'
    rewritten="$(git_fixture -C "${base}/pkg-repo" show HEAD:docs/nightly/ce-2.8/index.html)"
    The variable rewritten should equal 'autoindex stub: nightly/ce-2.8'
  End

  It 'still stages a rewrite of an already-tracked channel autoindex'
    printf 'old channel index\n' > "${base}/pkg-repo/docs/edge/index.html"
    ( cd "${base}/pkg-repo" && git_fixture add docs/edge/index.html \
        && git_fixture commit -q -m preseed-channel-index \
        && git_fixture push -q origin main )
    export FAKE_MODE=success
    export FAKE_TOUCHED=edge/ce-2.8
    When run script "$script"
    The status should equal 0
    The output should include 'ADVANCE'
    The stderr should include 'main'
    committed="$(git_fixture -C "${base}/pkg-repo" show --name-only --format= HEAD)"
    The variable committed should include 'docs/edge/index.html'
    rewritten="$(cat "${base}/pkg-repo/docs/edge/index.html")"
    The variable rewritten should equal 'autoindex stub: edge'
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

  It 'commits nothing on a no-op run with current client scripts'
    # The catalogue-NOOP path still regenerates every client script
    # (issue #2408, issue #2416) — pre-seed them byte-identical to the stub
    # generator's output so the full-NOOP branch is reached honestly, not via drift.
    write_client_script_stubs
    # shellcheck disable=SC2086  # CLIENT_SCRIPT_PATHS is a controlled, space-separated pathspec list
    ( cd "${base}/pkg-repo" && git_fixture add $CLIENT_SCRIPT_PATHS \
        && git_fixture commit -q -m preseed-scripts && git_fixture push -q origin main )
    original_head="$(git_fixture -C "${base}/pkg-repo" rev-parse main)"
    original_remote_head="$(git_fixture -C "${base}/remote.git" rev-parse refs/heads/main)"
    export FAKE_MODE=noop
    When run script "$script"
    The status should equal 0
    The output should include 'NOOP'
    The result of function local_head_now should equal "$original_head"
    The result of function remote_head_now should equal "$original_remote_head"
  End

  # Fixture for the client-script-refresh examples: a catalogue no-op with
  # drifted scripts, plus every trap an over-broad stage could sweep in —
  # committed landing pages whose bytes DIFFER from the stub generator's
  # output (a regression that regenerates the timestamped pages on a no-op
  # produces a real diff there), an untracked file, and a dirty tracked file
  # (either of which a `git add -A`/`.` regression would commit).
  seed_refresh_drift() {
    printf 'old landing\n' > "${base}/pkg-repo/docs/index.html"
    printf 'old browse\n' > "${base}/pkg-repo/docs/browse.html"
    ( cd "${base}/pkg-repo" && git_fixture add docs/index.html docs/browse.html \
        && git_fixture commit -q -m preseed-landing && git_fixture push -q origin main )
    original_head="$(git_fixture -C "${base}/pkg-repo" rev-parse main)"
    original_remote_head="$(git_fixture -C "${base}/remote.git" rev-parse refs/heads/main)"
    echo debris > "${base}/pkg-repo/debris.txt"
    echo dirty >> "${base}/pkg-repo/README.txt"
  }

  It 'ships a client-script refresh when the catalogue is a no-op but the scripts drifted'
    # The seed tree carries NO committed client scripts — maximal drift. A
    # catalogue no-op must still publish every one of them: the scripts are
    # generated from PFB_SRC, not from release assets, so a script-only fix was
    # otherwise unshippable via a republish of an already-published release
    # (issue #2408, issue #2416).
    seed_refresh_drift
    export FAKE_MODE=noop
    When run script "$script"
    The status should equal 0
    The output should include 'ADVANCE'
    # The wrapper's own no-op verdict must not appear; the publisher's
    # "NOOP: every destination already matches" line legitimately does.
    The output should not include 'publish-pkg-repo: NOOP'
    The stderr should include 'main'
    The result of function remote_head_now should not equal "$original_remote_head"
    committed="$(git_fixture -C "${base}/pkg-repo" show --name-only --format= HEAD | sort | xargs)"
    The variable committed should equal "$SORTED_CLIENT_SCRIPT_PATHS"
  End

  It 'a client-script refresh commits EXACTLY the four scripts and says so in the commit'
    # Exact-list equality: no landing/browse/autoindex page, no untracked or
    # unrelated dirty file may ride along (the seeded traps above would each
    # break the equality), and the commit subject + run-id trailer must
    # identify the refresh.
    seed_refresh_drift
    export FAKE_MODE=noop
    When run script "$script"
    The status should equal 0
    The output should include 'ADVANCE'
    The stderr should include 'main'
    committed="$(git_fixture -C "${base}/pkg-repo" show --name-only --format= HEAD | sort | xargs)"
    The variable committed should equal "$SORTED_CLIENT_SCRIPT_PATHS"
    msg="$(git_fixture -C "${base}/pkg-repo" log -1 --format=%B)"
    The variable msg should include 'publish: refresh client scripts'
    The variable msg should include 'pfBlockerNG-Source-Run-Id: 10:1'
  End

  It 'a stale single client script still ships a refresh that touches only it'
    # issue #2416 follow-up made install.sh the SOLE client entry point. Pre-seed it
    # stale (byte-different from the stub generator's current output) with nothing
    # else dirty: the refresh is reached, and the resulting commit touches ONLY
    # that one script.
    printf '#!/bin/sh\n# stale install\n' > "${base}/pkg-repo/docs/install.sh"
    # shellcheck disable=SC2086  # CLIENT_SCRIPT_PATHS is a controlled, space-separated pathspec list
    ( cd "${base}/pkg-repo" && git_fixture add $CLIENT_SCRIPT_PATHS \
        && git_fixture commit -q -m preseed-scripts && git_fixture push -q origin main )
    original_remote_head="$(git_fixture -C "${base}/remote.git" rev-parse refs/heads/main)"
    export FAKE_MODE=noop
    When run script "$script"
    The status should equal 0
    The output should include 'ADVANCE'
    The stderr should include 'main'
    The result of function remote_head_now should not equal "$original_remote_head"
    committed="$(git_fixture -C "${base}/pkg-repo" show --name-only --format= HEAD | sort | xargs)"
    The variable committed should equal 'docs/install.sh'
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
    write_client_script_stubs
    # docs/.nojekyll is truncate-and-recreated unconditionally whenever the
    # script has any touched target (regardless of whether the target itself
    # changed) — pre-seed it too, or its own first-ever creation would be a
    # genuine diff and mask the branch this test means to reach.
    true > "${base}/pkg-repo/docs/.nojekyll"
    # shellcheck disable=SC2086  # CLIENT_SCRIPT_PATHS is a controlled, space-separated pathspec list
    ( cd "${base}/pkg-repo" && git_fixture add docs/index.html docs/browse.html \
        docs/edge/index.html docs/edge/ce-2.8/index.html docs/.nojekyll $CLIENT_SCRIPT_PATHS \
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

  # --- PUBLISH_REFRESH_LANDING (issue #2416 follow-up: republish of an
  # already-published release must be able to refresh the landing page, not
  # just the client scripts) ------------------------------------------------

  It 'refresh-landing: PUBLISH_REFRESH_LANDING=1 forces a full landing regen on the NOOP path, committing index.html plus the client script'
    export PUBLISH_REFRESH_LANDING=1
    export FAKE_MODE=noop
    When run script "$script"
    The status should equal 0
    The output should include 'ADVANCE'
    The stderr should include 'main'
    The path "${base}/pkg-repo/docs/index.html" should be exist
    committed="$(git_fixture -C "${base}/pkg-repo" show --name-only --format= HEAD | sort | xargs)"
    The variable committed should include 'docs/index.html'
    The variable committed should include 'docs/install.sh'
    msg="$(git_fixture -C "${base}/pkg-repo" log -1 --format=%B)"
    The variable msg should include 'publish: refresh landing page'
    The variable msg should include 'pfBlockerNG-Source-Run-Id: 10:1'
  End

  It 'refresh-landing: PUBLISH_REFRESH_LANDING unset leaves the NOOP path unchanged — no landing regen'
    write_client_script_stubs
    # shellcheck disable=SC2086  # CLIENT_SCRIPT_PATHS is a controlled, space-separated pathspec list
    ( cd "${base}/pkg-repo" && git_fixture add $CLIENT_SCRIPT_PATHS \
        && git_fixture commit -q -m preseed-scripts && git_fixture push -q origin main )
    export FAKE_MODE=noop
    When run script "$script"
    The status should equal 0
    The output should include 'NOOP'
    The path "${base}/pkg-repo/docs/index.html" should not be exist
  End

  It 'refresh-landing: PUBLISH_REFRESH_LANDING=1 is rejected under PUBLISH_STAGE=stage, before any git call'
    export PUBLISH_REFRESH_LANDING=1
    export PUBLISH_STAGE=stage
    When run script "$script"
    The status should equal 1
    The stderr should include '::error::PUBLISH_REFRESH_LANDING=1 requires PUBLISH_KIND=tagged and PUBLISH_STAGE=direct'
    The result of function local_head_now should equal "$original_head"
    The result of function remote_head_now should equal "$original_remote_head"
  End

  It 'refresh-landing: PUBLISH_REFRESH_LANDING=1 is rejected under PUBLISH_STAGE=promote, before any git call'
    export PUBLISH_REFRESH_LANDING=1
    export PUBLISH_STAGE=promote
    When run script "$script"
    The status should equal 1
    The stderr should include '::error::PUBLISH_REFRESH_LANDING=1 requires PUBLISH_KIND=tagged and PUBLISH_STAGE=direct'
    The result of function local_head_now should equal "$original_head"
    The result of function remote_head_now should equal "$original_remote_head"
  End

  It 'refresh-landing: PUBLISH_REFRESH_LANDING=1 is rejected under PUBLISH_STAGE=discard, before any git call'
    export PUBLISH_REFRESH_LANDING=1
    export PUBLISH_STAGE=discard
    When run script "$script"
    The status should equal 1
    The stderr should include '::error::PUBLISH_REFRESH_LANDING=1 requires PUBLISH_KIND=tagged and PUBLISH_STAGE=direct'
    The result of function local_head_now should equal "$original_head"
    The result of function remote_head_now should equal "$original_remote_head"
  End

  It 'refresh-landing: PUBLISH_REFRESH_LANDING=1 is rejected under PUBLISH_KIND=nightly, before any git call'
    nightly_env
    export PUBLISH_REFRESH_LANDING=1
    When run script "$script"
    The status should equal 1
    The stderr should include '::error::PUBLISH_REFRESH_LANDING=1 requires PUBLISH_KIND=tagged and PUBLISH_STAGE=direct'
    The result of function local_head_now should equal "$original_head"
    The result of function remote_head_now should equal "$original_remote_head"
  End

  It 'refresh-landing: rejects a PUBLISH_REFRESH_LANDING value other than 0 or 1, before any git call'
    export PUBLISH_REFRESH_LANDING=yes
    When run script "$script"
    The status should equal 1
    The stderr should include "::error::PUBLISH_REFRESH_LANDING must be '0' or '1', got 'yes'"
    The result of function local_head_now should equal "$original_head"
    The result of function remote_head_now should equal "$original_remote_head"
  End

  # --- retired client scripts (docs/add-repo.sh, docs/migrate-channel.sh —
  # replaced by the single --channel install.sh, issue #2416 follow-up) must be
  # swept off an already-live site by a republish -----------------------------

  It 'retired: PUBLISH_REFRESH_LANDING=1 sweeps retired client scripts into the landing-regen NOOP commit'
    # The sweep only ever rides a commit that ALSO regenerates the landing page —
    # the knob-off NOOP path below never sweeps (the live index.html still links
    # the retired scripts; a knob-off sweep would 404 it without a regen).
    write_client_script_stubs
    # shellcheck disable=SC2086  # CLIENT_SCRIPT_PATHS is a controlled, space-separated pathspec list
    ( cd "${base}/pkg-repo" && git_fixture add $CLIENT_SCRIPT_PATHS \
        && git_fixture commit -q -m preseed-scripts && git_fixture push -q origin main )
    printf '#!/bin/sh\n# add-repo stub\n' > "${base}/pkg-repo/docs/add-repo.sh"
    printf '#!/bin/sh\n# migrate-channel stub\n' > "${base}/pkg-repo/docs/migrate-channel.sh"
    ( cd "${base}/pkg-repo" && git_fixture add docs/add-repo.sh docs/migrate-channel.sh \
        && git_fixture commit -q -m preseed-retired-scripts && git_fixture push -q origin main )
    export PUBLISH_REFRESH_LANDING=1
    export FAKE_MODE=noop
    When run script "$script"
    The status should equal 0
    The output should include 'ADVANCE'
    The stderr should include 'main'
    committed="$(git_fixture -C "${base}/pkg-repo" show --name-only --format= HEAD | sort | xargs)"
    The variable committed should include 'docs/add-repo.sh'
    The variable committed should include 'docs/migrate-channel.sh'
    The variable committed should include 'docs/index.html'
    The path "${base}/pkg-repo/docs/add-repo.sh" should not be exist
    The path "${base}/pkg-repo/docs/migrate-channel.sh" should not be exist
  End

  It 'retired: PUBLISH_REFRESH_LANDING unset leaves retired scripts in place on the catalogue+script NOOP — no landing regen, no 404'
    # The retired-script sweep must never run without a landing regen in the
    # same commit — the live index.html still links docs/add-repo.sh, so a
    # knob-off sweep would 404 it. Knob unset (default '0') on an otherwise
    # true NOOP must leave the retired scripts untouched and commit nothing.
    write_client_script_stubs
    # shellcheck disable=SC2086  # CLIENT_SCRIPT_PATHS is a controlled, space-separated pathspec list
    ( cd "${base}/pkg-repo" && git_fixture add $CLIENT_SCRIPT_PATHS \
        && git_fixture commit -q -m preseed-scripts && git_fixture push -q origin main )
    printf '#!/bin/sh\n# add-repo stub\n' > "${base}/pkg-repo/docs/add-repo.sh"
    printf '#!/bin/sh\n# migrate-channel stub\n' > "${base}/pkg-repo/docs/migrate-channel.sh"
    ( cd "${base}/pkg-repo" && git_fixture add docs/add-repo.sh docs/migrate-channel.sh \
        && git_fixture commit -q -m preseed-retired-scripts && git_fixture push -q origin main )
    original_head="$(git_fixture -C "${base}/pkg-repo" rev-parse main)"
    original_remote_head="$(git_fixture -C "${base}/remote.git" rev-parse refs/heads/main)"
    export FAKE_MODE=noop
    When run script "$script"
    The status should equal 0
    The output should include 'NOOP'
    The result of function local_head_now should equal "$original_head"
    The result of function remote_head_now should equal "$original_remote_head"
    The path "${base}/pkg-repo/docs/add-repo.sh" should be exist
    The path "${base}/pkg-repo/docs/migrate-channel.sh" should be exist
  End

  It 'retired: a real publish also removes retired client scripts still present on the site'
    printf '#!/bin/sh\n# add-repo stub\n' > "${base}/pkg-repo/docs/add-repo.sh"
    printf '#!/bin/sh\n# migrate-channel stub\n' > "${base}/pkg-repo/docs/migrate-channel.sh"
    ( cd "${base}/pkg-repo" && git_fixture add docs/add-repo.sh docs/migrate-channel.sh \
        && git_fixture commit -q -m preseed-retired-scripts && git_fixture push -q origin main )
    export FAKE_MODE=success
    export FAKE_TOUCHED=edge/ce-2.8
    When run script "$script"
    The status should equal 0
    The output should include 'ADVANCE'
    The stderr should include 'main'
    committed="$(git_fixture -C "${base}/pkg-repo" show --name-only --format= HEAD | sort | xargs)"
    The variable committed should include 'docs/add-repo.sh'
    The variable committed should include 'docs/migrate-channel.sh'
    The variable committed should include 'docs/edge/ce-2.8/marker.pkg'
    The path "${base}/pkg-repo/docs/add-repo.sh" should not be exist
    The path "${base}/pkg-repo/docs/migrate-channel.sh" should not be exist
  End

  It 'retired: retired client scripts absent from the site never error the run'
    export FAKE_MODE=success
    export FAKE_TOUCHED=edge/ce-2.8
    When run script "$script"
    The status should equal 0
    The output should include 'ADVANCE'
    The stderr should include 'main'
    committed="$(git_fixture -C "${base}/pkg-repo" show --name-only --format= HEAD)"
    The variable committed should not include 'add-repo.sh'
    The variable committed should not include 'migrate-channel.sh'
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
    # Same pre-seed as the tagged no-op example: the catalogue-NOOP path
    # regenerates every client script (issue #2408, issue #2416), so a true
    # no-op needs them all current in the seed tree.
    write_client_script_stubs
    # shellcheck disable=SC2086  # CLIENT_SCRIPT_PATHS is a controlled, space-separated pathspec list
    ( cd "${base}/pkg-repo" && git_fixture add $CLIENT_SCRIPT_PATHS \
        && git_fixture commit -q -m preseed-scripts && git_fixture push -q origin main )
    original_head="$(git_fixture -C "${base}/pkg-repo" rev-parse main)"
    original_remote_head="$(git_fixture -C "${base}/remote.git" rev-parse refs/heads/main)"
    export FAKE_MODE=noop
    When run script "$script"
    The status should equal 0
    The output should include 'NOOP'
    The result of function local_head_now should equal "$original_head"
    The result of function remote_head_now should equal "$original_remote_head"
  End

  It 'n5b: nightly mode ships the same mode-independent client-script refresh'
    # The refresh branch precedes the PUBLISH_KIND commit-message split and
    # must never acquire nightly identity: no jq pkg_version read, no
    # pfBlockerNG-Nightly-Version trailer (the handoff fixture carries a
    # pkg_version, so the nightly arm COULD produce one — this pins that the
    # refresh arm does not route through it).
    nightly_env
    seed_refresh_drift
    export FAKE_MODE=noop
    When run script "$script"
    The status should equal 0
    The output should include 'ADVANCE'
    The stderr should include 'main'
    committed="$(git_fixture -C "${base}/pkg-repo" show --name-only --format= HEAD | sort | xargs)"
    The variable committed should equal "$SORTED_CLIENT_SCRIPT_PATHS"
    msg="$(git_fixture -C "${base}/pkg-repo" log -1 --format=%B)"
    The variable msg should include 'publish: refresh client scripts'
    The variable msg should include 'pfBlockerNG-Source-Run-Id: 10:1'
    The variable msg should not include 'pfBlockerNG-Nightly-Version'
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

  It 'n9: nightly mode derives the landing matrix from the handoff route_matrix, not $ROUTE_MATRIX'
    # nightly_env's handoff route_matrix (freebsd 16/2.9/Plus/8.4/py312) is
    # DELIBERATELY a different row than common_env's own $ROUTE_MATRIX
    # (freebsd 15/2.8/CE/8.3/py311, still exported here): asserting the
    # HANDOFF row's own values is what a wrong `landing_input="$ROUTE_MATRIX"`
    # read in the nightly arm would actually fail on -- byte-identical
    # fixtures would let that regression pass silently.
    nightly_env
    export FAKE_MODE=success
    export FAKE_TOUCHED=nightly/ce-2.8
    export FAKE_LANDING_MATRIX_RECORD="${base}/landing-matrix-seen.json"
    When run script "$script"
    The status should equal 0
    The output should include 'ADVANCE'
    The stderr should include 'main'
    seen="$(cat "${base}/landing-matrix-seen.json")"
    The variable seen should equal '[{"abi":"FreeBSD:16:*","pfsense_version":"2.9","variant":"Plus","php_version":"8.4","py_flavor":"py312"}]'
    The variable seen should not include '"pfsense_version":"2.8"'
  End

  # --- PUBLISH_STAGE=stage|promote|discard (issue #2389 S1, gate-before-announce) --
  # docs/ on `main` IS the Pages site, so a plain tagged publish commits the
  # catalogue and the landing page atomically and nothing can be live-gated before
  # announce. common_env's SOURCE_RUN_ID is "10:1" (colon, matching the real
  # release-published.yml workflow) -- PUBLISH_STAGE=stage translates it to the
  # dash-form staging segment "10-1" throughout these examples.

  It 's1: stage relocates a touched target under docs/staging/<segment>, restoring the original at its real location'
    # Materialize + commit every client script BEFORE the run (as a prior "direct"
    # publish would have left them) so the negative assertions below can actually
    # FAIL on a regression — a stage run that never wrote them in the first place
    # would pass those assertions vacuously (issue #2416 CodeRabbit finding).
    write_client_script_stubs
    # shellcheck disable=SC2086  # CLIENT_SCRIPT_PATHS is a controlled, space-separated pathspec list
    ( cd "${base}/pkg-repo" && git_fixture add $CLIENT_SCRIPT_PATHS \
        && git_fixture commit -q -m preseed-scripts && git_fixture push -q origin main )
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
    The path "${base}/pkg-repo/docs/index.html" should not be exist
    # No landing regen during "stage" (staging is never served) — the client script
    # (already on disk/tracked from the preseed above) is not touched, staged, or
    # re-committed by this run. Every candidate path was materialized above so each
    # negative assertion can actually fail.
    committed="$(git_fixture -C "${base}/pkg-repo" show --stat --format= HEAD | tr -s ' ' | sed 's/^ *//;s/ .*//')"
    The variable committed should include 'docs/staging/10-1/edge/ce-2.8/marker.pkg'
    The variable committed should not include 'docs/index.html'
    The path "${base}/pkg-repo/docs/install.sh" should be exist
    The variable committed should not include 'docs/install.sh'
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

  It 's4: stage full no-op (nothing touched, scripts current) writes noop=true and prints STAGE NOOP'
    export PUBLISH_STAGE=stage
    write_client_script_stubs
    # shellcheck disable=SC2086  # CLIENT_SCRIPT_PATHS is a controlled, space-separated pathspec list
    (cd "${base}/pkg-repo" && git_fixture add $CLIENT_SCRIPT_PATHS \
        && git_fixture commit -q -m preseed-scripts && git_fixture push -q origin main)
    original_head="$(git_fixture -C "${base}/pkg-repo" rev-parse main)"
    original_remote_head="$(git_fixture -C "${base}/remote.git" rev-parse refs/heads/main)"
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

  It 's4b: stage full no-op with retired scripts present leaves them untouched — PUBLISH_REFRESH_LANDING is always 0 under stage'
    # PUBLISH_REFRESH_LANDING=1 is rejected under PUBLISH_STAGE=stage (see the
    # refresh-landing rejection examples above), so the knob is always '0' here
    # — the shared no-op branch must never sweep retired scripts on a stage run
    # either.
    export PUBLISH_STAGE=stage
    write_client_script_stubs
    # shellcheck disable=SC2086  # CLIENT_SCRIPT_PATHS is a controlled, space-separated pathspec list
    (cd "${base}/pkg-repo" && git_fixture add $CLIENT_SCRIPT_PATHS \
        && git_fixture commit -q -m preseed-scripts && git_fixture push -q origin main)
    printf '#!/bin/sh\n# add-repo stub\n' > "${base}/pkg-repo/docs/add-repo.sh"
    printf '#!/bin/sh\n# migrate-channel stub\n' > "${base}/pkg-repo/docs/migrate-channel.sh"
    ( cd "${base}/pkg-repo" && git_fixture add docs/add-repo.sh docs/migrate-channel.sh \
        && git_fixture commit -q -m preseed-retired-scripts && git_fixture push -q origin main )
    original_head="$(git_fixture -C "${base}/pkg-repo" rev-parse main)"
    original_remote_head="$(git_fixture -C "${base}/remote.git" rev-parse refs/heads/main)"
    export FAKE_MODE=noop
    export GITHUB_OUTPUT="${base}/github_output.txt"
    true >"$GITHUB_OUTPUT"
    When run script "$script"
    The status should equal 0
    The output should include 'NOOP'
    The result of function local_head_now should equal "$original_head"
    The result of function remote_head_now should equal "$original_remote_head"
    The path "${base}/pkg-repo/docs/add-repo.sh" should be exist
    The path "${base}/pkg-repo/docs/migrate-channel.sh" should be exist
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

  It 's8: stage mode client-script refresh (nothing touched, scripts drifted) still emits noop=true'
    # The workflow (S2) keys its live-gate dispatch on GITHUB_OUTPUT noop != 'true'
    # -- a script-only refresh has nothing staged to gate, so it must report
    # noop=true (touched=[]) even though a real commit landed on main (ADVANCE).
    export PUBLISH_STAGE=stage
    seed_refresh_drift
    export FAKE_MODE=noop
    export GITHUB_OUTPUT="${base}/github_output.txt"
    true >"$GITHUB_OUTPUT"
    When run script "$script"
    The status should equal 0
    The output should include 'ADVANCE'
    The stderr should include 'main'
    committed="$(git_fixture -C "${base}/pkg-repo" show --name-only --format= HEAD | sort | xargs)"
    The variable committed should equal "$SORTED_CLIENT_SCRIPT_PATHS"
    out="$(cat "$GITHUB_OUTPUT")"
    The variable out should include 'staging_prefix=staging/10-1'
    The variable out should include 'touched=[]'
    The variable out should include 'noop=true'
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
    The output should include 'ADVANCE'
    The stderr should include 'main'
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

  It 'p1: promote moves a staged tree live, regenerates the landing page, and never sweeps unrelated dirty/untracked files'
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
    The path "${base}/pkg-repo/docs/index.html" should be exist
    landing="$(cat "${base}/pkg-repo/docs/index.html")"
    The variable landing should equal 'landing stub'
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

  It 'p1b: promote also sweeps retired client scripts still present on the live site'
    # promote runs landing_regen_and_stage (it IS a landing regen — the step
    # that goes live), so the retired-script sweep belongs there too, same as
    # the direct real-publish path.
    seed_staged_tree
    printf '#!/bin/sh\n# add-repo stub\n' > "${base}/pkg-repo/docs/add-repo.sh"
    printf '#!/bin/sh\n# migrate-channel stub\n' > "${base}/pkg-repo/docs/migrate-channel.sh"
    ( cd "${base}/pkg-repo" && git_fixture add docs/add-repo.sh docs/migrate-channel.sh \
        && git_fixture commit -q -m preseed-retired-scripts && git_fixture push -q origin main )
    export PUBLISH_STAGE=promote
    export STAGING_PREFIX=staging/10-1
    When run script "$script"
    The status should equal 0
    The output should include 'ADVANCE'
    The stderr should include 'main'
    committed="$(git_fixture -C "${base}/pkg-repo" show --name-only --format= HEAD | sort | xargs)"
    The variable committed should include 'docs/add-repo.sh'
    The variable committed should include 'docs/migrate-channel.sh'
    The variable committed should include 'docs/edge/ce-2.8/marker.pkg'
    The path "${base}/pkg-repo/docs/add-repo.sh" should not be exist
    The path "${base}/pkg-repo/docs/migrate-channel.sh" should not be exist
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
