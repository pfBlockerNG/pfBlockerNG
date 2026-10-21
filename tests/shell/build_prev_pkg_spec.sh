#shellcheck shell=sh
# build_prev_pkg_spec.sh — issue #3455 S1: scripts/build-prev-pkg.sh.
#
# The script builds the previous-devel .pkg (SMOKE_PREV_PKG) the HA mixed-version smoke
# rows install on node B. Layer: argv + filesystem contract, no real build. build-leg.sh
# is stubbed (argv recorded, the local-src listing captured AT BUILD TIME, a fake .pkg
# printed); git is real, run against fixture repos so the P tree extraction and the
# fetch-by-SHA path execute for real.
#
# The script copy lives in a fixture repo's scripts/ dir, so its repo root (where it runs
# git and finds build-leg.sh) is the fixture, never this checkout. The real pin is a commit
# this fixture repo cannot contain, so install_scripts writes PIN_REF into each fixture
# copy's `_PIN=` line; the shipped script has no override seam.

Describe 'build-prev-pkg.sh (issue #3455)'
  SCRIPT="${PFB_ROOT}/scripts/build-prev-pkg.sh"

  setup() {
    scrub_git_env
    unset PFB_PREV_PKG_REF PFB_PREV_PKG_WORK PFB_GIT_REMOTE \
      FAKE_BUILD_EXIT FAKE_NOISE FAKE_NO_FILE FAKE_CHAN
    WORK="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/prevpkg.XXXXXX")"
    FAKE_ROOT="${WORK}/repo"
    mkdir -p "${FAKE_ROOT}/scripts/lib"
    PFB_PREV_PKG_WORK="${WORK}/scratch dir"
    BUILD_LEG_ARGV_LOG="${WORK}/build-leg-argv"
    TREE_LISTING_LOG="${WORK}/tree-listing"
    export PFB_PREV_PKG_WORK BUILD_LEG_ARGV_LOG TREE_LISTING_LOG

    # Fixture history: P1 carries src/usr/old, HEAD carries src/usr/new. The build must
    # package P1's tree, never the checked-out one.
    git_fixture init --quiet "$FAKE_ROOT" >/dev/null 2>&1
    mkdir -p "${FAKE_ROOT}/src/usr"
    true > "${FAKE_ROOT}/src/usr/old"
    printf 'outside src\n' > "${FAKE_ROOT}/README"
    git_fixture -C "$FAKE_ROOT" add -A >/dev/null 2>&1
    git_fixture -C "$FAKE_ROOT" -c user.name=t -c user.email=t@example.com \
      commit --quiet -m p1 >/dev/null 2>&1
    P1="$(git_fixture -C "$FAKE_ROOT" rev-parse HEAD)"
    rm "${FAKE_ROOT}/src/usr/old"
    true > "${FAKE_ROOT}/src/usr/new"
    git_fixture -C "$FAKE_ROOT" add -A >/dev/null 2>&1
    git_fixture -C "$FAKE_ROOT" -c user.name=t -c user.email=t@example.com \
      commit --quiet -m head >/dev/null 2>&1

    PIN_REF="$P1"
    install_scripts "$FAKE_ROOT"
  }

  # The real script and lib, plus a build-leg.sh stub, inside a fixture repo's scripts/.
  install_scripts() {
    mkdir -p "$1/scripts/lib"
    # The pin is not overridable in production, so each fixture copy carries PIN_REF as its pin.
    sed "s/^_PIN=.*/_PIN=${PIN_REF}/" "$SCRIPT" > "$1/scripts/build-prev-pkg.sh"
    grep -qx "_PIN=${PIN_REF}" "$1/scripts/build-prev-pkg.sh" || return 1
    cp "${PFB_ROOT}/scripts/lib/git-env-scrub.sh" "$1/scripts/lib/"
    cat > "$1/scripts/build-leg.sh" <<'STUBEOF'
#!/bin/sh
printf '%s\n' "$@" > "$BUILD_LEG_ARGV_LOG"
_src=''; _out=''
while [ "$#" -gt 0 ]; do
    case "$1" in
        --local-src) _src="$2"; shift ;;
        --out-dir) _out="$2"; shift ;;
    esac
    shift
done
ls "$_src/src/usr" > "$TREE_LISTING_LOG" 2>&1
[ -z "${FAKE_NOISE:-}" ] || printf 'git chatter on stdout\n'
_pkg="${_out}/pfSense-pkg-pfBlockerNG-${FAKE_CHAN:-edge}-4.0.0.a1.pkg"
if [ -z "${FAKE_NO_FILE:-}" ]; then
    mkdir -p "$_out"
    true > "$_pkg"
fi
printf '%s\n' "$_pkg"
exit "${FAKE_BUILD_EXIT:-0}"
STUBEOF
    chmod +x "$1/scripts/build-leg.sh"
  }

  teardown() { rm -rf "$WORK"; }

  BeforeEach 'setup'
  AfterEach 'teardown'

  run_prev() { sh "${FAKE_ROOT}/scripts/build-prev-pkg.sh" "$@"; }
  # True when FILE (one arg per line) holds FLAG followed by VALUE.
  argv_has_pair() { awk -v f="$1" -v v="$2" 'prev==f && $0==v{found=1} {prev=$0} END{exit !found}' "$3"; }
  # True when VALUE follows the LAST occurrence of FLAG: build-leg's later flag wins.
  last_arg_is() { awk -v f="$1" -v v="$2" 'want{val=$0;want=0} $0==f{want=1} END{exit !(val==v)}' "$3"; }

  # ── the pin ───────────────────────────────────────────────────────────────── #

  It '--print-ref prints the shipped pin: one 40-hex commit id and nothing else'
    check_pin() {
      _got="$(sh "$SCRIPT" --print-ref)" || return 1
      case "$_got" in
        '' | *[!0-9a-f]*) printf 'not hex: %s\n' "$_got"; return 1 ;;
      esac
      [ "${#_got}" -eq 40 ] && printf 'ok\n'
    }
    When call check_pin
    The status should be success
    The output should equal 'ok'
  End

  # The pin is production code, reachable from any environment: no variable may move it.
  It 'ignores PFB_PREV_PKG_REF: a garbage, empty or foreign value cannot move the pin'
    check_ignored() {
      _pin="$(sed -n 's/^_PIN=//p' "$SCRIPT")"
      for _bad in garbage '' 0000000000000000000000000000000000000000 "$P1"; do
        _got="$(PFB_PREV_PKG_REF="$_bad" sh "$SCRIPT" --print-ref)" || return 1
        [ "$_got" = "$_pin" ] || { printf 'override [%s] moved the pin to [%s]\n' "$_bad" "$_got"; return 1; }
      done
      printf 'ok\n'
    }
    When call check_ignored
    The status should be success
    The output should equal 'ok'
  End

  It 'builds the pinned commit even when PFB_PREV_PKG_REF holds garbage'
    PFB_PREV_PKG_REF=garbage
    export PFB_PREV_PKG_REF
    When call run_prev
    The status should be success
    The output should be present
    The stderr should include "build-prev-pkg: ref=${P1}"
  End

  # ── building from P's tree ────────────────────────────────────────────────── #

  It 'packages the pinned commit tree, not the checked-out one, and prints only the pkg path'
    When call run_prev --abi FreeBSD:15:amd64
    The status should be success
    The output should equal "${PFB_PREV_PKG_WORK}/out/pfSense-pkg-pfBlockerNG-edge-4.0.0.a1.pkg"
    The stderr should include "build-prev-pkg: ref=${P1}"
    The contents of file "$TREE_LISTING_LOG" should equal 'old'
  End

  It 'names P, the package file and its version on one line'
    When call run_prev
    The status should be success
    The output should be present
    The stderr should include "build-prev-pkg: ref=${P1} pkg=${PFB_PREV_PKG_WORK}/out/pfSense-pkg-pfBlockerNG-edge-4.0.0.a1.pkg version=4.0.0.a1"
  End

  It 'hands build-leg the caller args, then its own --local-src and --out-dir last'
    When call run_prev --abi FreeBSD:16:amd64 --local-src /elsewhere
    The status should be success
    The output should be present
    The stderr should be present
    Assert argv_has_pair --abi FreeBSD:16:amd64 "$BUILD_LEG_ARGV_LOG"
    # build-leg's later flag wins, so the caller's --local-src can never win.
    Assert last_arg_is --local-src "${PFB_PREV_PKG_WORK}/tree" "$BUILD_LEG_ARGV_LOG"
    Assert last_arg_is --out-dir "${PFB_PREV_PKG_WORK}/out" "$BUILD_LEG_ARGV_LOG"
  End

  # The ports recipe is pinned beside the source, so the script names it and never the caller.
  ports_pin() { sed -n 's/^_PORTS_PIN=//p' "$SCRIPT"; }
  # An empty pin would match a missing --ports-ref, so the pin must be a commit id first.
  is_sha() { case "$1" in '' | *[!0-9a-f]*) return 1 ;; esac; [ "${#1}" -eq 40 ]; }

  It 'pins the ports recipe and its checkout dir last, overriding the caller ports args'
    _pin="$(ports_pin)"
    When call run_prev --ports-ref --evil --ports-repo /caller/ports --ports-dir /caller/dir --abi FreeBSD:15:amd64
    The status should be success
    The output should be present
    The stderr should be present
    Assert is_sha "$_pin"
    Assert last_arg_is --ports-ref "$_pin" "$BUILD_LEG_ARGV_LOG"
    Assert last_arg_is --ports-repo pfBlockerNG/FreeBSD-ports "$BUILD_LEG_ARGV_LOG"
    Assert last_arg_is --ports-dir "${PFB_PREV_PKG_WORK}/ports" "$BUILD_LEG_ARGV_LOG"
  End

  It 'pins the ports recipe and its checkout dir when the caller passes no ports args'
    _pin="$(ports_pin)"
    When call run_prev --abi FreeBSD:15:amd64
    The status should be success
    The output should be present
    The stderr should be present
    Assert is_sha "$_pin"
    Assert last_arg_is --ports-ref "$_pin" "$BUILD_LEG_ARGV_LOG"
    Assert last_arg_is --ports-repo pfBlockerNG/FreeBSD-ports "$BUILD_LEG_ARGV_LOG"
    Assert last_arg_is --ports-dir "${PFB_PREV_PKG_WORK}/ports" "$BUILD_LEG_ARGV_LOG"
  End

  keep_ports() { mkdir -p "${PFB_PREV_PKG_WORK}/ports"; true > "${PFB_PREV_PKG_WORK}/ports/marker"; }

  It 'keeps the ports checkout across a rebuild, so the next run reuses it'
    BeforeCall 'keep_ports'
    When call run_prev
    The status should be success
    The output should be present
    The stderr should be present
    The path "${PFB_PREV_PKG_WORK}/ports/marker" should be exist
  End

  It 'takes the last stdout line of build-leg when it prints more than the path'
    FAKE_NOISE=1
    export FAKE_NOISE
    When call run_prev
    The status should be success
    The output should equal "${PFB_PREV_PKG_WORK}/out/pfSense-pkg-pfBlockerNG-edge-4.0.0.a1.pkg"
    The stderr should be present
  End

  It 'recreates a stale scratch dir instead of reusing its contents'
    stale() {
      mkdir -p "${PFB_PREV_PKG_WORK}/tree/src/usr" "${PFB_PREV_PKG_WORK}/out"
      true > "${PFB_PREV_PKG_WORK}/tree/src/usr/stale"
      true > "${PFB_PREV_PKG_WORK}/out/pfSense-pkg-pfBlockerNG-edge-0.0.1.pkg"
    }
    BeforeCall 'stale'
    When call run_prev
    The status should be success
    The output should be present
    The stderr should be present
    The contents of file "$TREE_LISTING_LOG" should equal 'old'
    The path "${PFB_PREV_PKG_WORK}/out/pfSense-pkg-pfBlockerNG-edge-0.0.1.pkg" should not be exist
  End

  It 'is not thrown off by an inherited GIT_DIR from a hook'
    hook_env() { GIT_DIR="${WORK}/not-a-repo"; export GIT_DIR; }
    BeforeCall 'hook_env'
    When call run_prev
    The status should be success
    The output should be present
    The stderr should be present
    The contents of file "$TREE_LISTING_LOG" should equal 'old'
  End

  # ── getting P into the checkout ───────────────────────────────────────────── #
  # A CI checkout is shallow, so P is not there: it is fetched by SHA, from the remote
  # the caller names (PFB_GIT_REMOTE, the one local-smoke.sh's box fetched the ref from).

  shallow_checkout() {
    REMOTE="${WORK}/remote.git"
    SHALLOW="${WORK}/shallow"
    git_fixture init --quiet --bare "$REMOTE" >/dev/null 2>&1
    git_fixture -C "$REMOTE" config uploadpack.allowAnySHA1InWant true
    git_fixture -C "$FAKE_ROOT" push --quiet "$REMOTE" HEAD:refs/heads/main >/dev/null 2>&1
    git_fixture clone --quiet --depth 1 "file://${REMOTE}" "$SHALLOW" >/dev/null 2>&1
    install_scripts "$SHALLOW"
    FAKE_ROOT="$SHALLOW"
  }
  full_clone_is_still_full() { git_fixture -C "$FULL" rev-parse --is-shallow-repository; }

  It 'fetches P by SHA into a shallow checkout that lacks it, then builds its tree'
    shallow_checkout
    When call run_prev
    The status should be success
    The output should be present
    The stderr should include "build-prev-pkg: ref=${P1}"
    The contents of file "$TREE_LISTING_LOG" should equal 'old'
  End

  It 'keeps a full clone full when it fetches P, instead of truncating its history to depth 1'
    # A box clone holds the whole history of the ref under test but not P when P sits on a
    # side branch; a depth-1 fetch there would turn the box's repo shallow for every later run.
    REMOTE="${WORK}/remote.git"
    FULL="${WORK}/full"
    _main="$(git_fixture -C "$FAKE_ROOT" rev-parse --abbrev-ref HEAD)"
    git_fixture -C "$FAKE_ROOT" checkout --quiet -b side "$P1" >/dev/null 2>&1
    true > "${FAKE_ROOT}/src/usr/side"
    git_fixture -C "$FAKE_ROOT" add -A >/dev/null 2>&1
    git_fixture -C "$FAKE_ROOT" -c user.name=t -c user.email=t@example.com \
      commit --quiet -m side >/dev/null 2>&1
    PIN_REF="$(git_fixture -C "$FAKE_ROOT" rev-parse HEAD)"
    git_fixture -C "$FAKE_ROOT" checkout --quiet "$_main" >/dev/null 2>&1
    git_fixture init --quiet --bare "$REMOTE" >/dev/null 2>&1
    git_fixture -C "$REMOTE" config uploadpack.allowAnySHA1InWant true
    git_fixture -C "$FAKE_ROOT" push --quiet "$REMOTE" "$_main" side >/dev/null 2>&1
    git_fixture clone --quiet --single-branch --branch "$_main" "file://${REMOTE}" "$FULL" >/dev/null 2>&1
    install_scripts "$FULL"
    FAKE_ROOT="$FULL"
    When call run_prev
    The status should be success
    The output should be present
    The stderr should be present
    The contents of file "$TREE_LISTING_LOG" should equal "old
side"
    The result of function full_clone_is_still_full should equal 'false'
  End

  It 'fetches from the remote named by PFB_GIT_REMOTE, not a hard-coded origin'
    shallow_checkout
    git_fixture -C "$FAKE_ROOT" remote rename origin mirror >/dev/null 2>&1
    PFB_GIT_REMOTE=mirror
    export PFB_GIT_REMOTE
    When call run_prev
    The status should be success
    The output should be present
    The stderr should be present
    The contents of file "$TREE_LISTING_LOG" should equal 'old'
  End

  It 'stops naming the fetch when no remote can supply P, and never builds'
    shallow_checkout
    git_fixture -C "$FAKE_ROOT" remote rename origin mirror >/dev/null 2>&1
    When call run_prev
    The status should be failure
    The output should equal ''
    The stderr should include 'build-prev-pkg: fetch failed'
    The stderr should include "$P1"
    The path "$BUILD_LEG_ARGV_LOG" should not be exist
  End

  It 'refuses a -- among the build-leg args, which would hide its own pins, and never builds'
    When call run_prev --abi FreeBSD:16:amd64 -- --ports-ref pfblockerng/use-github
    The status should be failure
    The output should equal ''
    The stderr should include "build-prev-pkg: '--'"
    The path "$BUILD_LEG_ARGV_LOG" should not be exist
  End

  It 'reads a remote that looks like an option as a remote, never as a git option'
    # An operator-supplied PFB_GIT_REMOTE of "--upload-pack=<cmd>" must not run <cmd>.
    shallow_checkout
    PFB_GIT_REMOTE="--upload-pack=touch ${WORK}/injected"
    export PFB_GIT_REMOTE
    When call run_prev
    The status should be failure
    The output should equal ''
    The stderr should include 'build-prev-pkg: fetch failed'
    The path "${WORK}/injected" should not be exist
    The path "$BUILD_LEG_ARGV_LOG" should not be exist
  End

  # ── failing loud ──────────────────────────────────────────────────────────── #

  It 'exits non-zero naming the build stage when build-leg fails'
    FAKE_BUILD_EXIT=1
    export FAKE_BUILD_EXIT
    When call run_prev
    The status should be failure
    The output should equal ''
    The stderr should include 'build-prev-pkg: build failed'
  End

  It 'exits non-zero when build-leg prints a path that is not a file'
    FAKE_NO_FILE=1
    export FAKE_NO_FILE
    When call run_prev
    The status should be failure
    The output should equal ''
    The stderr should include 'build-prev-pkg: build produced no package file'
  End

  # ── --like: build the same channel as the branch package ──────────────────── #

  It '--like carries the branch package channel to build-leg'
    When call run_prev --like "/some dir/pfSense-pkg-pfBlockerNG-testing-4.1.0.pkg"
    The status should be success
    The output should be present
    The stderr should be present
    Assert argv_has_pair --channel testing "$BUILD_LEG_ARGV_LOG"
    The contents of file "$BUILD_LEG_ARGV_LOG" should not include '--pkgversion'
  End

  It '--like reads a channel-less package name as the stable channel'
    When call run_prev --like /x/pfSense-pkg-pfBlockerNG-4.1.0.pkg
    The status should be success
    The output should be present
    The stderr should be present
    Assert argv_has_pair --channel stable "$BUILD_LEG_ARGV_LOG"
  End

  It '--like on a nightly package also carries its version, which a nightly build requires'
    When call run_prev --like /x/pfSense-pkg-pfBlockerNG-nightly-20261014120000.abcdef0.pkg
    The status should be success
    The output should be present
    The stderr should be present
    Assert argv_has_pair --channel nightly "$BUILD_LEG_ARGV_LOG"
    Assert argv_has_pair --pkgversion 20261014120000.abcdef0 "$BUILD_LEG_ARGV_LOG"
  End

  It '--like refuses a file that is not a pfBlockerNG package, before any fetch or build'
    When call run_prev --like /x/not-our-package-1.0.pkg
    The status should be failure
    The output should equal ''
    The stderr should include 'build-prev-pkg: --like'
    The path "$BUILD_LEG_ARGV_LOG" should not be exist
  End
End
