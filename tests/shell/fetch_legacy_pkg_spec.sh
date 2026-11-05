#shellcheck shell=sh
# fetch_legacy_pkg_spec.sh — issue #3710: scripts/fetch-legacy-pkg.sh.
#
# The script fetches the SHIPPED v3.3.13 .pkg (SMOKE_LEGACY_PKG) the settings-family
# lifecycle smoke installs over the branch build. Layer: argv + filesystem + hash contract,
# no network. The release URL is replaced by a file:// fixture directory (PFB_LEGACY_PKG_BASE_URL,
# a test-only seam); the pinned sha256 values have no override, so each fixture copy of the
# script gets its pin lines rewritten to the fixture assets' hashes, as build_prev_pkg_spec.sh
# does with its `_PIN=` line.

Describe 'fetch-legacy-pkg.sh (issue #3710)'
  SCRIPT="${PFB_ROOT}/scripts/fetch-legacy-pkg.sh"
  LEGS='CE-2.8 CE-2.9 Plus-25.11 Plus-26.03 Plus-26.07'

  # The sha256 of file $1.
  sha_of() { sha256sum "$1" | cut -d ' ' -f 1; }

  setup() {
    unset PFB_LEGACY_PKG_WORK PFB_LEGACY_PKG_BASE_URL
    WORK="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/legacypkg.XXXXXX")"
    RELEASE="${WORK}/release"
    PFB_LEGACY_PKG_WORK="${WORK}/scratch dir"
    PFB_LEGACY_PKG_BASE_URL="file://${RELEASE}"
    export PFB_LEGACY_PKG_WORK PFB_LEGACY_PKG_BASE_URL
    mkdir -p "$RELEASE"
    # One distinct fixture asset per shipped leg, so a wrong leg is a wrong file, never a lucky match.
    FIXTURE_SCRIPT="${WORK}/fetch-legacy-pkg.sh"
    cp "$SCRIPT" "$FIXTURE_SCRIPT"
    for _leg in $LEGS; do
      printf 'fixture bytes of %s\n' "$_leg" > "${RELEASE}/pfSense-pkg-pfBlockerNG-3.3.13-${_leg}.pkg"
      _sha="$(sha_of "${RELEASE}/pfSense-pkg-pfBlockerNG-3.3.13-${_leg}.pkg")"
      sed "s/^\\( *${_leg}) printf '%s\\\\n' '\\)[0-9a-f]*\\('.*\\)$/\\1${_sha}\\2/" \
        "$FIXTURE_SCRIPT" > "${FIXTURE_SCRIPT}.new" && mv "${FIXTURE_SCRIPT}.new" "$FIXTURE_SCRIPT"
      grep -q "'${_sha}'" "$FIXTURE_SCRIPT" || return 1
    done
  }
  teardown() { rm -rf "$WORK"; }

  BeforeEach 'setup'
  AfterEach 'teardown'

  run_fetch() { sh "$FIXTURE_SCRIPT" "$@"; }
  asset() { printf '%s/pfSense-pkg-pfBlockerNG-3.3.13-%s.pkg' "$PFB_LEGACY_PKG_WORK" "$1"; }

  # ── the pins ──────────────────────────────────────────────────────────────── #

  It '--print-tag prints the one pinned release tag and nothing else'
    When run sh "$SCRIPT" --print-tag
    The status should be success
    The output should equal 'v3.3.13'
  End

  It 'pins a 64-hex sha256 for every asset the v3.3.13 release ships, and no other leg'
    count_pins() {
      grep -Ecx " +(CE|Plus)-[0-9.]+\) printf '%s\\\\n' '[0-9a-f]{64}' ;;" "$SCRIPT"
    }
    When call count_pins
    The output should equal '5'
  End

  # ── resolving the leg from the image ref ──────────────────────────────────── #

  It 'prints only the absolute path of the verified package, and names tag, leg and hash on stderr'
    When call run_fetch --image-ref ghcr.io/pfblockerng/pfsense-ce:2.8
    The status should be success
    The output should equal "$(asset CE-2.8)"
    The stderr should include "fetch-legacy-pkg: tag=v3.3.13 leg=CE-2.8 pkg=$(asset CE-2.8) sha256=$(sha_of "${RELEASE}/pfSense-pkg-pfBlockerNG-3.3.13-CE-2.8.pkg")"
    The contents of file "$(asset CE-2.8)" should equal 'fixture bytes of CE-2.8'
  End

  It 'maps every edition and pfSense version to its own asset'
    check_legs() {
      for _case in 'pfsense-ce:2.8=CE-2.8' 'pfsense-ce:2.9=CE-2.9' 'pfsense-plus:25.11=Plus-25.11' \
        'pfsense-plus:26.03=Plus-26.03' 'pfsense-plus:26.07=Plus-26.07'; do
        _got="$(run_fetch --image-ref "ghcr.io/o/${_case%=*}" 2>/dev/null)" || { printf 'failed for %s\n' "$_case"; return 1; }
        [ "$_got" = "$(asset "${_case#*=}")" ] || { printf '%s -> %s\n' "$_case" "$_got"; return 1; }
      done
      printf 'ok\n'
    }
    When call check_legs
    The status should be success
    The output should equal 'ok'
  End

  It 'reads the edition from the image name behind a registry port and a digest'
    When call run_fetch --image-ref 'registry.lan:5000/pfblockerng/pfsense-plus@sha256:abc' --pfsense-version 26.03
    The status should be success
    The output should equal "$(asset Plus-26.03)"
    The stderr should include 'leg=Plus-26.03'
  End

  It 'uses major.minor of the version flag, which wins over the ref tag'
    When call run_fetch --image-ref ghcr.io/pfblockerng/pfsense-ce:2.8 --pfsense-version 2.9.1-RELEASE
    The status should be success
    The output should equal "$(asset CE-2.9)"
    The stderr should include 'leg=CE-2.9'
  End

  It 'falls back to the ref tag when the version flag is not a version (smoke-on-box passes ? for a digest-only ref)'
    When call run_fetch --image-ref ghcr.io/pfblockerng/pfsense-ce:2.9 --pfsense-version '?'
    The status should be success
    The output should equal "$(asset CE-2.9)"
    The stderr should include 'leg=CE-2.9'
  End

  # ── refusing what it cannot pin ───────────────────────────────────────────── #

  It 'refuses an image that is neither pfsense-ce nor pfsense-plus, and fetches nothing'
    When call run_fetch --image-ref ghcr.io/pfblockerng/civm:v1 --pfsense-version 2.8
    The status should be failure
    The output should equal ''
    The stderr should include 'fetch-legacy-pkg: unknown image'
    The path "$PFB_LEGACY_PKG_WORK" should not be exist
  End

  It 'refuses a pfSense version v3.3.13 never shipped for, naming the leg'
    When call run_fetch --image-ref ghcr.io/pfblockerng/pfsense-ce:2.7
    The status should be failure
    The output should equal ''
    The stderr should include 'fetch-legacy-pkg: no pinned package for leg CE-2.7'
    The path "$PFB_LEGACY_PKG_WORK" should not be exist
  End

  It 'refuses a digest-only ref with no usable version, naming the version'
    When call run_fetch --image-ref 'ghcr.io/pfblockerng/pfsense-ce@sha256:abc' --pfsense-version '?'
    The status should be failure
    The output should equal ''
    The stderr should include 'fetch-legacy-pkg: no pfSense version'
  End

  It 'requires --image-ref'
    When call run_fetch --pfsense-version 2.8
    The status should be failure
    The output should equal ''
    The stderr should include 'fetch-legacy-pkg: --image-ref is required'
  End

  It 'refuses an argument it does not know'
    When call run_fetch --image-ref ghcr.io/o/pfsense-ce:2.8 --bogus
    The status should be failure
    The output should equal ''
    The stderr should include 'fetch-legacy-pkg: unknown argument: --bogus'
  End

  # ── the hash gate ─────────────────────────────────────────────────────────── #

  It 'exits non-zero naming both hashes when the asset does not match its pin, and leaves no package behind'
    printf 'tampered\n' > "${RELEASE}/pfSense-pkg-pfBlockerNG-3.3.13-CE-2.8.pkg"
    When call run_fetch --image-ref ghcr.io/pfblockerng/pfsense-ce:2.8
    The status should be failure
    The output should equal ''
    The stderr should include 'fetch-legacy-pkg: sha256 mismatch for pfSense-pkg-pfBlockerNG-3.3.13-CE-2.8.pkg'
    The stderr should include "got $(sha_of "${RELEASE}/pfSense-pkg-pfBlockerNG-3.3.13-CE-2.8.pkg")"
    The path "$(asset CE-2.8)" should not be exist
    The path "$(asset CE-2.8).part" should not be exist
  End

  It 'exits non-zero naming the download when the release has no such asset'
    rm "${RELEASE}/pfSense-pkg-pfBlockerNG-3.3.13-CE-2.8.pkg"
    When call run_fetch --image-ref ghcr.io/pfblockerng/pfsense-ce:2.8
    The status should be failure
    The output should equal ''
    The stderr should include 'fetch-legacy-pkg: download failed'
    The path "$(asset CE-2.8)" should not be exist
  End

  # ── the cache ─────────────────────────────────────────────────────────────── #

  keep_verified() {
    mkdir -p "$PFB_LEGACY_PKG_WORK"
    cp "${RELEASE}/pfSense-pkg-pfBlockerNG-3.3.13-CE-2.8.pkg" "$(asset CE-2.8)"
    PFB_LEGACY_PKG_BASE_URL="file://${WORK}/nowhere"
    export PFB_LEGACY_PKG_BASE_URL
  }
  It 'reuses an already verified package without downloading it again'
    BeforeCall 'keep_verified'
    When call run_fetch --image-ref ghcr.io/pfblockerng/pfsense-ce:2.8
    The status should be success
    The output should equal "$(asset CE-2.8)"
    The stderr should include 'leg=CE-2.8'
  End

  stale_package() {
    mkdir -p "$PFB_LEGACY_PKG_WORK"
    printf 'stale\n' > "$(asset CE-2.8)"
  }
  It 'never trusts a cached package that fails its pin: it downloads the real one over it'
    BeforeCall 'stale_package'
    When call run_fetch --image-ref ghcr.io/pfblockerng/pfsense-ce:2.8
    The status should be success
    The output should equal "$(asset CE-2.8)"
    The stderr should be present
    The contents of file "$(asset CE-2.8)" should equal 'fixture bytes of CE-2.8'
  End
End
