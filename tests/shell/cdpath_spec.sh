#shellcheck shell=sh
# cdpath_spec.sh — path derivation must ignore inherited CDPATH.

Describe 'script path derivation'
  assert_cdpath_guards() {
    _cdp_failed=0
    while IFS='|' read -r _cdp_file _cdp_line; do
      [ -n "$_cdp_file" ] || continue
      if ! grep -Fqx "$_cdp_line" "${PFB_ROOT}/${_cdp_file}"; then
        printf '%s: expected exact path guard: %s\n' "$_cdp_file" "$_cdp_line" >&2
        _cdp_failed=1
      fi
    done <<'EOF'
scripts/bench_ip_recompute.sh|REPO_ROOT="$(CDPATH='' cd "$(dirname "$0")/.." && pwd)"
scripts/build-leg.sh|SCRIPT_DIR="$(CDPATH='' cd "$(dirname "$0")" && pwd)"
scripts/deploy.sh|REPO_ROOT="$(CDPATH='' cd "$(dirname "$0")/.." && pwd)"
scripts/git-env-scrub-guard.sh|_SELF_DIR="$(CDPATH='' cd "$(dirname "$0")" && pwd)"
scripts/image-publish.sh|SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
scripts/image-upgrade.sh|SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
scripts/install-from-repo.sh|REPO_ROOT="$(CDPATH='' cd "$(dirname "$0")/.." && pwd)"
scripts/install.sh|SCRIPT_DIR="$(CDPATH='' cd "$(dirname "$0")" && pwd)"
scripts/local-smoke.sh|REPO_ROOT="$(CDPATH='' cd "$(dirname "$0")/.." && pwd)"
scripts/publish-smoke-image.sh|SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
scripts/resolve-legs.sh|_RL_DIR="$(CDPATH='' cd "$(dirname "$0")" && pwd)"
scripts/run-smoke.sh|REPO_ROOT="$(CDPATH='' cd "$(dirname "$0")/.." && pwd)"
scripts/select-box.sh|_SB_SELF="$(CDPATH='' cd "$(dirname "$0")" && pwd)"
scripts/sparse-clone-ports.sh|SCRIPT_DIR="$(CDPATH='' cd "$(dirname "$0")" && pwd)"
tests/smoke/boot_vm.sh|    *) BASE_IMG="$(CDPATH='' cd "$(dirname "$BASE_IMG")" && pwd)/$(basename "$BASE_IMG")" ;;
EOF
    return "$_cdp_failed"
  }

  image_publish_help_matrix() (
    _cdp_work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/cdpathspec.XXXXXX")" || exit 1
    trap 'rm -rf "$_cdp_work"' EXIT INT TERM
    _cdp_decoy="${_cdp_work}/decoy"
    _cdp_space_decoy="${_cdp_work}/space decoy"
    mkdir -p "${_cdp_decoy}/scripts" "${_cdp_space_decoy}/scripts" || exit 1
    cd "$PFB_ROOT" || exit 1

    _cdp_help() {
      _cdp_label="$1"
      _cdp_value="$2"
      _cdp_argv0="$3"
      if [ "$_cdp_value" = __UNSET__ ]; then
        (unset CDPATH; sh "$_cdp_argv0" --help)
      else
        (CDPATH="$_cdp_value"; export CDPATH; sh "$_cdp_argv0" --help)
      fi > "${_cdp_work}/out" 2> "${_cdp_work}/err"
      _cdp_rc=$?
      if [ "$_cdp_rc" -ne 0 ] || ! grep -q 'Usage:' "${_cdp_work}/out"; then
        printf 'image-publish --help failed: %s rc=%s\nstdout:\n' "$_cdp_label" "$_cdp_rc" >&2
        sed 's/^/  /' "${_cdp_work}/out" >&2
        printf 'stderr:\n' >&2
        sed 's/^/  /' "${_cdp_work}/err" >&2
        return 1
      fi
    }

    _cdp_help 'CDPATH unset, absolute $0' __UNSET__ "${PFB_ROOT}/scripts/image-publish.sh" || exit 1
    _cdp_help 'CDPATH empty, ./scripts $0' '' './scripts/image-publish.sh' || exit 1
    _cdp_help 'CDPATH=., scripts $0' '.' 'scripts/image-publish.sh' || exit 1
    _cdp_help 'CDPATH=repo, scripts $0' "$PFB_ROOT" 'scripts/image-publish.sh' || exit 1
    _cdp_help 'CDPATH=decoy, scripts $0' "$_cdp_decoy" 'scripts/image-publish.sh' || exit 1
    _cdp_help 'CDPATH=decoy:repo, scripts $0' "${_cdp_decoy}:${PFB_ROOT}" 'scripts/image-publish.sh' || exit 1
    _cdp_help 'CDPATH=space-decoy, scripts $0' "$_cdp_space_decoy" 'scripts/image-publish.sh' || exit 1
  )

  It 'guards all path-producing cd substitutions'
    When call assert_cdpath_guards
    The status should be success
  End

  It 'keeps image-publish --help working across hostile CDPATH and invocation forms'
    When call image_publish_help_matrix
    The status should be success
  End
End
