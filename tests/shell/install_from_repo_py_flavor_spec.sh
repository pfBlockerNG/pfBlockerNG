#!/bin/sh
#shellcheck shell=sh
# install_from_repo_py_flavor_spec.sh — issue #2926: install-from-repo.sh's
# Python-flavor derivation must never select a BUILD row by freebsd_major
# alone. The BUILD matrix dedupes to one row per exact runtime tuple
# (freebsd_major, php_version, py_flavor), so when a major carries two tuples
# (e.g. FreeBSD 16 / PHP 8.4 / py311 and FreeBSD 16 / PHP 8.5 / py312) a
# major-only [0] pick installs the WRONG py3xx-* dependencies.
#
# TOPOLOGY: the script's runtime signals are stubbed — read-version-matrix.sh
# (matrix rows), and an `ssh` shim that answers the box's own py3xx probe —
# so the spec asserts only the flavor-derivation logic. The script is stopped
# right after the flavor echo by the missing rsync-dependent next step: the
# stubbed ssh returns 1 for the first pkg install, which the script exits on.

Describe 'install-from-repo.sh py-flavor derivation (issue #2926)'
  SCRIPT="${PFB_ROOT}/scripts/install-from-repo.sh"

  setup() {
    scrub_git_env
    WORK="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/ifrpyspec.XXXXXX")"
    FAKE_ROOT="${WORK}/repo"
    mkdir -p "${FAKE_ROOT}/scripts"

    cp "${PFB_ROOT}/scripts/install-from-repo.sh" "${FAKE_ROOT}/scripts/"

    # The matrix stub: two rows share freebsd_major=16 with DIFFERENT py_flavor.
    cat > "${FAKE_ROOT}/scripts/read-version-matrix.sh" <<'STUBEOF'
#!/bin/sh
printf '%s\n' '[{"freebsd_major":"15","extra_pkgs":[],"py_flavor":"py311","php_version":"8.3"},{"freebsd_major":"16","extra_pkgs":[],"py_flavor":"py311","php_version":"8.4"},{"freebsd_major":"16","extra_pkgs":[],"py_flavor":"py312","php_version":"8.5"}]'
STUBEOF
    chmod +x "${FAKE_ROOT}/scripts/read-version-matrix.sh"

    # ssh shim: answer `pkg config ABI` with FreeBSD 16; answer the box's own
    # py3xx probe per IPY_PROBE; let the run proceed to the flavor derivation
    # and stop at the first rsync transfer (see the shim's own header).
    mkdir -p "${WORK}/bin"
    cat > "${WORK}/bin/ssh" <<'STUBEOF'
#!/bin/sh
# Remote-command shim. Order matters: pkg config ABI and the py3xx probe are
# answered per their command text; `command -v rsync` succeeds (so the script
# reaches the flavor derivation); the dep pkg install reports a partial
# failure (best-effort: warn not abort); the first rsync transfer fails,
# which stops the script right after the flavor echo without any real remote
# work.
cmd=""
for arg in "$@"; do
    cmd="$arg"
done
case "$cmd" in
    *"pkg config ABI"*)
        printf 'FreeBSD:16:amd64\n'
        exit 0
        ;;
    *"-sqlite3"*)
        printf '%s-sqlite3\n' "${IPY_PROBE:-py311}"
        exit 0
        ;;
    *"command -v rsync"*)
        printf '/usr/local/bin/rsync\n'
        exit 0
        ;;
    *"pkg install -y rsync"*)
        printf 'install rsync failed\n' >&2
        exit 9
        ;;
esac
printf 'unhandled remote command: %s\n' "$cmd" >&2
exit 1
STUBEOF
    chmod +x "${WORK}/bin/ssh"
    PATH="${WORK}/bin:${PATH}"
    export PATH
  }

  teardown() { rm -rf "$WORK"; }

  BeforeEach 'setup'
  AfterEach 'teardown'

  It 'installs the SMOKE_PY_FLAVOR-named tuple flavor, not the first row'
    # GREEN (post-fix): a SMOKE_PY_FLAVOR disambiguator selects the exact
    # tuple's flavor (py312 here), never the major's first row (py311).
    IPY_PROBE=py312
    SMOKE_PY_FLAVOR=py312
    export IPY_PROBE SMOKE_PY_FLAVOR
    When run sh "${FAKE_ROOT}/scripts/install-from-repo.sh" root@target --port 2222
    The status should not equal 0
    The stderr should include 'unhandled remote command'
    The stdout should include 'Python dep flavor for FreeBSD:16:amd64: py312'
  End


  It 'refuses a py_flavor when SMOKE_PY_FLAVOR is absent and a major holds two tuples'
    When run sh "${FAKE_ROOT}/scripts/install-from-repo.sh" root@target --port 2222
    The status should not equal 0
    The stderr should include 'matches more than one BUILD row'
    The stdout should include 'Installing pfBlockerNG'
  End
End
