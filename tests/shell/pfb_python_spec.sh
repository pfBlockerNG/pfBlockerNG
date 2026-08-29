#shellcheck shell=sh
# pfb_python.sh resolver/exec contract. The dependency and pkg seams keep every
# row off-appliance while preserving strict POSIX argument and failure behavior.

Describe 'pfb_python.sh'
  setup() {
    work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pfbpy.XXXXXX")"
    bindir="${work}/bin"
    mkdir -p "${bindir}"
    marker="${work}/args"
    wrapper="${PFB_PKGDIR}/pfb_python.sh"
    cat > "${bindir}/python3.11" <<EOF
#!/bin/sh
printf '<%s>\n' "\$1" "\$2" "\$3" > "${marker}"
EOF
    chmod +x "${bindir}/python3.11"
  }

  cleanup() {
    rm -rf "${work}"
  }

  run_print() {
    PFB_PYTHON_DEPENDENCIES="${deps}" PFB_PYTHON_DIR="${bindir}" "${wrapper}" --print-interpreter
  }

  run_args() {
    PFB_PYTHON_DEPENDENCIES="${deps}" PFB_PYTHON_DIR="${bindir}" "${wrapper}" "$@"
  }

  run_invalids() {
    for deps in '' '   ' 'python3x' 'python3.11' 'py3' "$(printf 'py311\npython312')"; do
      if PFB_PYTHON_DEPENDENCIES="${deps}" PFB_PYTHON_DIR="${bindir}" "${wrapper}" --print-interpreter 2>&1; then
        return 1
      fi
    done
  }

  It 'resolves py/python aliases with whitespace and module rows collapsed'
    setup
    deps="$(printf '  py311  \npython311\npy311-sqlite3\n')"
    When call run_print
    The output should equal "${bindir}/python3.11"
    The status should be success
    cleanup
  End

  It 'rejects empty, malformed, one-digit, and ambiguous dependency lists'
    setup
    When call run_invalids
    The status should be success
    The output should include 'expected exactly one pyNN/pythonNN dependency'
    cleanup
  End

  It 'executes with spaces, shell metacharacters, and glob arguments byte-preserved'
    setup
    deps='py311'
    When call run_args 'a b' '$(touch should-not-run)' '*.txt'
    The status should be success
    The contents of file "${marker}" should equal "$(printf '<a b>\n<$(touch should-not-run)>\n<*.txt>\n')"
    The path 'should-not-run' should not be exist
    cleanup
  End

  It 'accepts every current package identity plus legacy devel after unknown names'
    setup
    pkg="${work}/pkg"
    cat > "${pkg}" <<'EOF'
#!/bin/sh
if [ "$2" = '-g' ]; then
  printf '%s\n' 'unknown-package' "$PFB_PKG_TEST_NAME"
else
  [ "$3" = "$PFB_PKG_TEST_NAME" ] || exit 1
  printf '%s\n' 'python311'
fi
EOF
    chmod +x "${pkg}"
    run_valid_packages() {
      for pkg_name in \
        pfSense-pkg-pfBlockerNG \
        pfSense-pkg-pfBlockerNG-testing \
        pfSense-pkg-pfBlockerNG-edge \
        pfSense-pkg-pfBlockerNG-devel \
        pfSense-pkg-pfBlockerNG-nightly \
        PFSENSE-PKG-PFBLOCKERNG-EDGE
      do
        PFB_PKG_TEST_NAME="${pkg_name}" PFB_PKG_BIN="${pkg}" PFB_PYTHON_DIR="${bindir}" \
          "${wrapper}" --print-interpreter || return
      done
    }
    expected=$(printf '%s\n' "${bindir}/python3.11" "${bindir}/python3.11" "${bindir}/python3.11" \
      "${bindir}/python3.11" "${bindir}/python3.11" "${bindir}/python3.11")
    When call run_valid_packages
    The output should equal "${expected}"
    The status should be success
    cleanup
  End

  It 'fails clearly for package query, dependency query, and missing package failures'
    setup
    pkg="${work}/pkg"
    cat > "${pkg}" <<'EOF'
#!/bin/sh
case "$PFB_PKG_TEST_MODE:$2" in
  names-fail:-g) exit 7 ;;
  deps-fail:-g) printf '%s\n' 'pfSense-pkg-pfBlockerNG'; exit 0 ;;
  deps-fail:*) exit 8 ;;
  none:-g) printf '%s\n' 'unknown-package'; exit 0 ;;
esac
EOF
    chmod +x "${pkg}"
    run_pkg_failures() {
      for mode in names-fail deps-fail none; do
        if PFB_PKG_TEST_MODE="${mode}" PFB_PKG_BIN="${pkg}" "${wrapper}" --print-interpreter 2>&1; then
          return 1
        fi
      done
    }
    When call run_pkg_failures
    The status should be success
    The output should include 'package-name query failed'
    The output should include 'dependency query failed'
    The output should include 'no valid pfBlockerNG package'
    cleanup
  End

  It 'requires a live derived interpreter to be executable'
    setup
    pkg="${work}/pkg"
    cat > "${pkg}" <<'EOF'
#!/bin/sh
if [ "$2" = '-g' ]; then
  printf '%s\n' 'pfSense-pkg-pfBlockerNG-nightly'
else
  printf '%s\n' 'py311'
fi
EOF
    chmod +x "${pkg}"
    empty_dir="${work}/empty"
    mkdir -p "${empty_dir}"
    When run env PFB_PKG_BIN="${pkg}" PFB_PYTHON_DIR="${empty_dir}" "${wrapper}" --print-interpreter
    The status should be failure
    The stderr should include 'interpreter is not executable'
    cleanup
  End
End
