#shellcheck shell=sh
# image_lib_push_spec.sh — pins image_oci_push's oras argv: the standard
# annotation set, plus the optional FULL_VERSION argument becoming the
# io.github.pfblockerng.pfsense-version annotation (issue #1820: the
# version-tracker's patch/GA detection compares it — via `oras manifest fetch` —
# against the newest released build on the Netgate versions page).
#
# Hermetic: stubs oras (records its argv) — nothing is pushed.

Describe 'image-lib.sh image_oci_push'
  LIB="${PFB_ROOT}/scripts/image-lib.sh"

  setup() {
    WORK="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/imglibspec.XXXXXX")"
    ARGV_FILE="${WORK}/argv"
    BIN="${WORK}/bin"; mkdir -p "$BIN"
    # Stub oras: record argv (one per line), push nothing.
    cat > "${BIN}/oras" << 'OEOF'
#!/bin/sh
printf '%s\n' "$@" > "$ARGV_FILE"
OEOF
    chmod +x "${BIN}/oras"
    true > "${WORK}/img.qcow2"
    export WORK ARGV_FILE BIN
  }
  teardown() { rm -rf "$WORK"; }
  BeforeEach 'setup'
  AfterEach 'teardown'

  # push [full-version] — source the lib and run image_oci_push against the stub.
  push() {
    PATH="${BIN}:${PATH}" sh -c '
      log() { :; }; warn() { :; }; die() { printf "%s\n" "$*" >&2; exit 1; }
      . "$1" || exit 1
      image_oci_push "$2" ghcr.io/example/pfsense-ce 2.8 \
        "application/vnd.test" "pfSense CE 2.8" img.qcow2 "$3"
    ' _ "$LIB" "${WORK}/img.qcow2" "${1:-}"
  }

  It 'stamps the pfSense full version annotation when given'
    When call push "2.8.1-RELEASE"
    The status should be success
    The contents of file "$ARGV_FILE" should include \
      "io.github.pfblockerng.pfsense-version=2.8.1-RELEASE"
  End

  It 'keeps the standard annotation set alongside the full version'
    When call push "2.8.1-RELEASE"
    The status should be success
    The contents of file "$ARGV_FILE" should include "org.opencontainers.image.version=2.8"
    The contents of file "$ARGV_FILE" should include "org.opencontainers.image.title=img.qcow2"
    The contents of file "$ARGV_FILE" should include "org.opencontainers.image.description=pfSense CE 2.8"
  End

  It 'omits the annotation when no full version is given'
    When call push
    The status should be success
    The contents of file "$ARGV_FILE" should include "org.opencontainers.image.version=2.8"
    The contents of file "$ARGV_FILE" should not include "io.github.pfblockerng.pfsense-version"
  End
End
