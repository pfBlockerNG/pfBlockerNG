#shellcheck shell=sh
# smoke_on_box_pkgversion_spec.sh — issue #2754: nightly --pkgversion on build-leg argv.
#
# WHY THIS EXISTS: after issue #2754 M1, nightly identity is derived HERE from
# the just-checked-out HEAD, not in local-smoke.sh. local_smoke_pkgversion_spec.sh
# pins that the orchestrator does not stamp a SHA from its own clone. This spec
# drives smoke-on-box.sh so the derivation-and-override branch (the nightly block
# before build-leg.sh) cannot be deleted while the suite stays green. Same
# PFB_ONBOX_* seams as smoke_on_box_spec.sh; build-leg.sh is stubbed to record
# argv and print a fake .pkg. The run then dies on the missing guest SSH key —
# after the argv is written.
#
# RED→GREEN: deleting the nightly block from smoke-on-box.sh leaves --channel
# nightly with no --pkgversion on the recorded build-leg argv. The helper-derived
# example is the pin that the identity matches FAKE_ROOT's HEAD (the built commit).

Describe 'smoke-on-box.sh --pkgversion (issue #2754)'
  SCRIPT="${PFB_ROOT}/scripts/smoke-on-box.sh"

  setup() {
    scrub_git_env
    unset PFB_NIGHTLY_PKGVERSION SMOKE_GHCR_TOKEN SMOKE_SSH_KEY
    WORK="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/onboxpkgver.XXXXXX")"
    FAKE_ROOT="${WORK}/repo"
    mkdir -p "${FAKE_ROOT}/scripts/lib" "${WORK}/bin"

    cp "${PFB_ROOT}/scripts/lib/git-env-scrub.sh" "${FAKE_ROOT}/scripts/lib/"
    cp "${PFB_ROOT}/scripts/lib/smoke-tier.sh"    "${FAKE_ROOT}/scripts/lib/"
    cp "${PFB_ROOT}/scripts/lib/lan-registry.sh"  "${FAKE_ROOT}/scripts/lib/"
    cp "${PFB_ROOT}/scripts/nightly-pkgversion.sh" "${FAKE_ROOT}/scripts/"

    cat > "${FAKE_ROOT}/scripts/sparse-clone-ports.sh" <<'STUBEOF'
#!/bin/sh
exit 0
STUBEOF
    chmod +x "${FAKE_ROOT}/scripts/sparse-clone-ports.sh"

    cat > "${FAKE_ROOT}/scripts/read-version-matrix.sh" <<'STUBEOF'
#!/bin/sh
printf '%s\n' '[{"freebsd_major":"15","php_version":"8.3","py_flavor":"py311","extra_pkgs":[]}]'
STUBEOF
    chmod +x "${FAKE_ROOT}/scripts/read-version-matrix.sh"

    BUILD_LEG_ARGV="${WORK}/build-leg-argv"
    cat > "${FAKE_ROOT}/scripts/build-leg.sh" <<STUBEOF
#!/bin/sh
printf '%s\n' "\$*" > "${BUILD_LEG_ARGV}"
printf '%s\n' "${WORK}/fake.pkg"
exit 0
STUBEOF
    chmod +x "${FAKE_ROOT}/scripts/build-leg.sh"

    cat > "${WORK}/bin/oras" <<'STUBEOF'
#!/bin/sh
case "$*" in
    resolve*) printf '%s\n' 'sha256:manifest'; exit 0 ;;
    *manifest\ fetch*)
        case "$*" in
            *--descriptor*) printf '{"digest":"sha256:manifest"}\n' ;;
            *) printf '%s\n' '{"annotations":{"org.opencontainers.image.version":"2.8"}}' ;;
        esac
        exit 0
        ;;
    *\ pull\ *|pull\ *)
        true > pfsense.qcow2
        exit 0
        ;;
esac
exit 0
STUBEOF
    chmod +x "${WORK}/bin/oras"

    cat > "${WORK}/bin/uv" <<'STUBEOF'
#!/bin/sh
exit 0
STUBEOF
    chmod +x "${WORK}/bin/uv"

    for _absent in qemu-system-x86_64 qemu-img iptables dig ssh pkill curl zstd tar unzip; do
        printf '#!/bin/sh\nexit 0\n' > "${WORK}/bin/${_absent}"
        chmod +x "${WORK}/bin/${_absent}"
    done
    PATH="${WORK}/bin:${PATH}"
    export PATH

    git_fixture -C "$FAKE_ROOT" init --quiet . >/dev/null 2>&1
    git_fixture -C "$FAKE_ROOT" -c user.name=t -c user.email=t@example.com \
        commit --quiet --allow-empty -m seed >/dev/null 2>&1
    HEAD_SHA="$(git_fixture -C "$FAKE_ROOT" rev-parse HEAD)"
    HEAD_SHORT="$(printf '%.7s' "$HEAD_SHA")"

    printf '53\n' > "${WORK}/port-floor"
    PFB_ONBOX_PORT_FLOOR_FILE="${WORK}/port-floor"
    PFB_ONBOX_REPO_ROOT="$FAKE_ROOT"
    PFB_ONBOX_PORTS_DIR="${WORK}/ports"
    PFB_ONBOX_IMAGES_DIR="${WORK}/images"
    export WORK FAKE_ROOT BUILD_LEG_ARGV HEAD_SHA HEAD_SHORT \
        PFB_ONBOX_REPO_ROOT PFB_ONBOX_PORTS_DIR PFB_ONBOX_IMAGES_DIR \
        PFB_ONBOX_PORT_FLOOR_FILE
  }

  teardown() { rm -rf "$WORK"; }

  BeforeEach 'setup'
  AfterEach  'teardown'

  run_to_build() {
    sh "$SCRIPT" --no-two-vm "$@" >/dev/null 2>&1 || true
    [ -f "$BUILD_LEG_ARGV" ] || { printf 'no-argv\n'; return 0; }
    cat "$BUILD_LEG_ARGV"
  }

  It 'puts a helper-derived --pkgversion on build-leg for --channel nightly'
    When call run_to_build --channel nightly
    The output should include "--channel nightly"
    The output should include "--pkgversion "
    The output should include ".${HEAD_SHORT}"
  End

  It 'forwards an explicit --pkgversion verbatim to build-leg on nightly'
    When call run_to_build --channel nightly --pkgversion 20260101120000.abcdef0
    The output should include "--pkgversion 20260101120000.abcdef0"
    The output should not include ".${HEAD_SHORT}"
  End

  It 'does not put --pkgversion on build-leg for --channel edge'
    When call run_to_build --channel edge --pkgversion 20260101120000.abcdef0
    The output should include "--channel edge"
    The output should not include "--pkgversion"
  End
End
