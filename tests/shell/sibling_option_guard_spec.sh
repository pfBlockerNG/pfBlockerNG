#!/bin/sh
#shellcheck shell=sh
# sibling_option_guard_spec.sh — issue #3312: guard every enumerated unguarded
# value-option `shift 2` (install-pkg.sh, build-repo.sh, image-publish.sh,
# image-upgrade.sh, read-version-matrix.sh, run-gates.sh) so a missing value
# prints that file's own diagnostic instead of dash's raw "shift: can't shift
# that many" / "parameter not set", and exits non-zero BEFORE any network call.
# Mirrors install_from_repo_option_guard_spec.sh's shape (stubs, stderr includes,
# no new framework). Already-guarded siblings are spot-checked unchanged, not
# re-tested; run-gates.sh's own usage() diagnostic is opt-agnostic, so its rows
# assert on that shared message rather than a per-option string.
#
# TOPOLOGY: ssh/scp/rsync/git/oras/curl/pkg/qm are PATH-stub shims that would
# answer any call; their shared log file staying ABSENT on every missing-arg row
# is the "fails before any network call" proof (issue #3312 hostile row 1).
# REAL_GIT is captured before the stub PATH exists, so the do-not-edit spot-check
# below always inspects the real working tree regardless of PATH stubbing.

REAL_GIT="$(command -v git)"

Describe 'sibling option-value guards fail closed before network (issue #3312)'
  setup() {
    scrub_git_env
    WORK="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/sibguard.XXXXXX")"
    LOG="${WORK}/calls.log"
    STUBDIR="${WORK}/bin"
    mkdir -p "$STUBDIR"
    for _stub in ssh scp rsync git oras curl pkg qm; do
      cat > "${STUBDIR}/${_stub}" <<STUBEOF
#!/bin/sh
printf '${_stub}: %s\n' "\$*" >> "$LOG"
exit 0
STUBEOF
      chmod +x "${STUBDIR}/${_stub}"
    done
    PATH="${STUBDIR}:${PATH}"
    export PATH
    rm -f /var/tmp/agents/issue-3312/pwned
  }
  teardown() { rm -rf "$WORK"; }
  BeforeEach 'setup'
  AfterEach 'teardown'

  install_pkg()       { sh "${PFB_ROOT}/scripts/install-pkg.sh" "$@"; }
  build_repo()        { sh "${PFB_ROOT}/scripts/build-repo.sh" "$@"; }
  image_publish()     { sh "${PFB_ROOT}/scripts/image-publish.sh" "$@"; }
  image_upgrade()     { sh "${PFB_ROOT}/scripts/image-upgrade.sh" "$@"; }
  read_matrix()       { sh "${PFB_ROOT}/scripts/read-version-matrix.sh" "$@"; }
  run_gates()         { sh "${PFB_ROOT}/scripts/agent/run-gates.sh" "$@"; }
  install_from_repo() { sh "${PFB_ROOT}/scripts/install-from-repo.sh" "$@"; }
  build_leg()         { sh "${PFB_ROOT}/scripts/build-leg.sh" "$@"; }
  install_sh()        { sh "${PFB_ROOT}/scripts/install.sh" "$@"; }
  box_facts()         { sh "${PFB_ROOT}/scripts/box-facts.sh" "$@"; }
  wait_checks()       { sh "${PFB_ROOT}/scripts/agent/wait-checks.sh" "$@"; }

  Describe 'install-pkg.sh'
    It 'rejects --pkg with no value, before any network call'
      When run install_pkg root@x --pkg
      The status should not equal 0
      The stderr should include '--pkg requires an argument'
      The path "$LOG" should not be exist
    End

    It '--pkg consumes a value; --port sentinel still diagnosed missing (not file-not-found)'
      When run install_pkg root@x --pkg /no/such --port
      The status should not equal 0
      The stderr should include '--port requires an argument'
      The stderr should not include 'file not found'
    End

    It 'accepts an explicit empty --pkg value; --port sentinel still diagnosed missing'
      When run install_pkg root@x --pkg '' --port
      The status should not equal 0
      The stderr should include '--port requires an argument'
    End

    It 'rejects --port with no value, before any network call'
      When run install_pkg root@x --port
      The status should not equal 0
      The stderr should include '--port requires an argument'
      The path "$LOG" should not be exist
    End

    It '--port consumes a value; --ssh-key sentinel still diagnosed missing'
      When run install_pkg root@x --port 2222 --ssh-key
      The status should not equal 0
      The stderr should include '--ssh-key requires an argument'
      The stderr should not include '--port requires an argument'
    End

    It 'accepts an explicit empty --port value; --ssh-key sentinel still diagnosed missing'
      When run install_pkg root@x --port '' --ssh-key
      The status should not equal 0
      The stderr should include '--ssh-key requires an argument'
      The stderr should not include '--port requires an argument'
    End

    It 'rejects --ssh-key with no value, before any network call'
      When run install_pkg root@x --ssh-key
      The status should not equal 0
      The stderr should include '--ssh-key requires an argument'
      The path "$LOG" should not be exist
    End

    It '--ssh-key consumes a value; --port sentinel still diagnosed missing'
      When run install_pkg root@x --ssh-key /tmp/k --port
      The status should not equal 0
      The stderr should include '--port requires an argument'
      The stderr should not include '--ssh-key requires an argument'
    End

    It 'accepts an explicit empty --ssh-key value; --port sentinel still diagnosed missing'
      When run install_pkg root@x --ssh-key '' --port
      The status should not equal 0
      The stderr should include '--port requires an argument'
      The stderr should not include '--ssh-key requires an argument'
    End

    It 'does not eat the positional ssh-target as a --port value'
      When run install_pkg --port 9 root@x --pkg
      The status should not equal 0
      The stderr should include '--pkg requires an argument'
    End
  End

  Describe 'build-repo.sh'
    It 'rejects --in with no value, before any network call'
      When run build_repo --in
      The status should equal 2
      The stderr should include '--in requires a value'
      The path "$LOG" should not be exist
    End

    It '--in consumes a value; --out sentinel still diagnosed missing'
      When run build_repo --in /tmp --out
      The status should equal 2
      The stderr should include '--out requires a value'
      The stderr should not include '--in requires a value'
    End

    It 'accepts an explicit empty --in value; --out sentinel still diagnosed missing'
      When run build_repo --in '' --out
      The status should equal 2
      The stderr should include '--out requires a value'
      The stderr should not include '--in requires a value'
    End

    It 'rejects --out with no value, before any network call'
      When run build_repo --out
      The status should equal 2
      The stderr should include '--out requires a value'
      The path "$LOG" should not be exist
    End

    It '--out consumes a value; --varver sentinel still diagnosed missing'
      When run build_repo --out /tmp --varver
      The status should equal 2
      The stderr should include '--varver requires a value'
      The stderr should not include '--out requires a value'
    End

    It 'accepts an explicit empty --out value; --varver sentinel still diagnosed missing'
      When run build_repo --out '' --varver
      The status should equal 2
      The stderr should include '--varver requires a value'
      The stderr should not include '--out requires a value'
    End

    It 'rejects --varver with no value, before any network call'
      When run build_repo --varver
      The status should equal 2
      The stderr should include '--varver requires a value'
      The path "$LOG" should not be exist
    End

    It '--varver consumes a value; --base-url sentinel still diagnosed missing'
      When run build_repo --varver vv --base-url
      The status should equal 2
      The stderr should include '--base-url requires a value'
      The stderr should not include '--varver requires a value'
    End

    It 'accepts an explicit empty --varver value; --base-url sentinel still diagnosed missing'
      When run build_repo --varver '' --base-url
      The status should equal 2
      The stderr should include '--base-url requires a value'
      The stderr should not include '--varver requires a value'
    End

    It 'rejects --base-url with no value, before any network call'
      When run build_repo --base-url
      The status should equal 2
      The stderr should include '--base-url requires a value'
      The path "$LOG" should not be exist
    End

    It '--base-url consumes a value; --catalog-path sentinel still diagnosed missing'
      When run build_repo --base-url http://x --catalog-path
      The status should equal 2
      The stderr should include '--catalog-path requires a value'
      The stderr should not include '--base-url requires a value'
    End

    It 'accepts an explicit empty --base-url value; --catalog-path sentinel still diagnosed missing'
      When run build_repo --base-url '' --catalog-path
      The status should equal 2
      The stderr should include '--catalog-path requires a value'
      The stderr should not include '--base-url requires a value'
    End

    It 'rejects --catalog-path with no value, before any network call'
      When run build_repo --catalog-path
      The status should equal 2
      The stderr should include '--catalog-path requires a value'
      The path "$LOG" should not be exist
    End

    It '--catalog-path consumes a value; --in sentinel still diagnosed missing'
      When run build_repo --catalog-path ce-15 --in
      The status should equal 2
      The stderr should include '--in requires a value'
      The stderr should not include '--catalog-path requires a value'
    End

    It 'accepts an explicit empty --catalog-path value; --in sentinel still diagnosed missing'
      When run build_repo --catalog-path '' --in
      The status should equal 2
      The stderr should include '--in requires a value'
      The stderr should not include '--catalog-path requires a value'
    End
  End

  Describe 'image-publish.sh'
    It 'rejects --proxmox with no value, before any network call'
      When run image_publish --proxmox
      The status should not equal 0
      The stderr should include '--proxmox requires an argument'
      The path "$LOG" should not be exist
    End

    It '--proxmox consumes a value; --proxmox-port sentinel still diagnosed missing'
      When run image_publish --proxmox X --proxmox-port
      The status should not equal 0
      The stderr should include '--proxmox-port requires an argument'
      The stderr should not include '--proxmox requires an argument'
    End

    It 'accepts an explicit empty --proxmox value; --proxmox-port sentinel still diagnosed missing'
      When run image_publish --proxmox '' --proxmox-port
      The status should not equal 0
      The stderr should include '--proxmox-port requires an argument'
      The stderr should not include '--proxmox requires an argument'
    End

    It 'rejects --proxmox-port with no value, before any network call'
      When run image_publish --proxmox-port
      The status should not equal 0
      The stderr should include '--proxmox-port requires an argument'
      The path "$LOG" should not be exist
    End

    It '--proxmox-port consumes a value; --proxmox-ssh-key sentinel still diagnosed missing'
      When run image_publish --proxmox-port X --proxmox-ssh-key
      The status should not equal 0
      The stderr should include '--proxmox-ssh-key requires an argument'
      The stderr should not include '--proxmox-port requires an argument'
    End

    It 'accepts an explicit empty --proxmox-port value; --proxmox-ssh-key sentinel still diagnosed missing'
      When run image_publish --proxmox-port '' --proxmox-ssh-key
      The status should not equal 0
      The stderr should include '--proxmox-ssh-key requires an argument'
      The stderr should not include '--proxmox-port requires an argument'
    End

    It 'rejects --proxmox-ssh-key with no value, before any network call'
      When run image_publish --proxmox-ssh-key
      The status should not equal 0
      The stderr should include '--proxmox-ssh-key requires an argument'
      The path "$LOG" should not be exist
    End

    It '--proxmox-ssh-key consumes a value; --remote-tmpdir sentinel still diagnosed missing'
      When run image_publish --proxmox-ssh-key X --remote-tmpdir
      The status should not equal 0
      The stderr should include '--remote-tmpdir requires an argument'
      The stderr should not include '--proxmox-ssh-key requires an argument'
    End

    It 'accepts an explicit empty --proxmox-ssh-key value; --remote-tmpdir sentinel still diagnosed missing'
      When run image_publish --proxmox-ssh-key '' --remote-tmpdir
      The status should not equal 0
      The stderr should include '--remote-tmpdir requires an argument'
      The stderr should not include '--proxmox-ssh-key requires an argument'
    End

    It 'rejects --remote-tmpdir with no value, before any network call'
      When run image_publish --remote-tmpdir
      The status should not equal 0
      The stderr should include '--remote-tmpdir requires an argument'
      The path "$LOG" should not be exist
    End

    It '--remote-tmpdir consumes a value; --type sentinel still diagnosed missing'
      When run image_publish --remote-tmpdir X --type
      The status should not equal 0
      The stderr should include '--type requires an argument'
      The stderr should not include '--remote-tmpdir requires an argument'
    End

    It 'accepts an explicit empty --remote-tmpdir value; --type sentinel still diagnosed missing'
      When run image_publish --remote-tmpdir '' --type
      The status should not equal 0
      The stderr should include '--type requires an argument'
      The stderr should not include '--remote-tmpdir requires an argument'
    End

    It 'rejects --type with no value, before any network call'
      When run image_publish --type
      The status should not equal 0
      The stderr should include '--type requires an argument'
      The path "$LOG" should not be exist
    End

    It '--type consumes a value; --vmid sentinel still diagnosed missing'
      When run image_publish --type X --vmid
      The status should not equal 0
      The stderr should include '--vmid requires an argument'
      The stderr should not include '--type requires an argument'
    End

    It 'accepts an explicit empty --type value; --vmid sentinel still diagnosed missing'
      When run image_publish --type '' --vmid
      The status should not equal 0
      The stderr should include '--vmid requires an argument'
      The stderr should not include '--type requires an argument'
    End

    It 'rejects --vmid with no value, before any network call'
      When run image_publish --vmid
      The status should not equal 0
      The stderr should include '--vmid requires an argument'
      The path "$LOG" should not be exist
    End

    It '--vmid consumes a value; --disk sentinel still diagnosed missing'
      When run image_publish --vmid X --disk
      The status should not equal 0
      The stderr should include '--disk requires an argument'
      The stderr should not include '--vmid requires an argument'
    End

    It 'accepts an explicit empty --vmid value; --disk sentinel still diagnosed missing'
      When run image_publish --vmid '' --disk
      The status should not equal 0
      The stderr should include '--disk requires an argument'
      The stderr should not include '--vmid requires an argument'
    End

    It 'rejects --disk with no value, before any network call'
      When run image_publish --disk
      The status should not equal 0
      The stderr should include '--disk requires an argument'
      The path "$LOG" should not be exist
    End

    It '--disk consumes a value; --registry sentinel still diagnosed missing'
      When run image_publish --disk X --registry
      The status should not equal 0
      The stderr should include '--registry requires an argument'
      The stderr should not include '--disk requires an argument'
    End

    It 'accepts an explicit empty --disk value; --registry sentinel still diagnosed missing'
      When run image_publish --disk '' --registry
      The status should not equal 0
      The stderr should include '--registry requires an argument'
      The stderr should not include '--disk requires an argument'
    End

    It 'rejects --registry with no value, before any network call'
      When run image_publish --registry
      The status should not equal 0
      The stderr should include '--registry requires an argument'
      The path "$LOG" should not be exist
    End

    It '--registry consumes a value; --image sentinel still diagnosed missing'
      When run image_publish --registry X --image
      The status should not equal 0
      The stderr should include '--image requires an argument'
      The stderr should not include '--registry requires an argument'
    End

    It 'accepts an explicit empty --registry value; --image sentinel still diagnosed missing'
      When run image_publish --registry '' --image
      The status should not equal 0
      The stderr should include '--image requires an argument'
      The stderr should not include '--registry requires an argument'
    End

    It 'rejects --image with no value, before any network call'
      When run image_publish --image
      The status should not equal 0
      The stderr should include '--image requires an argument'
      The path "$LOG" should not be exist
    End

    It '--image consumes a value; --compression sentinel still diagnosed missing'
      When run image_publish --image X --compression
      The status should not equal 0
      The stderr should include '--compression requires an argument'
      The stderr should not include '--image requires an argument'
    End

    It 'accepts an explicit empty --image value; --compression sentinel still diagnosed missing'
      When run image_publish --image '' --compression
      The status should not equal 0
      The stderr should include '--compression requires an argument'
      The stderr should not include '--image requires an argument'
    End

    It 'rejects --compression with no value, before any network call'
      When run image_publish --compression
      The status should not equal 0
      The stderr should include '--compression requires an argument'
      The path "$LOG" should not be exist
    End

    It '--compression consumes a value; --out sentinel still diagnosed missing'
      When run image_publish --compression X --out
      The status should not equal 0
      The stderr should include '--out requires an argument'
      The stderr should not include '--compression requires an argument'
    End

    It 'accepts an explicit empty --compression value; --out sentinel still diagnosed missing'
      When run image_publish --compression '' --out
      The status should not equal 0
      The stderr should include '--out requires an argument'
      The stderr should not include '--compression requires an argument'
    End

    It 'rejects --out with no value, before any network call'
      When run image_publish --out
      The status should not equal 0
      The stderr should include '--out requires an argument'
      The path "$LOG" should not be exist
    End

    It '--out consumes a value; --artifact-type sentinel still diagnosed missing'
      When run image_publish --out X --artifact-type
      The status should not equal 0
      The stderr should include '--artifact-type requires an argument'
      The stderr should not include '--out requires an argument'
    End

    It 'accepts an explicit empty --out value; --artifact-type sentinel still diagnosed missing'
      When run image_publish --out '' --artifact-type
      The status should not equal 0
      The stderr should include '--artifact-type requires an argument'
      The stderr should not include '--out requires an argument'
    End

    It 'rejects --artifact-type with no value, before any network call'
      When run image_publish --artifact-type
      The status should not equal 0
      The stderr should include '--artifact-type requires an argument'
      The path "$LOG" should not be exist
    End

    It '--artifact-type consumes a value; --description sentinel still diagnosed missing'
      When run image_publish --artifact-type X --description
      The status should not equal 0
      The stderr should include '--description requires an argument'
      The stderr should not include '--artifact-type requires an argument'
    End

    It 'accepts an explicit empty --artifact-type value; --description sentinel still diagnosed missing'
      When run image_publish --artifact-type '' --description
      The status should not equal 0
      The stderr should include '--description requires an argument'
      The stderr should not include '--artifact-type requires an argument'
    End

    It 'rejects --description with no value, before any network call'
      When run image_publish --description
      The status should not equal 0
      The stderr should include '--description requires an argument'
      The path "$LOG" should not be exist
    End

    It '--description consumes a value; --os-version sentinel still diagnosed missing'
      When run image_publish --description X --os-version
      The status should not equal 0
      The stderr should include '--os-version requires an argument'
      The stderr should not include '--description requires an argument'
    End

    It 'accepts an explicit empty --description value; --os-version sentinel still diagnosed missing'
      When run image_publish --description '' --os-version
      The status should not equal 0
      The stderr should include '--os-version requires an argument'
      The stderr should not include '--description requires an argument'
    End

    It 'rejects --os-version with no value, before any network call'
      When run image_publish --os-version
      The status should not equal 0
      The stderr should include '--os-version requires an argument'
      The path "$LOG" should not be exist
    End

    It '--os-version consumes a value; --type sentinel still diagnosed missing'
      When run image_publish --os-version X --type
      The status should not equal 0
      The stderr should include '--type requires an argument'
      The stderr should not include '--os-version requires an argument'
    End

    It 'accepts an explicit empty --os-version value; --type sentinel still diagnosed missing'
      When run image_publish --os-version '' --type
      The status should not equal 0
      The stderr should include '--type requires an argument'
      The stderr should not include '--os-version requires an argument'
    End
  End

  Describe 'image-upgrade.sh'
    It 'rejects --proxmox with no value, before any network call'
      When run image_upgrade --proxmox
      The status should not equal 0
      The stderr should include '--proxmox requires an argument'
      The path "$LOG" should not be exist
    End

    It '--proxmox consumes a value; --proxmox-port sentinel still diagnosed missing'
      When run image_upgrade --proxmox X --proxmox-port
      The status should not equal 0
      The stderr should include '--proxmox-port requires an argument'
      The stderr should not include '--proxmox requires an argument'
    End

    It 'accepts an explicit empty --proxmox value; --proxmox-port sentinel still diagnosed missing'
      When run image_upgrade --proxmox '' --proxmox-port
      The status should not equal 0
      The stderr should include '--proxmox-port requires an argument'
      The stderr should not include '--proxmox requires an argument'
    End

    It 'rejects --proxmox-port with no value, before any network call'
      When run image_upgrade --proxmox-port
      The status should not equal 0
      The stderr should include '--proxmox-port requires an argument'
      The path "$LOG" should not be exist
    End

    It '--proxmox-port consumes a value; --proxmox-ssh-key sentinel still diagnosed missing'
      When run image_upgrade --proxmox-port X --proxmox-ssh-key
      The status should not equal 0
      The stderr should include '--proxmox-ssh-key requires an argument'
      The stderr should not include '--proxmox-port requires an argument'
    End

    It 'accepts an explicit empty --proxmox-port value; --proxmox-ssh-key sentinel still diagnosed missing'
      When run image_upgrade --proxmox-port '' --proxmox-ssh-key
      The status should not equal 0
      The stderr should include '--proxmox-ssh-key requires an argument'
      The stderr should not include '--proxmox-port requires an argument'
    End

    It 'rejects --proxmox-ssh-key with no value, before any network call'
      When run image_upgrade --proxmox-ssh-key
      The status should not equal 0
      The stderr should include '--proxmox-ssh-key requires an argument'
      The path "$LOG" should not be exist
    End

    It '--proxmox-ssh-key consumes a value; --remote-tmpdir sentinel still diagnosed missing'
      When run image_upgrade --proxmox-ssh-key X --remote-tmpdir
      The status should not equal 0
      The stderr should include '--remote-tmpdir requires an argument'
      The stderr should not include '--proxmox-ssh-key requires an argument'
    End

    It 'accepts an explicit empty --proxmox-ssh-key value; --remote-tmpdir sentinel still diagnosed missing'
      When run image_upgrade --proxmox-ssh-key '' --remote-tmpdir
      The status should not equal 0
      The stderr should include '--remote-tmpdir requires an argument'
      The stderr should not include '--proxmox-ssh-key requires an argument'
    End

    It 'rejects --remote-tmpdir with no value, before any network call'
      When run image_upgrade --remote-tmpdir
      The status should not equal 0
      The stderr should include '--remote-tmpdir requires an argument'
      The path "$LOG" should not be exist
    End

    It '--remote-tmpdir consumes a value; --from sentinel still diagnosed missing'
      When run image_upgrade --remote-tmpdir X --from
      The status should not equal 0
      The stderr should include '--from requires an argument'
      The stderr should not include '--remote-tmpdir requires an argument'
    End

    It 'accepts an explicit empty --remote-tmpdir value; --from sentinel still diagnosed missing'
      When run image_upgrade --remote-tmpdir '' --from
      The status should not equal 0
      The stderr should include '--from requires an argument'
      The stderr should not include '--remote-tmpdir requires an argument'
    End

    It 'rejects --from with no value, before any network call'
      When run image_upgrade --from
      The status should not equal 0
      The stderr should include '--from requires an argument'
      The path "$LOG" should not be exist
    End

    It '--from consumes a value; --to sentinel still diagnosed missing'
      When run image_upgrade --from X --to
      The status should not equal 0
      The stderr should include '--to requires an argument'
      The stderr should not include '--from requires an argument'
    End

    It 'accepts an explicit empty --from value; --to sentinel still diagnosed missing'
      When run image_upgrade --from '' --to
      The status should not equal 0
      The stderr should include '--to requires an argument'
      The stderr should not include '--from requires an argument'
    End

    It 'rejects --to with no value, before any network call'
      When run image_upgrade --to
      The status should not equal 0
      The stderr should include '--to requires an argument'
      The path "$LOG" should not be exist
    End

    It '--to consumes a value; --type sentinel still diagnosed missing'
      When run image_upgrade --to X --type
      The status should not equal 0
      The stderr should include '--type requires an argument'
      The stderr should not include '--to requires an argument'
    End

    It 'accepts an explicit empty --to value; --type sentinel still diagnosed missing'
      When run image_upgrade --to '' --type
      The status should not equal 0
      The stderr should include '--type requires an argument'
      The stderr should not include '--to requires an argument'
    End

    It 'rejects --type with no value, before any network call'
      When run image_upgrade --type
      The status should not equal 0
      The stderr should include '--type requires an argument'
      The path "$LOG" should not be exist
    End

    It '--type consumes a value; --registry sentinel still diagnosed missing'
      When run image_upgrade --type X --registry
      The status should not equal 0
      The stderr should include '--registry requires an argument'
      The stderr should not include '--type requires an argument'
    End

    It 'accepts an explicit empty --type value; --registry sentinel still diagnosed missing'
      When run image_upgrade --type '' --registry
      The status should not equal 0
      The stderr should include '--registry requires an argument'
      The stderr should not include '--type requires an argument'
    End

    It 'rejects --registry with no value, before any network call'
      When run image_upgrade --registry
      The status should not equal 0
      The stderr should include '--registry requires an argument'
      The path "$LOG" should not be exist
    End

    It '--registry consumes a value; --image sentinel still diagnosed missing'
      When run image_upgrade --registry X --image
      The status should not equal 0
      The stderr should include '--image requires an argument'
      The stderr should not include '--registry requires an argument'
    End

    It 'accepts an explicit empty --registry value; --image sentinel still diagnosed missing'
      When run image_upgrade --registry '' --image
      The status should not equal 0
      The stderr should include '--image requires an argument'
      The stderr should not include '--registry requires an argument'
    End

    It 'rejects --image with no value, before any network call'
      When run image_upgrade --image
      The status should not equal 0
      The stderr should include '--image requires an argument'
      The path "$LOG" should not be exist
    End

    It '--image consumes a value; --description sentinel still diagnosed missing'
      When run image_upgrade --image X --description
      The status should not equal 0
      The stderr should include '--description requires an argument'
      The stderr should not include '--image requires an argument'
    End

    It 'accepts an explicit empty --image value; --description sentinel still diagnosed missing'
      When run image_upgrade --image '' --description
      The status should not equal 0
      The stderr should include '--description requires an argument'
      The stderr should not include '--image requires an argument'
    End

    It 'rejects --description with no value, before any network call'
      When run image_upgrade --description
      The status should not equal 0
      The stderr should include '--description requires an argument'
      The path "$LOG" should not be exist
    End

    It '--description consumes a value; --artifact-type sentinel still diagnosed missing'
      When run image_upgrade --description X --artifact-type
      The status should not equal 0
      The stderr should include '--artifact-type requires an argument'
      The stderr should not include '--description requires an argument'
    End

    It 'accepts an explicit empty --description value; --artifact-type sentinel still diagnosed missing'
      When run image_upgrade --description '' --artifact-type
      The status should not equal 0
      The stderr should include '--artifact-type requires an argument'
      The stderr should not include '--description requires an argument'
    End

    It 'rejects --artifact-type with no value, before any network call'
      When run image_upgrade --artifact-type
      The status should not equal 0
      The stderr should include '--artifact-type requires an argument'
      The path "$LOG" should not be exist
    End

    It '--artifact-type consumes a value; --ssh-key sentinel still diagnosed missing'
      When run image_upgrade --artifact-type X --ssh-key
      The status should not equal 0
      The stderr should include '--ssh-key requires an argument'
      The stderr should not include '--artifact-type requires an argument'
    End

    It 'accepts an explicit empty --artifact-type value; --ssh-key sentinel still diagnosed missing'
      When run image_upgrade --artifact-type '' --ssh-key
      The status should not equal 0
      The stderr should include '--ssh-key requires an argument'
      The stderr should not include '--artifact-type requires an argument'
    End

    It 'rejects --ssh-key with no value, before any network call'
      When run image_upgrade --ssh-key
      The status should not equal 0
      The stderr should include '--ssh-key requires an argument'
      The path "$LOG" should not be exist
    End

    It '--ssh-key consumes a value; --ssh-port sentinel still diagnosed missing'
      When run image_upgrade --ssh-key X --ssh-port
      The status should not equal 0
      The stderr should include '--ssh-port requires an argument'
      The stderr should not include '--ssh-key requires an argument'
    End

    It 'accepts an explicit empty --ssh-key value; --ssh-port sentinel still diagnosed missing'
      When run image_upgrade --ssh-key '' --ssh-port
      The status should not equal 0
      The stderr should include '--ssh-port requires an argument'
      The stderr should not include '--ssh-key requires an argument'
    End

    It 'rejects --ssh-port with no value, before any network call'
      When run image_upgrade --ssh-port
      The status should not equal 0
      The stderr should include '--ssh-port requires an argument'
      The path "$LOG" should not be exist
    End

    It '--ssh-port consumes a value; --mac sentinel still diagnosed missing'
      When run image_upgrade --ssh-port X --mac
      The status should not equal 0
      The stderr should include '--mac requires an argument'
      The stderr should not include '--ssh-port requires an argument'
    End

    It 'accepts an explicit empty --ssh-port value; --mac sentinel still diagnosed missing'
      When run image_upgrade --ssh-port '' --mac
      The status should not equal 0
      The stderr should include '--mac requires an argument'
      The stderr should not include '--ssh-port requires an argument'
    End

    It 'rejects --mac with no value, before any network call'
      When run image_upgrade --mac
      The status should not equal 0
      The stderr should include '--mac requires an argument'
      The path "$LOG" should not be exist
    End

    It '--mac consumes a value; --smbios-uuid sentinel still diagnosed missing'
      When run image_upgrade --mac X --smbios-uuid
      The status should not equal 0
      The stderr should include '--smbios-uuid requires an argument'
      The stderr should not include '--mac requires an argument'
    End

    It 'accepts an explicit empty --mac value; --smbios-uuid sentinel still diagnosed missing'
      When run image_upgrade --mac '' --smbios-uuid
      The status should not equal 0
      The stderr should include '--smbios-uuid requires an argument'
      The stderr should not include '--mac requires an argument'
    End

    It 'rejects --smbios-uuid with no value, before any network call'
      When run image_upgrade --smbios-uuid
      The status should not equal 0
      The stderr should include '--smbios-uuid requires an argument'
      The path "$LOG" should not be exist
    End

    It '--smbios-uuid consumes a value; --compression sentinel still diagnosed missing'
      When run image_upgrade --smbios-uuid X --compression
      The status should not equal 0
      The stderr should include '--compression requires an argument'
      The stderr should not include '--smbios-uuid requires an argument'
    End

    It 'accepts an explicit empty --smbios-uuid value; --compression sentinel still diagnosed missing'
      When run image_upgrade --smbios-uuid '' --compression
      The status should not equal 0
      The stderr should include '--compression requires an argument'
      The stderr should not include '--smbios-uuid requires an argument'
    End

    It 'rejects --compression with no value, before any network call'
      When run image_upgrade --compression
      The status should not equal 0
      The stderr should include '--compression requires an argument'
      The path "$LOG" should not be exist
    End

    It '--compression consumes a value; --branch sentinel still diagnosed missing'
      When run image_upgrade --compression X --branch
      The status should not equal 0
      The stderr should include '--branch requires an argument'
      The stderr should not include '--compression requires an argument'
    End

    It 'accepts an explicit empty --compression value; --branch sentinel still diagnosed missing'
      When run image_upgrade --compression '' --branch
      The status should not equal 0
      The stderr should include '--branch requires an argument'
      The stderr should not include '--compression requires an argument'
    End

    It 'rejects --branch with no value, before any network call'
      When run image_upgrade --branch
      The status should not equal 0
      The stderr should include '--branch requires an argument'
      The path "$LOG" should not be exist
    End

    It '--branch consumes a value; --facts-out sentinel still diagnosed missing'
      When run image_upgrade --branch X --facts-out
      The status should not equal 0
      The stderr should include '--facts-out requires an argument'
      The stderr should not include '--branch requires an argument'
    End

    It 'accepts an explicit empty --branch value; --facts-out sentinel still diagnosed missing'
      When run image_upgrade --branch '' --facts-out
      The status should not equal 0
      The stderr should include '--facts-out requires an argument'
      The stderr should not include '--branch requires an argument'
    End

    It 'rejects --facts-out with no value, before any network call'
      When run image_upgrade --facts-out
      The status should not equal 0
      The stderr should include '--facts-out requires an argument'
      The path "$LOG" should not be exist
    End

    It '--facts-out consumes a value; --from sentinel still diagnosed missing'
      When run image_upgrade --facts-out X --from
      The status should not equal 0
      The stderr should include '--from requires an argument'
      The stderr should not include '--facts-out requires an argument'
    End

    It 'accepts an explicit empty --facts-out value; --from sentinel still diagnosed missing'
      When run image_upgrade --facts-out '' --from
      The status should not equal 0
      The stderr should include '--from requires an argument'
      The stderr should not include '--facts-out requires an argument'
    End

    It 'rejects --upgrade-timeout with no value: the missing-argument diagnostic, not the decimal-integer die() or a raw shift error'
      When run image_upgrade --upgrade-timeout
      The status should not equal 0
      The stderr should include '--upgrade-timeout requires an argument'
      The stderr should not include 'decimal integer'
      The stderr should not include 'can'\''t shift that many'
      The path "$LOG" should not be exist
    End

    It '--upgrade-timeout consumes a valid value; --from sentinel still diagnosed missing'
      When run image_upgrade --upgrade-timeout 300 --from
      The status should not equal 0
      The stderr should include '--from requires an argument'
      The stderr should not include '--upgrade-timeout requires an argument'
    End

    It 'an explicit empty --upgrade-timeout fails the existing decimal-integer case, not the missing-argument guard (issue #3312 domain row)'
      When run image_upgrade --upgrade-timeout ''
      The status should not equal 0
      The stderr should include 'decimal integer'
      The stderr should not include 'requires an argument'
    End

    It 'rejects --expect-freebsd-major with no value: the missing-argument diagnostic, not a raw shift error'
      When run image_upgrade --expect-freebsd-major
      The status should not equal 0
      The stderr should include '--expect-freebsd-major requires an argument'
      The stderr should not include 'can'\''t shift'
      The path "$LOG" should not be exist
    End

    It '--expect-freebsd-major consumes a valid value; --from sentinel still diagnosed missing'
      When run image_upgrade --expect-freebsd-major 15 --from
      The status should not equal 0
      The stderr should include '--from requires an argument'
      The stderr should not include '--expect-freebsd-major requires an argument'
    End

    It 'accepts an explicit empty --expect-freebsd-major value; --from sentinel still diagnosed missing'
      When run image_upgrade --expect-freebsd-major '' --from
      The status should not equal 0
      The stderr should include '--from requires an argument'
      The stderr should not include '--expect-freebsd-major requires an argument'
    End

    It 'an explicit empty --expect-freebsd-major alone is not a non-digit, so the existing case lets it through to the real missing-target validation (issue #3312 domain row)'
      When run image_upgrade --expect-freebsd-major ''
      The status should not equal 0
      The stderr should include 'missing --from'
      The stderr should not include 'requires an argument'
      The stderr should not include 'can'\''t shift'
    End
  End

  Describe 'read-version-matrix.sh'
    It 'rejects --ref with no value, before git fetch reaches the network'
      When run read_matrix --ref
      The status should not equal 0
      The stderr should include '--ref requires an argument'
      The path "$LOG" should not be exist
    End

    It '--ref consumes a value; --file sentinel still diagnosed missing'
      When run read_matrix --ref X --file
      The status should not equal 0
      The stderr should include '--file requires an argument'
      The stderr should not include '--ref requires an argument'
    End

    It 'accepts an explicit empty --ref value; --file sentinel still diagnosed missing'
      When run read_matrix --ref '' --file
      The status should not equal 0
      The stderr should include '--file requires an argument'
      The stderr should not include '--ref requires an argument'
    End

    It 'rejects --file with no value, before git fetch reaches the network'
      When run read_matrix --file
      The status should not equal 0
      The stderr should include '--file requires an argument'
      The path "$LOG" should not be exist
    End

    It '--file consumes a value; --variant sentinel still diagnosed missing'
      When run read_matrix --file X --variant
      The status should not equal 0
      The stderr should include '--variant requires an argument'
      The stderr should not include '--file requires an argument'
    End

    It 'accepts an explicit empty --file value; --variant sentinel still diagnosed missing'
      When run read_matrix --file '' --variant
      The status should not equal 0
      The stderr should include '--variant requires an argument'
      The stderr should not include '--file requires an argument'
    End

    It 'rejects --variant with no value, before git fetch reaches the network'
      When run read_matrix --variant
      The status should not equal 0
      The stderr should include '--variant requires an argument'
      The path "$LOG" should not be exist
    End

    It '--variant consumes a value; --ref sentinel still diagnosed missing'
      When run read_matrix --variant X --ref
      The status should not equal 0
      The stderr should include '--ref requires an argument'
      The stderr should not include '--variant requires an argument'
    End

    It 'accepts an explicit empty --variant value; --ref sentinel still diagnosed missing'
      When run read_matrix --variant '' --ref
      The status should not equal 0
      The stderr should include '--ref requires an argument'
      The stderr should not include '--variant requires an argument'
    End
  End

  Describe 'run-gates.sh missing/consumed value guards'
    It 'rejects --worktree with no value: usage, not a raw shift error'
      When run run_gates --worktree
      The status should equal 2
      The stderr should include 'usage: run-gates.sh'
      The stderr should not include 'can'\''t shift'
      The path "$LOG" should not be exist
    End

    It '--worktree consumes a value; the bare --diff sentinel still hits usage'
      When run run_gates --worktree /tmp --diff
      The status should equal 2
      The stderr should include 'usage: run-gates.sh'
    End

    It 'rejects --diff with no value: usage, not a raw shift error'
      When run run_gates --diff
      The status should equal 2
      The stderr should include 'usage: run-gates.sh'
      The stderr should not include 'can'\''t shift'
      The path "$LOG" should not be exist
    End

    It '--diff consumes a value; the bare --worktree sentinel still hits usage'
      When run run_gates --diff origin/devel --worktree
      The status should equal 2
      The stderr should include 'usage: run-gates.sh'
    End
  End

  Describe 'hostile inputs (issue #3312 §4)'
    It 'does not evaluate a shell-metacharacter option value (command substitution stays inert)'
      When run install_pkg root@x --port '$(touch /var/tmp/agents/issue-3312/pwned)' --ssh-key
      The status should not equal 0
      The stderr should include '--ssh-key requires an argument'
      Assert [ ! -e /var/tmp/agents/issue-3312/pwned ]
    End

    It 'treats a space-containing quoted value as one argument (issue #3312 hostile row 5)'
      When run image_publish --description 'a b' --os-version
      The status should not equal 0
      The stderr should include '--os-version requires an argument'
      The stderr should not include '--description requires an argument'
    End

    It 'accepts an option-like token as a legal value instead of re-parsing it as an option (issue #3312 hostile row 6)'
      When run build_repo --in --out /tmp
      The status should equal 2
      The stderr should include 'unknown arg: /tmp'
      The stderr should not include '--in requires a value'
      The stderr should not include '--out requires a value'
    End
  End

  Describe 'already-guarded siblings stay unchanged (spot-check, issue #3312 §3)'
    It 'install-from-repo.sh --port stays guarded, no ssh/rsync call'
      When run install_from_repo root@x --port
      The status should not equal 0
      The stderr should include '--port requires an argument'
      The path "$LOG" should not be exist
    End

    It 'install-from-repo.sh --ssh-key stays guarded, no ssh/rsync call'
      When run install_from_repo root@x --ssh-key
      The status should not equal 0
      The stderr should include '--ssh-key requires an argument'
      The path "$LOG" should not be exist
    End

    It 'build-repo.sh --channel arm stays byte-identical'
      When run build_repo --channel
      The status should equal 2
      The stderr should include 'build-repo: --channel requires a value'
    End

    It 'install.sh --channel stays guarded'
      When run install_sh --channel
      The status should equal 2
      The stderr should include 'install.sh: --channel requires a value'
    End

    It 'box-facts.sh --ssh-key stays guarded'
      When run box_facts --ssh-key
      The status should equal 2
      The stderr should include 'Usage: '
    End

    It 'wait-checks.sh --repo stays guarded'
      When run wait_checks --repo
      The status should equal 2
      The stderr should include 'usage: wait-checks.sh'
    End

    It 'build-leg.sh --channel stays guarded'
      When run build_leg --channel
      The status should equal 2
      The stderr should include 'build-leg.sh: --channel requires an argument'
    End

    It 'leaves every do-not-edit sibling file byte-identical (git diff empty)'
      When run "$REAL_GIT" -C "$PFB_ROOT" diff --quiet -- scripts/install-from-repo.sh scripts/box-facts.sh scripts/install.sh scripts/build-leg.sh scripts/agent/wait-checks.sh scripts/agent/wait-reviewer.sh scripts/agent/work-branch.sh
      The status should equal 0
    End
  End
End

Describe 'run-gates.sh accepts an explicit empty option value (real git, unstubbed PATH)'
  setup() { scrub_git_env; }
  BeforeEach 'setup'

  run_gates_in_root() { (cd "$PFB_ROOT" && sh "${PFB_ROOT}/scripts/agent/run-gates.sh" "$@"); }

  It 'accepts an explicit empty --worktree (falls back to cwd) and completes --plan (the ${2?}/[ $# -ge 2 ] accept-empty proof)'
    When run run_gates_in_root --worktree '' --plan
    The status should equal 0
    The stdout should include 'check-graph-fresh.sh'
    The stderr should not include 'usage: run-gates.sh'
    The stderr should not include 'requires an argument'
  End

  It 'accepts an explicit empty --diff without printing usage or a requires-an-argument diagnostic'
    When run run_gates_in_root --diff '' --plan
    The stdout should be present
    The stderr should not include 'usage: run-gates.sh'
    The stderr should not include 'requires an argument'
  End
End
