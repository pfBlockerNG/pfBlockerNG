#shellcheck shell=sh
# oras_refresh_spec.sh — issue #2218: the smoke image refresh must be safe to run against a
# SHARED image store.
#
# WHY THIS EXISTS: the PFB_BOXES pool now shares one qcow2 directory. Two facts make the
# previous in-place refresh unsafe there, both measured rather than assumed:
#
#   1. `oras pull` is NOT atomic — the target file appears immediately under its FINAL name
#      and grows in place (observed: 26 MB -> 971 MB, no temp file, no rename).
#   2. tests/smoke/boot_vm.sh runs `qemu-img create -b "$BASE_IMG"`, so a booted VM reads the
#      base image for its whole lifetime.
#
# Together, one box re-pulling truncates a RUNNING VM's backing store on another box. A lock
# around the pull cannot fix that: the reader holds the file for the length of a smoke run.
# The fix is to pull into a staging directory and publish with a rename — a running VM keeps
# its open inode and finishes on the old bytes, while the next boot picks up the new file.
#
# The per-ref digest is the second half: ${IMAGES_DIR}/pfsense holds images for MULTIPLE refs
# (pfsense-ce and pfsense-plus both live there, selected per leg by SMOKE_PFSENSE_REF) under
# ONE .digest, so alternating legs always saw a mismatch and re-pulled an image already on
# disk. On a read-only or contended shared store that is not just waste, it is a failure.

Describe 'oras-refresh library (shared image store, issue #2218)'
  LIB="${PFB_ROOT}/scripts/lib/oras-refresh.sh"

  setup() {
    WORK="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/orasrefresh.XXXXXX")"
    BIN="${WORK}/bin"
    IMGDIR="${WORK}/images/pfsense"
    mkdir -p "$BIN" "$IMGDIR"

    # Stub `oras`: `resolve` prints the digest the example asked for; `pull` writes a file
    # whose content is that digest, into the CURRENT directory (mirroring real oras, which
    # pulls into cwd). ORAS_PULL_FAIL makes the pull die AFTER writing partial bytes — the
    # interrupted-transfer case the published store must survive.
    cat > "${BIN}/oras" <<'EOF'
#!/bin/sh
case "$1" in
  resolve) printf '%s\n' "${STUB_REMOTE_DIGEST}" ;;
  pull)
    # Where the transfer lands (real oras pulls into cwd) — the staging-location
    # example asserts on this.
    printf '%s\n' "$PWD" >> "${STUB_CWD_LOG}"
    printf 'PARTIAL' > "${STUB_ARTIFACT_NAME}"
    if [ -n "${ORAS_PULL_FAIL:-}" ]; then exit 7; fi
    printf '%s' "${STUB_REMOTE_DIGEST}" > "${STUB_ARTIFACT_NAME}"
    printf 'pulled\n' >> "${STUB_PULL_LOG}"
    ;;
  login) : ;;
  *) exit 1 ;;
esac
EOF
    chmod +x "${BIN}/oras"

    STUB_PULL_LOG="${WORK}/pulls.log"
    STUB_CWD_LOG="${WORK}/cwds.log"
    printf "" > "$STUB_PULL_LOG"
    printf "" > "$STUB_CWD_LOG"
    STUB_ARTIFACT_NAME="pfSense-CE_2.8.qcow2"
    PATH="${BIN}:${PATH}"
    export PATH STUB_PULL_LOG STUB_CWD_LOG STUB_ARTIFACT_NAME STUB_REMOTE_DIGEST ORAS_PULL_FAIL
  }

  cleanup() { rm -rf "$WORK"; }

  BeforeEach 'setup'
  AfterEach 'cleanup'

  pull_count() { wc -l < "$STUB_PULL_LOG" | tr -d ' '; }

  # ── the published store must never expose a partial file ──────────────────── #

  It 'leaves the published image untouched when a pull dies mid-transfer'
    # The safety property the shared store exists on. A reader (a live VM backing file) must
    # never observe the truncated bytes of a failed transfer.
    When call sh -c '
      . "$1"; shift
      STUB_REMOTE_DIGEST=sha256:old pfb_oras_refresh ghcr.io/x/pfsense-ce:2.8 "$1" pfSense
      published_before="$(cat "$1/pfSense-CE_2.8.qcow2")"
      STUB_REMOTE_DIGEST=sha256:new ORAS_PULL_FAIL=1 \
        pfb_oras_refresh ghcr.io/x/pfsense-ce:2.8 "$1" pfSense
      printf "before=%s after=%s\n" "$published_before" "$(cat "$1/pfSense-CE_2.8.qcow2")"
    ' sh "$LIB" "$IMGDIR"
    The output should include 'before=sha256:old after=sha256:old'
    The stdout should not include 'PARTIAL'
    The stderr should be present
  End

  It 'publishes into the image directory only after a complete pull'
    When call sh -c '
      . "$1"; shift
      STUB_REMOTE_DIGEST=sha256:new pfb_oras_refresh ghcr.io/x/pfsense-ce:2.8 "$1" pfSense
      cat "$1/pfSense-CE_2.8.qcow2"
    ' sh "$LIB" "$IMGDIR"
    The output should include 'sha256:new'
    The stderr should be present
  End

  It 'stages inside the published store so the publish rename never crosses filesystems'
    # `mv` across devices degrades to a progressive copy onto the FINAL filename —
    # the truncate-in-place hazard this library exists to prevent, resurfacing
    # whenever the store directory is its own mountpoint (issue #2231). Staging
    # INSIDE the store makes the rename same-filesystem by construction; the dot
    # name keeps it out of the *.qcow2 glob and the digest bookkeeping.
    When call sh -c '
      . "$1"; shift
      STUB_REMOTE_DIGEST=sha256:new pfb_oras_refresh ghcr.io/x/pfsense-ce:2.8 "$1" pfSense
      cat "$STUB_CWD_LOG"
    ' sh "$LIB" "$IMGDIR"
    The output should include '/images/pfsense/.staging.'
    The stderr should be present
  End

  It 'never leaves a staging directory behind in the published store'
    # A leftover staging dir inside the shared store would be picked up by the *.qcow2 glob
    # counting and by anything listing the directory.
    When call sh -c '
      . "$1"; shift
      STUB_REMOTE_DIGEST=sha256:new pfb_oras_refresh ghcr.io/x/pfsense-ce:2.8 "$1" pfSense
      STUB_REMOTE_DIGEST=sha256:x ORAS_PULL_FAIL=1 \
        pfb_oras_refresh ghcr.io/x/pfsense-ce:2.8 "$1" pfSense 2>/dev/null || true
      find "$(dirname "$1")" -mindepth 1 -type d -name ".staging.*" | wc -l | tr -d " "
    ' sh "$LIB" "$IMGDIR"
    The output should eq '0'
    The stderr should be present
  End

  It 'pulls when the digest matches but the artifact is gone'
    # Regression guard: keying purely on the digest skips the pull for an image that is not
    # actually on disk, and the boot then dies on a missing base image.
    When call sh -c '
      . "$1"; shift
      STUB_REMOTE_DIGEST=sha256:ce pfb_oras_refresh ghcr.io/x/pfsense-ce:2.8 "$1" pfSense
      rm -f "$1"/*.qcow2
      STUB_REMOTE_DIGEST=sha256:ce pfb_oras_refresh ghcr.io/x/pfsense-ce:2.8 "$1" pfSense
      test -f "$1/pfSense-CE_2.8.qcow2" && echo RESTORED
    ' sh "$LIB" "$IMGDIR"
    The output should include 'RESTORED'
    The stderr should be present
  End

  It 'pulls a ref whose own artifact is gone even when a sibling ref image is present'
    # The store holds several refs' images in ONE directory, so "some .qcow2 exists" is
    # satisfied by a sibling ref and hides this ref's missing image.
    When call sh -c '
      . "$1"; shift
      STUB_REMOTE_DIGEST=sha256:ce pfb_oras_refresh ghcr.io/x/pfsense-ce:2.8 "$1" CE
      STUB_ARTIFACT_NAME=pfSense-Plus_26.03.qcow2 STUB_REMOTE_DIGEST=sha256:plus \
        pfb_oras_refresh ghcr.io/x/pfsense-plus:26.03 "$1" Plus
      rm -f "$1/pfSense-Plus_26.03.qcow2"
      STUB_ARTIFACT_NAME=pfSense-Plus_26.03.qcow2 STUB_REMOTE_DIGEST=sha256:plus \
        pfb_oras_refresh ghcr.io/x/pfsense-plus:26.03 "$1" Plus
      test -f "$1/pfSense-Plus_26.03.qcow2" && echo RESTORED || echo MISSING
    ' sh "$LIB" "$IMGDIR"
    The output should include 'RESTORED'
    The stderr should be present
  End

  # ── per-ref digests ───────────────────────────────────────────────────────── #

  It 'does not re-pull a ref whose own digest is unchanged'
    When call sh -c '
      . "$1"; shift
      STUB_REMOTE_DIGEST=sha256:ce pfb_oras_refresh ghcr.io/x/pfsense-ce:2.8 "$1" pfSense
      STUB_REMOTE_DIGEST=sha256:ce pfb_oras_refresh ghcr.io/x/pfsense-ce:2.8 "$1" pfSense
      wc -l < "$STUB_PULL_LOG" | tr -d " "
    ' sh "$LIB" "$IMGDIR"
    The output should eq '1'
    The stderr should be present
  End

  It 'does not re-pull one ref because a DIFFERENT ref was refreshed into the same directory'
    # The regression: one .digest per directory, two refs sharing it. A CE leg followed by a
    # Plus leg followed by a CE leg re-pulled CE every time, despite CE being on disk.
    When call sh -c '
      . "$1"; shift
      STUB_REMOTE_DIGEST=sha256:ce   pfb_oras_refresh ghcr.io/x/pfsense-ce:2.8    "$1" pfSense
      STUB_ARTIFACT_NAME=pfSense-Plus_26.03.qcow2 STUB_REMOTE_DIGEST=sha256:plus \
        pfb_oras_refresh ghcr.io/x/pfsense-plus:26.03 "$1" pfSense
      STUB_REMOTE_DIGEST=sha256:ce   pfb_oras_refresh ghcr.io/x/pfsense-ce:2.8    "$1" pfSense
      wc -l < "$STUB_PULL_LOG" | tr -d " "
    ' sh "$LIB" "$IMGDIR"
    The output should eq '2'
    The stderr should be present
  End

  It 'does not let two different refs collide onto one digest file'
    # `:` and `/` both mapping to `-` makes ghcr.io/x/a:1 and ghcr.io/x/a-1 indistinguishable,
    # which silently suppresses a needed pull for the second ref.
    When call sh -c '
      . "$1"; shift
      a="$(pfb_oras_digest_file ghcr.io/x/a:1 "$1")"
      b="$(pfb_oras_digest_file ghcr.io/x/a-1 "$1")"
      [ "$a" = "$b" ] && echo COLLISION || echo DISTINCT
    ' sh "$LIB" "$IMGDIR"
    The output should eq 'DISTINCT'
  End

  It 'refuses to name a digest file when sha256sum is unavailable'
    # Hide sha256sum from PATH: without it the pipe yields an empty suffix and every ref
    # shares one name again. Asserting the shape of the NAME cannot catch that -- the guard
    # has to be exercised by removing the tool it guards against.
    When call sh -c '
      . "$1"; shift
      PATH=/nonexistent-dir pfb_oras_digest_file ghcr.io/x/pfsense-ce:2.8 "$1"
      echo "rc=$?"
    ' sh "$LIB" "$IMGDIR"
    # rc alone cannot discriminate: without the guard the inner failure is 127 and this
    # function's own `|| return 1` normalises it back to 1. Assert the guard's message.
    The output should include 'rc=1'
    The stderr should include 'sha256sum is required'
  End

  It 'refuses to derive a ref hash when sha256sum is unavailable'
    # BOTH the digest filename and the lock filename derive a hash. Routing them through
    # one guarded helper is what stops the lock path degrading to an empty suffix.
    When call sh -c '
      . "$1"; shift
      PATH=/nonexistent-dir pfb_oras_ref_hash ghcr.io/x/pfsense-ce:2.8
      echo "rc=$?"
    ' sh "$LIB" "$IMGDIR"
    # EXACT match: without the guard the helper exits 127 (command not found), and
    # `include 'rc=1'` matches 'rc=127' as a substring -- the test would never fail.
    The output should eq 'rc=1'
    The stderr should be present
  End

  It 'refuses to take the per-ref lock when sha256sum is unavailable'
    # The lock name derives its own hash. Hiding sha256sum via a bare empty PATH would also
    # hide flock and fall through to the unserialised branch, never reaching the lock path.
    # This PATH keeps every tool the lock path needs EXCEPT sha256sum.
    When call sh -c '
      . "$1"; shift
      mkdir -p "$2/onlybin"
      for t in flock mktemp tr cut sed rm mv basename wc cat; do
        p="$(command -v $t 2>/dev/null)" && ln -sf "$p" "$2/onlybin/$t"
      done
      # A `VAR=val func` prefix PERSISTS after a shell function returns in POSIX sh, so
      # PATH must be restored explicitly or the assertion below runs without its tools.
      _saved_path="$PATH"
      PATH="$2/onlybin"; pfb_oras_refresh ghcr.io/x/pfsense-ce:2.8 "$1" pfSense 2>/dev/null
      PATH="$_saved_path"
      # The DISCRIMINATING signal: the guarded path returns before opening the lock file.
      # An unguarded lock path derives an empty hash and creates ".lock-" regardless, then
      # fails later in the digest helper -- which an rc or stderr assertion cannot tell
      # apart, because both paths end in the same message and the same status.
      find "$1" -name ".lock-*" | wc -l | tr -d " "
    ' sh "$LIB" "$IMGDIR" "$WORK"
    The output should eq '0'
  End

  It 'pulls when the ref digest actually moved'
    When call sh -c '
      . "$1"; shift
      STUB_REMOTE_DIGEST=sha256:one pfb_oras_refresh ghcr.io/x/pfsense-ce:2.8 "$1" pfSense
      STUB_REMOTE_DIGEST=sha256:two pfb_oras_refresh ghcr.io/x/pfsense-ce:2.8 "$1" pfSense
      wc -l < "$STUB_PULL_LOG" | tr -d " "
    ' sh "$LIB" "$IMGDIR"
    The output should eq '2'
    The stderr should be present
  End

  It 'keeps each ref digest in its own file so the store is self-describing'
    When call sh -c '
      . "$1"; shift
      STUB_REMOTE_DIGEST=sha256:ce pfb_oras_refresh ghcr.io/x/pfsense-ce:2.8 "$1" pfSense
      ls -a "$1" | grep -c "^\.digest"
    ' sh "$LIB" "$IMGDIR"
    The output should eq '1'
    The status should be success
    The stderr should be present
  End
End
