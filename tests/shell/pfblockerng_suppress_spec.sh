#shellcheck shell=sh
# suppress() spec (ADR-53). Phase 1 pinned TODAY's IP-suppression semantics
# (including the containing-entry defect) as a behaviour-preserving oracle.
# Phase 3 (this revision) flips that oracle red->green against the REWRITTEN
# suppress(): the grep -F /24-explode + dupfile dedup + `grepcidr -vf`
# whole-token pass are GONE, replaced by a single `iprange --except` set
# subtraction (ADR-53 §2.1) -- true CIDR set-subtraction with a minimal
# covering-CIDR remainder, so a suppressed host is now carved out of ANY
# containing entry, not just the exact /24 the old explode required.
#
# suppress() (pfblockerng.sh) carves suppression-list entries out of a deny
# member file (${max}/${alias}.txt), gated on a non-empty ${pfbsuppression}
# file. Both inputs are pre-filtered to strict IPv4 host/CIDR token shape
# before either reaches iprange (ADR-53 §1.2's DNS-resolution hazard: a
# malformed token is not rejected by iprange -- it is silently treated as a
# HOSTNAME and DNS-resolved, rc=0, no opt-out flag). Cases (a, b, f, g) use a
# lightweight iprange-shaped STUB (address-equality removal -- the only shape
# suppress()'s own wiring/gating logic needs to prove itself); cases (c, d, j)
# assert something about iprange's OWN empirically-proven behaviour (the
# covering-CIDR carve math, rc=0-on-empty) and so need the REAL binary,
# skip-if-absent locally (house pattern: CI installs it and is the hard
# gate -- see ADR-53 §1.2 for the measured covering-CIDR counts this pins).
#
# Note: tests/shell/pfblockerng_fail_open_redirect_spec.sh's suppress()
# Describe blocks (Class A/B) also switched from the grepcidr-rc gate to the
# iprange-rc gate in this same phase -- see that file's header. The two
# files' fail-safe cases stay deliberately redundant, not duplicative: each
# proves the rc-gating contract from its own file's self-contained narrative.

Describe 'suppress() (ADR-53 Phase 1 oracle)'
  BeforeAll 'pfb_source'

  # Real iprange --except performs actual CIDR set-subtraction with a minimal
  # covering-CIDR remainder (ADR-53 §1.2) -- a stub cannot fake that math, so
  # cases (c, d, j) below need the real binary. CI installs it (test.yml);
  # locally, absent = skip (house pattern: missing tool reported + skipped,
  # CI is the hard gate).
  # spec_helper.sh prepends PFB_SHIMS onto PATH with its OWN `iprange` stand-in
  # (a bare `sort -u` passthrough built for the AWS pre-script tests -- no
  # --except/aggregation semantics), so a bare `command -v iprange` would
  # resolve to THAT, not the real binary. Search past it explicitly.
  pfb_real_iprange() {
    ( PATH="$(printf '%s\n' "${PATH}" | sed "s#${PFB_SHIMS}:##")"; command -v iprange 2>/dev/null )
  }
  have_iprange() { [ -n "$(pfb_real_iprange)" ]; }
  # `Skip if` runs its condition as a simple command -- a leading `!` is not
  # a command in POSIX sh, so wrap the negation in a function.
  #
  # Hardened (adversarial-review item E on PR #768): GitHub Actions sets
  # CI=true and test.yml installs the real iprange binary for these specs --
  # a silent skip there would be coverage theater (the install step broke and
  # nothing would notice). In CI, refuse to skip: if the real binary is truly
  # absent, let the example run and FAIL against the empty pathaggregate (the
  # stderr line below explains why) rather than silently reporting green-via-
  # skip. Locally (CI unset) the skip stays legitimate -- the house "missing
  # tool = skip, CI is the hard gate" pattern is unchanged there.
  no_iprange() {
    have_iprange && return 1
    if [ -n "${CI:-}" ]; then
      echo 'FATAL (adversarial-review item E): real iprange binary not found on PATH in CI;' \
        'refusing to silently skip -- test.yml is supposed to install it (ADR-53 §1.2)' >&2
      return 1
    fi
    return 0
  }

  # ---- iprange stub (address-equality) ----
  # Fake `<shim> <haystack-file> --except <except-file>` (iprange's own CLI
  # shape -- see --help) for cases that pin suppress()'s OWN wiring/gating
  # logic rather than iprange's covering-CIDR carve math itself (that needs
  # the REAL binary -- see cases c/d/j further down).
  #
  # Default mode performs plain ADDRESS-EQUALITY filtering with the mask
  # stripped from both sides: every suppression entry the UI accepts today is
  # a /32 host (mask enforcement at pfblockerng_ip.php:159), so real
  # iprange's exact CIDR-set subtraction collapses to "is this haystack
  # line's address exactly a suppressed host". A bare host, or a line written
  # as that exact /32, is REMOVED -- iprange's proven whole-token/host
  # removal (ADR-53 §1.2, empirically verified). This stub does NOT attempt
  # covering-CIDR carve math (a wider haystack CIDR is left untouched by this
  # fake) -- cases needing that assert against the real binary instead.
  #
  # IPRANGE_MODE=error overrides the default for the #713-equivalent
  # fail-safe rc-gating case: simulates a real iprange error (rc!=0, e.g. a
  # missing/unloadable ipset file).
  write_pathaggregate_shim() {
    cat > "$1" <<'SHIM'
#!/bin/sh
case "${IPRANGE_MODE:-}" in
	error) echo 'iprange: simulated error (missing/unloadable ipset)' >&2; exit 1 ;;
esac

haystack="$1"
except="$3"
faddrs="$(sed 's#/.*##' "${except}")"
while IFS= read -r line; do
	[ -z "${line}" ] && continue
	addr="${line%%/*}"
	if ! printf '%s\n' "${faddrs}" | grep -qxF "${addr}"; then
		printf '%s\n' "${line}"
	fi
done < "${haystack}"
SHIM
    chmod +x "$1"
  }

  # ---- iprange stub (identity pass-through) ----
  # Ignores --except entirely and echoes the haystack file back unchanged.
  # Used only where the assertion targets something OTHER than the published
  # member-file content (e.g. case h's pre-filter-drop check) and a fixed,
  # always-succeeding binary is all that's needed to satisfy suppress()'s
  # executable guard + rc-gated publish.
  write_pathaggregate_identity_shim() {
    cat > "$1" <<'SHIM'
#!/bin/sh
cat "$1"
SHIM
    chmod +x "$1"
  }

  # ---- iprange stub (always fails) ----
  # Simulates a real iprange error (rc!=0) unconditionally -- the #713-style
  # fail-safe gate (case i): suppress() must keep the previous list and log,
  # never truncate/publish on a real engine error.
  write_pathaggregate_fail_shim() {
    cat > "$1" <<'SHIM'
#!/bin/sh
echo 'iprange: simulated error (missing/unloadable ipset)' >&2
exit 1
SHIM
    chmod +x "$1"
  }

  Describe 'a — suppression file absent or empty: early return, member file untouched'
    setup() {
      work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pfbsuppa.XXXXXX")"
      max="${work}"
      alias='TestList_v4'
      pfbsuppression="${work}/suppression.txt"
      tempfile="${work}/t1"; tempfile2="${work}/t2"; dupfile="${work}/t3"; dedupfile="${work}/t4"
      masterfile="${work}/master"; mastercat="${work}/mastercat"
      true > "${masterfile}"
      dedup='off'
      errorlog="${work}/error.log"; true > "${errorlog}"
      pathaggregate="${work}/iprange"
      write_pathaggregate_shim "${pathaggregate}"
      member="${work}/${alias}.txt"
      printf '203.0.113.5\n' > "${member}"
    }
    cleanup() { rm -rf "${work}"; }
    Before 'setup'
    After 'cleanup'

    It 'leaves the member file byte-identical when the suppression file does not exist'
      # Given: no pfbsuppression file was ever created (the "-e" leg of the gate).
      When call silently suppress
      The status should be success
      The contents of file "${member}" should equal '203.0.113.5'
    End

    It 'leaves the member file byte-identical when the suppression file exists but is empty'
      # Given: the file exists but is zero-length (the "-s" leg of the gate).
      true > "${pfbsuppression}"
      When call silently suppress
      The status should be success
      The contents of file "${member}" should equal '203.0.113.5'
    End
  End

  Describe 'b — bare-host token + matching /32 suppression: token removed (the working case)'
    setup() {
      work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pfbsuppb.XXXXXX")"
      max="${work}"
      alias='TestList_v4'
      pfbsuppression="${work}/suppression.txt"
      printf '203.0.113.7/32\n' > "${pfbsuppression}"
      tempfile="${work}/t1"; tempfile2="${work}/t2"; dupfile="${work}/t3"; dedupfile="${work}/t4"
      masterfile="${work}/master"; mastercat="${work}/mastercat"
      true > "${masterfile}"
      dedup='off'
      errorlog="${work}/error.log"; true > "${errorlog}"
      pathaggregate="${work}/iprange"
      write_pathaggregate_shim "${pathaggregate}"
      member="${work}/${alias}.txt"
      printf '203.0.113.5\n203.0.113.7\n203.0.113.9\n' > "${member}"
    }
    cleanup() { rm -rf "${work}"; }
    Before 'setup'
    After 'cleanup'

    It 'removes the exact suppressed host, keeping its siblings'
      When call silently suppress
      The status should be success
      The contents of file "${member}" should equal "$(printf '203.0.113.5\n203.0.113.9')"
    End
  End

  Describe 'c — exact-/24 carve: a /32 suppression inside a containing /24 member entry (real iprange)'
    setup() {
      work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pfbsuppc.XXXXXX")"
      max="${work}"
      alias='TestList_v4'
      pfbsuppression="${work}/suppression.txt"
      tempfile="${work}/t1"; tempfile2="${work}/t2"; dupfile="${work}/t3"; dedupfile="${work}/t4"
      masterfile="${work}/master"; mastercat="${work}/mastercat"
      true > "${masterfile}"
      dedup='off'
      errorlog="${work}/error.log"; true > "${errorlog}"
      pathaggregate="$(pfb_real_iprange)"
      member="${work}/${alias}.txt"
      printf '10.9.8.0/24\n' > "${member}"
    }
    cleanup() { rm -rf "${work}"; }
    Before 'setup'
    After 'cleanup'

    It 'carves the /32 hole out of the /24, publishing the 8 minimal covering CIDRs -- NEVER a host explosion (Phase 3: was 254 host lines pre-rewrite)'
      Skip if 'needs the real iprange binary (apt-get install iprange in CI; absent locally)' no_iprange
      printf '10.9.8.4/32\n' > "${pfbsuppression}"
      When call silently suppress
      The status should be success
      The contents of file "${member}" should not include '10.9.8.0/24'
      # Exact-line greps (never substring "include") -- '10.9.8.4' as a
      # substring would false-positive-match '10.9.8.40'..'10.9.8.49'. `|| true`
      # so a legitimate zero-match (grep rc=1) doesn't abort the example.
      has4="$(grep -c '^10\.9\.8\.4$' "${member}" || true)"
      The variable has4 should equal 0
      # /24 - /32 = 8 minimal covering CIDRs (empirically pinned, ADR-53 §1.2) --
      # never the old 254-host explosion.
      linecount="$(grep -c ^ "${member}")"
      The variable linecount should equal 8
      # Representative samples of the expected covering-CIDR remainder --
      # asserting PRESENCE (not just the hole's absence) so a "carve away
      # everything" bug can't false-pass.
      The contents of file "${member}" should include '10.9.8.5'
      The contents of file "${member}" should include '10.9.8.128/25'
    End

    It 'a SECOND /32 suppression inside the same containing /24 is carved in the SAME iprange call (no dedup bookkeeping needed): both holes gone, minimal cover, no duplicates'
      Skip if 'needs the real iprange binary (apt-get install iprange in CI; absent locally)' no_iprange
      # Given: two DIFFERENT /32 holes that both map to the same containing
      # /24 -- iprange --except subtracts every hole in ONE pass, so there is
      # no per-hole dedup guard left to prove (the old dupfile/"dcheck" check
      # is gone).
      printf '10.9.8.4/32\n10.9.8.55/32\n' > "${pfbsuppression}"
      When call silently suppress
      The status should be success
      The contents of file "${member}" should not include '10.9.8.0/24'
      has4="$(grep -c '^10\.9\.8\.4$' "${member}" || true)"
      The variable has4 should equal 0
      has55="$(grep -c '^10\.9\.8\.55$' "${member}" || true)"
      The variable has55 should equal 0
      # 12 minimal covering CIDRs for two /32 holes in one /24 (empirically
      # verified against the real binary).
      linecount="$(grep -c ^ "${member}")"
      The variable linecount should equal 12
      # Then: no line is duplicated -- a real double-explode would leave every
      # non-suppressed host appearing twice.
      dupcount="$(sort "${member}" | uniq -d | grep -c ^ || true)"
      The variable dupcount should equal 0
    End
  End

  Describe 'd — containing-entry carve: the DEFECT FIXED (Phase 3) -- a wider containing block is genuinely carved (real iprange)'
    setup() {
      work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pfbsuppd.XXXXXX")"
      max="${work}"
      alias='TestList_v4'
      pfbsuppression="${work}/suppression.txt"
      printf '10.0.3.4/32\n' > "${pfbsuppression}"
      tempfile="${work}/t1"; tempfile2="${work}/t2"; dupfile="${work}/t3"; dedupfile="${work}/t4"
      masterfile="${work}/master"; mastercat="${work}/mastercat"
      true > "${masterfile}"
      dedup='off'
      errorlog="${work}/error.log"; true > "${errorlog}"
      pathaggregate="$(pfb_real_iprange)"
      member="${work}/${alias}.txt"
      # A /16 member entry containing the suppressed /32 host -- the OLD
      # engine's literal grep -F match only ever fired for the EXACT
      # containing /24, so this survived byte-identical (Phase 1's pinned
      # oracle). iprange --except subtracts it regardless of the containing
      # prefix length.
      printf '10.0.0.0/16\n' > "${member}"
    }
    cleanup() { rm -rf "${work}"; }
    Before 'setup'
    After 'cleanup'

    It 'CARVES the suppressed host out of the containing /16 (was a silent no-op pre-Phase-3, ADR-53 §1.2) -- 16 covering CIDRs, suppressed host gone, siblings still covered'
      Skip if 'needs the real iprange binary (apt-get install iprange in CI; absent locally)' no_iprange
      When call silently suppress
      The status should be success
      # Before Phase 3, this line was pinned BYTE-IDENTICAL '10.0.0.0/16' --
      # today's defect. After the carve, the /16 line itself is gone,
      # replaced by its minimal covering-CIDR remainder.
      The contents of file "${member}" should not include '10.0.0.0/16'
      # /16 - /32 = 16 minimal covering CIDRs (empirically pinned, ADR-53 §1.2).
      linecount="$(grep -c ^ "${member}")"
      The variable linecount should equal 16
      has_host="$(grep -c '^10\.0\.3\.4$' "${member}" || true)"
      The variable has_host should equal 0
      # Representative samples either side of the hole -- proves the
      # remainder genuinely covers the siblings, not an over-carve.
      The contents of file "${member}" should include '10.0.0.0/23'
      The contents of file "${member}" should include '10.0.128.0/17'
    End
  End

  Describe 'f — masterfile resync under dedup="on" mirrors the post-suppression list'
    setup() {
      work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pfbsuppf.XXXXXX")"
      max="${work}"
      alias='DedupList_v4'
      pfbsuppression="${work}/suppression.txt"
      printf '203.0.113.7/32\n' > "${pfbsuppression}"
      tempfile="${work}/t1"; tempfile2="${work}/t2"; dupfile="${work}/t3"; dedupfile="${work}/t4"
      masterfile="${work}/master"; mastercat="${work}/mastercat"
      # A stale pair of rows for THIS alias, plus one unrelated alias's row
      # that must survive the resync untouched.
      printf 'DedupList_v4 PRIOR-1\nDedupList_v4 PRIOR-2\nOtherList_v4 198.51.100.5\n' > "${masterfile}"
      dedup='on'
      errorlog="${work}/error.log"; true > "${errorlog}"
      pathaggregate="${work}/iprange"
      write_pathaggregate_shim "${pathaggregate}"
      member="${work}/${alias}.txt"
      printf '203.0.113.5\n203.0.113.7\n203.0.113.9\n' > "${member}"
    }
    cleanup() { rm -rf "${work}"; }
    Before 'setup'
    After 'cleanup'

    It 'drops the stale alias rows, keeps the unrelated row, and appends the post-suppression list'
      When call silently suppress
      The status should be success
      The contents of file "${masterfile}" should include 'OtherList_v4 198.51.100.5'
      The contents of file "${masterfile}" should not include 'PRIOR-1'
      The contents of file "${masterfile}" should not include 'PRIOR-2'
      The contents of file "${masterfile}" should include 'DedupList_v4 203.0.113.5'
      The contents of file "${masterfile}" should include 'DedupList_v4 203.0.113.9'
      The contents of file "${masterfile}" should not include 'DedupList_v4 203.0.113.7'
    End
  End

  Describe 'g — the Suppression Stats table'
    setup() {
      work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pfbsuppg.XXXXXX")"
      max="${work}"
      pfbsuppression="${work}/suppression.txt"
      printf '203.0.113.7/32\n' > "${pfbsuppression}"
      tempfile="${work}/t1"; tempfile2="${work}/t2"; dupfile="${work}/t3"; dedupfile="${work}/t4"
      masterfile="${work}/master"; mastercat="${work}/mastercat"
      true > "${masterfile}"
      dedup='off'
      errorlog="${work}/error.log"; true > "${errorlog}"
      pathaggregate="${work}/iprange"
      write_pathaggregate_shim "${pathaggregate}"
      alias='StatsList_v4'
      member="${work}/${alias}.txt"
      printf '203.0.113.5\n203.0.113.7\n203.0.113.9\n' > "${member}"
    }
    cleanup() { rm -rf "${work}"; }
    Before 'setup'
    After 'cleanup'

    It 'prints the header block when alias="suppressheader"'
      alias='suppressheader'
      When call suppress
      The status should be success
      The stdout should include '===[ Suppression Stats ]==================================='
      The stdout should include 'List'
      The stdout should include 'Pre'
      The stdout should include 'Suppress'
      The stdout should include 'Master'
    End

    It 'prints the per-alias Pre/Suppress/Master row shape on a normal call'
      When call suppress
      The status should be success
      The stdout should include 'StatsList_v4'
      # Pre = 3 (member file before this call); Suppress = 2 (one host removed).
      The stdout should match pattern "*StatsList_v4*3*2*0*"
    End
  End

  Describe 'h — iprange DNS-resolution hazard (ADR-53 §1.2): a hostname-shaped suppression token is dropped BEFORE it ever reaches iprange'
    setup() {
      work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pfbsupph.XXXXXX")"
      max="${work}"
      alias='TestList_v4'
      pfbsuppression="${work}/suppression.txt"
      tempfile="${work}/t1"; tempfile2="${work}/t2"; dupfile="${work}/t3"; dedupfile="${work}/t4"
      masterfile="${work}/master"; mastercat="${work}/mastercat"
      true > "${masterfile}"
      dedup='off'
      errorlog="${work}/error.log"; true > "${errorlog}"
      pathaggregate="${work}/iprange"
      write_pathaggregate_identity_shim "${pathaggregate}"
      member="${work}/${alias}.txt"
      printf '203.0.113.5\n203.0.113.7\n203.0.113.9\n' > "${member}"
    }
    cleanup() { rm -rf "${work}"; }
    Before 'setup'
    After 'cleanup'

    It 'never reaches iprange: dropped from the filtered suppression scratch file before the call, and logged'
      # A hostname-shaped token in the suppression list -- ADR-53 §1.2 proved
      # iprange treats a malformed token as a HOSTNAME and DNS-resolves it
      # (rc=0, no opt-out flag): a silent mid-update DNS lookup that, if it
      # resolved, would subtract the resolved IPs as if they were a real
      # suppression entry. The pre-filter must drop it before iprange ever
      # sees it -- proven here by inspecting suppress()'s OWN filtered
      # scratch file (${dupfile}) directly, not merely that the published
      # result "looks right".
      printf '203.0.113.7/32\nevil.example.com\n' > "${pfbsuppression}"
      When call silently suppress
      The status should be success
      The contents of file "${dupfile}" should not include 'evil.example.com'
      The contents of file "${dupfile}" should include '203.0.113.7/32'
      The contents of file "${errorlog}" should include 'dropping malformed suppression entry'
    End
  End

  Describe 'i — iprange fail-safe publish gating (#713-equivalent): a real engine error keeps the previous list'
    setup() {
      work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pfbsuppi.XXXXXX")"
      max="${work}"
      alias='TestList_v4'
      pfbsuppression="${work}/suppression.txt"
      printf '203.0.113.7/32\n' > "${pfbsuppression}"
      tempfile="${work}/t1"; tempfile2="${work}/t2"; dupfile="${work}/t3"; dedupfile="${work}/t4"
      masterfile="${work}/master"; mastercat="${work}/mastercat"
      true > "${masterfile}"
      dedup='off'
      errorlog="${work}/error.log"; true > "${errorlog}"
      pathaggregate="${work}/iprange"
      write_pathaggregate_fail_shim "${pathaggregate}"
      member="${work}/${alias}.txt"
      printf '203.0.113.5\n203.0.113.7\n203.0.113.9\n' > "${member}"
    }
    cleanup() { rm -rf "${work}"; }
    Before 'setup'
    After 'cleanup'

    It 'keeps the PRIOR member list unchanged when iprange errors (rc!=0, e.g. a missing/unloadable ipset file), and logs the error'
      When call silently suppress
      The status should be success
      The contents of file "${member}" should equal "$(printf '203.0.113.5\n203.0.113.7\n203.0.113.9')"
      The contents of file "${errorlog}" should include 'iprange error'
    End
  End

  Describe 'j — full suppression: the suppression set exactly equals the member set (real iprange)'
    setup() {
      work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pfbsuppj.XXXXXX")"
      max="${work}"
      alias='TestList_v4'
      pfbsuppression="${work}/suppression.txt"
      printf '203.0.113.7/32\n' > "${pfbsuppression}"
      tempfile="${work}/t1"; tempfile2="${work}/t2"; dupfile="${work}/t3"; dedupfile="${work}/t4"
      masterfile="${work}/master"; mastercat="${work}/mastercat"
      true > "${masterfile}"
      dedup='off'
      errorlog="${work}/error.log"; true > "${errorlog}"
      pathaggregate="$(pfb_real_iprange)"
      member="${work}/${alias}.txt"
      printf '203.0.113.7\n' > "${member}"
    }
    cleanup() { rm -rf "${work}"; }
    Before 'setup'
    After 'cleanup'

    It 'publishes an EMPTY member list when suppression removes every entry -- a LEGITIMATE outcome (iprange rc=0 either way; no grepcidr-style rc=1 quirk to special-case)'
      Skip if 'needs the real iprange binary (apt-get install iprange in CI; absent locally)' no_iprange
      When call silently suppress
      The status should be success
      The contents of file "${member}" should equal ''
      The contents of file "${errorlog}" should equal ''
    End
  End

  Describe 'k — member-file pre-filter is ONE grep -E pass (adversarial-review item C on PR #768)'
    setup() {
      work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pfbsuppk.XXXXXX")"
      max="${work}"
      alias='TestList_v4'
      pfbsuppression="${work}/suppression.txt"
      printf '203.0.113.99/32\n' > "${pfbsuppression}"
      tempfile="${work}/t1"; tempfile2="${work}/t2"; dupfile="${work}/t3"; dedupfile="${work}/t4"
      masterfile="${work}/master"; mastercat="${work}/mastercat"
      true > "${masterfile}"
      dedup='off'
      errorlog="${work}/error.log"; true > "${errorlog}"
      pathaggregate="${work}/iprange"
      # Identity shim (echoes the haystack -- here the pre-filtered member
      # file -- back unchanged): isolates the member-file grep pre-filter
      # itself, not iprange's own carve math (that's cases c/d/j above).
      write_pathaggregate_identity_shim "${pathaggregate}"
      member="${work}/${alias}.txt"
      # One valid IPv4 host + one malformed (hostname-shaped) line. The
      # member file is normally already-sanitised feed data -- the pre-filter
      # is defense-in-depth against exactly this shape ever reaching iprange
      # (which would silently DNS-resolve it as a hostname, ADR-53 §1.2).
      printf '203.0.113.5\nevil.example.com\n' > "${member}"
    }
    cleanup() { rm -rf "${work}"; }
    Before 'setup'
    After 'cleanup'

    It 'drops the malformed line, keeps the valid line, and logs ONE summary line (replacing the old while-read loop)'
      When call silently suppress
      The status should be success
      # The filtered scratch file (what iprange actually sees) holds only the
      # valid entry -- proving the grep pass, not just the published result.
      The contents of file "${dedupfile}" should equal '203.0.113.5'
      The contents of file "${dedupfile}" should not include 'evil.example.com'
      # The identity shim echoes the haystack back unchanged, so the
      # published member file mirrors the filtered scratch file exactly.
      The contents of file "${member}" should equal '203.0.113.5'
      The contents of file "${errorlog}" should include 'dropped 1 malformed member-file line'
    End
  End

  Describe 'l — iprange binary missing entirely: the executable guard fails safe (adversarial-review item D on PR #768)'
    setup() {
      work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pfbsuppl.XXXXXX")"
      max="${work}"
      alias='TestList_v4'
      pfbsuppression="${work}/suppression.txt"
      printf '203.0.113.7/32\n' > "${pfbsuppression}"
      tempfile="${work}/t1"; tempfile2="${work}/t2"; dupfile="${work}/t3"; dedupfile="${work}/t4"
      masterfile="${work}/master"; mastercat="${work}/mastercat"
      true > "${masterfile}"
      dedup='off'
      errorlog="${work}/error.log"; true > "${errorlog}"
      # A path that does not exist at all -- `[ ! -x "${pathaggregate}" ]`
      # (pfblockerng.sh's suppress()) must fire before ANY of the pre-filter
      # or iprange machinery runs. No coverage existed for this guard before
      # this ADR's shellspec suite.
      pathaggregate="${work}/does-not-exist-iprange"
      member="${work}/${alias}.txt"
      printf '203.0.113.5\n203.0.113.7\n203.0.113.9\n' > "${member}"
    }
    cleanup() { rm -rf "${work}"; }
    Before 'setup'
    After 'cleanup'

    It 'returns early: member file byte-identical, "Not found" error logged'
      When call silently suppress
      The status should be success
      The contents of file "${member}" should equal "$(printf '203.0.113.5\n203.0.113.7\n203.0.113.9')"
      The contents of file "${errorlog}" should include 'Not found'
    End
  End

  Describe 'm — no_iprange CI-hardening (adversarial-review item E on PR #768): a broken CI install FAILS, never silently skips'
    # Force the "no real iprange reachable" condition via a local override of
    # have_iprange() -- NOT by scrubbing PATH, which would also break
    # shellspec's own use of coreutils (sed et al.) mid-example. Proves the
    # CI-vs-local discrimination itself, independent of whatever is actually
    # installed on the host running this suite (CI included, where the real
    # binary is normally present).
    setup() { have_iprange() { return 1; }; }
    Before 'setup'

    It 'does NOT skip when CI is set and no real iprange is reachable -- fails loudly instead'
      CI='true'
      When call no_iprange
      unset CI
      The status should be failure
      The stderr should include 'FATAL'
    End

    It 'still skips locally (CI unset) when no real iprange is reachable -- unchanged house pattern'
      unset CI
      When call no_iprange
      The status should be success
    End
  End

  Describe 'n — identical remainder does not republish (issue #3158)'
    pfb_mtime() { stat -c %Y "$1" 2>/dev/null || stat -f %m "$1"; }
    setup() {
      work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pfbsuppn.XXXXXX")"
      max="${work}"
      alias='QuietList_v4'
      pfbsuppression="${work}/suppression.txt"
      tempfile="${work}/t1"; tempfile2="${work}/t2"; dupfile="${work}/t3"; dedupfile="${work}/t4"
      masterfile="${work}/master"; mastercat="${work}/mastercat"
      true > "${masterfile}"
      dedup='off'
      errorlog="${work}/error.log"; true > "${errorlog}"
      pathaggregate="${work}/iprange"
      member="${work}/${alias}.txt"
      printf '203.0.113.5\n203.0.113.9\n' > "${member}"
    }
    cleanup() { rm -rf "${work}"; }
    Before 'setup'
    After 'cleanup'

    It 'leaves the member mtime unchanged when the remainder is byte-identical'
      write_pathaggregate_identity_shim "${pathaggregate}"
      printf '198.51.100.1/32\n' > "${pfbsuppression}"
      touch -t 200001010000.00 "${member}"
      pfb_mtime "${member}" > "${work}/before"
      check_mtime_unchanged() {
        silently suppress || return $?
        after=$(pfb_mtime "${member}")
        before=$(cat "${work}/before")
        [ "$after" = "$before" ] || {
          printf 'mtime moved: %s -> %s\n' "$before" "$after" >&2
          return 1
        }
        return 0
      }
      When call check_mtime_unchanged
      The status should be success
      The contents of file "${member}" should equal "$(printf '203.0.113.5\n203.0.113.9')"
    End

    It 'publishes and moves mtime when suppression removes an entry'
      write_pathaggregate_shim "${pathaggregate}"
      printf '203.0.113.5/32\n' > "${pfbsuppression}"
      touch -t 200001010000.00 "${member}"
      pfb_mtime "${member}" > "${work}/before"
      check_mtime_moved() {
        silently suppress || return $?
        after=$(pfb_mtime "${member}")
        before=$(cat "${work}/before")
        [ "$after" != "$before" ] || {
          printf 'mtime did not move: %s\n' "$before" >&2
          return 1
        }
        return 0
      }
      When call check_mtime_moved
      The status should be success
      The contents of file "${member}" should equal '203.0.113.9'
    End
  End
End
