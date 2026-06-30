#shellcheck shell=sh
# pfb_aggregate() family-correct collapse (issue #651).
#
# The ADR-11 "Uber" aggregate builder must NOT run iprange on the IPv6 union: iprange is
# IPv4-only, so given IPv6 it truncates each address at the first ':' and reads the leading
# hextet as a decimal, emitting bogus 0.0.x.y entries (observed live: pfB_Deny_Aggregated_v6
# held 40 mangled IPv4 entries instead of its ~16k-address v6 union). The fix: v6 takes the
# deduped sort -u union verbatim; v4 still CIDR-collapses through iprange.

Describe 'pfb_aggregate() family-correct collapse (issue #651)'
  setup() {
    work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/agg.XXXXXX")"
    tempfile="${work}/t1"
    dedupfile="${work}/dedup"
    errorlog="${work}/err.log"
    memberlist="${work}/members"
    aggout="${work}/agg.txt"
    consumer="${work}/agg.lst"

    # iprange stub that FAITHFULLY mimics the real IPv4-only tool (iprange 1.0.4): it records
    # that it ran (so a test can assert it was/was not invoked) and truncates each line at the
    # first ':' -- exactly how the real tool mangles IPv6 (2000::/16 -> "2000"). v4 lines (no
    # ':') pass through unchanged, so the v4 path keeps working.
    marker="${work}/iprange_called"
    export PFB_AGG_MARKER="${marker}"
    pathaggregate="${work}/iprange"
    cat > "${pathaggregate}" <<'STUB'
#!/bin/sh
echo called > "${PFB_AGG_MARKER}"
sed 's/:.*$//' "$1"
STUB
    chmod +x "${pathaggregate}"
  }
  cleanup() { rm -rf "${work}"; }
  BeforeAll 'pfb_source'
  Before 'setup'
  After 'cleanup'

  It 'writes the deduped v6 union verbatim and does NOT run iprange (v6)'
    # Given two IPv6 member files sharing a duplicate entry
    printf '2001:db8::/32\n2606:4700::/32\n' > "${work}/m1"
    printf '2606:4700::/32\n2a00:1450::/32\n' > "${work}/m2"
    printf '%s\n%s\n' "${work}/m1" "${work}/m2" > "${memberlist}"
    # The EXACT deduped union, LC_ALL=C-sorted (the duplicate 2606:4700::/32 collapses).
    expected_v6="$(printf '%s\n' '2001:db8::/32' '2606:4700::/32' '2a00:1450::/32')"

    When call pfb_aggregate agg v6 "${memberlist}" "${aggout}" "${consumer}"

    The status should be success
    # Then the aggregate is EXACTLY the deduped IPv6 union: no duplicates, no extra lines, and
    # none iprange-mangled to "2001"/"2a00" (an `include` check would miss all three).
    The contents of file "${aggout}" should equal "${expected_v6}"
    # and iprange was NOT invoked for v6 (the bug was running the IPv4-only tool on it)
    The path "${marker}" should not be exist
    # consumer mirror equals the aggregate (never-empty contract)
    The contents of file "${consumer}" should equal "${expected_v6}"
    The stdout should include 'aggregate'
  End

  It 'passes the v4 union through iprange (v4 path unchanged)'
    # Given two IPv4 member files sharing a duplicate entry
    printf '192.0.2.0/24\n198.51.100.0/24\n' > "${work}/m1"
    printf '198.51.100.0/24\n203.0.113.0/24\n' > "${work}/m2"
    printf '%s\n%s\n' "${work}/m1" "${work}/m2" > "${memberlist}"
    expected_v4="$(printf '%s\n' '192.0.2.0/24' '198.51.100.0/24' '203.0.113.0/24')"

    When call pfb_aggregate agg v4 "${memberlist}" "${aggout}" "${consumer}"

    The status should be success
    # iprange WAS invoked for v4 (the CIDR-collapse path), and the union is exactly the deduped set
    The path "${marker}" should be exist
    The contents of file "${aggout}" should equal "${expected_v4}"
    The stdout should include 'aggregate'
  End

  It 'empties the aggregate and writes the consumer placeholder on an empty union'
    # The third branch: no members -> empty union. A pre-existing (stale) aggregate must be
    # truncated, the never-empty consumer must fall back to the '#' placeholder, and iprange is
    # never invoked. Pre-seed stale content to prove the rebuild actually clears it.
    printf 'stale\n' > "${aggout}"
    printf 'stale\n' > "${consumer}"
    : > "${memberlist}"

    When call pfb_aggregate agg v6 "${memberlist}" "${aggout}" "${consumer}"

    The status should be success
    The contents of file "${aggout}" should equal ''
    The contents of file "${consumer}" should equal '#'
    The path "${marker}" should not be exist
    The stdout should include 'aggregate'
  End
End
