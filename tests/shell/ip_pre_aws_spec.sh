#shellcheck shell=sh
# ip_pre_AWS_*.sh — per-region AWS prefix pre-scripts (list_scripts/).
#
# The 25 region scripts are now thin wrappers under list_scripts/ that each pass a
# jq `startswith()` region filter to the shared list_scripts/aws_region_prefixes.sh
# (the parse/aggregate logic). This suite pins, per region, that the wrapper +
# shared script still select exactly the right prefix set: each is run over the
# SAME fixture and the exact surviving set is asserted.
#
# Mechanics: aws_filter (spec_helper) copies fixtures/aws-ip-ranges.json, runs the
# wrapper (cwd = list_scripts/, so $0/dirname resolves the shared script) against
# the copy (which it overwrites in place), and emits the result sorted +
# space-joined. The real FreeBSD `iprange` aggregator is replaced by a `sort -u`
# shim (tests/shell/bin/iprange); the fixture uses one non-adjacent /24 per region
# so there is nothing to coalesce and the shim is faithful.
#
# NOTE on the us-/us-gov- overlap: ip_pre_AWS_US.sh filters `startswith("us-")`,
# which by design also matches the `us-gov-*` regions — so US includes the two
# us-gov prefixes below, while US_GOV (`us-gov-`) and US_EAST/US_WEST (`us-east-`/
# `us-west-`) stay disjoint from each other. These rows pin that behaviour.

Describe 'ip_pre_AWS_*.sh region filters'
  Parameters
    # script                        proto  expected (sorted, space-joined)
    "ip_pre_AWS_AF.sh"              _v4    "10.10.0.0/24"
    "ip_pre_AWS_ALL_REGIONS.sh"     _v4    "10.10.0.0/24 10.11.0.0/24 10.12.0.0/24 10.13.0.0/24 10.14.0.0/24 10.15.0.0/24 10.16.0.0/24 10.17.0.0/24 10.18.0.0/24 10.19.0.0/24 10.20.0.0/24 10.21.0.0/24 10.22.0.0/24 10.23.0.0/24 10.24.0.0/24 10.25.0.0/24 10.26.0.0/24 10.27.0.0/24 10.28.0.0/24 10.29.0.0/24 10.30.0.0/24"
    "ip_pre_AWS_AP.sh"              _v4    "10.11.0.0/24 10.12.0.0/24 10.13.0.0/24 10.14.0.0/24"
    "ip_pre_AWS_AP_EAST.sh"         _v4    "10.11.0.0/24"
    "ip_pre_AWS_AP_NORTHEAST.sh"    _v4    "10.12.0.0/24"
    "ip_pre_AWS_AP_SOUTH.sh"        _v4    "10.13.0.0/24"
    "ip_pre_AWS_AP_SOUTHEAST.sh"    _v4    "10.14.0.0/24"
    "ip_pre_AWS_CA.sh"              _v4    "10.15.0.0/24"
    "ip_pre_AWS_CN.sh"              _v4    "10.16.0.0/24 10.17.0.0/24"
    "ip_pre_AWS_CN_NORTH.sh"        _v4    "10.16.0.0/24"
    "ip_pre_AWS_CN_NORTHWEST.sh"    _v4    "10.17.0.0/24"
    "ip_pre_AWS_EU.sh"              _v4    "10.18.0.0/24 10.19.0.0/24 10.20.0.0/24 10.21.0.0/24"
    "ip_pre_AWS_EU_CENTRAL.sh"      _v4    "10.18.0.0/24"
    "ip_pre_AWS_EU_NORTH.sh"        _v4    "10.19.0.0/24"
    "ip_pre_AWS_EU_SOUTH.sh"        _v4    "10.20.0.0/24"
    "ip_pre_AWS_EU_WEST.sh"         _v4    "10.21.0.0/24"
    "ip_pre_AWS_IL.sh"              _v4    "10.22.0.0/24"
    "ip_pre_AWS_ME.sh"              _v4    "10.23.0.0/24 10.24.0.0/24"
    "ip_pre_AWS_ME_CENTRAL.sh"      _v4    "10.23.0.0/24"
    "ip_pre_AWS_ME_SOUTH.sh"        _v4    "10.24.0.0/24"
    "ip_pre_AWS_SA.sh"              _v4    "10.25.0.0/24"
    "ip_pre_AWS_US.sh"              _v4    "10.26.0.0/24 10.27.0.0/24 10.28.0.0/24 10.29.0.0/24"
    "ip_pre_AWS_US_EAST.sh"         _v4    "10.26.0.0/24"
    "ip_pre_AWS_US_GOV.sh"          _v4    "10.28.0.0/24 10.29.0.0/24"
    "ip_pre_AWS_US_WEST.sh"         _v4    "10.27.0.0/24"
    # IPv6 path (no iprange): a representative subset incl. the overlaps.
    "ip_pre_AWS_ALL_REGIONS.sh"     _v6    "2001:db8:10::/48 2001:db8:11::/48 2001:db8:12::/48 2001:db8:13::/48 2001:db8:14::/48 2001:db8:15::/48 2001:db8:16::/48 2001:db8:17::/48 2001:db8:18::/48 2001:db8:19::/48 2001:db8:20::/48 2001:db8:21::/48 2001:db8:22::/48 2001:db8:23::/48 2001:db8:24::/48 2001:db8:25::/48 2001:db8:26::/48 2001:db8:27::/48 2001:db8:28::/48 2001:db8:29::/48 2001:db8:30::/48"
    "ip_pre_AWS_EU.sh"              _v6    "2001:db8:18::/48 2001:db8:19::/48 2001:db8:20::/48 2001:db8:21::/48"
    "ip_pre_AWS_US.sh"              _v6    "2001:db8:26::/48 2001:db8:27::/48 2001:db8:28::/48 2001:db8:29::/48"
    "ip_pre_AWS_US_GOV.sh"          _v6    "2001:db8:28::/48 2001:db8:29::/48"
    "ip_pre_AWS_AP_SOUTH.sh"        _v6    "2001:db8:13::/48"
    "ip_pre_AWS_AP_SOUTHEAST.sh"    _v6    "2001:db8:14::/48"
  End

  Example "$1 ($2) selects only its region prefixes"
    When call aws_filter "$1" "$2"
    The output should equal "$3"
  End
End

# Failure handling (the shared aws_region_prefixes.sh). The pre-refactor scripts
# piped `jq | iprange` with no pipefail and exited 0 even on failure: a malformed
# download could be silently truncated into the alias, and "failed" looked like
# success. The shared script parses to a temp, checks jq's status, and only then
# publishes — failing loudly and leaving the input untouched.
Describe 'aws_region_prefixes.sh failure handling'
  awswork=""
  setup()   { awswork="$(mktemp "${SHELLSPEC_TMPBASE:-/tmp}/awsfail.XXXXXX")"; }
  cleanup() { rm -f "$awswork"; }
  Before 'setup'
  After 'cleanup'

  It 'fails (non-zero) and leaves the input untouched on malformed JSON'
    printf 'not-json{' > "$awswork"
    When run sh "${PFB_PKGDIR}/list_scripts/ip_pre_AWS_AF.sh" "$awswork" _v4
    The status should be failure
    The output should include "jq failed"
    The contents of file "$awswork" should equal "not-json{"
  End

  It 'fails (non-zero) and leaves the input untouched when no region prefixes match'
    # Valid JSON, but the af- filter matches nothing -> empty result.
    printf '{"prefixes":[{"ip_prefix":"10.0.0.0/24","region":"us-east-1"}],"ipv6_prefixes":[]}' > "$awswork"
    When run sh "${PFB_PKGDIR}/list_scripts/ip_pre_AWS_AF.sh" "$awswork" _v4
    The status should be failure
    The output should include "no prefixes matched"
    The contents of file "$awswork" should include '"region":"us-east-1"'
  End
End
