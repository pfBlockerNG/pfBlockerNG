#shellcheck shell=sh
# issue #1084: pins the incremental IP dedup/reputation shell behaviour that
# SURVIVES the batch-recompute swap -- remove()/process255()/reputation_pmax()/
# closingprocess() are still live (pfb_recompute() only replaced duplicate()'s
# masterfile surgery and reputation_dmax()'s incremental per-file mutation for
# the callers routed through it; see pfblockerng_recompute_spec.sh for that
# coverage). Behaviour-preserving oracle work (CLAUDE.md Test coverage #1
# refactor exception) -- green against today's code, no red run required.
#
# Fixtures are primarily RFC 5737 (192.0.2.0/24, 198.51.100.0/24,
# 203.0.113.0/24); the suffix-sibling hazard (#714/#730) pair reuses the
# established Ads_v4/BadAds_v4 aliases.

Describe "remove() masterfile row removal (suffix-sibling intact) + file cleanup"
	# shellcheck disable=SC2034  # consumed by the sourced remove()
	setup() {
		work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/rmsuffix.XXXXXX")"
		pfborig="${work}/orig/"; pfbdeny="${work}/deny/"; pfbmatch="${work}/match/"
		pfbpermit="${work}/permit/"; pfbnative="${work}/native/"
		mkdir -p "$pfborig" "$pfbdeny" "$pfbmatch" "$pfbpermit" "$pfbnative"
		masterfile="${work}/master"; mastercat="${work}/mastercat"
		tempfile="${work}/t1"; tempfile2="${work}/t2"
	}
	cleanup() { rm -rf "$work"; }
	BeforeAll 'pfb_source'
	Before 'setup'
	After 'cleanup'

	It 'strips exactly Ads_v4 rows/files, keeps BadAds_v4 intact, regenerates mastercat'
		alias='Ads_v4'
		cc='Ads_v4,'
		printf 'Ads_v4 10.0.0.0/24\nBadAds_v4 20.0.0.0/24\n' > "$masterfile"
		: > "${pfborig}Ads_v4.orig"; : > "${pfbdeny}Ads_v4.txt"; : > "${pfbmatch}Ads_v4.txt"
		: > "${pfbdeny}BadAds_v4.txt"

		When call remove
		The status should be success
		The output should include 'has been REMOVED'
		The contents of file "$masterfile" should not include 'Ads_v4 10.0.0.0/24'
		The contents of file "$masterfile" should include 'BadAds_v4 20.0.0.0/24'
		The contents of file "$mastercat" should equal '20.0.0.0/24'
		The path "${pfbdeny}Ads_v4.txt" should not be exist
		The path "${pfborig}Ads_v4.orig" should not be exist
		The path "${pfbmatch}Ads_v4.txt" should not be exist
		The path "${pfbdeny}BadAds_v4.txt" should be exist
	End

	It 'deletes both masterfile and mastercat once the last alias is removed'
		alias='Solo_v4'
		cc='Solo_v4,'
		printf 'Solo_v4 30.0.0.0/24\n' > "$masterfile"
		: > "${pfbdeny}Solo_v4.txt"

		When call remove
		The status should be success
		The output should include 'has been REMOVED'
		The path "$masterfile" should not be exist
		The path "$mastercat" should not be exist
	End
End

Describe 'reputation_pmax() collapse (no GeoIP, block-only)'
	# shellcheck disable=SC2034  # consumed by the sourced reputation_pmax()
	setup() {
		work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pmax.XXXXXX")"
		pfbdeny="${work}/deny/"
		mkdir -p "$pfbdeny"
		tmpdir="${work}"
		tempfile="${work}/t1"; tempfile2="${work}/t2"
		dedupfile="${work}/d4"; addfile="${work}/d5"; : > "$dedupfile"; : > "$addfile"
		masterfile="${work}/master"; mastercat="${work}/mastercat"
		ip_placeholder='240.0.0.0'
		ip_placeholder3="$(echo "${ip_placeholder}" | cut -d '.' -f 1-3)"
		now="now"
		count=0; countb=0
		max=2
		printf '198.51.100.1\n198.51.100.2\n198.51.100.3\n' > "${pfbdeny}PALIAS_v4.txt"
		printf 'PALIAS_v4 198.51.100.1\nPALIAS_v4 198.51.100.2\nPALIAS_v4 198.51.100.3\n' > "$masterfile"
	}
	cleanup() { rm -rf "$work"; }
	BeforeAll 'pfb_source'
	Before 'setup'
	After 'cleanup'

	It 'collapses the offending /24 with no GeoIP dependency and mirrors masterfile'
		When call reputation_pmax
		The status should be success
		The stdout should include 'Reputation - pMax Stats'
		The contents of file "${pfbdeny}PALIAS_v4.txt" should not include '198.51.100.1'
		The contents of file "${pfbdeny}PALIAS_v4.txt" should include '198.51.100.0/24'
		The contents of file "$masterfile" should not include 'PALIAS_v4 198.51.100.1'
		The contents of file "$masterfile" should include 'PALIAS_v4 198.51.100.0/24'
	End
End

Describe 'process255() collapses >253 same-/24 members within one feed'
	setup() {
		work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/proc255.XXXXXX")"
		pfbdeny="${work}/deny/"
		mkdir -p "$pfbdeny"
		tempfile="${work}/t1"; dedupfile="${work}/d1"
	}
	cleanup() { rm -rf "$work"; }
	BeforeAll 'pfb_source'
	Before 'setup'
	After 'cleanup'

	# Defined before the It that calls it -- shellspec's per-example run only
	# executes a Describe body's top-level statements up to the target It, so a
	# def placed AFTER an It that calls it is never reached (command not found).
	# `|| true`: grep -c exits 1 on a zero count (the expected outcome here),
	# and shellspec's `The result of` treats a nonzero exit as no captured value.
	pfb_no_more_per_host_rows() { grep -c '^203\.0\.113\.[0-9]*$' "${pfbdeny}BIGLIST_v4.txt" || true; }

	It 'collapses the /24 to a single CIDR row, tolerating trailing blank lines'
		alias='BIGLIST_v4'
		i=1
		while [ "$i" -le 254 ]; do
			printf '203.0.113.%s\n' "$i" >> "${pfbdeny}BIGLIST_v4.txt"
			i=$((i + 1))
		done
		# Hostile: trailing blank lines must not corrupt the collapse.
		printf '\n\n' >> "${pfbdeny}BIGLIST_v4.txt"

		When call process255
		The status should be success
		The contents of file "${pfbdeny}BIGLIST_v4.txt" should include '203.0.113.0/24'
		The result of "pfb_no_more_per_host_rows()" should equal 0
	End
End

Describe 'closingprocess() dedup-on Database Sanity check (masterfile vs deny-folder)'
	# shellcheck disable=SC2034  # consumed by the sourced closingprocess()
	setup() {
		work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/closesanity.XXXXXX")"
		pfborig="${work}/orig/"; pfbdeny="${work}/deny/"
		pfbpermit="${work}/permit/"; pfbmatch="${work}/match/"; pfbnative="${work}/native/"
		mkdir -p "$pfborig" "$pfbdeny" "$pfbpermit" "$pfbmatch" "$pfbnative"
		masterfile="${work}/master"; mastercat="${work}/mastercat"
		tempfile="${work}/t1"; errorlog="${work}/err.log"; now="now"
		ip_placeholder2='127.0.0.1'
		pathpfctl="${work}/pfctl"; printf '#!/bin/sh\n' > "$pathpfctl"; chmod +x "$pathpfctl"
		alias='on'
	}
	cleanup() { rm -rf "$work"; }
	BeforeAll 'pfb_source'
	Before 'setup'
	After 'cleanup'

	It 'reports PASSED when the masterfile count matches the deny-folder count'
		printf 'AAA 1.1.1.1\nBBB 2.2.2.2\n' > "$masterfile"
		printf '1.1.1.1\n2.2.2.2\n' > "$mastercat"
		printf '1.1.1.1\n' > "${pfbdeny}AAA.txt"
		printf '2.2.2.2\n' > "${pfbdeny}BBB.txt"

		When call closingprocess
		The status should be success
		The stdout should include 'Database Sanity check [  PASSED  ]'
	End

	It 'reports FAILED with both counts when the deny folder disagrees with the masterfile'
		printf 'AAA 1.1.1.1\nBBB 2.2.2.2\n' > "$masterfile"
		printf '1.1.1.1\n2.2.2.2\n' > "$mastercat"
		# BBB's member is missing from the deny folder -> counts diverge.
		printf '1.1.1.1\n' > "${pfbdeny}AAA.txt"

		When call closingprocess
		The status should be success
		The stdout should include 'Database Sanity check [  FAILED  ]'
		The stdout should include 'Masterfile Count    [ 2 ]'
		The stdout should include 'Deny folder Count   [ 1 ]'
	End
End

Describe 'dedup OFF: closingprocess() skips the sanity block and no cross-file dedup ever runs'
	# shellcheck disable=SC2034  # consumed by the sourced closingprocess()
	setup() {
		work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/dedupoff.XXXXXX")"
		pfbdeny="${work}/deny/"
		mkdir -p "$pfbdeny"
		tempfile="${work}/t1"; errorlog="${work}/err.log"; now="now"
		ip_placeholder2='127.0.0.1'
		pathpfctl="${work}/pfctl"; printf '#!/bin/sh\n' > "$pathpfctl"; chmod +x "$pathpfctl"
		alias='off'
		# Two feeds sharing an IP. With dedup off, no cross-feed dedup step runs
		# at all -- pin that BOTH keep their own copy, since nothing in the
		# shell pipeline ever cross-checks them.
		printf '198.51.100.7\n198.51.100.8\n' > "${pfbdeny}FeedX_v4.txt"
		printf '198.51.100.7\n198.51.100.9\n' > "${pfbdeny}FeedY_v4.txt"
	}
	cleanup() { rm -rf "$work"; }
	BeforeAll 'pfb_source'
	Before 'setup'
	After 'cleanup'

	It 'never runs the masterfile/mastercat sanity block, and leaves both feeds unmerged'
		When call closingprocess
		The status should be success
		The output should not include 'Database Sanity check'
		# Neither feed was touched -- the shared IP still lives in both.
		The contents of file "${pfbdeny}FeedX_v4.txt" should equal "$(printf '198.51.100.7\n198.51.100.8')"
		The contents of file "${pfbdeny}FeedY_v4.txt" should equal "$(printf '198.51.100.7\n198.51.100.9')"
	End
End
