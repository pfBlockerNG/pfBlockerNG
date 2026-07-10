#shellcheck shell=sh
# issue #1084: pins pfb_recompute() -- the single-pass batch v4/v6-Deny
# cross-feed dedup + v4 dMax/pMax reputation verb. Brand-new code (no
# pre-existing behaviour to pin); every example asserts real output, not
# mere execution. Fixtures reuse RFC 5737 (192.0.2.0/24, 198.51.100.0/24,
# 203.0.113.0/24) and RFC 3849 (2001:db8::/32) documentation ranges.

# grepcidr(1) v4 stand-in (reused verbatim from the ip_dedup oracle spec):
# `-vf <patternfile> <targetfile>` -> target lines whose address is NOT
# inside ANY pattern CIDR/host, via portable integer arithmetic.
make_grepcidr_stub() {
	cat > "$1" <<'EOF'
#!/bin/sh
awk -v patfile="$2" '
function ip2int(ip,   a) {
	split(ip, a, ".")
	return (a[1]*16777216) + (a[2]*65536) + (a[3]*256) + a[4]
}
function net(ipint, bits,   div) {
	div = 2 ^ (32 - bits)
	return int(ipint / div)
}
BEGIN {
	while ((getline line < patfile) > 0) {
		if (line == "") continue
		split(line, parts, "/")
		n++
		pbits[n] = (parts[2] == "" ? 32 : parts[2])
		pnet[n] = net(ip2int(parts[1]), pbits[n])
	}
	close(patfile)
}
{
	if ($0 == "") { print; next }
	split($0, tp, "/")
	matched = 0
	for (i = 1; i <= n; i++) {
		if (net(ip2int(tp[1]), pbits[i]) == pnet[i]) { matched = 1; break }
	}
	if (!matched) print
}
' "$3"
EOF
	chmod +x "$1"
}

# grepcidr(1) v6 stand-in: hex-group prefix containment on ALREADY-canonical
# (step 1's inet_ntop, lowercase, no leading zeros) fixture addresses --
# group-for-group STRING equality on both sides of the SAME expand()
# function needs no numeric hex parsing. Test-only simplification: CIDR
# prefixes must fall on a 16-bit (hex-group) boundary, true of every
# RFC 3849 documentation prefix this suite uses.
make_grepcidr_v6_stub() {
	cat > "$1" <<'EOF'
#!/bin/sh
awk -v patfile="$2" '
function expand(addr, arr,    dc, left, right, lparts, rparts, ln, rn, i, missing) {
	dc = index(addr, "::")
	if (dc > 0) {
		left = substr(addr, 1, dc - 1)
		right = substr(addr, dc + 2)
		ln = (left == "") ? 0 : split(left, lparts, ":")
		rn = (right == "") ? 0 : split(right, rparts, ":")
		missing = 8 - ln - rn
		for (i = 1; i <= ln; i++) arr[i] = lparts[i]
		for (i = 1; i <= missing; i++) arr[ln + i] = "0"
		for (i = 1; i <= rn; i++) arr[ln + missing + i] = rparts[i]
	} else {
		split(addr, lparts, ":")
		for (i = 1; i <= 8; i++) arr[i] = lparts[i]
	}
}
BEGIN {
	while ((getline line < patfile) > 0) {
		if (line == "") continue
		split(line, parts, "/")
		n++
		pbits[n] = (parts[2] == "" ? 128 : parts[2])
		delete parr
		expand(parts[1], parr)
		for (i = 1; i <= 8; i++) pgroup[n, i] = parr[i]
	}
	close(patfile)
}
{
	if ($0 == "") { print; next }
	split($0, tp, "/")
	delete tarr
	expand(tp[1], tarr)
	matched = 0
	for (k = 1; k <= n; k++) {
		ngroups = int(pbits[k] / 16)
		ok = 1
		for (i = 1; i <= ngroups; i++) {
			if (pgroup[k, i] != tarr[i]) { ok = 0; break }
		}
		if (ok) { matched = 1; break }
	}
	if (!matched) print
}
' "$3"
EOF
	chmod +x "$1"
}

Describe 'pfb_recompute() v4 cross-feed dedup (Stage A/B/D/E)'
	# shellcheck disable=SC2034  # consumed by the sourced pfb_recompute()
	setup() {
		work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/recdedup.XXXXXX")"
		snap="${work}/snap"; pfbdeny="${work}/deny/"; pfbmatch="${work}/match/"
		mkdir -p "$snap" "$pfbdeny" "$pfbmatch"
		tmpdir="${work}/tmp"; mkdir -p "$tmpdir"
		masterfile="${work}/master"; mastercat="${work}/mastercat"
		errorlog="${work}/err.log"
		ip_placeholder3='240.0.0'
		pathgrepcidr="${work}/grepcidr"; make_grepcidr_stub "$pathgrepcidr"
		memberlist="${work}/members"
		countsfile="${work}/counts"
	}
	cleanup() { rm -rf "$work"; }
	BeforeAll 'pfb_source'
	Before 'setup'
	After 'cleanup'

	pfb_counts_line() { grep "^FeedB_v4 " "$countsfile"; }

	It "keeps the first-priority feed's copy and prunes a later feed's exact repeat"
		printf '192.0.2.10\n192.0.2.11\n' > "${snap}/FeedA_v4.orig"
		printf '192.0.2.10\n192.0.2.12\n' > "${snap}/FeedB_v4.orig"
		printf '%s\n%s\n' "${snap}/FeedA_v4.orig" "${snap}/FeedB_v4.orig" > "$memberlist"

		When call silently pfb_recompute recompute v4 "$memberlist" "$countsfile" on off
		The status should be success
		The contents of file "${pfbdeny}FeedA_v4.txt" should equal "$(printf '192.0.2.10\n192.0.2.11')"
		The contents of file "${pfbdeny}FeedB_v4.txt" should equal '192.0.2.12'
		The contents of file "$masterfile" should include 'FeedA_v4 192.0.2.10'
		The contents of file "$masterfile" should not include 'FeedB_v4 192.0.2.10'
		The result of "pfb_counts_line()" should equal 'FeedB_v4 1'
	End

	It 'prunes via CIDR containment, not exact string match (a host inside an aggregated /24)'
		printf '192.0.2.0/24\n' > "${snap}/FeedA_v4.orig"
		printf '192.0.2.5\n198.51.100.9\n' > "${snap}/FeedB_v4.orig"
		printf '%s\n%s\n' "${snap}/FeedA_v4.orig" "${snap}/FeedB_v4.orig" > "$memberlist"

		When call silently pfb_recompute recompute v4 "$memberlist" "$countsfile" on off
		The status should be success
		The contents of file "${pfbdeny}FeedB_v4.txt" should equal '198.51.100.9'
	End

	It 'gives ownership to whichever alias is listed FIRST (Alpha before Beta)'
		printf '192.0.2.50\n' > "${snap}/Alpha_v4.orig"
		printf '192.0.2.50\n' > "${snap}/Beta_v4.orig"
		printf '%s\n%s\n' "${snap}/Alpha_v4.orig" "${snap}/Beta_v4.orig" > "$memberlist"
		When call silently pfb_recompute recompute v4 "$memberlist" "$countsfile" on off
		The status should be success
		The contents of file "${pfbdeny}Alpha_v4.txt" should equal '192.0.2.50'
		The contents of file "${pfbdeny}Beta_v4.txt" should equal ''
	End

	It 'flips ownership deterministically when the memberlist priority order is reversed (Beta before Alpha)'
		printf '192.0.2.50\n' > "${snap}/Alpha_v4.orig"
		printf '192.0.2.50\n' > "${snap}/Beta_v4.orig"
		printf '%s\n%s\n' "${snap}/Beta_v4.orig" "${snap}/Alpha_v4.orig" > "$memberlist"
		When call silently pfb_recompute recompute v4 "$memberlist" "$countsfile" on off
		The status should be success
		The contents of file "${pfbdeny}Beta_v4.txt" should equal '192.0.2.50'
		The contents of file "${pfbdeny}Alpha_v4.txt" should equal ''
	End

	It 'the higher-priority feed owns a shared IP when both are listed'
		printf '192.0.2.77\n' > "${snap}/High_v4.orig"
		printf '192.0.2.77\n' > "${snap}/Low_v4.orig"
		printf '%s\n%s\n' "${snap}/High_v4.orig" "${snap}/Low_v4.orig" > "$memberlist"
		When call silently pfb_recompute recompute v4 "$memberlist" "$countsfile" on off
		The status should be success
		The contents of file "${pfbdeny}Low_v4.txt" should equal ''
		The contents of file "$masterfile" should include 'High_v4 192.0.2.77'
	End

	It 'gives an IP back to the next-priority owner once the higher-priority feed is removed from the memberlist'
		# Pre-existing state as the prior pass (High_v4 owning the IP) left it.
		printf 'High_v4 192.0.2.77\n' > "$masterfile"
		: > "${pfbdeny}Low_v4.txt"
		printf '192.0.2.77\n' > "${snap}/Low_v4.orig"
		# High_v4 removed from the memberlist entirely (a genuine feed removal).
		printf '%s\n' "${snap}/Low_v4.orig" > "$memberlist"

		When call silently pfb_recompute recompute v4 "$memberlist" "$countsfile" on off
		The status should be success
		The contents of file "${pfbdeny}Low_v4.txt" should equal '192.0.2.77'
		The contents of file "$masterfile" should include 'Low_v4 192.0.2.77'
		The contents of file "$masterfile" should not include 'High_v4'
	End

	It 'leaves overlaps in place, still emits per-alias files and counts, and never writes masterfile (dedup=off)'
		printf 'MASTER_v4 9.9.9.9\n' > "$masterfile"
		printf '198.51.100.7\n198.51.100.8\n' > "${snap}/FeedX_v4.orig"
		printf '198.51.100.7\n198.51.100.9\n' > "${snap}/FeedY_v4.orig"
		printf '%s\n%s\n' "${snap}/FeedX_v4.orig" "${snap}/FeedY_v4.orig" > "$memberlist"

		When call silently pfb_recompute recompute v4 "$memberlist" "$countsfile" off off
		The status should be success
		The contents of file "${pfbdeny}FeedX_v4.txt" should equal "$(printf '198.51.100.7\n198.51.100.8')"
		The contents of file "${pfbdeny}FeedY_v4.txt" should equal "$(printf '198.51.100.7\n198.51.100.9')"
		The contents of file "$countsfile" should include 'FeedX_v4 2'
		The contents of file "$countsfile" should include 'FeedY_v4 2'
		# dedup=off: masterfile is never touched by this pass.
		The contents of file "$masterfile" should equal 'MASTER_v4 9.9.9.9'
	End

	It 'derives mastercat as exactly column 2 of masterfile'
		printf '203.0.113.1\n203.0.113.2\n' > "${snap}/CatCheck_v4.orig"
		printf '%s\n' "${snap}/CatCheck_v4.orig" > "$memberlist"
		When call silently pfb_recompute recompute v4 "$memberlist" "$countsfile" on off
		The status should be success
		The contents of file "$mastercat" should equal "$(printf '203.0.113.1\n203.0.113.2')"
	End

	It 'a single-feed class is a plain copy (no grepcidr call needed) and still gets counted'
		: > "${work}/grepcidr.never-called"
		printf '#!/bin/sh\nrm -f "%s/grepcidr.never-called"\n' "$work" > "$pathgrepcidr"
		chmod +x "$pathgrepcidr"
		printf '203.0.113.30\n203.0.113.31\n' > "${snap}/Solo_v4.orig"
		printf '%s\n' "${snap}/Solo_v4.orig" > "$memberlist"

		When call silently pfb_recompute recompute v4 "$memberlist" "$countsfile" on off
		The status should be success
		The path "${work}/grepcidr.never-called" should be exist
		The contents of file "${pfbdeny}Solo_v4.txt" should equal "$(printf '203.0.113.30\n203.0.113.31')"
		The contents of file "$countsfile" should include 'Solo_v4 2'
	End

	It 'an alias whose snapshot is empty ends up with an empty (present, not missing) deny file'
		: > "${snap}/Empty_v4.orig"
		printf '%s\n' "${snap}/Empty_v4.orig" > "$memberlist"
		When call silently pfb_recompute recompute v4 "$memberlist" "$countsfile" on off
		The status should be success
		The path "${pfbdeny}Empty_v4.txt" should be exist
		The contents of file "${pfbdeny}Empty_v4.txt" should equal ''
		The contents of file "$countsfile" should include 'Empty_v4 0'
	End

	It 'tolerates a trailing blank line in a snapshot without emitting a blank member row'
		printf '203.0.113.40\n203.0.113.41\n\n' > "${snap}/Blank_v4.orig"
		printf '%s\n' "${snap}/Blank_v4.orig" > "$memberlist"
		When call silently pfb_recompute recompute v4 "$memberlist" "$countsfile" on off
		The status should be success
		The contents of file "${pfbdeny}Blank_v4.txt" should equal "$(printf '203.0.113.40\n203.0.113.41')"
		The contents of file "$countsfile" should include 'Blank_v4 2'
	End
End

Describe 'pfb_recompute() suffix-sibling aliases (issue #714/#730 class, family-scoped rebuild)'
	# shellcheck disable=SC2034  # consumed by the sourced pfb_recompute()
	setup() {
		work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/recsuffix.XXXXXX")"
		snap="${work}/snap"; pfbdeny="${work}/deny/"; pfbmatch="${work}/match/"
		mkdir -p "$snap" "$pfbdeny" "$pfbmatch"
		tmpdir="${work}/tmp"; mkdir -p "$tmpdir"
		masterfile="${work}/master"; mastercat="${work}/mastercat"
		errorlog="${work}/err.log"
		ip_placeholder3='240.0.0'
		pathgrepcidr="${work}/grepcidr"; make_grepcidr_stub "$pathgrepcidr"
		memberlist="${work}/members"
		countsfile="${work}/counts"
	}
	cleanup() { rm -rf "$work"; }
	BeforeAll 'pfb_source'
	Before 'setup'
	After 'cleanup'

	It 'regenerates both Ads_v4 and BadAds_v4 without cross-contamination when both are in the memberlist'
		printf '10.0.0.1\n' > "${snap}/Ads_v4.orig"
		printf '10.0.0.2\n' > "${snap}/BadAds_v4.orig"
		printf '%s\n%s\n' "${snap}/Ads_v4.orig" "${snap}/BadAds_v4.orig" > "$memberlist"

		When call silently pfb_recompute recompute v4 "$memberlist" "$countsfile" on off
		The status should be success
		The contents of file "${pfbdeny}Ads_v4.txt" should equal '10.0.0.1'
		The contents of file "${pfbdeny}BadAds_v4.txt" should equal '10.0.0.2'
		The contents of file "$masterfile" should include 'Ads_v4 10.0.0.1'
		The contents of file "$masterfile" should include 'BadAds_v4 10.0.0.2'
	End

	It 'strips a removed suffix-sibling (BadAds_v4) from masterfile without touching Ads_v4, on a rerun that drops it'
		printf '10.0.0.1\n' > "${snap}/Ads_v4.orig"
		# Seed BadAds_v4 into the live masterfile as if a prior pass wrote it,
		# plus a row whose alias CONTAINS "_v4" but does not END with it (the
		# family strip is an endswith check, never a substring match).
		printf 'Ads_v4 stale\nBadAds_v4 20.0.0.0/24\nWeird_v4x 9.9.9.9\n' > "$masterfile"

		printf '%s\n' "${snap}/Ads_v4.orig" > "$memberlist"
		When call silently pfb_recompute recompute v4 "$memberlist" "$countsfile" on off
		The status should be success
		The contents of file "$masterfile" should include 'Ads_v4 10.0.0.1'
		The contents of file "$masterfile" should not include 'BadAds_v4'
		The contents of file "$masterfile" should include 'Weird_v4x 9.9.9.9'
	End
End

Describe 'pfb_recompute() v6 dedup (same Stage A/B/D/E loop, per family)'
	# shellcheck disable=SC2034  # consumed by the sourced pfb_recompute()
	setup() {
		work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/recv6.XXXXXX")"
		snap="${work}/snap"; pfbdeny="${work}/deny/"; pfbmatch="${work}/match/"
		mkdir -p "$snap" "$pfbdeny" "$pfbmatch"
		tmpdir="${work}/tmp"; mkdir -p "$tmpdir"
		masterfile="${work}/master"; mastercat="${work}/mastercat"
		errorlog="${work}/err.log"
		ip_placeholder3='240.0.0'
		pathgrepcidr="${work}/grepcidr"; make_grepcidr_v6_stub "$pathgrepcidr"
		memberlist="${work}/members"
		countsfile="${work}/counts"
	}
	cleanup() { rm -rf "$work"; }
	BeforeAll 'pfb_source'
	Before 'setup'
	After 'cleanup'

	It 'dedups an exact cross-feed repeat and prunes via CIDR containment'
		printf '2001:db8::/32\n' > "${snap}/SixA_v6.orig"
		printf '2001:db8:dead:beef::1\nfd12:3456::1\n' > "${snap}/SixB_v6.orig"
		printf '%s\n%s\n' "${snap}/SixA_v6.orig" "${snap}/SixB_v6.orig" > "$memberlist"

		When call silently pfb_recompute recompute v6 "$memberlist" "$countsfile" on off
		The status should be success
		The contents of file "${pfbdeny}SixB_v6.txt" should equal 'fd12:3456::1'
		The contents of file "$masterfile" should include 'SixA_v6 2001:db8::/32'
	End

	It 'keeps v4 and v6 masterfile rows separate: a v6 recompute never touches v4 family rows and vice versa'
		printf 'Legacy_v4 1.2.3.4\n' > "$masterfile"
		printf 'fd99::5\n' > "${snap}/Six_v6.orig"
		printf '%s\n' "${snap}/Six_v6.orig" > "$memberlist"

		When call silently pfb_recompute recompute v6 "$memberlist" "$countsfile" on off
		The status should be success
		The contents of file "$masterfile" should include 'Legacy_v4 1.2.3.4'
		The contents of file "$masterfile" should include 'Six_v6 fd99::5'
	End
End

Describe 'pfb_recompute() dMax block-mode (class-wide offender collapse, priority-owned)'
	# shellcheck disable=SC2034  # consumed by the sourced pfb_recompute()
	setup() {
		work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/recdmaxblock.XXXXXX")"
		snap="${work}/snap"; pfbdeny="${work}/deny/"; pfbmatch="${work}/match/"
		mkdir -p "$snap" "$pfbdeny" "$pfbmatch"
		tmpdir="${work}/tmp"; mkdir -p "$tmpdir"
		masterfile="${work}/master"; mastercat="${work}/mastercat"
		errorlog="${work}/err.log"
		ip_placeholder3='240.0.0'
		pathgrepcidr="${work}/grepcidr"; make_grepcidr_stub "$pathgrepcidr"
		pathgeoip="${work}/mmdblookup"; pathgeoipdat="${work}/geo.mmdb"; touch "$pathgeoipdat"
		make_geoip_stub "$pathgeoip" 'Could not find an entry for this IP address'
		memberlist="${work}/members"
		countsfile="${work}/counts"
	}
	cleanup() { rm -rf "$work"; }
	BeforeAll 'pfb_source'
	Before 'setup'
	After 'cleanup'

	It 'collapses a class-wide /24 offender to ONE row owned by the HIGHEST-PRIORITY member alias (not glob/alphabetical order)'
		# 192.0.2.* appears 3x total (max=2 -> offender). ZZZ_v4 is listed
		# FIRST (highest priority) though AAA_v4 sorts first alphabetically --
		# proves attribution follows loop order, not glob order (the
		# documented delta from today's incidental first-in-glob behaviour).
		printf '192.0.2.10\n192.0.2.11\n' > "${snap}/AAA_v4.orig"
		printf '192.0.2.12\n' > "${snap}/ZZZ_v4.orig"
		printf '198.51.100.50\n' > "${snap}/OTHER_v4.orig"
		printf '%s\n%s\n%s\n' "${snap}/ZZZ_v4.orig" "${snap}/AAA_v4.orig" "${snap}/OTHER_v4.orig" > "$memberlist"

		When call silently pfb_recompute recompute v4 "$memberlist" "$countsfile" on dmax 2 US off block
		The status should be success
		The contents of file "${pfbdeny}AAA_v4.txt" should not include '192.0.2.10'
		The contents of file "${pfbdeny}AAA_v4.txt" should not include '192.0.2.0/24'
		The contents of file "${pfbdeny}ZZZ_v4.txt" should not include '192.0.2.12'
		The contents of file "${pfbdeny}ZZZ_v4.txt" should equal '192.0.2.0/24'
		The contents of file "${pfbdeny}OTHER_v4.txt" should equal '198.51.100.50'
		The contents of file "$masterfile" should include 'ZZZ_v4 192.0.2.0/24'
		The contents of file "$masterfile" should not include 'AAA_v4 192.0.2.10'
		The contents of file "$masterfile" should include 'OTHER_v4 198.51.100.50'
	End

	It 'excludes the ip_placeholder prefix from offender detection'
		i=1
		while [ "$i" -le 5 ]; do
			printf '240.0.0.0\n' > "${snap}/PH${i}_v4.orig"
			i=$((i + 1))
		done
		set --
		i=1
		while [ "$i" -le 5 ]; do
			set -- "$@" "${snap}/PH${i}_v4.orig"
			i=$((i + 1))
		done
		printf '%s\n' "$@" > "$memberlist"

		When call silently pfb_recompute recompute v4 "$memberlist" "$countsfile" on dmax 2 US off block
		The status should be success
		The contents of file "${pfbdeny}PH1_v4.txt" should equal '240.0.0.0'
		The contents of file "$countsfile" should include 'PH1_v4 1'
	End
End

Describe 'pfb_recompute() dMax match-mode + GeoIP-unavailable bail + pMax'
	# shellcheck disable=SC2034  # consumed by the sourced pfb_recompute()
	setup() {
		work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/recdmaxmatch.XXXXXX")"
		snap="${work}/snap"; pfbdeny="${work}/deny/"; pfbmatch="${work}/match/"
		mkdir -p "$snap" "$pfbdeny" "$pfbmatch"
		tmpdir="${work}/tmp"; mkdir -p "$tmpdir"
		masterfile="${work}/master"; mastercat="${work}/mastercat"
		errorlog="${work}/err.log"
		ip_placeholder3='240.0.0'
		pathgrepcidr="${work}/grepcidr"; make_grepcidr_stub "$pathgrepcidr"
		pathgeoip="${work}/mmdblookup"; pathgeoipdat="${work}/geo.mmdb"; touch "$pathgeoipdat"
		memberlist="${work}/members"
		countsfile="${work}/counts"
		matchdedup='matchdedup_v4.txt'
	}
	cleanup() { rm -rf "$work"; }
	BeforeAll 'pfb_source'
	Before 'setup'
	After 'cleanup'

	It 'ccblack=match: leaves the stream untouched and writes match<alias>.txt (cidr + negated members)'
		make_geoip_stub "$pathgeoip" 'Could not find an entry for this IP address'
		printf '192.0.2.20\n192.0.2.21\n' > "${snap}/ONE_v4.orig"
		printf '%s\n' "${snap}/ONE_v4.orig" > "$memberlist"

		When call silently pfb_recompute recompute v4 "$memberlist" "$countsfile" on dmax 1 US off match
		The status should be success
		The contents of file "${pfbdeny}ONE_v4.txt" should equal "$(printf '192.0.2.20\n192.0.2.21')"
		The contents of file "${pfbmatch}matchONE_v4.txt" should include '192.0.2.0/24'
		The contents of file "${pfbmatch}matchONE_v4.txt" should include '!192.0.2.20'
		The contents of file "${pfbmatch}matchONE_v4.txt" should include '!192.0.2.21'
	End

	It "ccwhite=match on a cc-list hit: writes the consolidated matchdedup file, leaves the stream untouched"
		make_geoip_stub "$pathgeoip" 'xx iso_code: "US" xx'
		printf '198.51.100.20\n198.51.100.21\n' > "${snap}/EX_v4.orig"
		printf '%s\n' "${snap}/EX_v4.orig" > "$memberlist"

		When call silently pfb_recompute recompute v4 "$memberlist" "$countsfile" on dmax 1 US match off
		The status should be success
		The contents of file "${pfbdeny}EX_v4.txt" should equal "$(printf '198.51.100.20\n198.51.100.21')"
		The contents of file "${pfbmatch}${matchdedup}" should include '198.51.100.0/24'
		The contents of file "${pfbmatch}${matchdedup}" should include '!198.51.100.20'
	End

	It "ccblack=match (not ccwhite) on a cc-list hit: logs nowhere -- no matchdedup file is written (today's asymmetric gate)"
		make_geoip_stub "$pathgeoip" 'xx iso_code: "US" xx'
		printf '198.51.100.30\n198.51.100.31\n' > "${snap}/EX2_v4.orig"
		printf '%s\n' "${snap}/EX2_v4.orig" > "$memberlist"

		When call silently pfb_recompute recompute v4 "$memberlist" "$countsfile" on dmax 1 US off match
		The status should be success
		The path "${pfbmatch}${matchdedup}" should not be exist
	End

	It 'GeoIP unavailable: dMax bails like reputation_depends, the pass still completes with no reputation applied'
		rm -f "$pathgeoip" "$pathgeoipdat"
		printf '192.0.2.60\n192.0.2.61\n192.0.2.62\n' > "${snap}/NOBAIL_v4.orig"
		printf '%s\n' "${snap}/NOBAIL_v4.orig" > "$memberlist"

		When call silently pfb_recompute recompute v4 "$memberlist" "$countsfile" on dmax 2 US off block
		The status should be success
		The contents of file "${pfbdeny}NOBAIL_v4.txt" should equal "$(printf '192.0.2.60\n192.0.2.61\n192.0.2.62')"
		The contents of file "$countsfile" should include 'NOBAIL_v4 3'
	End

	It 'pMax collapses the offending /24 with no GeoIP dependency (block-only, no match output)'
		rm -f "$pathgeoip" "$pathgeoipdat"
		printf '198.51.100.1\n198.51.100.2\n198.51.100.3\n' > "${snap}/PALIAS_v4.orig"
		printf '%s\n' "${snap}/PALIAS_v4.orig" > "$memberlist"

		When call silently pfb_recompute recompute v4 "$memberlist" "$countsfile" on pmax 2
		The status should be success
		The contents of file "${pfbdeny}PALIAS_v4.txt" should equal '198.51.100.0/24'
		The contents of file "$masterfile" should include 'PALIAS_v4 198.51.100.0/24'
		The path "${pfbmatch}matchPALIAS_v4.txt" should not be exist
	End
End

Describe 'pfb_recompute() hostile inputs'
	# shellcheck disable=SC2034  # consumed by the sourced pfb_recompute()
	setup() {
		work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/rechostile.XXXXXX")"
		snap="${work}/snap"; pfbdeny="${work}/deny/"; pfbmatch="${work}/match/"
		mkdir -p "$snap" "$pfbdeny" "$pfbmatch"
		tmpdir="${work}/tmp"; mkdir -p "$tmpdir"
		masterfile="${work}/master"; mastercat="${work}/mastercat"
		errorlog="${work}/err.log"
		ip_placeholder3='240.0.0'
		pathgrepcidr="${work}/grepcidr"; make_grepcidr_stub "$pathgrepcidr"
		pathgeoip="${work}/mmdblookup"; pathgeoipdat="${work}/geo.mmdb"; touch "$pathgeoipdat"
		memberlist="${work}/members"
		countsfile="${work}/counts"
	}
	cleanup() { rm -rf "$work"; }
	BeforeAll 'pfb_source'
	Before 'setup'
	After 'cleanup'

	It 'counts a CIDR row and a bare member of the same /24 in ONE snapshot toward the same offender window'
		make_geoip_stub "$pathgeoip" 'Could not find an entry for this IP address'
		printf '192.0.2.0/24\n192.0.2.55\n' > "${snap}/MIX_v4.orig"
		printf '%s\n' "${snap}/MIX_v4.orig" > "$memberlist"

		When call silently pfb_recompute recompute v4 "$memberlist" "$countsfile" on dmax 1 US off block
		The status should be success
		The contents of file "${pfbdeny}MIX_v4.txt" should equal '192.0.2.0/24'
	End

	It 'merges a snapshot whose rows are NOT numerically sorted just as correctly as a sorted one (defensive internal sort)'
		printf '192.0.2.0/24\n' > "${snap}/Owner_v4.orig"
		# Scrambled order on purpose -- pfb_recompute sorts internally, never
		# trusting caller ordering for the class-wide merge invariant.
		printf '198.51.100.9\n192.0.2.99\n192.0.2.5\n' > "${snap}/Scrambled_v4.orig"
		printf '%s\n%s\n' "${snap}/Owner_v4.orig" "${snap}/Scrambled_v4.orig" > "$memberlist"

		When call silently pfb_recompute recompute v4 "$memberlist" "$countsfile" on off
		The status should be success
		The contents of file "${pfbdeny}Scrambled_v4.txt" should equal '198.51.100.9'
	End

	It 'accepts an alias basename right at the \w boundary (bare underscore-terminated name)'
		printf '203.0.113.90\n' > "${snap}/A_.orig"
		printf '%s\n' "${snap}/A_.orig" > "$memberlist"
		When call silently pfb_recompute recompute v4 "$memberlist" "$countsfile" on off
		The status should be success
		The contents of file "${pfbdeny}A_.txt" should equal '203.0.113.90'
	End

	It 'aborts the WHOLE pass on grepcidr rc>=2, leaving pre-existing live artifacts byte-identical and no .new debris'
		printf 'A_v4 5.5.5.5\nB_v4 6.6.6.6\n' > "$masterfile"
		printf '5.5.5.5\n' > "${pfbdeny}A_v4.txt"
		printf '6.6.6.6\n' > "${pfbdeny}B_v4.txt"
		printf '5.5.5.5\n' > "${snap}/A_v4.orig"
		printf '9.9.9.9\n' > "${snap}/B_v4.orig"
		printf '%s\n%s\n' "${snap}/A_v4.orig" "${snap}/B_v4.orig" > "$memberlist"
		printf '#!/bin/sh\nexit 2\n' > "$pathgrepcidr"
		chmod +x "$pathgrepcidr"

		When call silently pfb_recompute recompute v4 "$memberlist" "$countsfile" on off
		The status should be failure
		The contents of file "${pfbdeny}A_v4.txt" should equal '5.5.5.5'
		The contents of file "${pfbdeny}B_v4.txt" should equal '6.6.6.6'
		The contents of file "$masterfile" should equal "$(printf 'A_v4 5.5.5.5\nB_v4 6.6.6.6')"
		The path "${pfbdeny}A_v4.txt.new" should not be exist
		The path "${pfbdeny}B_v4.txt.new" should not be exist
		The path "${masterfile}.new" should not be exist
	End

	It 'aborts cleanly (log + .new cleanup, live files untouched) when directory debris blocks a .txt.new staging path'
		printf '1.1.1.1\n' > "${pfbdeny}AAA_v4.txt"
		printf '1.1.1.1\n' > "${snap}/AAA_v4.orig"
		printf '2.2.2.2\n' > "${snap}/ZZZ_v4.orig"
		# A crash-leftover DIRECTORY at MMM_v4's .txt.new path must abort the
		# pass through the cleanup path -- never exit the whole shell (POSIX
		# special-builtin redirection abort on ash/dash) and never limp on.
		printf '3.3.3.3\n' > "${snap}/MMM_v4.orig"
		printf '%s\n%s\n%s\n' "${snap}/AAA_v4.orig" "${snap}/MMM_v4.orig" "${snap}/ZZZ_v4.orig" > "$memberlist"
		mkdir -p "${pfbdeny}MMM_v4.txt.new"

		When call silently pfb_recompute recompute v4 "$memberlist" "$countsfile" on off
		The status should be failure
		The contents of file "${errorlog}" should include 'cannot create'
		The path "${pfbdeny}AAA_v4.txt.new" should not be exist
		The path "${pfbdeny}ZZZ_v4.txt.new" should not be exist
		The contents of file "${pfbdeny}AAA_v4.txt" should equal '1.1.1.1'
		The path "${countsfile}" should not be exist
	End
End

Describe 'pfb_recompute() mastercat consistency + empty-pass edges'
	# shellcheck disable=SC2034  # consumed by the sourced pfb_recompute()
	setup() {
		work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/reccat.XXXXXX")"
		snap="${work}/snap"; pfbdeny="${work}/deny/"; pfbmatch="${work}/match/"
		mkdir -p "$snap" "$pfbdeny" "$pfbmatch"
		tmpdir="${work}/tmp"; mkdir -p "$tmpdir"
		masterfile="${work}/master"; mastercat="${work}/mastercat"
		errorlog="${work}/err.log"
		ip_placeholder3='240.0.0'
		pathgrepcidr="${work}/grepcidr"; make_grepcidr_stub "$pathgrepcidr"
		pathgeoip="${work}/mmdblookup"; pathgeoipdat="${work}/geo.mmdb"; touch "$pathgeoipdat"
		make_geoip_stub "$pathgeoip" 'Could not find an entry for this IP address'
		memberlist="${work}/members"
		countsfile="${work}/counts"
	}
	cleanup() { rm -rf "$work"; }
	BeforeAll 'pfb_source'
	Before 'setup'
	After 'cleanup'

	It 'keeps mastercat equal to masterfile column 2 after back-to-back family passes'
		printf '192.0.2.10\n' > "${snap}/Four_v4.orig"
		printf '%s\n' "${snap}/Four_v4.orig" > "$memberlist"
		pfb_recompute recompute v4 "$memberlist" "$countsfile" on off >/dev/null 2>&1
		printf 'fd99::5\n' > "${snap}/Six_v6.orig"
		printf '%s\n' "${snap}/Six_v6.orig" > "$memberlist"
		When call silently pfb_recompute recompute v6 "$memberlist" "$countsfile" on off
		The status should be success
		The contents of file "$masterfile" should include 'Four_v4 192.0.2.10'
		The contents of file "$masterfile" should include 'Six_v6 fd99::5'
		The contents of file "$mastercat" should include '192.0.2.10'
		The contents of file "$mastercat" should include 'fd99::5'
	End

	It 'swaps a consistent empty mastercat when a dedup=on pass emits zero rows'
		printf 'Stale_v4 198.51.100.9\n' > "$masterfile"
		printf '198.51.100.9\n' > "$mastercat"
		: > "${snap}/Empty_v4.orig"
		printf '%s\n' "${snap}/Empty_v4.orig" > "$memberlist"
		When call silently pfb_recompute recompute v4 "$memberlist" "$countsfile" on off
		The status should be success
		The contents of file "$masterfile" should equal ''
		The contents of file "$mastercat" should equal ''
	End

	It 'completes an all-empty memberlist under repmode=dmax exactly like repmode=off'
		: > "${snap}/Empty_v4.orig"
		printf '%s\n' "${snap}/Empty_v4.orig" > "$memberlist"
		When call silently pfb_recompute recompute v4 "$memberlist" "$countsfile" on dmax 2 US off block
		The status should be success
		The path "${pfbdeny}Empty_v4.txt" should be exist
		The contents of file "$countsfile" should include 'Empty_v4 0'
	End
End
