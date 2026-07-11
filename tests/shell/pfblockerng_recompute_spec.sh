#shellcheck shell=sh
# issue #1084: pins pfb_recompute() -- the single-pass batch v4/v6-Deny
# cross-feed dedup + v4 dMax/pMax reputation verb. Brand-new code (no
# pre-existing behaviour to pin); every example asserts real output, not
# mere execution. Fixtures reuse RFC 5737 (192.0.2.0/24, 198.51.100.0/24,
# 203.0.113.0/24) and RFC 3849 (2001:db8::/32) documentation ranges.

# grepcidr(1) v4 stand-in (reused verbatim from the ip_dedup oracle spec):
# `-vf <patternfile> <targetfile>` -> target lines whose address is NOT
# inside ANY pattern CIDR/host, via portable integer arithmetic. Fidelity
# probed against the real binary: a pattern file with ZERO parseable
# patterns (blank lines only, or empty) prints NOTHING and exits 1 --
# never "no patterns matched, so keep every line" -- so `n == 0` short-
# circuits to that outcome before the per-line filter ever runs.
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
n == 0 { next }
{
	if ($0 == "") { print; next }
	split($0, tp, "/")
	matched = 0
	for (i = 1; i <= n; i++) {
		if (net(ip2int(tp[1]), pbits[i]) == pnet[i]) { matched = 1; break }
	}
	if (!matched) print
}
END { if (n == 0) exit 1 }
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

	It 'a single-feed class is a plain copy (no grepcidr call needed), dedups an internal repeat, and still gets counted'
		: > "${work}/grepcidr.never-called"
		printf '#!/bin/sh\nrm -f "%s/grepcidr.never-called"\n' "$work" > "$pathgrepcidr"
		chmod +x "$pathgrepcidr"
		# issue #1084 review: an internal repeat (203.0.113.30 twice) discriminates the
		# emit's plain `sort` from `sort -u` -- the cp -f short-circuit path never runs
		# grepcidr, so only the emit's own dedup can prune this repeat.
		printf '203.0.113.30\n203.0.113.31\n203.0.113.30\n' > "${snap}/Solo_v4.orig"
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

	It 'tolerates a trailing blank line in a snapshot without emitting a blank member row, or leaking it into the cumulative stream for a later feed (issue #1084 review)'
		printf '203.0.113.40\n203.0.113.41\n\n' > "${snap}/Blank_v4.orig"
		printf '198.51.100.60\n' > "${snap}/Later_v4.orig"
		printf '%s\n%s\n' "${snap}/Blank_v4.orig" "${snap}/Later_v4.orig" > "$memberlist"
		When call silently pfb_recompute recompute v4 "$memberlist" "$countsfile" on off
		The status should be success
		The contents of file "${pfbdeny}Blank_v4.txt" should equal "$(printf '203.0.113.40\n203.0.113.41')"
		The contents of file "$countsfile" should include 'Blank_v4 2'
		The contents of file "${pfbdeny}Later_v4.txt" should equal '198.51.100.60'
	End

	It 'never lets a blank-line-only high-priority snapshot poison the cumulative dedup stream into eating a disjoint lower feed (issue #1084 review)'
		printf '\n' > "${snap}/OnlyBlank_v4.orig"
		printf '198.51.100.70\n' > "${snap}/Disjoint_v4.orig"
		printf '%s\n%s\n' "${snap}/OnlyBlank_v4.orig" "${snap}/Disjoint_v4.orig" > "$memberlist"
		When call silently pfb_recompute recompute v4 "$memberlist" "$countsfile" on off
		The status should be success
		The contents of file "${pfbdeny}OnlyBlank_v4.txt" should equal ''
		The contents of file "${pfbdeny}Disjoint_v4.txt" should equal '198.51.100.70'
		The contents of file "$countsfile" should include 'Disjoint_v4 1'
	End

	It 'dedups an internal repeat within a single feed snapshot (within-feed dupes, issue #1084 review)'
		printf '192.0.2.9\n192.0.2.9\n192.0.2.10\n' > "${snap}/DupFeed_v4.orig"
		printf '%s\n' "${snap}/DupFeed_v4.orig" > "$memberlist"

		When call silently pfb_recompute recompute v4 "$memberlist" "$countsfile" on off
		The status should be success
		The contents of file "${pfbdeny}DupFeed_v4.txt" should equal "$(printf '192.0.2.10\n192.0.2.9')"
		The contents of file "$masterfile" should equal "$(printf 'DupFeed_v4 192.0.2.10\nDupFeed_v4 192.0.2.9')"
		The contents of file "$countsfile" should include 'DupFeed_v4 2'
	End

	It 'self-heals from the live deny file when a memberlist-listed snapshot is missing on disk (dangling snapshot, issue #1084 review)'
		printf '192.0.2.200\n' > "${pfbdeny}Ghost_v4.txt"
		# Memberlist names a snapshot that was never written / already removed from disk --
		# the corresponding live deny file still exists and still serves traffic.
		printf '%s\n' "${snap}/Ghost_v4.orig" > "$memberlist"
		printf 'Ghost_v4 192.0.2.200\n' > "$masterfile"

		When call silently pfb_recompute recompute v4 "$memberlist" "$countsfile" on off
		The status should be success
		The contents of file "${pfbdeny}Ghost_v4.txt" should equal '192.0.2.200'
		The contents of file "$masterfile" should include 'Ghost_v4 192.0.2.200'
		The contents of file "$countsfile" should include 'Ghost_v4 1'
		The contents of file "${errorlog}" should include 'Ghost_v4'
	End

	It 'still skips (with a logged warning, never silent) an alias with no snapshot AND no live deny file'
		printf '%s\n' "${snap}/Vanished_v4.orig" > "$memberlist"
		printf 'Vanished_v4 9.9.9.9\n' > "$masterfile"

		When call silently pfb_recompute recompute v4 "$memberlist" "$countsfile" on off
		The status should be success
		The contents of file "$masterfile" should not include 'Vanished_v4'
		The contents of file "${errorlog}" should include 'Vanished_v4'
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

	It 'ccwhite passed uppercase (MATCH) still fires the exempt-match path on a cc-list hit (issue #1084 review, case-fold parity with the legacy verb init)'
		make_geoip_stub "$pathgeoip" 'xx iso_code: "US" xx'
		printf '198.51.100.40\n198.51.100.41\n' > "${snap}/UP_v4.orig"
		printf '%s\n' "${snap}/UP_v4.orig" > "$memberlist"

		When call silently pfb_recompute recompute v4 "$memberlist" "$countsfile" on dmax 1 US MATCH off
		The status should be success
		The contents of file "${pfbmatch}${matchdedup}" should include '198.51.100.0/24'
		The contents of file "${pfbmatch}${matchdedup}" should include '!198.51.100.40'
	End

	It 'ccblack=match emits match<alias>.txt for EVERY member alias sharing an offender /24 (issue #1084: multi-alias delta from the legacy single-owner write)'
		make_geoip_stub "$pathgeoip" 'Could not find an entry for this IP address'
		printf '192.0.2.30\n' > "${snap}/First_v4.orig"
		printf '192.0.2.31\n192.0.2.32\n' > "${snap}/Second_v4.orig"
		printf '%s\n%s\n' "${snap}/First_v4.orig" "${snap}/Second_v4.orig" > "$memberlist"

		When call silently pfb_recompute recompute v4 "$memberlist" "$countsfile" on dmax 2 US off match
		The status should be success
		The contents of file "${pfbmatch}matchFirst_v4.txt" should include '192.0.2.0/24'
		The contents of file "${pfbmatch}matchFirst_v4.txt" should include '!192.0.2.30'
		The contents of file "${pfbmatch}matchSecond_v4.txt" should include '192.0.2.0/24'
		The contents of file "${pfbmatch}matchSecond_v4.txt" should include '!192.0.2.31'
		The contents of file "${pfbmatch}matchSecond_v4.txt" should include '!192.0.2.32'
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
	# chmod-restore first: a permission-denial example below may leave $work
	# read-only, which would make a bare rm -rf silently strand debris.
	cleanup() { chmod -R u+rwx "$work" 2>/dev/null; rm -rf "$work"; }
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

	It 'aborts cleanly (log + .new cleanup, live files untouched) when a Stage-A snapshot copy fails (source unreadable, issue #1084 review)'
		Skip if 'root bypasses file permissions' [ "$(id -u)" -eq 0 ]
		printf '1.1.1.1\n' > "${pfbdeny}Blocked_v4.txt"
		printf '9.9.9.9\n' > "${snap}/Blocked_v4.orig"
		chmod 000 "${snap}/Blocked_v4.orig"
		printf '%s\n' "${snap}/Blocked_v4.orig" > "$memberlist"

		When call silently pfb_recompute recompute v4 "$memberlist" "$countsfile" off off
		The status should be failure
		The contents of file "${errorlog}" should include 'could not copy snapshot'
		The contents of file "${pfbdeny}Blocked_v4.txt" should equal '1.1.1.1'
		The path "${pfbdeny}Blocked_v4.txt.new" should not be exist
	End

	It 'aborts the masterfile-strip pass cleanly (no masterfile.new debris) when it fails mid-write (issue #1084 review)'
		Skip if 'root bypasses file permissions' [ "$(id -u)" -eq 0 ]
		printf 'Old_v4 9.9.9.9\n' > "$masterfile"
		# The shell's own output redirect creates (empty) masterfile.new BEFORE
		# awk ever runs -- an unreadable masterfile then fails awk's OWN open,
		# leaving that empty file as debris unless the abort path cleans it up.
		chmod 000 "$masterfile"
		printf '192.0.2.5\n' > "${snap}/New_v4.orig"
		printf '%s\n' "${snap}/New_v4.orig" > "$memberlist"

		When call silently pfb_recompute recompute v4 "$memberlist" "$countsfile" on off
		chmod 644 "$masterfile"
		The status should be failure
		The path "${masterfile}.new" should not be exist
	End

	It 'stops the swap and logs the failing artifact -- without rolling anything back -- when the deny dir denies the mv (EACCES mid-swap, issue #1084 review)'
		Skip if 'root bypasses directory permissions' [ "$(id -u)" -eq 0 ]
		printf '192.0.2.1\n' > "${snap}/Alpha_v4.orig"
		printf '%s\n' "${snap}/Alpha_v4.orig" > "$memberlist"
		# Pre-create the .txt.new sibling: pfb_recompute_emit_alias then only
		# TRUNCATES an existing file (no directory-write needed), so emit
		# succeeds while the later mv (a rename -- directory write required)
		# still fails once pfbdeny itself goes read-only.
		: > "${pfbdeny}Alpha_v4.txt.new"
		chmod 555 "$pfbdeny"

		When call silently pfb_recompute recompute v4 "$memberlist" "$countsfile" on off
		chmod 755 "$pfbdeny"
		The status should be failure
		The contents of file "${errorlog}" should include 'Alpha_v4.txt.new'
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

Describe 'pfb_recompute() continent/Uber alias exclusion from reputation (issue #1084 review)'
	# shellcheck disable=SC2034  # consumed by the sourced pfb_recompute()
	setup() {
		work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/recpfbexcl.XXXXXX")"
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

	It 'never collapses/diverts a pfB_-prefixed (Continent/Uber) alias, even when its own volume trips the offender threshold'
		rm -f "$pathgeoip" "$pathgeoipdat"
		# pfB_Test_v4's OWN two rows in the 192.0.2 prefix exceed max=1 by themselves --
		# pre-fix, detection counts them and the divert/window collapses the alias to a
		# bare '192.0.2.0/24', silently losing everything else the real CIDR covered.
		printf '192.0.2.0/23\n192.0.2.55\n' > "${snap}/pfB_Test_v4.orig"
		# A real feed with its own, unrelated offender window -- must still collapse
		# exactly like today (this fix must not blunt reputation for real feeds).
		printf '198.51.100.10\n198.51.100.11\n198.51.100.12\n' > "${snap}/Feed_v4.orig"
		printf '%s\n%s\n' "${snap}/pfB_Test_v4.orig" "${snap}/Feed_v4.orig" > "$memberlist"

		When call silently pfb_recompute recompute v4 "$memberlist" "$countsfile" on pmax 1
		The status should be success
		The contents of file "${pfbdeny}pfB_Test_v4.txt" should equal "$(printf '192.0.2.0/23\n192.0.2.55')"
		The contents of file "${pfbdeny}Feed_v4.txt" should equal '198.51.100.0/24'
	End

	It "excludes a pfB_-prefixed alias's rows from the offender DETECTION count so a real feed's own (below-threshold) row is never dragged into a false collapse"
		rm -f "$pathgeoip" "$pathgeoipdat"
		# Neither alias alone exceeds max=1 in prefix 203.0.113 -- only if the
		# continent's row is (wrongly) counted alongside the real feed's does the
		# combined count trip the threshold and collapse the real feed's single IP.
		printf '203.0.113.9\n' > "${snap}/pfB_Leak_v4.orig"
		printf '203.0.113.10\n' > "${snap}/RealFeed_v4.orig"
		printf '%s\n%s\n' "${snap}/pfB_Leak_v4.orig" "${snap}/RealFeed_v4.orig" > "$memberlist"

		When call silently pfb_recompute recompute v4 "$memberlist" "$countsfile" on pmax 1
		The status should be success
		The contents of file "${pfbdeny}RealFeed_v4.txt" should equal '203.0.113.10'
		The contents of file "${pfbdeny}pfB_Leak_v4.txt" should equal '203.0.113.9'
	End
End

Describe 'pfb_recompute() finish-arm reputation reconcile (issue #1084 review: stale .new resurrection + GeoIP-outage destructive reconcile)'
	# shellcheck disable=SC2034  # consumed by the sourced pfb_recompute()
	setup() {
		work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/recfinisharm.XXXXXX")"
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

	It 'never promotes a crash-leftover match<alias>.txt.new debris on a clean no-offender dmax pass (GeoIP healthy)'
		printf '9.9.9.0/24\n!9.9.9.9\n' > "${pfbmatch}matchSTALE_v4.txt.new"
		printf '192.0.2.1\n' > "${snap}/STALE_v4.orig"
		printf '%s\n' "${snap}/STALE_v4.orig" > "$memberlist"

		When call silently pfb_recompute recompute v4 "$memberlist" "$countsfile" on dmax 100 US off block
		The status should be success
		The path "${pfbmatch}matchSTALE_v4.txt" should not be exist
	End

	It 'keeps ALL previous match artifacts (+ logs) when GeoIP is unavailable this pass, instead of destructively reconciling them away'
		rm -f "$pathgeoip" "$pathgeoipdat"
		printf '5.5.5.0/24\n!5.5.5.5\n' > "${pfbmatch}matchALIAS_v4.txt"
		printf '192.0.2.1\n192.0.2.2\n192.0.2.3\n' > "${snap}/ALIAS_v4.orig"
		printf '%s\n' "${snap}/ALIAS_v4.orig" > "$memberlist"

		When call silently pfb_recompute recompute v4 "$memberlist" "$countsfile" on dmax 1 US off block
		The status should be success
		The contents of file "${pfbmatch}matchALIAS_v4.txt" should equal "$(printf '5.5.5.0/24\n!5.5.5.5')"
		The contents of file "${errorlog}" should include 'GeoIP unavailable'
	End

	It 'clears a stale consolidated matchdedup file once a clean (offender-free) dmax pass confirms zero cc-list matches (matchdedup symmetry, issue #1084 review)'
		printf '1.1.1.0/24\n!1.1.1.1\n' > "${pfbmatch}matchdedup_v4.txt"
		printf '192.0.2.1\n' > "${snap}/CLEAN_v4.orig"
		printf '%s\n' "${snap}/CLEAN_v4.orig" > "$memberlist"

		When call silently pfb_recompute recompute v4 "$memberlist" "$countsfile" on dmax 100 US match off
		The status should be success
		The path "${pfbmatch}matchdedup_v4.txt" should not be exist
	End
End

Describe 'pfb_recompute() coverage-matrix gap rows (issue #1084 review: dedup=off x reputation, placeholder-as-data)'
	# shellcheck disable=SC2034  # consumed by the sourced pfb_recompute()
	# Brand-new coverage (no fix landed here) -- every dMax/pMax example above
	# runs dedup=on; reputation's own gate (rec_do_rep) never reads rec_dedup,
	# so the passthrough (dedup=off) cells and the deleted duplicate() oracle's
	# placeholder-as-data row were unpinned. Pins existing behaviour as-is.
	setup() {
		work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/recgaprows.XXXXXX")"
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

	It 'dedup=off + repmode=dmax still classifies/collapses an offender window and writes counts, but never touches masterfile'
		make_geoip_stub "$pathgeoip" 'Could not find an entry for this IP address'
		printf 'Stale_v4 1.2.3.4\n' > "$masterfile"
		printf '192.0.2.10\n192.0.2.11\n192.0.2.12\n' > "${snap}/NoDedup_v4.orig"
		printf '%s\n' "${snap}/NoDedup_v4.orig" > "$memberlist"

		When call silently pfb_recompute recompute v4 "$memberlist" "$countsfile" off dmax 2 US off block
		The status should be success
		The contents of file "${pfbdeny}NoDedup_v4.txt" should equal '192.0.2.0/24'
		The contents of file "$countsfile" should include 'NoDedup_v4 1'
		The contents of file "$masterfile" should equal 'Stale_v4 1.2.3.4'
	End

	It 'dedup=off + repmode=pmax still collapses the offender /24 (block-only) and writes counts, but never touches masterfile'
		printf 'Stale_v4 1.2.3.4\n' > "$masterfile"
		printf '198.51.100.1\n198.51.100.2\n198.51.100.3\n' > "${snap}/NoDedupP_v4.orig"
		printf '%s\n' "${snap}/NoDedupP_v4.orig" > "$memberlist"

		When call silently pfb_recompute recompute v4 "$memberlist" "$countsfile" off pmax 2
		The status should be success
		The contents of file "${pfbdeny}NoDedupP_v4.txt" should equal '198.51.100.0/24'
		The contents of file "$countsfile" should include 'NoDedupP_v4 1'
		The contents of file "$masterfile" should equal 'Stale_v4 1.2.3.4'
	End

	It 'treats a feed already reduced to the placeholder IP as ordinary data, no special-casing (the deleted duplicate() oracle row)'
		printf '240.0.0.0\n' > "${snap}/PlaceholderRow_v4.orig"
		printf '%s\n' "${snap}/PlaceholderRow_v4.orig" > "$memberlist"

		When call silently pfb_recompute recompute v4 "$memberlist" "$countsfile" on off
		The status should be success
		The contents of file "${pfbdeny}PlaceholderRow_v4.txt" should equal '240.0.0.0'
		The contents of file "$masterfile" should include 'PlaceholderRow_v4 240.0.0.0'
		The contents of file "$countsfile" should include 'PlaceholderRow_v4 1'
	End
End

Describe 'pfb_recompute() renders a per-feed Original/Final stats table on stdout from its own .counts artifact (issue #1174)'
	# shellcheck disable=SC2034  # consumed by the sourced pfb_recompute()
	setup() {
		work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/recstats.XXXXXX")"
		snap="${work}/snap"; pfbdeny="${work}/deny/"; pfbmatch="${work}/match/"
		pfborig="${work}/orig/"
		mkdir -p "$snap" "$pfbdeny" "$pfbmatch" "$pfborig"
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

	It 'v4: renders the title, the Alias/Original/Final header, and one row per fixture feed with its Original (.aggcount) and Final numbers'
		printf '192.0.2.10\n192.0.2.11\n' > "${snap}/FeedA_v4.orig"
		printf '192.0.2.10\n192.0.2.12\n' > "${snap}/FeedB_v4.orig"
		printf '2\n' > "${pfborig}FeedA_v4.aggcount"
		printf '2\n' > "${pfborig}FeedB_v4.aggcount"
		printf '%s\n%s\n' "${snap}/FeedA_v4.orig" "${snap}/FeedB_v4.orig" > "$memberlist"
		row_a="$(printf '%-36s %-10s %-10s' '  FeedA_v4' '2' '2')"
		row_b="$(printf '%-36s %-10s %-10s' '  FeedB_v4' '2' '1')"

		When call pfb_recompute recompute v4 "$memberlist" "$countsfile" on off
		The status should be success
		The output should include '===[ Recompute Stats [ v4 ] ]'
		The output should include "$(printf '%-36s %-10s %-10s' '  Alias' 'Original' 'Final')"
		The output should include "$row_a"
		The output should include "$row_b"
	End

	It 'v6: renders the same table shape for a v6 pass'
		printf '2001:db8::/32\n' > "${snap}/SixA_v6.orig"
		printf '1\n' > "${pfborig}SixA_v6.aggcount"
		printf '%s\n' "${snap}/SixA_v6.orig" > "$memberlist"
		row="$(printf '%-36s %-10s %-10s' '  SixA_v6' '1' '1')"

		When call pfb_recompute recompute v6 "$memberlist" "$countsfile" on off
		The status should be success
		The output should include '===[ Recompute Stats [ v6 ] ]'
		The output should include "$row"
	End

	It 'a zero-final-count feed still renders its row with Final 0 (Original also 0, from its .aggcount)'
		: > "${snap}/ZeroFeed_v4.orig"
		printf '0\n' > "${pfborig}ZeroFeed_v4.aggcount"
		printf '%s\n' "${snap}/ZeroFeed_v4.orig" > "$memberlist"
		row="$(printf '%-36s %-10s %-10s' '  ZeroFeed_v4' '0' '0')"

		When call pfb_recompute recompute v4 "$memberlist" "$countsfile" on off
		The status should be success
		The output should include "$row"
	End

	It 'falls back to the raw .orig row count when the .aggcount sidecar is missing (pre-1084 upgrade case)'
		printf '192.0.2.20\n' > "${snap}/OrigOnly_v4.orig"
		printf '192.0.2.20\n192.0.2.21\n192.0.2.22\n#comment\n\n' > "${pfborig}OrigOnly_v4.orig"
		printf '%s\n' "${snap}/OrigOnly_v4.orig" > "$memberlist"
		row="$(printf '%-36s %-10s %-10s' '  OrigOnly_v4' '3' '1')"

		When call pfb_recompute recompute v4 "$memberlist" "$countsfile" on off
		The status should be success
		The output should include "$row"
	End

	It "renders '?' for Original when neither .aggcount nor .orig exists for the alias"
		printf '203.0.113.5\n' > "${snap}/NoOrigin_v4.orig"
		printf '%s\n' "${snap}/NoOrigin_v4.orig" > "$memberlist"
		row="$(printf '%-36s %-10s %-10s' '  NoOrigin_v4' '?' '1')"

		When call pfb_recompute recompute v4 "$memberlist" "$countsfile" on off
		The status should be success
		The output should include "$row"
	End

	It 'a blank line in the .counts artifact is skipped -- never rendered as an empty/garbage row (hostile input)'
		# shellcheck disable=SC2034  # rec_countsfile/rec_family read by the sourced renderer
		rec_countsfile="${work}/hostile.counts"
		printf 'Real_v4 3\n\n' > "$rec_countsfile"
		rec_family='v4'

		When call pfb_recompute_render_stats
		The status should be success
		The output should include "$(printf '%-36s %-10s %-10s' '  Real_v4' '?' '3')"
		The lines of output should equal 7
	End

	It 'aborts the whole pass (grepcidr rc>=2): the .counts artifact never gets swapped in, so no stats table renders and the failure status is unaffected'
		printf '5.5.5.5\n' > "${snap}/A_v4.orig"
		printf '9.9.9.9\n' > "${snap}/B_v4.orig"
		printf '%s\n%s\n' "${snap}/A_v4.orig" "${snap}/B_v4.orig" > "$memberlist"
		printf '#!/bin/sh\nexit 2\n' > "$pathgrepcidr"
		chmod +x "$pathgrepcidr"

		When call pfb_recompute recompute v4 "$memberlist" "$countsfile" on off
		The status should be failure
		The output should not include '===[ Recompute Stats'
		The path "$countsfile" should not be exist
	End
End
