#shellcheck shell=sh
# issue #1084 ORACLE: pins TODAY'S incremental IP dedup/reputation shell
# behaviour (duplicate/remove/process255/reputation_{max,dmax,pmax}/
# closingprocess) end-to-end on inert fixtures, so the upcoming batch-recompute
# swap (steps 3-4) can diff its output against a known-green baseline instead
# of guessing. Behaviour-preserving oracle work (CLAUDE.md Test coverage #1
# refactor exception) -- green against today's code, no red run required.
#
# Fixtures are primarily RFC 5737 (192.0.2.0/24, 198.51.100.0/24,
# 203.0.113.0/24); count-heavy and short-form examples reuse the inert literal
# style of sibling specs (10.0.0.0/24-style rows). Aliases exercising the
# suffix-sibling hazard (#714/#730) reuse the established Ads_v4/BadAds_v4 pair.

# grepcidr(1) stand-in implementing REAL CIDR containment (`-vf <patternfile>
# <targetfile>` -> target lines whose address is NOT inside ANY pattern
# CIDR/host), via portable integer arithmetic (no bitwise ops -- runs the same
# under BSD awk (macOS dev) and gawk (CI)). The existing suffix-anchor spec's
# stub only does exact-string exclusion, which cannot exercise duplicate()'s
# genuine CIDR-containment prune (row 2 below).
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

Describe 'duplicate() cross-feed pruning (dedup ON)'
	# shellcheck disable=SC2034  # consumed by the sourced duplicate()
	setup() {
		work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/dupcross.XXXXXX")"
		pfbdeny="${work}/deny/"; pfborig="${work}/orig/"
		mkdir -p "$pfbdeny" "$pfborig"
		masterfile="${work}/master"; mastercat="${work}/mastercat"
		tempfile="${work}/t1"; tempfile2="${work}/t2"; errorlog="${work}/err.log"
		ip_placeholder='203.0.113.254'
		pathgrepcidr="${work}/grepcidr"; make_grepcidr_stub "$pathgrepcidr"
	}
	cleanup() { rm -rf "$work"; }
	BeforeAll 'pfb_source'
	Before 'setup'
	After 'cleanup'

	# Helper kept OUT of the shared library on purpose -- one-shot count used by
	# a single assertion below; shellspec's `The result of "func()"` needs a
	# named function, not an inline pipeline. Defined here (before the It that
	# calls it) -- shellspec's per-example run only executes a Describe body's
	# top-level statements up to the target It, so a def placed AFTER an It
	# that calls it is never reached (command not found).
	pfb_count_192_0_2_10() { grep -c '192\.0\.2\.10' "$masterfile"; }

	It "keeps the first owner's copy and prunes a later feed's exact repeat"
		alias='FeedB_v4'
		printf 'FeedA_v4 192.0.2.10\nFeedA_v4 192.0.2.11\n' > "$masterfile"
		printf '192.0.2.10\n192.0.2.11\n' > "$mastercat"
		printf '192.0.2.10\n192.0.2.12\n' > "${pfbdeny}FeedB_v4.txt"

		When call duplicate
		The status should be success
		The stdout should include 'Pass'
		# FeedB's own repeat of FeedA's IP is gone; its unique IP survives.
		The contents of file "${pfbdeny}FeedB_v4.txt" should equal '192.0.2.12'
		# FeedA keeps its original row (first owner untouched)...
		The contents of file "$masterfile" should include 'FeedA_v4 192.0.2.10'
		# ...and the partition stays disjoint: the shared IP appears exactly once.
		The result of "pfb_count_192_0_2_10()" should equal 1
	End

	It 'prunes via CIDR containment, not exact string match (a host inside an aggregated /24)'
		alias='FeedB_v4'
		printf 'FeedA_v4 192.0.2.0/24\n' > "$masterfile"
		printf '192.0.2.0/24\n' > "$mastercat"
		# .5 is CONTAINED in FeedA's /24 (never an exact-string match against it);
		# the other host is outside any owned range.
		printf '192.0.2.5\n198.51.100.9\n' > "${pfbdeny}FeedB_v4.txt"

		When call duplicate
		The status should be success
		The stdout should include 'Master'
		The contents of file "${pfbdeny}FeedB_v4.txt" should equal '198.51.100.9'
	End

	It 'treats a feed already reduced to the placeholder IP as ordinary data (no special-casing)'
		alias='FeedC_v4'
		ip_placeholder='203.0.113.99'
		printf 'OTHER_v4 1.2.3.4\n' > "$masterfile"
		printf '1.2.3.4\n' > "$mastercat"
		printf '203.0.113.99\n' > "${pfbdeny}FeedC_v4.txt"

		When call duplicate
		The status should be success
		The stdout should include 'Master'
		# The placeholder row lands in masterfile exactly like any real member --
		# duplicate() has no placeholder-awareness of its own.
		The contents of file "$masterfile" should include 'FeedC_v4 203.0.113.99'
		The contents of file "${pfbdeny}FeedC_v4.txt" should equal '203.0.113.99'
	End

	It 'contributes ZERO masterfile rows for a feed fully pruned to empty, then gets placeholder-refilled'
		alias='FeedD_v4'
		ip_placeholder='203.0.113.253'
		printf 'FeedA_v4 192.0.2.10\nFeedA_v4 192.0.2.11\n' > "$masterfile"
		printf '192.0.2.10\n192.0.2.11\n' > "$mastercat"
		# Both members already owned by FeedA -- the prune empties this file.
		printf '192.0.2.10\n192.0.2.11\n' > "${pfbdeny}FeedD_v4.txt"

		When call duplicate
		The status should be success
		The stdout should include 'Master'
		# emptyfiles() (called at duplicate()'s own end) refilled the now-empty
		# deny file with the placeholder...
		The contents of file "${pfbdeny}FeedD_v4.txt" should equal '203.0.113.253'
		# ...but masterfile disagrees: it has NO row for FeedD_v4 at all, because
		# the merge-into-masterfile step ran BEFORE the file had anything to
		# contribute. Deny-folder and masterfile can genuinely disagree about
		# whether an alias "exists".
		The contents of file "$masterfile" should not include 'FeedD_v4'
	End

	# issue #1084: a feed that starts (not merely ends up, via pruning) as a
	# genuinely empty deny file.
	It 'contributes nothing for a feed that starts as an empty deny file, then gets placeholder-refilled'
		alias='FeedE_v4'
		ip_placeholder='203.0.113.252'
		printf 'FeedA_v4 192.0.2.10\n' > "$masterfile"
		printf '192.0.2.10\n' > "$mastercat"
		: > "${pfbdeny}FeedE_v4.txt"

		When call duplicate
		The status should be success
		The stdout should include 'Master'
		The contents of file "${pfbdeny}FeedE_v4.txt" should equal '203.0.113.252'
		The contents of file "$masterfile" should not include 'FeedE_v4'
		The contents of file "$masterfile" should include 'FeedA_v4 192.0.2.10'
	End
End

Describe 'duplicate() masterfile row shape + Original/Master/Final sanity'
	# shellcheck disable=SC2034  # consumed by the sourced duplicate()
	setup() {
		work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/dupshape.XXXXXX")"
		pfbdeny="${work}/deny/"; pfborig="${work}/orig/"
		mkdir -p "$pfbdeny" "$pfborig"
		masterfile="${work}/master"; mastercat="${work}/mastercat"
		tempfile="${work}/t1"; tempfile2="${work}/t2"; errorlog="${work}/err.log"
		ip_placeholder='203.0.113.254'
		pathgrepcidr="${work}/grepcidr"; make_grepcidr_stub "$pathgrepcidr"
		printf 'OTHER_v4 9.9.9.9\n' > "$masterfile"
		printf '9.9.9.9\n' > "$mastercat"
	}
	cleanup() { rm -rf "$work"; }
	BeforeAll 'pfb_source'
	Before 'setup'
	After 'cleanup'

	# Defined before the It that calls it -- see the identical note in the
	# cross-feed-pruning Describe above (a def placed after the It is never
	# reached: shellspec only runs statements up to the target It).
	pfb_mastercat_matches_col2() {
		cut -d ' ' -f2 "$masterfile" > "${work}/col2"
		if diff -q "${work}/col2" "$mastercat" > /dev/null; then
			echo same
		else
			echo different
		fi
	}

	It 'writes masterfile rows as "alias IP" and keeps mastercat = masterfile column 2'
		alias='ROW3_v4'
		printf '203.0.113.5\n203.0.113.6\n' > "${pfbdeny}ROW3_v4.txt"

		When call duplicate
		The status should be success
		The contents of file "$masterfile" should include 'ROW3_v4 203.0.113.5'
		The contents of file "$masterfile" should include 'ROW3_v4 203.0.113.6'
		# mastercat is regenerated as exactly column 2 of masterfile.
		The result of "pfb_mastercat_matches_col2()" should equal 'same'
		# The sanity block printed a real Pass (counts balanced).
		The stdout should include 'Pass'
		The stdout should not include 'FAILED'
	End

	It 'keeps the Original/Master/Final sanity Pass despite a trailing blank line in the feed'
		alias='ROW3B_v4'
		printf '203.0.113.7\n203.0.113.8\n\n' > "${pfbdeny}ROW3B_v4.txt"

		When call duplicate
		The status should be success
		The stdout should include 'Pass'
		The stdout should not include 'FAILED'
	End
End

Describe 'duplicate() short-circuits (hcheck=0)'
	# shellcheck disable=SC2034  # consumed by the sourced duplicate()
	setup() {
		work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/dupshort.XXXXXX")"
		pfbdeny="${work}/deny/"; pfborig="${work}/orig/"
		mkdir -p "$pfbdeny" "$pfborig"
		masterfile="${work}/master"; mastercat="${work}/mastercat"
		tempfile="${work}/t1"; tempfile2="${work}/t2"; errorlog="${work}/err.log"
		ip_placeholder='203.0.113.254'
		pathgrepcidr="${work}/grepcidr"; make_grepcidr_stub "$pathgrepcidr"
	}
	cleanup() { rm -rf "$work"; }
	BeforeAll 'pfb_source'
	Before 'setup'
	After 'cleanup'

	It 'skips both the grepcidr prune and sort -u for a single-alias masterfile'
		# issue #1084: `sort -u`/mv and the grepcidr prune share ONE guard
		# (`if [ ! "${hcheck}" -eq 0 ]`) -- a single-occupant masterfile skips
		# BOTH, so the feed passes through raw (unsorted, duplicates intact).
		alias='MYLIST'
		printf 'MYLIST 5.5.5.5\n' > "$masterfile"
		printf '5.5.5.5\n' > "$mastercat"
		printf '9.9.9.9\n1.1.1.1\n1.1.1.1\n' > "${pfbdeny}MYLIST.txt"
		# Marker: proves grepcidr (our stub) was never invoked.
		: > "${work}/grepcidr.never-called"
		printf '#!/bin/sh\nrm -f "%s/grepcidr.never-called"\n' "$work" > "$pathgrepcidr"
		chmod +x "$pathgrepcidr"

		When call duplicate
		The status should be success
		The stdout should include 'Master'
		The path "${work}/grepcidr.never-called" should be exist
		# Raw, unsorted, WITH the duplicate -- not sort -u'd.
		The contents of file "${pfbdeny}MYLIST.txt" should equal "$(printf '9.9.9.9\n1.1.1.1\n1.1.1.1')"
		The contents of file "$masterfile" should equal "$(printf 'MYLIST 9.9.9.9\nMYLIST 1.1.1.1\nMYLIST 1.1.1.1')"
	End

	It 'lets the very first feed ever added enter whole (empty masterfile short-circuit)'
		alias='FIRSTLIST'
		: > "$masterfile"
		printf '203.0.113.20\n203.0.113.21\n' > "${pfbdeny}FIRSTLIST.txt"

		When call duplicate
		The status should be success
		The stdout should include 'Master'
		The contents of file "$masterfile" should include 'FIRSTLIST 203.0.113.20'
		The contents of file "$masterfile" should include 'FIRSTLIST 203.0.113.21'
	End
End

Describe 'duplicate() masterfile grep is anchored (issue #714 suffix over-match) -- full round trip'
	# shellcheck disable=SC2034  # consumed by the sourced duplicate()
	setup() {
		work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/dupsuffix.XXXXXX")"
		pfbdeny="${work}/deny/"; pfborig="${work}/orig/"
		mkdir -p "$pfbdeny" "$pfborig"
		masterfile="${work}/master"; mastercat="${work}/mastercat"
		tempfile="${work}/t1"; tempfile2="${work}/t2"; errorlog="${work}/err.log"
		ip_placeholder='203.0.113.254'
		pathgrepcidr="${work}/grepcidr"; make_grepcidr_stub "$pathgrepcidr"
	}
	cleanup() { rm -rf "$work"; }
	BeforeAll 'pfb_source'
	Before 'setup'
	After 'cleanup'

	It 'never strips BadAds_v4 (suffix-sibling of Ads_v4) when Ads_v4 is re-added'
		alias='Ads_v4'
		printf 'Ads_v4 10.0.0.0/24\nBadAds_v4 20.0.0.0/24\n' > "$masterfile"
		printf '10.0.0.0/24\n20.0.0.0/24\n' > "$mastercat"
		printf '10.0.0.0/24\n' > "${pfbdeny}Ads_v4.txt"

		When call duplicate
		The status should be success
		# Consumed, not asserted on: this particular fixture also exposes a
		# separate, pre-existing sanity-print false positive (line 800's
		# unanchored `grep -c "${alias}"` counts BOTH rows since "BadAds_v4"
		# contains the substring "Ads_v4") -- unrelated to the #714 anchor
		# fix under test here, carried forward for step 3.
		The stdout should include 'Master'
		The contents of file "$masterfile" should include 'BadAds_v4 20.0.0.0/24'
		The contents of file "$masterfile" should include 'Ads_v4 10.0.0.0/24'
	End
End

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

Describe 'reputation_dmax() block-mode repeat-offender collapse (ccblack=block)'
	# shellcheck disable=SC2034  # consumed by the sourced reputation_dmax()
	setup() {
		work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/dmaxblock.XXXXXX")"
		pfbdeny="${work}/deny/"; pfbmatch="${work}/match/"
		mkdir -p "$pfbdeny" "$pfbmatch"
		tmpdir="${work}"
		tempfile="${work}/t1"; tempfile2="${work}/t2"; dupfile="${work}/t3"
		matchfile="${work}/t7"; tempmatchfile="${work}/t8"
		dedupfile="${work}/d4"; addfile="${work}/d5"; : > "$dedupfile"; : > "$addfile"
		masterfile="${work}/master"; mastercat="${work}/mastercat"
		pathgeoip="${work}/mmdblookup"
		pathgeoipdat="${work}/geo.mmdb"; touch "$pathgeoipdat"
		ip_placeholder='240.0.0.0'
		ip_placeholder3="$(echo "${ip_placeholder}" | cut -d '.' -f 1-3)"
		now="now"
		count=0; countb=0; counts=0; countr=0
		dedup="off"; ccwhite="off"; ccblack="block"; cc="US"
		matchdedup="matchdedup_v4.txt"
		max=2
		# A GeoIP miss routes every offender down the block path.
		make_geoip_stub "$pathgeoip" 'Could not find an entry for this IP address'
	}
	cleanup() { rm -rf "$work"; }
	BeforeAll 'pfb_source'
	Before 'setup'
	After 'cleanup'

	It 'anti-joins the offending /24 out of EVERY carrying alias, collapses it into the first alias (glob order), and mirrors masterfile'
		# 192.0.2.* appears 3x total (AAA_v4 x2, ZZZ_v4 x1) -- max=2 -> offender.
		printf '192.0.2.10\n192.0.2.11\n' > "${pfbdeny}AAA_v4.txt"
		printf '192.0.2.12\n' > "${pfbdeny}ZZZ_v4.txt"
		printf 'AAA_v4 192.0.2.10\nAAA_v4 192.0.2.11\nZZZ_v4 192.0.2.12\nOTHER_v4 198.51.100.50\n' > "$masterfile"

		When call reputation_dmax
		The status should be success
		The stdout should include 'Reputation - dMax Stats'
		# Every carrying file lost its individual offender members...
		The contents of file "${pfbdeny}AAA_v4.txt" should not include '192.0.2.10'
		The contents of file "${pfbdeny}ZZZ_v4.txt" should not include '192.0.2.12'
		# ...the collapsed /24 landed in exactly ONE file: the first in glob
		# (alphabetical) order, AAA_v4.
		The contents of file "${pfbdeny}AAA_v4.txt" should include '192.0.2.0/24'
		The contents of file "${pfbdeny}ZZZ_v4.txt" should not include '192.0.2.0/24'
		# ZZZ_v4 lost its only member and never got the collapsed row -> it's now
		# empty -> refilled with the placeholder by dmax's own emptyfiles() call.
		The contents of file "${pfbdeny}ZZZ_v4.txt" should equal '240.0.0.0'
		# masterfile mirror: both aliases' individual offender rows are gone,
		# the collapsed row was added under the FIRST (AAA_v4) alias only, and
		# an unrelated alias outside the /24 survives untouched.
		The contents of file "$masterfile" should not include 'AAA_v4 192.0.2.10'
		The contents of file "$masterfile" should not include 'ZZZ_v4 192.0.2.12'
		The contents of file "$masterfile" should include 'AAA_v4 192.0.2.0/24'
		The contents of file "$masterfile" should include 'OTHER_v4 198.51.100.50'
	End

	It 'excludes the ip_placeholder prefix from offender detection'
		# Five deny files each holding only the placeholder IP (as emptyfiles()
		# would have left them) -- the /24 "240.0.0" appears 5x (> max=2), which
		# would ordinarily flag as a repeat offender were it not explicitly
		# filtered (`grep -v "^${ip_placeholder3}$"`).
		i=1
		while [ "$i" -le 5 ]; do
			printf '240.0.0.0\n' > "${pfbdeny}PH${i}_v4.txt"
			i=$((i + 1))
		done

		When call reputation_dmax
		The status should be success
		The stdout should include 'Reputation -dMax ( None )'
		The path "$masterfile" should not be exist
	End
End

Describe 'reputation_dmax() match-mode (ccblack=match) leaves deny files untouched'
	# shellcheck disable=SC2034  # consumed by the sourced reputation_dmax()
	setup() {
		work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/dmaxmatch.XXXXXX")"
		pfbdeny="${work}/deny/"; pfbmatch="${work}/match/"
		mkdir -p "$pfbdeny" "$pfbmatch"
		tmpdir="${work}"
		tempfile="${work}/t1"; tempfile2="${work}/t2"; dupfile="${work}/t3"
		matchfile="${work}/t7"; tempmatchfile="${work}/t8"
		dedupfile="${work}/d4"; addfile="${work}/d5"; : > "$dedupfile"; : > "$addfile"
		masterfile="${work}/master"; mastercat="${work}/mastercat"
		pathgeoip="${work}/mmdblookup"
		pathgeoipdat="${work}/geo.mmdb"; touch "$pathgeoipdat"
		ip_placeholder='240.0.0.0'
		ip_placeholder3="$(echo "${ip_placeholder}" | cut -d '.' -f 1-3)"
		now="now"
		count=0; countb=0; counts=0; countr=0
		dedup="off"; ccwhite="off"; ccblack="match"; cc="US"
		matchdedup="matchdedup_v4.txt"
		max=1
		make_geoip_stub "$pathgeoip" 'Could not find an entry for this IP address'
		printf '192.0.2.20\n192.0.2.21\n' > "${pfbdeny}ONEALIAS_v4.txt"
		printf 'ONEALIAS_v4 192.0.2.20\nONEALIAS_v4 192.0.2.21\n' > "$masterfile"
	}
	cleanup() { rm -rf "$work"; }
	BeforeAll 'pfb_source'
	Before 'setup'
	After 'cleanup'

	It 'writes the collapsed CIDR + negated members to matchONEALIAS.txt, never touching the deny file'
		When call reputation_dmax
		The status should be success
		The stdout should include 'Reputation - dMax Stats'
		# The deny list is byte-identical: match mode never mutates it.
		The contents of file "${pfbdeny}ONEALIAS_v4.txt" should equal "$(printf '192.0.2.20\n192.0.2.21')"
		The contents of file "${pfbmatch}matchONEALIAS_v4.txt" should include '192.0.2.0/24'
		The contents of file "${pfbmatch}matchONEALIAS_v4.txt" should include '!192.0.2.20'
		The contents of file "${pfbmatch}matchONEALIAS_v4.txt" should include '!192.0.2.21'
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

	# Defined before the It that calls it -- see the identical note in the
	# cross-feed-pruning Describe above.
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
		# Two feeds sharing an IP. With dedup off, duplicate() is simply never
		# invoked by the caller -- pin that BOTH keep their own copy, since
		# nothing in the shell pipeline ever cross-checks them.
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
