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
# patterns (blank OR whitespace-only lines, or empty) prints NOTHING and
# exits 1 -- never "no patterns matched, so keep every line" -- so a
# whitespace-only pattern line is skipped like a blank one (issue #1279)
# and `n == 0` short-circuits to that outcome before the per-line filter
# ever runs.
make_grepcidr_stub() {
	cat > "$1" <<'EOF'
#!/bin/sh
LC_ALL=C awk -v patfile="$2" '
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
		sub(/\r$/, "", line)
		if (line ~ /^[ \t]*$/) continue
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
LC_ALL=C awk -v patfile="$2" '
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
		sub(/\r$/, "", line)
		if (line ~ /^[ \t]*$/) continue
		split(line, parts, "/")
		n++
		pbits[n] = (parts[2] == "" ? 128 : parts[2])
		delete parr
		expand(parts[1], parr)
		for (i = 1; i <= 8; i++) pgroup[n, i] = parr[i]
	}
	close(patfile)
}
n == 0 { next }
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
END { if (n == 0) exit 1 }
' "$3"
EOF
	chmod +x "$1"
}

setup_grepcidr_stub_fidelity() {
	work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/recgrepcidr.XXXXXX")"
	patterns="${work}/patterns"
	target="${work}/target"
}

cleanup_grepcidr_stub_fidelity() { rm -rf "$work"; }

Describe 'recompute grepcidr stand-ins'
	Before 'setup_grepcidr_stub_fidelity'
	After 'cleanup_grepcidr_stub_fidelity'

	It 'v4 treats CRLF blank, space-only, and tab-only patterns as zero parseable patterns'
		grepcidr="${work}/grepcidr"
		make_grepcidr_stub "$grepcidr"
		printf '\r\n   \r\n\t\t\r\n' > "$patterns"
		printf '198.51.100.10\n' > "$target"

		When run "$grepcidr" -vf "$patterns" "$target"
		The status should be failure
		The output should equal ''
	End

	It 'v6 matches v4 zero-pattern output and rc parity for CRLF blank, space-only, and tab-only patterns'
		grepcidr="${work}/grepcidr"
		make_grepcidr_v6_stub "$grepcidr"
		printf '\r\n   \r\n\t\t\r\n' > "$patterns"
		printf '2001:db8::10\n' > "$target"

		When run "$grepcidr" -vf "$patterns" "$target"
		The status should be failure
		The output should equal ''
	End
End

recompute_matches_expected() {
	expected="$1"; actual="$2"; shift 2
	pfb_recompute "$@" || return
	cmp "$expected" "$actual"
}

c_utf8_unavailable() { ! locale -a 2>/dev/null | grep -qiE '^C\.UTF-?8$'; }

recompute_matches_expected_c_utf8() {
	expected="$1"; actual="$2"; shift 2
	LC_ALL=C.UTF-8 pfb_recompute "$@" || return
	cmp "$expected" "$actual"
}

make_window_awk_fail_stub() {
	realawk="$(command -v awk)"
	mkdir -p "$1"
	cat > "$1/awk" <<EOF
#!/bin/sh
window=0
for arg do
	case "\${arg}" in
		*'pfB_Match_Rep_'*'.txt.new'*) window=1 ;;
	esac
done
"${realawk}" "\$@"
rc=\$?
if [ "\${window}" -eq 1 ]; then
	true > "$1/window-hit"
	[ "\${rc}" -eq 0 ] && exit 74
fi
exit "\${rc}"
EOF
	chmod +x "$1/awk"
}

recompute_with_window_awk_failure() {
	(
		PATH="$1:${PATH}"
		export PATH
		shift
		pfb_recompute "$@"
	)
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
	pfb_allnet_log_count() { grep -c 'dropped total-range row(s) from \[ AllNet_v4 \]' "$errorlog"; }

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
		true > "${pfbdeny}Low_v4.txt"
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
		true > "${work}/grepcidr.never-called"
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
		true > "${snap}/Empty_v4.orig"
		printf '%s\n' "${snap}/Empty_v4.orig" > "$memberlist"
		When call silently pfb_recompute recompute v4 "$memberlist" "$countsfile" on off
		The status should be success
		The path "${pfbdeny}Empty_v4.txt" should be exist
		The contents of file "${pfbdeny}Empty_v4.txt" should equal ''
		The contents of file "$countsfile" should include 'Empty_v4 0'
	End

	It 'direct v4 emit preserves invalid bytes under C.UTF-8 while filtering zero-field rows and terminal CR'
		Skip if 'requires C.UTF-8 to exercise invalid-byte handling' c_utf8_unavailable
		printf '\n   \n\t\t\n\r\n198.51.100.10\r\n  198.51.100.11  \r\n198.51.100.12\377' > "${snap}/Direct_v4.orig"
		printf '%s\n' "${snap}/Direct_v4.orig" > "$memberlist"
		expected="${work}/expected-direct-v4"
		printf '  198.51.100.11  \n198.51.100.10\n198.51.100.12\377\n' > "$expected"

		When call silently recompute_matches_expected_c_utf8 "$expected" "${pfbdeny}Direct_v4.txt" recompute v4 "$memberlist" "$countsfile" off off
		The status should be success
		The contents of file "$countsfile" should include 'Direct_v4 3'
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

	It 'cumulative dedup preserves invalid bytes under C.UTF-8 and rejects zero-field rows (issues #1279/#1326)'
		Skip if 'requires C.UTF-8 to exercise invalid-byte handling' c_utf8_unavailable
		printf '\n   \n\t\t\n\r\n203.0.113.71\377\n' > "${snap}/OnlySpaces_v4.orig"
		printf '198.51.100.71\n' > "${snap}/Disjoint_v4.orig"
		printf '%s\n%s\n' "${snap}/OnlySpaces_v4.orig" "${snap}/Disjoint_v4.orig" > "$memberlist"
		expected="${work}/expected-cumulative-v4"
		printf '203.0.113.71\377\n' > "$expected"
		When call silently recompute_matches_expected_c_utf8 "$expected" "${pfbdeny}OnlySpaces_v4.txt" recompute v4 "$memberlist" "$countsfile" on off
		The status should be success
		The contents of file "${pfbdeny}Disjoint_v4.txt" should equal '198.51.100.71'
		The contents of file "$countsfile" should include 'OnlySpaces_v4 1'
		The contents of file "$countsfile" should include 'Disjoint_v4 1'
	End

	It 'never lets a whitespace-only (tabs) high-priority snapshot poison the cumulative dedup stream into eating a disjoint lower feed (issue #1279)'
		printf '\t\t\n' > "${snap}/OnlyTabs_v4.orig"
		printf '198.51.100.72\n' > "${snap}/Disjoint_v4.orig"
		printf '%s\n%s\n' "${snap}/OnlyTabs_v4.orig" "${snap}/Disjoint_v4.orig" > "$memberlist"
		When call silently pfb_recompute recompute v4 "$memberlist" "$countsfile" on off
		The status should be success
		The contents of file "${pfbdeny}Disjoint_v4.txt" should equal '198.51.100.72'
		The contents of file "$countsfile" should include 'Disjoint_v4 1'
	End

	It 'a whitespace-only line mixed with a valid row in the same snapshot never wipes a later disjoint feed, and the valid row still dedups (issue #1279)'
		printf '203.0.113.50\n   \n' > "${snap}/Mixed_v4.orig"
		printf '198.51.100.73\n' > "${snap}/Disjoint_v4.orig"
		# a third, lowest-priority repeat of Mixed's OWN valid row: proves that row
		# reached rec_cumulative (not just that Disjoint survived) -- a bad fix that
		# skips a whole owned-file on any embedded blank line would leave this repeat
		# undeduped instead of empty.
		printf '203.0.113.50\n' > "${snap}/Repeat_v4.orig"
		printf '%s\n%s\n%s\n' "${snap}/Mixed_v4.orig" "${snap}/Disjoint_v4.orig" "${snap}/Repeat_v4.orig" > "$memberlist"
		When call silently pfb_recompute recompute v4 "$memberlist" "$countsfile" on off
		The status should be success
		The contents of file "${pfbdeny}Disjoint_v4.txt" should equal '198.51.100.73'
		The contents of file "${pfbdeny}Repeat_v4.txt" should equal ''
	End

	It 'a pattern row with surrounding whitespace still counts as valid content and dedups a later feed exact repeat (issue #1279 -- do not over-fix into stripping valid rows)'
		printf '  198.51.100.75  \n' > "${snap}/Padded_v4.orig"
		printf '198.51.100.75\n198.51.100.76\n' > "${snap}/PaddedLower_v4.orig"
		printf '%s\n%s\n' "${snap}/Padded_v4.orig" "${snap}/PaddedLower_v4.orig" > "$memberlist"
		When call silently pfb_recompute recompute v4 "$memberlist" "$countsfile" on off
		The status should be success
		The contents of file "${pfbdeny}PaddedLower_v4.txt" should equal '198.51.100.76'
	End

	It 'a 0.0.0.0/0 row never acts as a cumulative dedup pattern: lower-priority disjoint feeds survive, its own alias still ships it, and the drop is logged (issue #1929)'
		printf '203.0.113.60\n0.0.0.0/0\n' > "${snap}/AllNet_v4.orig"
		printf '198.51.100.80\n198.51.100.81\n' > "${snap}/LowerA_v4.orig"
		# a lowest-priority repeat of AllNet's ORDINARY row: proves that row still
		# reached rec_cumulative -- a bad fix that skips the whole owned file on a
		# total-range row would leave this repeat undeduped instead of pruned.
		printf '203.0.113.60\n192.0.2.90\n' > "${snap}/LowerB_v4.orig"
		printf '%s\n%s\n%s\n' "${snap}/AllNet_v4.orig" "${snap}/LowerA_v4.orig" "${snap}/LowerB_v4.orig" > "$memberlist"

		When call silently pfb_recompute recompute v4 "$memberlist" "$countsfile" on off
		The status should be success
		The contents of file "${pfbdeny}AllNet_v4.txt" should equal "$(printf '0.0.0.0/0\n203.0.113.60')"
		The contents of file "${pfbdeny}LowerA_v4.txt" should equal "$(printf '198.51.100.80\n198.51.100.81')"
		The contents of file "${pfbdeny}LowerB_v4.txt" should equal '192.0.2.90'
		The contents of file "$countsfile" should include 'AllNet_v4 2'
		The contents of file "$countsfile" should include 'LowerA_v4 2'
		The contents of file "$countsfile" should include 'LowerB_v4 1'
		The result of "pfb_allnet_log_count()" should equal 1
	End

	It 'a broad-but-not-total prefix (10.0.0.0/8) still prunes contained lower rows -- the total-range guard never over-matches (issue #1929 negative control)'
		printf '10.0.0.0/8\n' > "${snap}/Broad_v4.orig"
		printf '10.1.2.3\n198.51.100.90\n' > "${snap}/UnderBroad_v4.orig"
		printf '%s\n%s\n' "${snap}/Broad_v4.orig" "${snap}/UnderBroad_v4.orig" > "$memberlist"

		When call silently pfb_recompute recompute v4 "$memberlist" "$countsfile" on off
		The status should be success
		The contents of file "${pfbdeny}UnderBroad_v4.txt" should equal '198.51.100.90'
		The contents of file "$countsfile" should include 'UnderBroad_v4 1'
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

	pfb_allnet_v6_log_count() { grep -c 'dropped total-range row(s) from \[ AllNet_v6 \]' "$errorlog"; }

	It 'dedups an exact cross-feed repeat and prunes via CIDR containment'
		printf '2001:db8::/32\n' > "${snap}/SixA_v6.orig"
		printf '2001:db8:dead:beef::1\nfd12:3456::1\n' > "${snap}/SixB_v6.orig"
		printf '%s\n%s\n' "${snap}/SixA_v6.orig" "${snap}/SixB_v6.orig" > "$memberlist"

		When call silently pfb_recompute recompute v6 "$memberlist" "$countsfile" on off
		The status should be success
		The contents of file "${pfbdeny}SixB_v6.txt" should equal 'fd12:3456::1'
		The contents of file "$masterfile" should include 'SixA_v6 2001:db8::/32'
	End

	It 'direct v6 emit drops zero-field rows, strips one terminal CR, and preserves padded and unterminated rows'
		printf '\n   \n\t\t\n\r\n2001:db8::10\r\n  2001:db8::11  \r\n2001:db8::12' > "${snap}/Direct_v6.orig"
		printf '%s\n' "${snap}/Direct_v6.orig" > "$memberlist"
		expected="${work}/expected-direct-v6"
		printf '  2001:db8::11  \n2001:db8::10\n2001:db8::12\n' > "$expected"

		When call silently recompute_matches_expected "$expected" "${pfbdeny}Direct_v6.txt" recompute v6 "$memberlist" "$countsfile" off off
		The status should be success
		The contents of file "$countsfile" should include 'Direct_v6 3'
	End

	It 'never lets zero-field LF, spaces, tabs, or CRLF in a high-priority v6 snapshot poison the cumulative dedup stream'
		printf '\n   \n\t\t\n\r\n' > "${snap}/OnlySpaces_v6.orig"
		printf '2001:db8::71\n' > "${snap}/Disjoint_v6.orig"
		printf '%s\n%s\n' "${snap}/OnlySpaces_v6.orig" "${snap}/Disjoint_v6.orig" > "$memberlist"

		When call silently pfb_recompute recompute v6 "$memberlist" "$countsfile" on off
		The status should be success
		The contents of file "${pfbdeny}OnlySpaces_v6.txt" should equal ''
		The contents of file "${pfbdeny}Disjoint_v6.txt" should equal '2001:db8::71'
		The contents of file "$countsfile" should include 'OnlySpaces_v6 0'
		The contents of file "$countsfile" should include 'Disjoint_v6 1'
	End

	It 'a ::/0 row never acts as a cumulative dedup pattern: lower-priority disjoint v6 feeds survive, its own alias still ships it, and the drop is logged (issue #1929)'
		printf '2001:db8::60\n::/0\n' > "${snap}/AllNet_v6.orig"
		printf 'fd12:3456::2\n' > "${snap}/LowerA_v6.orig"
		# a lowest-priority repeat of AllNet's ORDINARY row: proves it still
		# reached rec_cumulative despite the total-range drop.
		printf '2001:db8::60\nfd99::7\n' > "${snap}/LowerB_v6.orig"
		printf '%s\n%s\n%s\n' "${snap}/AllNet_v6.orig" "${snap}/LowerA_v6.orig" "${snap}/LowerB_v6.orig" > "$memberlist"

		When call silently pfb_recompute recompute v6 "$memberlist" "$countsfile" on off
		The status should be success
		The contents of file "${pfbdeny}AllNet_v6.txt" should equal "$(printf '2001:db8::60\n::/0')"
		The contents of file "${pfbdeny}LowerA_v6.txt" should equal 'fd12:3456::2'
		The contents of file "${pfbdeny}LowerB_v6.txt" should equal 'fd99::7'
		The contents of file "$countsfile" should include 'LowerA_v6 1'
		The contents of file "$countsfile" should include 'LowerB_v6 1'
		The result of "pfb_allnet_v6_log_count()" should equal 1
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

	It 'ordinary v4 reputation emit preserves invalid bytes under C.UTF-8 while filtering zero-field rows'
		Skip if 'requires C.UTF-8 to exercise invalid-byte handling' c_utf8_unavailable
		printf '\n   \n\t\t\n\r\n192.0.2.10\r\n192.0.2.11\r\n  198.51.100.20  \r\n203.0.113.30\377' > "${snap}/Ordinary_v4.orig"
		printf '%s\n' "${snap}/Ordinary_v4.orig" > "$memberlist"
		expected="${work}/expected-ordinary-v4"
		printf '  198.51.100.20  \n192.0.2.0/24\n203.0.113.30\377\n' > "$expected"

		When call silently recompute_matches_expected_c_utf8 "$expected" "${pfbdeny}Ordinary_v4.txt" recompute v4 "$memberlist" "$countsfile" on pmax 1
		The status should be success
		The contents of file "$countsfile" should include 'Ordinary_v4 3'
	End
End

Describe 'pfb_recompute() dMax match-mode + GeoIP-unavailable bail + pMax'
	# shellcheck disable=SC2034  # consumed by the sourced pfb_recompute()
	setup() {
		work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/recdmaxmatch.XXXXXX")"
		snap="${work}/snap"; pfbdeny="${work}/deny/"; pfbmatch="${work}/match/"
		pfbmatchgen="${work}/match/generated/"
		mkdir -p "$snap" "$pfbdeny" "$pfbmatch" "$pfbmatchgen"
		tmpdir="${work}/tmp"; mkdir -p "$tmpdir"
		masterfile="${work}/master"; mastercat="${work}/mastercat"
		errorlog="${work}/err.log"
		ip_placeholder3='240.0.0'
		pathgrepcidr="${work}/grepcidr"; make_grepcidr_stub "$pathgrepcidr"
		pathgeoip="${work}/mmdblookup"; pathgeoipdat="${work}/geo.mmdb"; touch "$pathgeoipdat"
		memberlist="${work}/members"
		countsfile="${work}/counts"
		matchexemptfile='pfB_Match_Exempt_v4.txt'
	}
	cleanup() { rm -rf "$work"; }
	BeforeAll 'pfb_source'
	Before 'setup'
	After 'cleanup'

	It 'cleans per-alias reputation staging when the window awk fails after writing it'
		make_geoip_stub "$pathgeoip" 'Could not find an entry for this IP address'
		printf '192.0.2.20\n192.0.2.21\n' > "${snap}/ONE_v4.orig"
		printf '%s\n' "${snap}/ONE_v4.orig" > "$memberlist"
		printf '198.51.100.1\n' > "${pfbdeny}ONE_v4.txt"
		printf '198.51.100.0/24\n!198.51.100.1\n' > "${pfbmatchgen}pfB_Match_Rep_ONE_v4.txt"
		awkshim="${work}/awkshim"
		make_window_awk_fail_stub "$awkshim"

		When call silently recompute_with_window_awk_failure "$awkshim" recompute v4 "$memberlist" "$countsfile" on dmax 1 US off match
		The status should be failure
		The path "${awkshim}/window-hit" should be exist
		The contents of file "$errorlog" should include 'reputation-apply pass failed'
		The path "${pfbmatchgen}pfB_Match_Rep_ONE_v4.txt.new" should not be exist
		The contents of file "${pfbdeny}ONE_v4.txt" should equal '198.51.100.1'
		The contents of file "${pfbmatchgen}pfB_Match_Rep_ONE_v4.txt" should equal "$(printf '198.51.100.0/24\n!198.51.100.1')"
	End

	It 'ccblack=match: leaves the stream untouched and writes pfB_Match_Rep_<alias>.txt (cidr + negated members)'
		make_geoip_stub "$pathgeoip" 'Could not find an entry for this IP address'
		printf '192.0.2.20\n192.0.2.21\n' > "${snap}/ONE_v4.orig"
		printf '%s\n' "${snap}/ONE_v4.orig" > "$memberlist"

		When call silently pfb_recompute recompute v4 "$memberlist" "$countsfile" on dmax 1 US off match
		The status should be success
		The contents of file "${pfbdeny}ONE_v4.txt" should equal "$(printf '192.0.2.20\n192.0.2.21')"
		The contents of file "${pfbmatchgen}pfB_Match_Rep_ONE_v4.txt" should include '192.0.2.0/24'
		The contents of file "${pfbmatchgen}pfB_Match_Rep_ONE_v4.txt" should include '!192.0.2.20'
		The contents of file "${pfbmatchgen}pfB_Match_Rep_ONE_v4.txt" should include '!192.0.2.21'
	End

	It "ccwhite=match on a cc-list hit: writes the consolidated exempt file, leaves the stream untouched"
		make_geoip_stub "$pathgeoip" 'xx iso_code: "US" xx'
		printf '198.51.100.20\n198.51.100.21\n' > "${snap}/EX_v4.orig"
		printf '%s\n' "${snap}/EX_v4.orig" > "$memberlist"

		When call silently pfb_recompute recompute v4 "$memberlist" "$countsfile" on dmax 1 US match off
		The status should be success
		The contents of file "${pfbdeny}EX_v4.txt" should equal "$(printf '198.51.100.20\n198.51.100.21')"
		The contents of file "${pfbmatchgen}${matchexemptfile}" should include '198.51.100.0/24'
		The contents of file "${pfbmatchgen}${matchexemptfile}" should include '!198.51.100.20'
	End

	It 'ccwhite passed uppercase (MATCH) still fires the exempt-match path on a cc-list hit (issue #1084 review, case-fold parity with the legacy verb init)'
		make_geoip_stub "$pathgeoip" 'xx iso_code: "US" xx'
		printf '198.51.100.40\n198.51.100.41\n' > "${snap}/UP_v4.orig"
		printf '%s\n' "${snap}/UP_v4.orig" > "$memberlist"

		When call silently pfb_recompute recompute v4 "$memberlist" "$countsfile" on dmax 1 US MATCH off
		The status should be success
		The contents of file "${pfbmatchgen}${matchexemptfile}" should include '198.51.100.0/24'
		The contents of file "${pfbmatchgen}${matchexemptfile}" should include '!198.51.100.40'
	End

	It 'ccblack=match emits pfB_Match_Rep_<alias>.txt for EVERY member alias sharing an offender /24 (issue #1084: multi-alias delta from the legacy single-owner write)'
		make_geoip_stub "$pathgeoip" 'Could not find an entry for this IP address'
		printf '192.0.2.30\n' > "${snap}/First_v4.orig"
		printf '192.0.2.31\n192.0.2.32\n' > "${snap}/Second_v4.orig"
		printf '%s\n%s\n' "${snap}/First_v4.orig" "${snap}/Second_v4.orig" > "$memberlist"

		When call silently pfb_recompute recompute v4 "$memberlist" "$countsfile" on dmax 2 US off match
		The status should be success
		The contents of file "${pfbmatchgen}pfB_Match_Rep_First_v4.txt" should include '192.0.2.0/24'
		The contents of file "${pfbmatchgen}pfB_Match_Rep_First_v4.txt" should include '!192.0.2.30'
		The contents of file "${pfbmatchgen}pfB_Match_Rep_Second_v4.txt" should include '192.0.2.0/24'
		The contents of file "${pfbmatchgen}pfB_Match_Rep_Second_v4.txt" should include '!192.0.2.31'
		The contents of file "${pfbmatchgen}pfB_Match_Rep_Second_v4.txt" should include '!192.0.2.32'
	End

	It "ccblack=match (not ccwhite) on a cc-list hit: logs nowhere -- no exempt file is written (today's asymmetric gate)"
		make_geoip_stub "$pathgeoip" 'xx iso_code: "US" xx'
		printf '198.51.100.30\n198.51.100.31\n' > "${snap}/EX2_v4.orig"
		printf '%s\n' "${snap}/EX2_v4.orig" > "$memberlist"

		When call silently pfb_recompute recompute v4 "$memberlist" "$countsfile" on dmax 1 US off match
		The status should be success
		The path "${pfbmatchgen}${matchexemptfile}" should not be exist
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
		The path "${pfbmatchgen}pfB_Match_Rep_PALIAS_v4.txt" should not be exist
	End

	# issue #1250: a Match-type list and a Deny-type list can share the same
	# header, so their on-disk artifacts collided under the single ${pfbmatch}
	# namespace -- the reputation-apply write must never touch a pre-existing
	# user Match-list file, and lands in ${pfbmatchgen} instead.
	It "a pre-existing user Match-list file at pfbmatch survives a same-named Deny alias's reputation match write (issue #1250)"
		make_geoip_stub "$pathgeoip" 'Could not find an entry for this IP address'
		# Two hosts in the same /24 (> max=1) so the Deny alias is a genuine
		# offender and the reputation-apply write actually fires.
		printf '192.0.2.50\n192.0.2.51\n' > "${snap}/Spam_v4.orig"
		printf '%s\n' "${snap}/Spam_v4.orig" > "$memberlist"
		# The user's OWN Match-type list content -- RFC 5737, unrelated to the
		# reputation output the Deny alias 'Spam_v4' is about to produce.
		printf '203.0.113.99\n' > "${pfbmatch}matchSpam_v4.txt"
		before_content="$(cat "${pfbmatch}matchSpam_v4.txt")"

		When call silently pfb_recompute recompute v4 "$memberlist" "$countsfile" on dmax 1 US off match
		The status should be success
		The value "$before_content" should equal '203.0.113.99'
		The contents of file "${pfbmatch}matchSpam_v4.txt" should equal '203.0.113.99'
		The contents of file "${pfbmatchgen}pfB_Match_Rep_Spam_v4.txt" should include '192.0.2.0/24'
		The contents of file "${pfbmatchgen}pfB_Match_Rep_Spam_v4.txt" should include '!192.0.2.50'
		The contents of file "${pfbmatchgen}pfB_Match_Rep_Spam_v4.txt" should include '!192.0.2.51'
	End

	It 'a pre-existing user Match-list file literally named matchdedup_v4.txt survives the ccwhite=match consolidated write (issue #1250)'
		make_geoip_stub "$pathgeoip" 'xx iso_code: "US" xx'
		printf '198.51.100.50\n198.51.100.51\n' > "${snap}/CCHIT_v4.orig"
		printf '%s\n' "${snap}/CCHIT_v4.orig" > "$memberlist"
		printf '203.0.113.88\n' > "${pfbmatch}matchdedup_v4.txt"
		before_content="$(cat "${pfbmatch}matchdedup_v4.txt")"

		When call silently pfb_recompute recompute v4 "$memberlist" "$countsfile" on dmax 1 US match off
		The status should be success
		The value "$before_content" should equal '203.0.113.88'
		The contents of file "${pfbmatch}matchdedup_v4.txt" should equal '203.0.113.88'
		The contents of file "${pfbmatchgen}${matchexemptfile}" should include '198.51.100.0/24'
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
		true > "${pfbdeny}Alpha_v4.txt.new"
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
		true > "${snap}/Empty_v4.orig"
		printf '%s\n' "${snap}/Empty_v4.orig" > "$memberlist"
		When call silently pfb_recompute recompute v4 "$memberlist" "$countsfile" on off
		The status should be success
		The contents of file "$masterfile" should equal ''
		The contents of file "$mastercat" should equal ''
	End

	It 'completes an all-empty memberlist under repmode=dmax exactly like repmode=off'
		true > "${snap}/Empty_v4.orig"
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

	It 'pfB_ reputation passthrough preserves invalid bytes under C.UTF-8 while filtering zero-field rows'
		Skip if 'requires C.UTF-8 to exercise invalid-byte handling' c_utf8_unavailable
		printf '\n   \n\t\t\n\r\n198.51.100.20\r\n  203.0.113.21  \r\n192.0.2.22\377' > "${snap}/pfB_Hostile_v4.orig"
		printf '10.0.0.1\n10.0.0.2\n' > "${snap}/Feed_v4.orig"
		printf '%s\n%s\n' "${snap}/pfB_Hostile_v4.orig" "${snap}/Feed_v4.orig" > "$memberlist"
		expected="${work}/expected-pfb-v4"
		printf '  203.0.113.21  \n192.0.2.22\377\n198.51.100.20\n' > "$expected"

		When call silently recompute_matches_expected_c_utf8 "$expected" "${pfbdeny}pfB_Hostile_v4.txt" recompute v4 "$memberlist" "$countsfile" on pmax 1
		The status should be success
		The contents of file "$countsfile" should include 'pfB_Hostile_v4 3'
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
		pfbmatchgen="${work}/match/generated/"
		mkdir -p "$snap" "$pfbdeny" "$pfbmatch" "$pfbmatchgen"
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
	artifact_is_unchanged() {
		expected="$1"; actual="$2"; label="$3"
		cmp -s "$expected" "$actual" && return 0
		printf '%s artifact changed (expected: %s; actual: %s)\n' \
			"$label" "$expected" "$actual" >&2
		printf '%s\n' '--- expected contents ---' >&2
		if [ -f "$expected" ]; then cat "$expected" >&2; else printf '%s\n' '<missing>' >&2; fi
		printf '%s\n' '--- actual contents ---' >&2
		if [ -f "$actual" ]; then cat "$actual" >&2; else printf '%s\n' '<missing>' >&2; fi
		if [ -f "$expected" ] && [ -f "$actual" ]; then diff -u "$expected" "$actual" >&2 || :; fi
		return 1
	}
	recompute_v6_and_check_match_artifacts() {
		rec_geoip_ok=1
		pfb_recompute recompute v6 "$memberlist" "$countsfile" on dmax 1 US match off >/dev/null || return
		artifact_is_unchanged "${work}/exempt.before" \
			"${pfbmatchgen}pfB_Match_Exempt_v4.txt" 'v4 exempt' || return
		artifact_is_unchanged "${work}/rep.before" \
			"${pfbmatchgen}pfB_Match_Rep_Six_v6.txt" 'v6 reputation'
	}
	BeforeAll 'pfb_source'
	Before 'setup'
	After 'cleanup'

	It 'never promotes a crash-leftover pfB_Match_Rep_<alias>.txt.new debris on a clean no-offender dmax pass (GeoIP healthy)'
		printf '9.9.9.0/24\n!9.9.9.9\n' > "${pfbmatchgen}pfB_Match_Rep_STALE_v4.txt.new"
		printf '192.0.2.1\n' > "${snap}/STALE_v4.orig"
		printf '%s\n' "${snap}/STALE_v4.orig" > "$memberlist"

		When call silently pfb_recompute recompute v4 "$memberlist" "$countsfile" on dmax 100 US off block
		The status should be success
		The path "${pfbmatchgen}pfB_Match_Rep_STALE_v4.txt" should not be exist
	End

	It 'keeps ALL previous match artifacts (+ logs) when GeoIP is unavailable this pass, instead of destructively reconciling them away'
		rm -f "$pathgeoip" "$pathgeoipdat"
		printf '5.5.5.0/24\n!5.5.5.5\n' > "${pfbmatchgen}pfB_Match_Rep_ALIAS_v4.txt"
		printf '192.0.2.1\n192.0.2.2\n192.0.2.3\n' > "${snap}/ALIAS_v4.orig"
		printf '%s\n' "${snap}/ALIAS_v4.orig" > "$memberlist"

		When call silently pfb_recompute recompute v4 "$memberlist" "$countsfile" on dmax 1 US off block
		The status should be success
		The contents of file "${pfbmatchgen}pfB_Match_Rep_ALIAS_v4.txt" should equal "$(printf '5.5.5.0/24\n!5.5.5.5')"
		The contents of file "${errorlog}" should include 'GeoIP unavailable'
	End

	It 'clears a stale consolidated exempt file once a clean (offender-free) dmax pass confirms zero cc-list matches (exempt-file symmetry, issue #1084 review)'
		printf '1.1.1.0/24\n!1.1.1.1\n' > "${pfbmatchgen}pfB_Match_Exempt_v4.txt"
		printf '192.0.2.1\n' > "${snap}/CLEAN_v4.orig"
		printf '%s\n' "${snap}/CLEAN_v4.orig" > "$memberlist"

		When call silently pfb_recompute recompute v4 "$memberlist" "$countsfile" on dmax 100 US match off
		The status should be success
		The path "${pfbmatchgen}pfB_Match_Exempt_v4.txt" should not be exist
	End

	It 'keeps v4 exempt and v6 reputation artifacts byte-identical when a direct v6 call carries dmax arguments'
		printf '1.1.1.0/24\n!1.1.1.1\n' > "${pfbmatchgen}pfB_Match_Exempt_v4.txt"
		printf '2a01:db8::/64\n!2a01:db8::1\n' > "${pfbmatchgen}pfB_Match_Rep_Six_v6.txt"
		cp "${pfbmatchgen}pfB_Match_Exempt_v4.txt" "${work}/exempt.before"
		cp "${pfbmatchgen}pfB_Match_Rep_Six_v6.txt" "${work}/rep.before"
		printf '2001:db8::1\n' > "${snap}/Six_v6.orig"
		printf '%s\n' "${snap}/Six_v6.orig" > "$memberlist"

		When call recompute_v6_and_check_match_artifacts
		The status should be success
		The contents of file "${pfbdeny}Six_v6.txt" should equal '2001:db8::1'
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
		true > "${snap}/ZeroFeed_v4.orig"
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
		rec_countsfile="${work}/hostile.counts"
		printf 'Real_v4 3\n\n' > "$rec_countsfile"
		# shellcheck disable=SC2034  # read by the sourced renderer
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

Describe 'pfb_recompute_finish() skips identical member swap (issue #3158)'
	# Direct call: the swap loop is the defect, not the compute. rec_dedup=off
	# and rec_do_rep=0 skip masterfile / reputation arms so only member
	# aliases + the countsfile staging are in play.
	# shellcheck disable=SC2034
	setup() {
		work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/recident.XXXXXX")"
		pfbdeny="${work}/deny/"; mkdir -p "$pfbdeny"
		errorlog="${work}/err.log"; true > "$errorlog"
		rec_family='v4'
		rec_prio=2
		rec_dedup='off'
		rec_repmode='off'
		rec_do_rep=0
		rec_ccwhite='off'
		rec_priority="${work}/priority"
		rec_countsfile="${work}/counts"
		rec_countsfile_new="${rec_countsfile}.new"
		printf 'Keep_v4 1\nChange_v4 2\n' > "$rec_priority"
		printf '192.0.2.1\n' > "${pfbdeny}Keep_v4.txt"
		printf '192.0.2.1\n' > "${pfbdeny}Keep_v4.txt.new"
		printf '198.51.100.1\n' > "${pfbdeny}Change_v4.txt"
		printf '198.51.100.9\n' > "${pfbdeny}Change_v4.txt.new"
		printf 'Keep_v4 1\nChange_v4 1\n' > "$rec_countsfile_new"
		touch -t 200001010000.00 "${pfbdeny}Keep_v4.txt"
		touch -t 200001010000.00 "${pfbdeny}Change_v4.txt"
		pfb_mtime "${pfbdeny}Keep_v4.txt" > "${work}/keep.before"
		pfb_mtime "${pfbdeny}Change_v4.txt" > "${work}/change.before"
	}
	cleanup() { rm -rf "$work"; }
	pfb_mtime() { stat -c %Y "$1" 2>/dev/null || stat -f %m "$1"; }
	run_finish_check_mtimes() {
		keep_before=$(cat "${work}/keep.before")
		change_before=$(cat "${work}/change.before")
		pfb_recompute_finish >/dev/null 2>&1 || return $?
		keep_after=$(pfb_mtime "${pfbdeny}Keep_v4.txt")
		change_after=$(pfb_mtime "${pfbdeny}Change_v4.txt")
		[ "$keep_after" = "$keep_before" ] || {
			printf 'Keep_v4.txt mtime moved: %s -> %s\n' "$keep_before" "$keep_after" >&2
			return 1
		}
		[ "$change_after" != "$change_before" ] || {
			printf 'Change_v4.txt mtime did not move: %s\n' "$change_before" >&2
			return 1
		}
		return 0
	}
	BeforeAll 'pfb_source'
	Before 'setup'
	After 'cleanup'

	It 'leaves a byte-identical member mtime unchanged and cleans .new; publishes a differing member'
		When call run_finish_check_mtimes
		The status should be success
		The contents of file "${pfbdeny}Keep_v4.txt" should equal '192.0.2.1'
		The path "${pfbdeny}Keep_v4.txt.new" should not be exist
		The contents of file "${pfbdeny}Change_v4.txt" should equal '198.51.100.9'
		The path "${pfbdeny}Change_v4.txt.new" should not be exist
	End
End
