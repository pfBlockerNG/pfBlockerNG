#shellcheck shell=sh
# issue #2778: ET input is staged separately from the live publication. Category
# no-match (grep rc 1) is normal; hard grep errors and invalid/empty replacements
# fail through processet()'s exit contract without touching a good live list.

Describe 'processet() validates staged ET category output before publication (issue #2778)'
	portable_binary_stderr() {
		case "${portable_binary_stderr}" in
			''|"grep: ${raw}: binary file matches") return 0 ;;
		esac
		return 1
	}

	setup() {
		work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/etpublish.XXXXXX")"
		orig="${work}/orig/"
		match="${work}/match/"
		etdir="${work}/etdir"
		scratch="${work}/scratch"
		alias='EtFeed'
		errorlog="${work}/error.log"
		runner="${work}/run.sh"
		live="${orig}${alias}.orig"
		raw="${orig}${alias}.raw"
		prior='198.51.100.77'
		prior_category='203.0.113.99'
		mkdir -p "${orig}" "${match}" "${etdir}" "${scratch}"
		printf '%s\n' "${prior}" > "${live}"
		printf '%s\n' "${prior_category}" > "${etdir}/ET_Cnc.txt"

		cat > "${runner}" <<RUNNER
#!/bin/sh
PFB_SOURCED=1
. "${PFB_PKGDIR}/pfblockerng.sh"
pfborig="${orig}"
alias="${alias}"
etdir="${etdir}"
pfbmatchgen="${match}"
errorlog="${errorlog}"
tempfile="${scratch}/et.tmp"
tempfile2="${scratch}/et2.tmp"
etblock="\${1:-ET_Cnc}"
etmatch="\${2:-x}"
now='2026-01-01 00:00:00'
ip_placeholder2='127\.1\.7\.7'
processet
RUNNER
		chmod +x "${runner}"
	}

	cleanup() {
		chmod -R u+w "${work}" 2>/dev/null
		rm -rf "${work}"
	}
	Before 'setup'
	After 'cleanup'


	Context 'when the staged body has no commas'
		It 'refuses the empty replacement and keeps the live publication'
			printf '%s\n' 'not an ET CSV' > "${raw}"
			When run sh "${runner}"
			The status should be failure
			The output should include 'ET processing failed'
			The contents of file "${live}" should equal "${prior}"
			The contents of file "${live}" should not include "${work}"
			The contents of file "${etdir}/ET_Cnc.txt" should equal "${prior_category}"
		End
	End

	Context 'when the staged body has a nonnumeric category'
		It 'refuses the empty replacement and keeps the live publication'
			printf '%s\n' '192.0.2.10,not-a-category,90' > "${raw}"
			When run sh "${runner}"
			The status should be failure
			The output should include 'ET processing failed'
			The contents of file "${live}" should equal "${prior}"
			The contents of file "${live}" should not include "${work}"
			The contents of file "${etdir}/ET_Cnc.txt" should equal "${prior_category}"
		End
	End

	Context 'when grep emits its binary-file diagnostic'
		It 'rejects the diagnostic instead of publishing its scratch path'
			printf '192.0.2.10,1,90\000tail\n' > "${raw}"
			When run sh "${runner}"
			The status should be failure
			The output should include 'ET processing failed'
			The stderr should satisfy portable_binary_stderr
			The contents of file "${live}" should equal "${prior}"
			The contents of file "${live}" should not include "${work}"
			The contents of file "${etdir}/ET_Cnc.txt" should equal "${prior_category}"
		End
	End

	Context 'when a conforming grep emits matching binary bytes'
		It 'rejects the NUL-bearing category and preserves the prior category generation'
			mkdir "${work}/shim"
			cat > "${work}/shim/grep" <<'SHIM'
#!/bin/sh
exec /usr/bin/grep -a "$@"
SHIM
			chmod +x "${work}/shim/grep"
			printf '%s\n' "${prior_category}" > "${etdir}/ET_Cnc.txt"
			printf '192.0.2.10\000garbage,1,90\n' > "${raw}"
			When run sh -c "PATH='${work}/shim:${PATH}' sh '${runner}'"
			The status should be failure
			The output should include 'ET processing failed'
			The contents of file "${live}" should equal "${prior}"
			The contents of file "${etdir}/ET_Cnc.txt" should equal "${prior_category}"
		End
	End

	Context 'when the staged body is UTF-16LE with a BOM'
		It 'rejects the NUL-bearing rows and keeps the live publication'
			printf '\377\3761\0009\0002\000.\0000\000.\0002\000.\0001\0000\000,\0001\000,\0009\0000\000\n\000' > "${raw}"
			When run sh "${runner}"
			The status should be failure
			The output should include 'ET processing failed'
			The contents of file "${live}" should equal "${prior}"
			The contents of file "${live}" should not include "${work}"
			The contents of file "${etdir}/ET_Cnc.txt" should equal "${prior_category}"
		End
	End

	Context 'when the staged source is unreadable'
		It 'returns grep hard failure through the existing exit contract'
			printf '%s\n' '192.0.2.10,1,90' > "${raw}"
			chmod 000 "${raw}"
			When run sh "${runner}"
			The status should equal 2
			The output should include 'ET processing failed'
			The stderr should not equal ''
			The contents of file "${errorlog}" should include 'exit 2'
			The contents of file "${live}" should equal "${prior}"
			The contents of file "${etdir}/ET_Cnc.txt" should equal "${prior_category}"
		End
	End

	Context 'when PHP staged a decompressed archive payload'
		It 'processes the isolated CSV stage instead of the compressed raw source'
			printf '\037\213\010\000compressed\n' > "${raw}"
			printf '%s\n' '192.0.2.10,1,90' > "${live}.etstage"
			When run sh "${runner}"
			The status should be success
			The output should include 'Final count'
			The contents of file "${live}" should equal '192.0.2.10'
			The contents of file "${raw}" should not equal '192.0.2.10,1,90'
		End
	End

	Context 'when every selected category has valid IPv4 rows'
		It 'publishes only the derived addresses'
			printf '%s\n' '192.0.2.10,1,90' '203.0.113.20,2,80' > "${raw}"
			When run sh "${runner}" 'ET_Cnc, ET_Bot' x
			The status should be success
			The output should include 'Final count'
			The contents of file "${live}" should equal "$(printf '%s\n' '203.0.113.20' '192.0.2.10')"
			The contents of file "${live}" should not include "${work}"
		End
	End

	Context 'when one selected category has no rows'
		It 'treats grep rc 1 as an empty category and publishes the valid sibling'
			printf '%s\n' '192.0.2.10,1,90' > "${raw}"
			When run sh "${runner}" 'ET_Cnc, ET_Bot' x
			The status should be success
			The output should include 'Final count'
			The contents of file "${live}" should equal '192.0.2.10'
		End
	End

	Context 'when the selected categories derive an empty candidate'
		It 'does not replace a non-empty live publication'
			printf '%s\n' '203.0.113.20,2,80' > "${raw}"
			When run sh "${runner}" ET_Cnc x
			The status should be failure
			The output should include 'ET processing failed'
			The contents of file "${live}" should equal "${prior}"
			The contents of file "${live}" should not include "${work}"
			The contents of file "${etdir}/ET_Cnc.txt" should equal "${prior_category}"
		End
	End
End
