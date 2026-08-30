#shellcheck shell=sh
# issue #2683: processet() reported no exit status. Its scratch-file abort used a
# bare `return`, so the function handed back whatever the preceding command had
# left behind, and the steps that WRITE -- the per-category splits, the two
# accumulations and the two publishes -- had no status read at all. The `et)`
# dispatch arm then fell through to the script tail's bare `exitnow`, which
# defaults to 0, so an aborted ET pass exited the process 0 and pfb_download()
# could not tell it from a completed one.
#
# These examples pin the contract the caller now gates on: every abort reports
# non-zero, a failing status comes back VERBATIM (so a child killed at issue
# #2658's extraction ceiling reaches the caller as the status that names it), and a
# failed pass leaves the live pfB_Match_ET_v4.txt publication byte-unchanged.
#
# Fixture shape: the feed's ".raw" is the staged ET IQRisk CSV ("IP,category,
# score"). processet() splits it into one file per category, accumulates the
# selected Block categories onto the live ".orig" and the selected Match
# categories onto pfB_Match_ET_v4.txt.

Describe 'processet() exit contract (issue #2683)'
	setup() {
		work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/etexit.XXXXXX")"
		orig="${work}/orig/"
		match="${work}/match/"
		etdir="${work}/etdir"
		scratch="${work}/scratch"
		alias='EtFeed'
		errorlog="${work}/error.log"
		runner="${work}/run.sh"
		mkdir -p "${orig}" "${match}" "${etdir}" "${scratch}"

		# The downloaded ET feed: two Block categories (1, 2) and one Match (3).
		et_csv="$(printf '%s\n' '192.0.2.10,1,127' '198.51.100.20,2,88' '203.0.113.30,3,50')"

		# `ls` sorts the category files, so the selected Block categories
		# accumulate in ALPHABETICAL order (ET_Bot, category 2, before ET_Cnc,
		# category 1) rather than in category-number order.
		expected="$(printf '%s\n' '198.51.100.20' '192.0.2.10')"
		expected_match='203.0.113.30'
		# What a live match publication looks like before a failed refresh: a
		# failure must leave exactly this behind.
		prior_match='PRIOR-MATCH-MARKER'
		prior_block='198.51.100.77'
		prior_hash='old-hash'
		prior_cnc='203.0.113.71'
		prior_bot='203.0.113.72'

		# processet() reads its inputs from the top-level init's globals, which
		# never resolve off-appliance. Source the script as a library, point those
		# globals at the fixture, and call the function -- from a real child
		# process, so an example may impose an RLIMIT_FSIZE without the shellspec
		# harness itself then writing under it, and so the child's exit status IS
		# the function's. $1/$2 override the selected Block/Match categories.
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
etblock="\${1:-ET_Cnc, ET_Bot}"
etmatch="\${2:-ET_Spam}"
now='2026-01-01 00:00:00'
ip_placeholder2='127\.1\.7\.7'
processet
RUNNER
		chmod +x "${runner}"
	}
	# A context that revokes write permission to force a failure has to hand it
	# back, or the tree cannot be removed.
	cleanup() {
		chmod -R u+w "${work}" 2>/dev/null
		rm -rf "${work}"
	}
	Before 'setup'
	After 'cleanup'

	plant_et_raw() {
		printf '%s\n' "${et_csv}" > "${orig}${alias}.raw"
	}

	# A live match publication left by a previous, successful pass.
	plant_prior_match() {
		printf '%s\n' "${prior_match}" > "${match}pfB_Match_ET_v4.txt"
	}

	plant_prior_generation() {
		printf '%s\n' "${prior_block}" > "${orig}${alias}.orig"
		printf '%s\n' "${prior_hash}" > "${orig}${alias}.orig.xxhash128"
		printf '%s\n' "${prior_match}" > "${match}pfB_Match_ET_v4.txt"
		printf '%s\n' "${prior_cnc}" > "${etdir}/ET_Cnc.txt"
		printf '%s\n' "${prior_bot}" > "${etdir}/ET_Bot.txt"
	}

	# A child killed the way the appliance's ceiling kills one: SIGXFSZ, which a
	# shell reports as 128 + 25. The shim stands in for the signal: a real
	# RLIMIT_FSIZE overrun does not report 153 everywhere (Darwin's awk exits 2),
	# while 153 is the status pfb_extract_cap_note() keys on.
	plant_killed_awk() {
		mkdir -p "${work}/shim"
		printf '#!/bin/sh\nexit 153\n' > "${work}/shim/awk"
		chmod +x "${work}/shim/awk"
	}

	Context 'on a healthy ET feed'
		Before 'plant_et_raw'
		Before 'plant_prior_match'

		It 'publishes both artifacts and reports success'
			When run sh "${runner}"
			The status should be success
			The contents of file "${orig}${alias}.orig" should equal "${expected}"
			The contents of file "${match}pfB_Match_ET_v4.txt" should equal "${expected_match}"
			The output should include 'Final count'
		End
	End

	Context 'when a selected Match category derives an empty replacement'
		Before 'plant_prior_match'

		It 'validates both candidates before publishing either one'
			printf '%s\n' '192.0.2.10,1,90' > "${orig}${alias}.raw"
			printf '%s\n' '198.51.100.77' > "${orig}${alias}.orig"
			When run sh "${runner}" ET_Cnc ET_Spam
			The status should be failure
			The output should include 'ET processing failed'
			The contents of file "${orig}${alias}.orig" should equal '198.51.100.77'
			The contents of file "${match}pfB_Match_ET_v4.txt" should equal "${prior_match}"
		End
	End

	Context 'when the ET scratch files cannot be created'
		# The abort issue #2683 names by hand. It printed its message and then
		# handed back the status of the `tee` that printed it -- 0.
		plant_readonly_scratch() { chmod 555 "${scratch}"; }
		Before 'plant_et_raw'
		Before 'plant_prior_generation'
		Before 'plant_readonly_scratch'

		It 'fails and keeps the live match publication byte-unchanged'
			When run sh "${runner}"
			The status should be failure
			The output should include 'cannot create ET scratch file'
			The contents of file "${match}pfB_Match_ET_v4.txt" should equal "${prior_match}"
			The contents of file "${orig}${alias}.orig" should equal "${prior_block}"
			The contents of file "${orig}${alias}.orig.xxhash128" should equal "${prior_hash}"
			The contents of file "${etdir}/ET_Cnc.txt" should equal "${prior_cnc}"
			The contents of file "${etdir}/ET_Bot.txt" should equal "${prior_bot}"
			The stderr should be present
		End
	End

	Context 'when no staged ET source is present'
		# The other abort: the function fell off the end of its `else` branch, so
		# its status was the closing `echo`'s.
		Before 'plant_prior_match'

		It 'fails instead of reporting a pass that processed nothing'
			When run sh "${runner}"
			The status should be failure
			The output should include 'No staged ET source file found!'
			The contents of file "${match}pfB_Match_ET_v4.txt" should equal "${prior_match}"
			The contents of file "${errorlog}" should include 'No staged ET source file'
		End
	End

	Context 'when a category split cannot be written'
		# The split is a pipeline, so its status is `cut`'s, not `grep`'s: a
		# category with no rows makes grep exit 1 and is entirely normal, while a
		# failed WRITE has to abort rather than publish a truncated block list.
		plant_readonly_etdir() { chmod 555 "${etdir}"; }
		Before 'plant_et_raw'
		Before 'plant_prior_match'
		Before 'plant_readonly_etdir'

		It 'fails and leaves both the feed and the live match publication untouched'
			When run sh "${runner}"
			The status should be failure
			The output should include 'ET processing failed'
			The contents of file "${match}pfB_Match_ET_v4.txt" should equal "${prior_match}"
			# The staged input stays available for pfb_download() to discard after
			# it observes this failure.
			The contents of file "${orig}${alias}.raw" should equal "${et_csv}"
			The stderr should be present
		End
	End

	Context 'when the block accumulation is killed'
		# The status has to come back VERBATIM, because pfb_extract_cap_note() reads
		# exactly 153 to tell the operator "too large" instead of printing a bare
		# exit code.
		#
		# The shim breaks every `awk` in the pass, so the two accumulations get one
		# example each with only their own categories selected -- otherwise whichever
		# runs first covers for the other and neither check is isolated.
		Before 'plant_et_raw'
		Before 'plant_prior_match'
		Before 'plant_killed_awk'

		It 'returns the kill status verbatim and publishes nothing'
			When run sh -c "PATH='${work}/shim:${PATH}' sh '${runner}' 'ET_Cnc, ET_Bot' x"
			The status should equal 153
			The contents of file "${match}pfB_Match_ET_v4.txt" should equal "${prior_match}"
			The output should include 'ET processing failed'
			The contents of file "${errorlog}" should include 'exit 153'
		End
	End

	Context 'when the match accumulation is killed'
		Before 'plant_et_raw'
		Before 'plant_prior_match'
		Before 'plant_killed_awk'

		It 'returns the kill status verbatim and keeps the live match publication'
			When run sh -c "PATH='${work}/shim:${PATH}' sh '${runner}' x ET_Spam"
			The status should equal 153
			The contents of file "${match}pfB_Match_ET_v4.txt" should equal "${prior_match}"
			The output should include 'ET processing failed'
			The contents of file "${errorlog}" should include 'exit 153'
		End
	End

	Context 'when the block publication cannot be moved into place'
		# The publish is a `mv` off the private temp directory, which is a separate
		# filesystem from /var on a default use_mfs_tmpvar install -- so it copies
		# rather than renames, and can fail on its own.
		plant_readonly_origdir() { chmod 555 "${orig}"; }
		Before 'plant_et_raw'
		Before 'plant_prior_generation'
		Before 'plant_readonly_origdir'

		It 'fails and keeps the live match publication byte-unchanged'
			When run sh "${runner}"
			The status should be failure
			The output should include 'ET processing failed'
			The contents of file "${match}pfB_Match_ET_v4.txt" should equal "${prior_match}"
			The contents of file "${orig}${alias}.orig" should equal "${prior_block}"
			The contents of file "${orig}${alias}.orig.xxhash128" should equal "${prior_hash}"
			The contents of file "${etdir}/ET_Cnc.txt" should equal "${prior_cnc}"
			The contents of file "${etdir}/ET_Bot.txt" should equal "${prior_bot}"
			The stderr should be present
		End
	End

	Context 'when the match publication cannot be moved into place'
		# The last write of the pass, and the only failure context that gets past
		# the block publish -- so this is where the pfB_Match_ET_v4.txt artifact
		# the issue names is the one left byte-unchanged by the failure itself.
		plant_readonly_matchdir() { chmod 555 "${match}"; }
		Before 'plant_et_raw'
		Before 'plant_prior_generation'
		Before 'plant_readonly_matchdir'

		It 'fails and keeps the live match publication byte-unchanged'
			When run sh "${runner}"
			The status should be failure
			The output should include 'ET processing failed'
			The contents of file "${match}pfB_Match_ET_v4.txt" should equal "${prior_match}"
			The contents of file "${orig}${alias}.orig" should equal "${prior_block}"
			The contents of file "${orig}${alias}.orig.xxhash128" should equal "${prior_hash}"
			The contents of file "${etdir}/ET_Cnc.txt" should equal "${prior_cnc}"
			The contents of file "${etdir}/ET_Bot.txt" should equal "${prior_bot}"
			The stderr should be present
		End
	End


	Context 'when an early category is valid and the next category is invalid'
		Before 'plant_prior_generation'

		It 'keeps the complete prior category and aggregate generation'
			printf '%s\n' '192.0.2.10,1,90' 'not-an-ip,2,80' > "${orig}${alias}.raw"
			When run sh "${runner}"
			The status should be failure
			The output should include 'ET processing failed'
			The contents of file "${orig}${alias}.orig" should equal "${prior_block}"
			The contents of file "${orig}${alias}.orig.xxhash128" should equal "${prior_hash}"
			The contents of file "${match}pfB_Match_ET_v4.txt" should equal "${prior_match}"
			The contents of file "${etdir}/ET_Cnc.txt" should equal "${prior_cnc}"
			The contents of file "${etdir}/ET_Bot.txt" should equal "${prior_bot}"
		End
	End

	Context 'when a same-filesystem block rename fails after writing partial bytes'
		Before 'plant_et_raw'
		Before 'plant_prior_generation'

		It 'restores every prior artifact and exposes same-directory staging'
			mkdir "${work}/shim"
			cat > "${work}/shim/mv" <<SHIM
#!/bin/sh
src=''
dest=''
for arg do
	case "\${arg}" in
		-*) ;;
		*) [ -z "\${src}" ] && src="\${arg}"; dest="\${arg}" ;;
	esac
done
if [ "\${dest}" = "${orig}${alias}.orig" ] && [ ! -e "${work}/block-failed" ]; then
	printf '%s' '192.' > "\${dest}"
	printf '%s\n%s\n' "\${src%/*}" "\${dest%/*}" > "${work}/block-paths"
	touch "${work}/block-failed"
	exit 73
fi
exec /bin/mv "\$@"
SHIM
			chmod +x "${work}/shim/mv"
			When run sh -c "PATH='${work}/shim:${PATH}' sh '${runner}'"
			The status should equal 73
			The output should include 'ET processing failed'
			The contents of file "${orig}${alias}.orig" should equal "${prior_block}"
			The contents of file "${orig}${alias}.orig.xxhash128" should equal "${prior_hash}"
			The contents of file "${match}pfB_Match_ET_v4.txt" should equal "${prior_match}"
			The contents of file "${etdir}/ET_Cnc.txt" should equal "${prior_cnc}"
			The contents of file "${etdir}/ET_Bot.txt" should equal "${prior_bot}"
			The contents of file "${work}/block-paths" should equal "$(printf '%s\n%s' "${orig%/}" "${orig%/}")"
		End
	End

	Context 'when the second aggregate rename fails after writing partial bytes'
		Before 'plant_et_raw'
		Before 'plant_prior_generation'

		It 'rolls block, Match, and categories back as one generation'
			mkdir "${work}/shim"
			cat > "${work}/shim/mv" <<SHIM
#!/bin/sh
src=''
dest=''
for arg do
	case "\${arg}" in
		-*) ;;
		*) [ -z "\${src}" ] && src="\${arg}"; dest="\${arg}" ;;
	esac
done
if [ "\${dest}" = "${match}pfB_Match_ET_v4.txt" ] && [ ! -e "${work}/match-failed" ]; then
	printf '%s' '203.' > "\${dest}"
	printf '%s\n%s\n' "\${src%/*}" "\${dest%/*}" > "${work}/match-paths"
	touch "${work}/match-failed"
	exit 73
fi
exec /bin/mv "\$@"
SHIM
			chmod +x "${work}/shim/mv"
			When run sh -c "PATH='${work}/shim:${PATH}' sh '${runner}'"
			The status should equal 73
			The output should include 'ET processing failed'
			The contents of file "${orig}${alias}.orig" should equal "${prior_block}"
			The contents of file "${orig}${alias}.orig.xxhash128" should equal "${prior_hash}"
			The contents of file "${match}pfB_Match_ET_v4.txt" should equal "${prior_match}"
			The contents of file "${etdir}/ET_Cnc.txt" should equal "${prior_cnc}"
			The contents of file "${etdir}/ET_Bot.txt" should equal "${prior_bot}"
			The contents of file "${work}/match-paths" should equal "$(printf '%s\n%s' "${match%/}" "${match%/}")"
		End
	End


	Context 'when an interrupted transaction left its rollback journal'
		It 'recovers the whole prior generation before processing new input'
			printf '%s\n' "${prior_hash}" > "${orig}${alias}.orig.xxhash128"
			printf '%s\n' 'partial-block' > "${orig}${alias}.orig"
			printf '%s\n' "${prior_block}" > "${orig}${alias}.orig.rollback"
			printf '%s\n' 'partial-match' > "${match}pfB_Match_ET_v4.txt"
			printf '%s\n' "${prior_match}" > "${match}pfB_Match_ET_v4.txt.rollback"
			printf '%s\n' 'partial-category' > "${etdir}/ET_Cnc.txt"
			mkdir "${etdir}.rollback"
			printf '%s\n' "${prior_cnc}" > "${etdir}.rollback/ET_Cnc.txt"
			printf '%s\n' "${prior_bot}" > "${etdir}.rollback/ET_Bot.txt"
			printf '%s\n' '1 1 1' > "${etdir}.transaction"
			printf '%s\n' 'not-an-ip,1,90' > "${orig}${alias}.raw"
			When run sh "${runner}"
			The status should be failure
			The output should include 'ET processing failed'
			The contents of file "${orig}${alias}.orig" should equal "${prior_block}"
			The contents of file "${orig}${alias}.orig.xxhash128" should equal "${prior_hash}"
			The contents of file "${match}pfB_Match_ET_v4.txt" should equal "${prior_match}"
			The contents of file "${etdir}/ET_Cnc.txt" should equal "${prior_cnc}"
			The contents of file "${etdir}/ET_Bot.txt" should equal "${prior_bot}"
			The path "${etdir}.transaction" should not be exist
		End
	End

	Context 'when the extraction ceiling fires'
		# issue #2658's ceiling (pfb_extract_cmd() -> `ulimit -f`) is what the
		# caller now wraps this helper in: RLIMIT_FSIZE is inherited by every
		# descendant, so a write past the ceiling kills whichever child is doing
		# it. One 512-byte block is far below this feed's ET_Cnc split, so a child
		# is guaranteed to be killed. The fixture carries Match rows too, so a pass
		# that got through would REPLACE the prior match publication -- the prior
		# surviving is therefore evidence of the refusal, not of an empty feed.
		plant_large_et_raw() {
			awk 'BEGIN { for (i = 1; i < 4000; i++) printf "192.0.2.%d,1,90\n203.0.113.%d,3,40\n", i % 254 + 1, i % 254 + 1 }' \
				> "${orig}${alias}.raw"
		}
		Before 'plant_large_et_raw'
		Before 'plant_prior_match'

		It 'refuses the feed instead of publishing the truncated remains of one'
			When run sh -c "ulimit -f 1 || exit 1; sh '${runner}' >/dev/null 2>&1"
			The status should be failure
			The contents of file "${match}pfB_Match_ET_v4.txt" should equal "${prior_match}"
		End
	End
End

Describe 'pfblockerng.sh et dispatch arm (issue #2683)'
	# The script tail's bare `exitnow` defaults to 0, so processet()'s status
	# would be discarded at the process boundary even once the function reports
	# one -- the same wiring bug the `recompute` arm fixed in issue #1084. Runs
	# the REAL entrypoint, because the propagation lives in the dispatch rather
	# than in the function.
	It 'exits non-zero when the feed has no staged ET source'
		# Off-appliance /var/db/pfblockerng/original/ holds nothing, so the
		# no-source abort is the one reached before any appliance-only tool is
		# needed. Argument order mirrors pfb_download()'s exec():
		# et <header> x x x x x <etblock> <etmatch> <elog>.
		When run sh "${PFB_PKGDIR}/pfblockerng.sh" et NoSuchEtFeed x x x x x ET_Cnc x
		The status should be failure
		The stdout should include 'No staged ET source file found!'
		# The top-level init spews unrelated noise off-appliance (missing
		# read_xml_tag.sh, /cf/conf/config.xml, unwritable /var/db) -- real but
		# incidental here, so only asserted as present.
		The stderr should not equal ''
	End
End
