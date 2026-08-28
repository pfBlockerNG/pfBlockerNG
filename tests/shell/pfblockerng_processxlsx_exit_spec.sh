#shellcheck shell=sh
# issue #2666: processxlsx() had no exit contract. It ran two unchecked `tar`
# invocations and a pipeline whose status nobody read, then ended on an `echo`,
# so its exit status was that `echo`'s -- always 0. Its caller in pfb_download()
# therefore decided the ingest had succeeded by testing that the output file
# existed, which a half-written file satisfies just as well as a complete one.
#
# These examples pin the contract the caller now gates on: every failing step
# reports non-zero, and the publication is staged so a failed run leaves the
# ".orig" already in service byte-unchanged instead of overwriting it with the
# empty or partial remains of the attempt.
#
# issue #2682: an extraction that parses but yields no address is one of those
# failing steps. `grep` reports it (exit 1, no lines selected) and that status is
# now read, so the feed is refused rather than published as zero bytes.
#
# Fixture shape: the downloaded ".raw" container holds one "*.xlsx" member, and
# that member is itself an archive holding "xl/sharedStrings.xml" -- the two
# layers processxlsx() opens. Real feeds ship ZIP containers; these fixtures are
# tars because the function only ever calls ${pathtar} with -xf/-xOf and the
# statuses under test are the same either way, while GNU tar (the CI runner's
# /usr/bin/tar) cannot read a ZIP at all -- a ZIP fixture would silently reduce
# this whole file to a macOS-only test.

Describe 'processxlsx() exit contract (issue #2666)'
	setup() {
		work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/xlsxexit.XXXXXX")"
		orig="${work}/orig/"
		alias='XlsxFeed'
		errorlog="${work}/error.log"
		runner="${work}/run.sh"
		mkdir -p "${orig}" "${work}/scratch" "${work}/build" "${work}/inner/xl"
		# The two addresses the fixture's shared-strings part carries, in the
		# LC_ALL=C sorted -u order processxlsx() publishes them in.
		expected="$(printf '%s\n' '192.0.2.10' '198.51.100.20')"
		# What a live publication looks like before a failed refresh: a failure
		# must leave exactly this behind.
		prior="$(printf '%s\n' '203.0.113.7' 'PRIOR-MARKER')"

		# processxlsx() reads its inputs from the top-level init's globals, which
		# never resolve off-appliance. Source the script as a library, point those
		# globals at the fixture, and call the function -- from a real child
		# process, so an example may impose an RLIMIT_FSIZE without the shellspec
		# harness itself then writing under it. $1 overrides the tar path.
		cat > "${runner}" <<RUNNER
#!/bin/sh
PFB_SOURCED=1
. "${PFB_PKGDIR}/pfblockerng.sh"
pathtar="\${1:-$(command -v tar)}"
pfborig="${orig}"
alias="${alias}"
tmpxlsx="${work}/scratch/"
errorlog="${errorlog}"
now='2026-01-01 00:00:00'
ip_placeholder2='127\.1\.7\.7'
processxlsx
RUNNER
		chmod +x "${runner}"
	}
	cleanup() { rm -rf "$work"; }
	Before 'setup'
	After 'cleanup'

	# A healthy container: outer archive holding an inner archive holding the
	# shared-strings part the addresses are read out of. The payload repeats one
	# address and lists them out of order, so every example that asserts
	# "${expected}" also pins the staging sort and its de-duplication.
	plant_healthy_raw() {
		printf '<si><t>198.51.100.20</t></si><si><t>192.0.2.10</t></si><si><t>198.51.100.20</t></si>\n' \
			> "${work}/inner/xl/sharedStrings.xml"
		( cd "${work}/inner" && tar -cf "${work}/build/${alias}.xlsx" xl )
		( cd "${work}/build" && tar -cf "${orig}${alias}.raw" "${alias}.xlsx" )
	}

	# A container whose workbook PARSES but carries no IPv4 literal at all: the
	# shape issue #2682 names -- an address column that came up empty, or a
	# workbook whose addresses live in an inline-string part instead of the
	# shared-strings table.
	plant_addressless_raw() {
		printf '<sst><si><t>Hostname</t></si><si><t>example.invalid</t></si><si><t>2001:db8::1</t></si></sst>\n' \
			> "${work}/inner/xl/sharedStrings.xml"
		( cd "${work}/inner" && tar -cf "${work}/build/${alias}.xlsx" xl )
		( cd "${work}/build" && tar -cf "${orig}${alias}.raw" "${alias}.xlsx" )
	}

	# A live publication left by a previous, successful run.
	plant_prior_publication() {
		printf '%s\n' "${prior}" > "${orig}${alias}.orig"
	}

	Context 'on a healthy container'
		Before 'plant_healthy_raw'

		It 'publishes the extracted addresses and reports success'
			When run sh "${runner}"
			The status should be success
			The contents of file "${orig}${alias}.orig" should equal "${expected}"
			# The one context where this can fail: the staged file really was
			# written here, so a publish that copied instead of renaming, or
			# forgot to clean up, would leave it behind.
			The path "${orig}${alias}.orig.tmp" should not be exist
			The output should include 'Final count'
		End
	End

	Context 'on a workbook that parses but carries no IPv4 literal'
		# issue #2682: `grep` exits 1 when nothing matched, but piped into `sort`
		# that status was lost -- a pipeline reports only its last command -- so
		# such a workbook staged zero bytes at status 0 and published them over
		# the last-good ".orig". Nothing downstream caught it either: an empty
		# file probes as "inode/x-empty", which pfb_download()'s inner-content
		# MIME gate allow-lists, so the ingest reported success and refreshed the
		# feed's content-hash sidecar for it.
		Before 'plant_prior_publication'
		Before 'plant_addressless_raw'

		It 'refuses the refresh and keeps the live publication byte-unchanged'
			When run sh "${runner}"
			The status should be failure
			The contents of file "${orig}${alias}.orig" should equal "${prior}"
			The path "${orig}${alias}.orig.tmp" should not be exist
			The output should include 'XLSX processing failed'
			# The sibling refusal line, verbatim: the operator reads the refusal
			# and that the previous publication is what stayed in service.
			The contents of file "${errorlog}" should include " [ ${alias} ] XLSX processing failed, exit 1; keeping existing [ 2026-01-01 00:00:00 ]"
		End
	End

	Context 'on an addressless workbook with no publication yet'
		# issue #2682, first fetch: with no ".orig" to keep, the refusal must
		# leave the feed absent rather than publish zero bytes as its content.
		Before 'plant_addressless_raw'

		It 'refuses without manufacturing an empty publication'
			When run sh "${runner}"
			The status should be failure
			The path "${orig}${alias}.orig" should not be exist
			The path "${orig}${alias}.orig.tmp" should not be exist
			The output should include 'XLSX processing failed'
		End
	End

	Context 'when the outer container is corrupt'
		# The first tar's status was never read: extraction failed, the scratch
		# directory stayed empty, and the pipeline still truncated the live .orig
		# to nothing while the function returned 0.
		plant_corrupt_raw() { printf 'this is not an archive\n' > "${orig}${alias}.raw"; }
		Before 'plant_prior_publication'
		Before 'plant_corrupt_raw'

		It 'fails and keeps the live publication byte-unchanged'
			When run sh "${runner}"
			The status should be failure
			The contents of file "${orig}${alias}.orig" should equal "${prior}"
			The output should include 'XLSX processing failed'
			The contents of file "${errorlog}" should include 'keeping existing'
			The stderr should be present
		End
	End

	Context 'when the container is truncated mid-stream'
		# The shape a child killed at the extraction ceiling leaves behind, and the
		# one issue #2666 names by hand: a container whose bytes simply stop.
		plant_truncated_raw() {
			plant_healthy_raw
			dd if="${orig}${alias}.raw" of="${work}/cut" bs=1 count=600 2>/dev/null
			mv -f "${work}/cut" "${orig}${alias}.raw"
		}
		Before 'plant_prior_publication'
		Before 'plant_truncated_raw'

		It 'fails and keeps the live publication byte-unchanged'
			When run sh "${runner}"
			The status should be failure
			The contents of file "${orig}${alias}.orig" should equal "${prior}"
			The output should include 'XLSX processing failed'
			The stderr should be present
		End
	End

	Context 'when the inner .xlsx member is not an archive'
		# The second tar's status was masked by the pipeline it fed: with nothing
		# on its stdin the grep matched nothing and `sort -u` still exited 0, so a
		# feed whose payload could not be read published as an EMPTY success.
		plant_bad_member() {
			printf 'not an archive either\n' > "${work}/build/${alias}.xlsx"
			( cd "${work}/build" && tar -cf "${orig}${alias}.raw" "${alias}.xlsx" )
		}
		Before 'plant_prior_publication'
		Before 'plant_bad_member'

		It 'fails and keeps the live publication byte-unchanged'
			When run sh "${runner}"
			The status should be failure
			The contents of file "${orig}${alias}.orig" should equal "${prior}"
			The output should include 'XLSX processing failed'
			The stderr should be present
		End
	End

	Context 'when the publication cannot be staged'
		# Crash-leftover DIRECTORY at the staged path, the issue #1172 fixture
		# class: the failure lands on the pipeline that WRITES the publication
		# rather than on one of the two tars ahead of it.
		plant_stage_debris() { mkdir "${orig}${alias}.orig.tmp"; }
		Before 'plant_healthy_raw'
		Before 'plant_prior_publication'
		Before 'plant_stage_debris'

		It 'fails and keeps the live publication byte-unchanged'
			When run sh "${runner}"
			The status should be failure
			The contents of file "${orig}${alias}.orig" should equal "${prior}"
			The output should include 'XLSX processing failed'
			The stderr should be present
		End

		It 'clears the debris, so the next healthy run is not refused too'
			# The cleanup has to remove a directory, not just a file. Leaving it
			# makes every later run fail against the same leftover: one crash mid
			# publish would take the feed down until someone cleaned up by hand.
			When run sh -c "sh '${runner}' >/dev/null 2>&1; sh '${runner}'"
			The status should be success
			The contents of file "${orig}${alias}.orig" should equal "${expected}"
			The path "${orig}${alias}.orig.tmp" should not be exist
			The output should include 'Final count'
		End
	End

	Context 'when the stage that writes the publication is killed'
		# What the extraction ceiling does, modelled at the one stage the two tars
		# ahead of it cannot mask: SIGXFSZ kills whichever child writes past the
		# limit, and the shell reports that as 128 + 25. The status has to come
		# back verbatim, because pfb_extract_cap_note() reads exactly 153 to tell
		# the operator "too large" instead of printing a bare exit code.
		plant_killed_sort() {
			mkdir -p "${work}/shim"
			printf '#!/bin/sh\nhead -c 32 > "%s"\nexit 153\n' "${orig}${alias}.orig.tmp" \
				> "${work}/shim/sort"
			chmod +x "${work}/shim/sort"
		}
		Before 'plant_healthy_raw'
		Before 'plant_prior_publication'
		Before 'plant_killed_sort'

		It 'returns the kill status verbatim and keeps the live publication'
			When run sh -c "PATH='${work}/shim:${PATH}' sh '${runner}'"
			The status should equal 153
			The contents of file "${orig}${alias}.orig" should equal "${prior}"
			The path "${orig}${alias}.orig.tmp" should not be exist
			The output should include 'XLSX processing failed'
			The contents of file "${errorlog}" should include 'exit 153'
		End
	End

	Context 'when the download is missing'
		Before 'plant_prior_publication'

		It 'fails and keeps the live publication byte-unchanged'
			When run sh "${runner}"
			The status should be failure
			The output should include 'XLSX download file missing'
			The contents of file "${orig}${alias}.orig" should equal "${prior}"
			The contents of file "${errorlog}" should include 'XLSX download file missing'
		End
	End

	Context 'when tar is not executable'
		plant_no_tar() { printf 'not executable\n' > "${work}/notar"; }
		Before 'plant_healthy_raw'
		Before 'plant_no_tar'

		It 'fails instead of falling through to the extraction'
			When run sh "${runner}" "${work}/notar"
			The status should be failure
			The output should include 'Application [ TAR ] Not found'
		End
	End

	Context 'on a container holding more than one workbook'
		# The glob splats into tar's argument list, where every match after the
		# first is read as a MEMBER selector rather than a second archive -- so tar
		# reports "not found in archive" and exits non-zero while still writing the
		# first workbook's part correctly. Harmless while the status was discarded;
		# once it is read, only reading the first workbook keeps such a feed
		# ingesting exactly as it did before.
		plant_two_workbooks() {
			plant_healthy_raw
			cp "${work}/build/${alias}.xlsx" "${work}/build/second.xlsx"
			( cd "${work}/build" && tar -cf "${orig}${alias}.raw" "${alias}.xlsx" second.xlsx )
		}
		Before 'plant_two_workbooks'

		It 'publishes the first workbook rather than refusing the feed'
			When run sh "${runner}"
			The status should be success
			The contents of file "${orig}${alias}.orig" should equal "${expected}"
			The output should include 'Final count'
			# Naming one archive also silences tar's "not found in archive" complaint
			# about the workbooks it was reading as member selectors.
			The stderr should equal ''
		End
	End

	Context 'under a restrictive umask'
		# Published feeds have unprivileged readers. Truncating the live file in
		# place used to keep its mode; replacing it by rename hands it whatever the
		# run's umask allows, so the publish sets the mode explicitly (the reason
		# pfb_stage_publish() chmods its staged file too).
		Before 'plant_healthy_raw'

		It 'publishes a world-readable file regardless of the run umask'
			When run sh -c "umask 077; sh '${runner}' >/dev/null 2>&1; ls -l '${orig}${alias}.orig' | cut -c1-10"
			The status should be success
			The output should equal '-rw-r--r--'
		End
	End

	Context 'when the extraction ceiling fires'
		# issue #2658's ceiling (pfb_extract_cmd() -> `ulimit -f`) is what the
		# caller wraps this helper in: RLIMIT_FSIZE is inherited by every
		# descendant, so a write past the ceiling kills whichever child is doing
		# it. Before the exit contract that kill was invisible -- the function
		# still returned 0 with a truncated file in place, which is exactly why
		# this call site was left uncapped. One 512-byte block is far below the
		# fixture, so a child is guaranteed to be killed.
		Before 'plant_healthy_raw'
		Before 'plant_prior_publication'

		It 'refuses the feed instead of publishing the truncated remains of one'
			When run sh -c "ulimit -f 1 || exit 1; sh '${runner}' >/dev/null 2>&1"
			The status should be failure
			The contents of file "${orig}${alias}.orig" should equal "${prior}"
		End
	End
End

Describe 'pfblockerng.sh xlsx dispatch arm (issue #2666)'
	# The script tail's bare `exitnow` defaults to 0, so processxlsx()'s status
	# would be discarded at the process boundary even once the function reports
	# one -- the same wiring bug the `recompute` arm fixed in issue #1084. Runs
	# the REAL entrypoint: the propagation lives in the dispatch, not in the
	# function.
	It 'exits non-zero when the feed has no downloaded container'
		# Off-appliance /var/db/pfblockerng/original/ holds nothing, so the
		# missing-download branch is the one reached, before any appliance-only
		# tool is needed.
		When run sh "${PFB_PKGDIR}/pfblockerng.sh" xlsx NoSuchFeed x
		The status should be failure
		The stdout should include 'XLSX download file missing'
		# The top-level init spews unrelated noise off-appliance (missing
		# read_xml_tag.sh, /cf/conf/config.xml, unwritable /var/db) -- real but
		# incidental here, so only asserted as present.
		The stderr should not equal ''
	End
End
