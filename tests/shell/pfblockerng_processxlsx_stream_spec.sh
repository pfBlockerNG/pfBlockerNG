#shellcheck shell=sh
# issue #2684: processxlsx() wrote the workbook's decompressed "xl/sharedStrings.xml"
# to a file under the per-run temp directory before scanning it. That part is XML and
# expands by two orders of magnitude past the workbook that carries it -- this file's
# own fixture reaches roughly 4.2 MB from a ~21 KB workbook, and a real ZIP-in-ZIP
# workbook was measured at 10,083,388 bytes from 49,160 on disk -- while ${tmpdir}
# lives under /tmp, a RAM disk on a default use_mfs_tmpvar install. A workbook well
# inside every existing ceiling could therefore fill the temp filesystem, or be
# killed at issue #2658's inherited RLIMIT_FSIZE, where it previously streamed
# through a pipe and never touched the disk.
#
# It was written to a file because POSIX sh has no `pipefail`: piped, a pipeline
# reports only its last command's status, and issue #2666's exit contract needs
# tar's. `set -o pipefail` is not available either -- `set` is a special builtin, so
# an option a base system does not support aborts the whole script rather than
# failing one command. So tar's status is stashed out of band instead, and these
# examples pin BOTH halves of that: the part no longer lands in ${tmpdir}, and every
# status the pipe could have swallowed still refuses the feed.
#
# Fixture shape: the ".raw" container holds one "*.xlsx" member which is itself a
# COMPRESSED archive holding "xl/sharedStrings.xml" -- the two layers processxlsx()
# opens, with the expansion that is the whole point of the ticket. Real feeds ship
# ZIP containers; these are tars because the function only ever calls ${pathtar}
# with -xf/-xOf, and GNU tar (the CI runner's /usr/bin/tar) cannot read a ZIP at
# all, which would silently reduce this file to a macOS-only test. Both flavours
# auto-detect the inner compression on read with no explicit -z (probed: bsdtar
# 3.5.3 rc=0, GNU tar 1.35 rc=0).

Describe 'processxlsx() streams the shared-strings part (issue #2684)'
	setup() {
		work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/xlsxstream.XXXXXX")"
		orig="${work}/orig/"
		alias='XlsxFeed'
		errorlog="${work}/error.log"
		runner="${work}/run.sh"
		probe="${work}/probe.sh"
		scratch="${work}/scratch"
		# The whole part must fit far outside this, and the workbook plus the
		# published feed far inside it: 64 KiB sits between the two by two orders
		# of magnitude, so neither verdict rides on a narrow margin.
		bound=65536
		mkdir -p "${orig}" "${scratch}" "${work}/build" "${work}/inner/xl" "${work}/shim"
		expected="$(printf '%s\n' '192.0.2.10' '198.51.100.20')"
		prior="$(printf '%s\n' '203.0.113.7' 'PRIOR-MARKER')"

		# processxlsx() reads its inputs from the top-level init's globals, which
		# never resolve off-appliance. Source the script as a library, point those
		# globals at the fixture, and call the function -- from a real child
		# process, so an example may impose an RLIMIT_FSIZE without the shellspec
		# harness itself then writing under it.
		cat > "${runner}" <<RUNNER
#!/bin/sh
PFB_SOURCED=1
. "${PFB_PKGDIR}/pfblockerng.sh"
pathtar="$(command -v tar)"
pfborig="${orig}"
alias="${alias}"
tmpxlsx="${scratch}/"
errorlog="${errorlog}"
now='2026-01-01 00:00:00'
ip_placeholder2='127\.1\.7\.7'
processxlsx
RUNNER
		chmod +x "${runner}"

		# Sampling point for the footprint: the moment the `sort` sink runs. By then
		# the whole part has been consumed either way -- written to ${tmpdir} or
		# streamed through the pipe -- so both shapes are measured at the same
		# instant, and the sample is the peak because nothing in ${tmpdir} is removed
		# before it. A PATH shim takes the sample and then execs the real sort, so
		# the rest of the contract still runs underneath the measurement.
		cat > "${work}/shim/sort" <<SHIM
#!/bin/sh
find "${scratch}" -type f -exec cat {} + | wc -c | tr -d ' ' > "${work}/sink_bytes"
exec "$(command -v sort)" "\$@"
SHIM
		chmod +x "${work}/shim/sort"

		# Reports the measurement on EVERY verdict, so a failure prints the bytes
		# that produced it instead of a bare boolean, and exits with the run's own
		# status so the ingest is still under test. A sample below the workbook's
		# own size is reported as `unmeasured`, never as a win: the workbook IS in
		# ${tmpdir} at the sink in the shape this pins, so a shim that silently
		# stopped measuring -- an absent file, a broken `find`, an empty `wc` --
		# would otherwise read as the smallest possible footprint and pass.
		cat > "${probe}" <<PROBE
#!/bin/sh
PATH="${work}/shim:\${PATH}" sh "${runner}" >/dev/null 2>&1
rc=\$?
observed="\$(cat "${work}/sink_bytes" 2>/dev/null)"
part="\$(wc -c < "${work}/inner/xl/sharedStrings.xml" | tr -d ' ')"
workbook="\$(wc -c < "${work}/build/${alias}.xlsx" | tr -d ' ')"
case "\${observed}" in
	'' | *[!0-9]*) verdict=unmeasured ;;
	*)
		if [ "\${observed}" -lt "\${workbook}" ]; then
			verdict=unmeasured
		elif [ "\${observed}" -lt ${bound} ]; then
			verdict=streamed
		else
			verdict=materialised
		fi
		;;
esac
echo "verdict=\${verdict} tmpdir_bytes_at_sink=\${observed:-none} bound=${bound} part_bytes=\${part} workbook_bytes=\${workbook}"
exit "\${rc}"
PROBE
		chmod +x "${probe}"
	}
	cleanup() { rm -rf "$work"; }
	Before 'setup'
	After 'cleanup'

	# A shared-strings table is a DEDUPLICATED string pool with a small vocabulary --
	# category names, country codes, comment boilerplate -- referenced over and over
	# by the sheet, which is why it deflates by two orders of magnitude. Cycling a
	# bounded pool of distinct rows reproduces that shape; one endlessly repeated
	# token would compress past anything real, a random one past nothing at all.
	build_part() {
		awk 'BEGIN {
			for (n = 0; n < 128; n++) { line = line "<si><t>row-" (n % 16) "-category-not-an-address</t></si>" }
			printf "<sst><si><t>192.0.2.10</t></si>"
			for (r = 0; r < 720; r++) { printf "%s", line }
			print "<si><t>198.51.100.20</t></si></sst>"
		}' > "${work}/inner/xl/sharedStrings.xml"
	}

	# The same pool with both addresses removed: a workbook that parses and carries
	# the same expansion, but no IPv4 literal for `grep` to match (issue #2682).
	build_addressless_part() {
		awk 'BEGIN {
			for (n = 0; n < 128; n++) { line = line "<si><t>row-" (n % 16) "-category-not-an-address</t></si>" }
			printf "<sst>"
			for (r = 0; r < 720; r++) { printf "%s", line }
			print "</sst>"
		}' > "${work}/inner/xl/sharedStrings.xml"
	}

	# The workbook is compressed, like the real thing; the outer container is not,
	# because a real producer does not re-deflate an already-deflated ZIP -- so the
	# ".raw" pfb_download() hands over is about the size of the workbook it carries.
	# The payload repeats one address and lists them out of order, so every example
	# asserting "${expected}" also pins the staging sort and its de-duplication.
	plant_streaming_raw() {
		build_part
		( cd "${work}/inner" && tar -czf "${work}/build/${alias}.xlsx" xl )
		( cd "${work}/build" && tar -cf "${orig}${alias}.raw" "${alias}.xlsx" )
	}

	# A live publication left by a previous, successful run.
	plant_prior_publication() {
		printf '%s\n' "${prior}" > "${orig}${alias}.orig"
	}

	Context 'on a healthy production-shape workbook'
		Before 'plant_streaming_raw'

		It 'keeps the run temp directory to the workbook, not the part it expands to'
			When run sh "${probe}"
			The output should include 'verdict=streamed'
			The status should be success
			The contents of file "${orig}${alias}.orig" should equal "${expected}"
			The path "${orig}${alias}.orig.tmp" should not be exist
		End

		It 'ingests a workbook whose part expands past the extraction write ceiling'
			# The availability regression the ticket names. pfb_extract_cmd() wraps
			# this call site in `ulimit -f`, and RLIMIT_FSIZE is inherited by every
			# descendant, so materialising the part made a workbook well inside every
			# ceiling refusable on size alone. 64 KiB is above the workbook and the
			# published feed and two orders of magnitude below the part, so this
			# passes only if the part is never written to a file at all.
			When run sh -c "ulimit -f 128 || exit 1; sh '${runner}' >/dev/null 2>&1"
			The status should be success
			The contents of file "${orig}${alias}.orig" should equal "${expected}"
		End
	End

	Context 'on a workbook whose compressed part stops mid-stream'
		# The one shape where tar's own status is the ONLY evidence the read failed:
		# tar emits the leading megabytes -- an address among them -- and then dies,
		# so `grep` matches, exits 0, and a pipeline reports only that. Probed on the
		# fixture: bsdtar 3.5.3 exits 1 and GNU tar 1.35 exits 2, both after emitting
		# ~2 MiB carrying one address. Publishing that is issue #2666's defect
		# exactly -- a truncated feed reported as a successful ingest -- so the
		# streamed shape has to carry tar's status past the pipe to keep refusing it.
		plant_partial_workbook() {
			build_part
			( cd "${work}/inner" && tar -czf "${work}/build/${alias}.xlsx" xl )
			whole="$(wc -c < "${work}/build/${alias}.xlsx" | tr -d ' ')"
			dd if="${work}/build/${alias}.xlsx" of="${work}/cut" bs=512 \
				count="$((whole / 1024))" 2>/dev/null
			mv -f "${work}/cut" "${work}/build/${alias}.xlsx"
			( cd "${work}/build" && tar -cf "${orig}${alias}.raw" "${alias}.xlsx" )
		}
		Before 'plant_prior_publication'
		Before 'plant_partial_workbook'

		It 'refuses the feed and keeps the live publication byte-unchanged'
			When run sh "${runner}"
			The status should be failure
			The contents of file "${orig}${alias}.orig" should equal "${prior}"
			The path "${orig}${alias}.orig.tmp" should not be exist
			The output should include 'XLSX processing failed'
			The contents of file "${errorlog}" should include 'keeping existing'
			The stderr should be present
		End
	End

	Context 'on a production-shape workbook carrying no IPv4 literal'
		# issue #2682's refusal, on the compressed fixture and through the pipe:
		# `grep` is the pipeline's LAST stage, so its no-match exit 1 is the
		# pipeline's own status and still reaches the caller verbatim. Reading the
		# stashed tar status in a way that overwrote a clean tar's 0 onto this would
		# publish zero bytes over the last-good feed again.
		plant_addressless_raw() {
			build_addressless_part
			( cd "${work}/inner" && tar -czf "${work}/build/${alias}.xlsx" xl )
			( cd "${work}/build" && tar -cf "${orig}${alias}.raw" "${alias}.xlsx" )
		}
		Before 'plant_prior_publication'
		Before 'plant_addressless_raw'

		It 'refuses the refresh and keeps the live publication byte-unchanged'
			When run sh "${runner}"
			The status should be failure
			The contents of file "${orig}${alias}.orig" should equal "${prior}"
			The path "${orig}${alias}.orig.tmp" should not be exist
			The output should include 'XLSX processing failed'
			The contents of file "${errorlog}" should include " [ ${alias} ] XLSX processing failed, exit 1; keeping existing [ 2026-01-01 00:00:00 ]"
		End
	End

	Context 'on a container that carries a status stash of its own'
		# The stash is the one new file this shape writes, and the container is
		# UNTRUSTED: a member landing on that path would hand a remote feed the
		# status the publish gate reads. Paired with a workbook carrying no address
		# it is issue #2682's defect back under the container's control -- `grep`
		# reports no match, a planted `0` overrides it, and zero bytes publish over
		# the live feed as a success. So the stash is derived as a SIBLING of the
		# extraction target rather than a file inside it -- that derivation is the
		# whole defence; there is no clearing step between the unpack and the read.
		plant_planted_stash_raw() {
			printf '0\n' > "${work}/build/sharedStrings.rc"
			build_addressless_part
			( cd "${work}/inner" && tar -czf "${work}/build/${alias}.xlsx" xl )
			( cd "${work}/build" && tar -cf "${orig}${alias}.raw" sharedStrings.rc "${alias}.xlsx" )
		}
		Before 'plant_prior_publication'
		Before 'plant_planted_stash_raw'

		It 'refuses the addressless workbook anyway and keeps the live publication'
			When run sh "${runner}"
			The status should be failure
			The contents of file "${orig}${alias}.orig" should equal "${prior}"
			The path "${orig}${alias}.orig.tmp" should not be exist
			The output should include 'XLSX processing failed'
		End
	End

	Context 'on a container whose member name climbs out of the extraction target'
		# The sibling path the stash now uses is exactly one "../" away, so the
		# escape is worth pinning rather than assuming. Both flavours refuse the
		# member outright and extract nothing (probed: bsdtar 3.5.3 "Path contains
		# '..'" exit 1, GNU tar 1.35 "Member name contains '..'" exit 2), so the
		# feed is refused on the first tar and the stash is never reachable.
		plant_traversal_raw() {
			printf '0\n' > "${work}/build/climb"
			python3 - "${orig}${alias}.raw" "${work}/build/climb" <<'PY'
import io, sys, tarfile
data = open(sys.argv[2], 'rb').read()
with tarfile.open(sys.argv[1], 'w') as tf:
    info = tarfile.TarInfo('../scratch.rc')
    info.size = len(data)
    tf.addfile(info, io.BytesIO(data))
PY
		}
		Before 'plant_prior_publication'
		Before 'plant_traversal_raw'

		It 'refuses the feed and plants nothing beside the extraction target'
			When run sh "${runner}"
			The status should be failure
			The contents of file "${orig}${alias}.orig" should equal "${prior}"
			The path "${work}/scratch.rc" should not be exist
			The output should include 'XLSX processing failed'
			The stderr should be present
		End
	End

	Context 'when the extraction ceiling kills the stage that writes'
		# Streamed, tar's only output is the pipe, and RLIMIT_FSIZE does not bound
		# a pipe write (probed: 64 KiB through a pipe under `ulimit -f 1` exits 0
		# where the same bytes to a file exit 1). So issue #2658's ceiling can only
		# bite the stage that writes a FILE -- `grep`, here -- and when it does,
		# tar dies of EPIPE behind it. Its status must NOT be read over the 153:
		# pfb_extract_cap_note() keys on exactly that value to tell the operator
		# "too large" instead of printing a bare exit code, and tar's EPIPE status
		# (1 under bsdtar, 141 under GNU tar) carries no such meaning.
		plant_killed_grep() {
			printf '#!/bin/sh\nhead -c 32\nexit 153\n' > "${work}/shim/grep"
			chmod +x "${work}/shim/grep"
		}
		Before 'plant_streaming_raw'
		Before 'plant_prior_publication'
		Before 'plant_killed_grep'

		It 'returns the kill status verbatim and keeps the live publication'
			When run sh -c "PATH='${work}/shim:${PATH}' sh '${runner}'"
			The status should equal 153
			The contents of file "${orig}${alias}.orig" should equal "${prior}"
			The path "${orig}${alias}.orig.tmp" should not be exist
			The output should include 'XLSX processing failed'
			The stderr should be present
			The contents of file "${errorlog}" should include 'exit 153'
		End
	End
End
