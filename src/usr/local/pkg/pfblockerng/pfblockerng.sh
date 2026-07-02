#!/bin/sh
# pfBlockerNG Shell Function Script - By BBcan177@gmail.com - 04-12-14
# Copyright (c) 2015-2023 BBcan177@gmail.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License Version 2 as
# published by the Free Software Foundation.  You may not use, modify or
# distribute this program under any other version of the GNU General
# Public License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.


# Create a private per-run temp directory and define the temp file paths beneath
# it. Using mktemp(1) instead of a low-entropy PRNG (jot) closes the predictable
# /tmp-path TOCTOU/symlink hole for this root-run script (issue #30). exitnow()
# removes the whole directory on exit.
pfb_make_tmpdir() {
	tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/pfb.XXXXXXXX")" || exit 1
	tempfile="${tmpdir}/pfbtemp1"
	tempfile2="${tmpdir}/pfbtemp2"
	dupfile="${tmpdir}/pfbtemp3"
	dedupfile="${tmpdir}/pfbtemp4"
	addfile="${tmpdir}/pfbtemp5"
	matchfile="${tmpdir}/pfbtemp7"
	tempmatchfile="${tmpdir}/pfbtemp8"
	# XLSX extraction scratch dir (issue #714) -- was a fixed /tmp/xlsx/ path
	# (mkdir guarded only by "[ ! -d ]", which follows symlinks): a predictable
	# world-writable location TOCTOU/symlink-attackable by another local user
	# against this root-run script. Folding it under the private 0700 mktemp
	# dir closes that hole the same way issue #30 closed it for the other temp
	# files above.
	tmpxlsx="${tmpdir}/xlsx/"
}

# Top-level initialisation. Guarded so the script can be sourced for unit tests
# (PFB_SOURCED=1) to exercise the functions below in isolation without running
# any of this; the executable path runs it because PFB_SOURCED is unset. The
# function definitions further down are always defined on source.
if [ -z "${PFB_SOURCED:-}" ]; then
	now=$(/bin/date +%Y-%m-%d' '%T)	# ISO-8601 (unambiguous; matches the PHP pfb_logger timestamps)

	# Application Locations
	pathgrepcidr="/usr/local/bin/grepcidr"
	pathaggregate="/usr/local/bin/iprange"
	pathgeoip="/usr/local/bin/mmdblookup"
	pathhost=/usr/bin/host
	pathtar=/usr/bin/tar
	pathpfctl=/sbin/pfctl

	# Script Arguments
	alias="${2}"
	max="${3}"
	dedup="${4}"
	cc="$(echo "${5}" | sed 's/,/, /g')"
	ccwhite="$(echo "${6}" | tr '[:upper:]' '[:lower:]')"
	ccblack="$(echo "${7}" | tr '[:upper:]' '[:lower:]')"
	etblock="$(echo "${8}" | sed 's/,/, /g')"
	etmatch="$(echo "${9}" | sed 's/,/, /g')"

	# File Locations
	# #468: extension-less BASES -- pfb_archive_{compress,extract} append .zst (zstd)
	# or .bz2 (bzip2 fallback / pre-#468 legacy) and pick the codec by availability.
	aliasarchive="/usr/local/etc/aliastables.tar"
	# DNSBL python-integration cache (#468). SEPARATE base from the IP aliastables
	# archive above -- different lifecycle (DNSBL changes, not IP-rule changes).
	dnsblarchive="/usr/local/etc/pfb_dnsbl_cache.tar"
	pathgeoipdat="/usr/local/share/GeoIP/GeoLite2-Country.mmdb"
	pathasndat="/usr/local/share/GeoIP/asn.mmdb"
	pathasncsv="/usr/local/share/GeoIP/asn.csv"
	pathasntable="/usr/local/www/pfblockerng/pfblockerng_asn.txt"
	pfbsuppression=/var/db/pfblockerng/pfbsuppression.txt
	# ADR-06: pfbdnsblsuppression / pfbalexa removed (only used by the dropped
	# dnsbl_scrub build-time whitelist/TOP1M removal; now applied at query time).
	masterfile=/var/db/pfblockerng/masterfile
	mastercat=/var/db/pfblockerng/mastercat
	geoiplog=/var/log/pfblockerng/geoip.log
	errorlog=/var/log/pfblockerng/error.log
	extraslog=/var/log/pfblockerng/extras.log

	# Folder Locations
	etdir=/var/db/pfblockerng/ET
	pfbdb=/var/db/pfblockerng/
	pfbdeny=/var/db/pfblockerng/deny/
	pfborig=/var/db/pfblockerng/original/
	pfbmatch=/var/db/pfblockerng/match/
	pfbpermit=/var/db/pfblockerng/permit/
	pfbnative=/var/db/pfblockerng/native/
	pfsensealias=/var/db/aliastables/
	pfbdomain=/var/db/pfblockerng/dnsbl/
	pfbdomainorig=/var/db/pfblockerng/dnsblorig/

	# Store 'Match' d-dedups in matchdedup.txt file
	matchdedup=matchdedup_v4.txt

	# Create a private per-run temp directory (sets tempfile, tempfile2, ...,
	# tmpxlsx).
	pfb_make_tmpdir

	# ADR-06: domainmaster / dnsbl_tld_remove / dnsbl_python_{data,zone,count} removed
	# along with dnsbl_scrub + domaintldpy (the dropped build-time DNSBL passes).

	ip_placeholder="$(/usr/local/sbin/read_xml_tag.sh string installedpackages/pfblockerngipsettings/config/ip_placeholder)"
	if [ -z "${ip_placeholder}" ]; then
		ip_placeholder=127.1.7.7
	fi
	ip_placeholder2="$(echo "${ip_placeholder}" | sed 's/\./\\\./g')"
	ip_placeholder3="$(echo "${ip_placeholder}" | cut -d '.' -f 1-3)"

	USE_MFS_TMPVAR="$(/usr/bin/grep -c use_mfs_tmpvar /cf/conf/config.xml)"
	DISK_NAME="$(/bin/df /var/db/rrd | /usr/bin/tail -1 | /usr/bin/awk '{print $1;}')"
	DISK_TYPE="$(/usr/bin/basename "${DISK_NAME}" | /usr/bin/cut -c1-2)"

	if [ ! -d "${pfbdb}" ]; then mkdir "${pfbdb}"; fi
	if [ ! -d "${pfsensealias}" ]; then mkdir "${pfsensealias}"; fi
	if [ ! -d "${pfbmatch}" ]; then mkdir "${pfbmatch}"; fi
	if [ ! -d "${etdir}" ]; then mkdir "${etdir}"; fi
	# tmpxlsx is a fresh subdir of the private mktemp -d tmpdir -- no existence
	# guard needed (and none wanted: a pre-existing entry there would be a
	# symlink-attack signal, not a legitimate state to tolerate).
	mkdir "${tmpxlsx}"

	if [ ! -f "${masterfile}" ]; then touch "${masterfile}"; fi
	if [ ! -f "${mastercat}" ]; then touch "${mastercat}"; fi
fi


# Remove the private per-run temp directory before exiting (issue #30).
exitnow() {
	rc="${1:-0}"
	rm -rf "${tmpdir}"
	exit "${rc}"
}


# Token-shape guards for feed-derived list data. The list-processing functions
# iterate values that ultimately originate from downloaded feeds and splice them
# into `grep` patterns (anchored octet-prefix matches such as `^10\.0\.0\.`).
# Previously only the literal dot was escaped, so any other regex metacharacter
# in a token stayed live and `grep` interpreted it as a pattern -- yielding an
# over-broad / incorrect match set, or an expensive pattern.
#
# Each guard returns success only when the token is built solely from the
# characters that shape allows (digits, dots, and -- for CIDR -- a slash). A
# token that fails is dropped by its caller (`continue`), never matched. Because
# the surviving tokens contain only digits/dots/slashes, the existing dot-escape
# + `^` anchor that follows is then exact and safe.
#
# Reject the empty string explicitly: `case ''` would match the `*[!set]*`
# negation as "no disallowed char present" and pass.

# An octet prefix: one or more dot-separated decimal octets, digits and dots
# only (e.g. '10' or '10.0.0'). No anchors, no slash.
pfb_is_octet_prefix() {
	case "${1}" in
		''|*[!0-9.]*) return 1 ;;
		*) return 0 ;;
	esac
}

# A CIDR token: digits/dots, then EXACTLY one '/', then a non-empty numeric mask
# (e.g. '10.0.0.1/32'). The suppress() caller splits on '/' and compares the mask
# with -eq, so a bare IP, an empty mask ('10.0.0.1/'), or a double slash
# ('10.0.0.1//32') is rejected here and skipped rather than reaching that compare.
pfb_is_cidr_token() {
	case "${1}" in
		''|*[!0-9./]*|*/*/*|/*|*/) return 1 ;;
	esac
	[ "${1#*/}" = "${1}" ] && return 1   # must contain a slash
	case "${1##*/}" in
		''|*[!0-9]*) return 1 ;;          # mask must be non-empty digits
	esac
	return 0
}

# Escape every '.' in $1 for use as a literal in a grep BRE, and emit the result
# anchored at line start ('^'). The caller MUST validate the token shape first
# (pfb_is_octet_prefix) so only digits/dots reach here; this then yields an exact
# '^10\.0\.0\.'-style prefix pattern with no live regex metacharacter.
pfb_anchor_octet_pattern() {
	printf '^%s' "${1}" | sed 's/\./\\./g'
}

# List the '*.orig' files in directory $1 oldest-first, one line per file:
# "<YYYY-MM-DD> <HH:MM><TAB><name>" (path stripped, '.orig' removed). ISO-8601 date
# (unambiguous, sorts lexically) replacing the old locale-dependent "<Mon> <Day>" form.
# mtime comes from stat(1) and is formatted by date(1); both flag-differ between BSD and
# GNU, so detect once via `stat --version` (GNU-only) and branch.
pfb_list_orig_by_mtime() {
	if stat --version >/dev/null 2>&1; then _gnu=1; else _gnu=0; fi
	for _f in "${1}"*.orig; do
		[ -e "${_f}" ] || continue
		if [ "${_gnu}" -eq 1 ]; then
			_m="$(stat -c '%Y' "${_f}" 2>/dev/null)"
		else
			_m="$(stat -f '%m' "${_f}" 2>/dev/null)"
		fi
		[ -n "${_m}" ] || continue
		printf '%s\t%s\n' "${_m}" "${_f}"
	done | LC_ALL=C sort -n | while IFS="$(printf '\t')" read -r _m _f; do
		_name="$(printf '%s' "${_f}" | sed -e 's#.*/##' -e 's/\.orig$//')"
		if [ "${_gnu:-0}" -eq 1 ]; then
			_ts="$(LC_ALL=C date -d "@${_m}" '+%Y-%m-%d %H:%M' 2>/dev/null)"
		else
			_ts="$(LC_ALL=C date -r "${_m}" '+%Y-%m-%d %H:%M' 2>/dev/null)"
		fi
		printf '%s\t%s\n' "${_ts}" "${_name}"
	done
}


# --- Shared MFS-restore archive helpers (#468) --------------------------------
# Both the IP aliastables archive and the DNSBL cache archive are zstd-compressed
# (.tar.zst). zstd ships OOTB on pfSense-CE, decompresses far faster than bzip2,
# and bsdtar (-P) auto-detects the format on extract, so a legacy .tar.bz2 from a
# prior install still restores. Single source of truth for compress/extract so the
# two callers stay identical.

# Worker thread count for zstd: ncpu-1, floored at 1, capped at 4 (leave a core
# free; never oversubscribe). Non-numeric ncpu -> 1.
pfb_zstd_threads() {
	_n="$(/sbin/sysctl -n hw.ncpu 2>/dev/null)"
	case "${_n}" in
		''|*[!0-9]*) _n=1 ;;
	esac
	_t=$((_n - 1))
	[ "${_t}" -lt 1 ] && _t=1
	[ "${_t}" -gt 4 ] && _t=4
	echo "${_t}"
}

# Compress <files...> into an archive, choosing the format by what is available:
# zstd present -> "<base>.zst" (zstd, multi-thread); else -> "<base>.bz2" (bzip2).
# The helper owns the extension + compressor; callers pass the extension-less <base>.
# On a verified zstd write, retire a stale "<base>.bz2" (e.g. a pre-upgrade install).
# Args: <base> <files...>. Returns non-zero (leaving any .bz2 intact) on zstd failure.
pfb_archive_compress() {
	_base="$1"
	shift
	# Tar to a private temp file FIRST and check tar's own exit status directly.
	# POSIX sh has no pipefail, so a `tar -Pcf - ... | zstd ...` pipe silently
	# discards tar's exit code (only zstd's mattered) -- and "zstd -tq" verifies
	# only the zstd FRAMING, not tar completeness, so a truncated tar stream still
	# compressed into a small but VALID .zst: the old check passed on a corrupt
	# archive AND deleted the still-good .bz2 (issue #713 bug 7). Both temp files
	# live alongside "${_base}" so the publish "mv" below is same-filesystem and
	# atomic; on ANY failure below, the pre-existing .bz2 is never touched (only
	# retired after a verified .zst is published), so the bzip2 fallback always
	# has a good backup to fall back to.
	_tartmp="$(mktemp "${_base}.XXXXXX")" || return 1
	_ztmp="$(mktemp "${_base}.XXXXXX")" || { rm -f "${_tartmp}"; return 1; }
	if "${pathtar}" -Pcf "${_tartmp}" "$@" \
		&& zstd -q -f -T"$(pfb_zstd_threads)" -o "${_ztmp}" "${_tartmp}" 2>/dev/null \
		&& zstd -tq "${_ztmp}" 2>/dev/null; then
		mv -f "${_ztmp}" "${_base}.zst"
		rm -f "${_tartmp}" "${_base}.bz2"
		return 0
	fi
	# tar, zstd compression, or zstd verification failed: drop the temp/partial
	# output (never the pre-existing .bz2 -- it was never touched above) and fall
	# back to bzip2 ("who knows what the future holds").
	rm -f "${_tartmp}" "${_ztmp}" "${_base}.zst"
	"${pathtar}" -Pjcf "${_base}.bz2" "$@"
}

# Extract "<base>.zst" (zstd) or "<base>.bz2" (bzip2) -- whichever exists. No reload.
# Args: <base>.
pfb_archive_extract() {
	_base="$1"
	# bsdtar -P auto-detects the compression (zstd or bzip2); no zstd binary needed.
	if [ -f "${_base}.zst" ]; then
		cd / && "${pathtar}" -Pxf "${_base}.zst"
	elif [ -f "${_base}.bz2" ]; then
		cd / && "${pathtar}" -Pxf "${_base}.bz2"
	fi
}


# Function to restore IP aliastables and DNSBL database from archive on reboot. ( Ramdisk installations only )
aliastables() {
	if [ "${USE_MFS_TMPVAR}" -gt 0 ] || [ "${DISK_TYPE}" = 'md' ]; then
		if [ ! -d '/var/unbound' ]; then
			mkdir '/var/unbound'
			chown -f unbound:unbound /var/unbound
			chgrp -f unbound /var/unbound
		fi
		pfb_archive_extract "${aliasarchive}"
	fi
}


# DNSBL python-integration cache (#468). On a RAM-disk /var (use_mfs_tmpvar) the
# chroot is wiped on reboot, so DNSBL comes up dead. This keeps DNSBL alive across a
# reboot with PURE FILE OPS (no reload/restart -- Unbound's normal start loads the
# restored files). Kept SEPARATE from the IP aliastables flow above on purpose: the
# two have different lifecycles (DNSBL state vs IP-rule state).
#
#   stage   -- single source of truth for the SHIPPED file set (PFB_PY_SHIPPED): copy
#              each from /usr/local into the chroot, after making the chroot + the
#              nullfs/devfs mount-point dirs (fresh MFS lacks them, which is what made
#              pfb_python_mount fail). Re-run on every save/restore so the shipped code
#              is always current from /usr/local (never restored stale from an archive).
#   save    -- stage, then archive ONLY the GENERATED set (pfb_unbound*/pfb_py_* +
#              pfb_unbound.ini: the manifest, raw feeds, caches, ini). Shipped files
#              are NOT archived -- they come from /usr/local on restore.
#   restore -- the boot earlyshellcmd: untar the generated set (if present) THEN stage.
#
# Naming contract: the generated archive set is matched by the pfb_unbound* / pfb_py_*
# globs below; a new generated DNSBL file MUST keep that prefix to be carried across a
# reboot. The shipped set is the explicit PFB_PY_SHIPPED list -- add a new shipped file
# there (and to the pkg-plist / chroot-copy wiring) so it stays the one definition.
dnsbl_cache() {
	# Overridable for unit tests; default to the live locations.
	pfbchroot="${pfbchroot:-/var/unbound}"
	pfbpkgdir="${pfbpkgdir:-/usr/local/pkg/pfblockerng}"
	dnsblarchive="${dnsblarchive:-/usr/local/etc/pfb_dnsbl_cache.tar}"
	pathtar="${pathtar:-/usr/bin/tar}"

	# The shipped (static) DNSBL python files -- the ONE definition of the set.
	PFB_PY_SHIPPED='pfb_unbound.py pfb_unbound_include.inc pfb_py_hsts.txt'

	dnsbl_cache_stage() {
		mkdir -p "${pfbchroot}"
		# The nullfs/devfs mount-point dirs pfb_python_mount expects (fresh-MFS safety).
		for _d in lib dev var/log/pfblockerng usr/local/share/GeoIP; do
			mkdir -p "${pfbchroot}/${_d}"
		done
		# Copy the shipped files from /usr/local into the chroot (current code).
		for _f in ${PFB_PY_SHIPPED}; do
			if [ -f "${pfbpkgdir}/${_f}" ]; then
				cp -f "${pfbpkgdir}/${_f}" "${pfbchroot}/${_f}"
				chown -f unbound:unbound "${pfbchroot}/${_f}"
			fi
		done
	}

	case "${1}" in
		stage)
			dnsbl_cache_stage
			;;
		save)
			dnsbl_cache_stage
			# Archive ONLY the generated set: pfb_unbound* + pfb_py_* + pfb_unbound.ini,
			# EXCLUDING the shipped files (PFB_PY_SHIPPED) -- those are re-staged from
			# /usr/local on restore, so archiving them would reinstate stale code (e.g.
			# pfb_py_hsts.txt matches the pfb_py_* glob but is shipped, not generated).
			set --
			for _g in "${pfbchroot}"/pfb_unbound* "${pfbchroot}"/pfb_py_*; do
				[ -e "${_g}" ] || continue
				_skip=''
				for _s in ${PFB_PY_SHIPPED}; do
					[ "${_g}" = "${pfbchroot}/${_s}" ] && _skip=1 && break
				done
				[ -z "${_skip}" ] && set -- "$@" "${_g}"
			done
			if [ "$#" -gt 0 ]; then
				# The helper appends .zst/.bz2 to the base and picks the codec.
				pfb_archive_compress "${dnsblarchive}" "$@"
			fi
			;;
		restore)
			pfb_archive_extract "${dnsblarchive}"
			dnsbl_cache_stage
			;;
	esac
}


# Function to write IP Placeholder IP to 'empty' final blocklist files.
emptyfiles() {
	emptyfiles="$(find "${pfbdeny}"*.txt -size 0 2>/dev/null)"
	for i in ${emptyfiles}; do
		echo "${ip_placeholder}" > "${i}";
	done
}


# Function to remove lists from masterfiles and delete associated files.
remove() {
	echo; echo

	# Self-defence: a path separator or traversal sequence in the alias must
	# never reach the "rm -f ...${header}*" globs below. Reject it at entry so
	# the script does not rely solely on the PHP caller having sanitised it.
	case "${alias}" in
		*/*|*..*)
			echo "Invalid alias [ ${alias} ], *aborting remove*"
			return 1
			;;
	esac

	for i in ${cc}; do
		header="${i%*,}"

		# Same guard for each per-entry header before it builds an rm glob.
		case "${header}" in
			*/*|*..*)
				echo "Invalid header [ ${header} ], *skipping*"
				continue
				;;
		esac

		if [ -n "${header}" ]; then
			# Make sure that alias exists in masterfile before removal.
			query="${header} "
			masterchk="$(grep -m1 "${query}" "${masterfile}")"

			if [ -n "${masterchk}" ]; then
				# Grep header with a trailing space character. Anchored (^) so a
				# shorter alias that is a SUFFIX of another (e.g. "Ads_v4" inside
				# "BadAds_v4") doesn't over-match and strip a sibling's masterfile
				# row -- masterfile rows always start with the alias at column 0.
				grep "^${header}[[:space:]]" "${masterfile}" > "${tempfile}"
				# #713: gate the publish on awk's own exit status (awk has no "empty
				# result = rc 1" quirk -- non-zero is a real error) so a failed dedup
				# can't truncate masterfile via an unconditional mv.
				awk 'FNR==NR{a[$0];next}!($0 in a)' "${tempfile}" "${masterfile}" > "${tempfile2}" && mv -f "${tempfile2}" "${masterfile}"
			fi

			rm -f "${pfborig}${header}"*; rm -f "${pfbdeny}${header}"*; rm -f "${pfbmatch}${header}"*
			rm -f "${pfbpermit}${header}"*; rm -f "${pfbnative}${header}"*
			echo "The Following List has been REMOVED [ ${header} ]"
		fi
	done
	cut -d ' ' -f2 "${masterfile}" > "${mastercat}"

	# Delete masterfiles if they are empty
	if [ ! -s "${masterfile}" ]; then
		rm -f "${masterfile}"; rm -f "${mastercat}"
	fi
}


# Function to remove IPs if exists over 253 IPs in a range and replace with a single /24 block. (excl. '0' & '255')
process255() {
	: > "${dedupfile}"
	data255="$(cut -d '.' -f 1-3 "${pfbdeny}${alias}.txt" | awk '{a[$0]++}END{for(i in a){if(a[i] > 253){print i}}}')" 

	if [ -n "${data255}" ]; then
		cp "${pfbdeny}${alias}.txt" "${tempfile}"

		# Iterate the octet prefixes safely (no IFS re-splitting) and validate each
		# to digits/dots before building the anchored '^10\.0\.0\.' grep pattern, so
		# a malformed token cannot reach grep as a live regex.
		while IFS= read -r ip; do
			pfb_is_octet_prefix "${ip}" || continue
			ii="$(pfb_anchor_octet_pattern "${ip}.")"
			grep "${ii}" "${tempfile}" >> "${dedupfile}"
		done <<EOF
${data255}
EOF

		# #713: gate the publish on awk's own exit status (awk has no "empty
		# result = rc 1" quirk -- non-zero is a real error) so a failed dedup
		# can't truncate the live deny list via a direct redirect; write to a
		# sibling temp and publish only on success.
		awk 'FNR==NR{a[$0];next}!($0 in a)' "${dedupfile}" "${tempfile}" > "${pfbdeny}${alias}.txt.tmp" && mv -f "${pfbdeny}${alias}.txt.tmp" "${pfbdeny}${alias}.txt"
		while IFS= read -r ip; do
			pfb_is_octet_prefix "${ip}" || continue
			echo "${ip}.0/24" >> "${pfbdeny}${alias}.txt"
		done <<EOF
${data255}
EOF
	fi
}

# Process to remove suppressed entries.
suppress() {
	if [ ! -x "${pathgrepcidr}" ]; then
		log="Application [ grepcidr ] Not found. Cannot proceed."
		echo "${log}" | tee -a "${errorlog}"
		return
	fi

	if [ -e "${pfbsuppression}" ] && [ -s "${pfbsuppression}" ]; then
		data="$(LC_ALL=C sort -u "${pfbsuppression}")"

		if [ -n "${data}" ] && [ -n "${alias}" ]; then
			if [ "${alias}" = 'suppressheader' ]; then
				echo; echo '===[ Suppression Stats ]==================================='; echo
				printf "%-20s %-10s %-10s %-10s\n" 'List' 'Pre' 'Suppress' 'Master'
				echo '-----------------------------------------------------------'
				return
			fi

			pfbfolder="${max}/"
			counter=0; : > "${dupfile}"

			if [ -n "${alias}" ]; then
				countg="$(grep -c ^ "${pfbfolder}${alias}.txt")"
				cp "${pfbfolder}${alias}.txt" "${tempfile}"

				# Iterate the suppression entries safely (no IFS re-splitting) via a
				# here-doc so the loop body stays in THIS shell -- it accumulates
				# ${counter} and appends to ${dupfile}/${tempfile}, which a `while|read`
				# subshell would discard. Validate each token to a CIDR shape
				# (digits/dots/slashes) and skip a malformed one, so only literal
				# octet text reaches the fixed-string greps below.
				while IFS= read -r ip; do
					pfb_is_cidr_token "${ip}" || continue
					found=''; dcheck='';
					mask="${ip##*/}"
					iptrim="${ip%.*}"
					ip="${ip%%/*}"
					# Fixed-string match: '${iptrim}.0/24' is a literal whole token,
					# no anchor needed, so grep -F matches it exactly (the '.' is a
					# literal dot, not a regex 'any char').
					found="$(grep -F -m1 "${iptrim}.0/24" "${tempfile}")"

					# If a suppression is '/32' and a blocklist has a full '/24' block, execute the following.
					if [ -n "${found}" ] && [ "${mask}" -eq 32 ]; then
						echo " Suppression ${alias}: ${iptrim}.0/24 (Excluding: ${ip}/32)"
						octet4="${ip##*.}"
						dcheck="$(grep -F "${iptrim}.0/24" "${dupfile}")"

						if [ -z "${dcheck}" ]; then
							echo "${iptrim}.0/24" >> "${dupfile}"
							counter="$((counter + 1))"

							# Add individual IP addresses from range excluding suppressed IP
							for i in $(seq 255); do
								if [ "${i}" != "${octet4}" ]; then
									echo "${iptrim}.${i}" >> "${tempfile}"
									counter="$((counter + 1))"
								fi
							done
						fi
					fi
				done <<EOF
${data}
EOF

				if [ -s "${dupfile}" ]; then
					# Remove '/24' suppressed ranges
					# #713: gate the publish on awk's own exit status (awk has no "empty
					# result = rc 1" quirk -- non-zero is a real error) so a failed dedup
					# can't truncate the working copy via an unconditional mv.
					awk 'FNR==NR{a[$0];next}!($0 in a)' "${dupfile}" "${tempfile}" > "${tempfile2}" && mv -f "${tempfile2}" "${tempfile}"
				fi

				# Remove all other suppressions from list. #713: redirect to a scratch
				# temp and gate the publish on grepcidr's exit status -- rc 0 (matches
				# removed) and rc 1 (everything suppressed, a LEGITIMATE empty result)
				# both replace the live list; rc >= 2 is a real grepcidr error, so keep
				# the previous list intact (no truncation) and warn instead.
				"${pathgrepcidr}" -vf "${pfbsuppression}" "${tempfile}" > "${tempfile2}"
				grc=$?
				if [ "${grc}" -lt 2 ]; then
					mv -f "${tempfile2}" "${pfbfolder}${alias}.txt"
				else
					rm -f "${tempfile2}"
					log="grepcidr error (rc=${grc}) suppressing [ ${alias} ]; keeping previous list"
					echo "${log}" | tee -a "${errorlog}"
				fi

				# Update masterfiles. Don't execute if duplication process is disabled
				if [ "${dedup}" = 'on' ]; then
					# Don't execute if alias doesn't exist in masterfile
					lcheck="$(grep -m1 "${alias}" "${masterfile}")"

					if [ -n "${lcheck}" ]; then
						# Replace masterfile with changes to list. Anchored (^) --
						# see duplicate()'s sibling grep for the suffix-over-match
						# rationale (issue #714).
						grep "^${alias}[[:space:]]" "${masterfile}" > "${tempfile}"
						# #713: gate the publish on awk's own exit status (awk has no "empty
						# result = rc 1" quirk -- non-zero is a real error) so a failed dedup
						# can't truncate masterfile via an unconditional mv.
						awk 'FNR==NR{a[$0];next}!($0 in a)' "${tempfile}" "${masterfile}" > "${tempfile2}" && mv -f "${tempfile2}" "${masterfile}"
						sed -e 's/^/'"$alias"' /' "${pfbfolder}${alias}.txt" >> "${masterfile}"
						cut -d ' ' -f2 "${masterfile}" > "${mastercat}"
					fi
				fi

				countk="$(grep -c ^ "${masterfile}")"
				countx="$(grep -c ^ "${pfbfolder}${alias}.txt")"
				counto="$((countx - counter))"
				printf "%-20s %-10s %-10s %-10s\n" "${alias}" "${countg}" "${counto}" "${countk}"
			fi
		fi
	fi
}


# Function to optimise CIDRs
cidr_aggregate() {
	if [ ! -x "${pathaggregate}" ]; then
		log="Application [ iprange ] Not found. Cannot proceed."
		echo "${log}" | tee -a "${errorlog}"
		return
	fi

	if [ "${agg_folder}" = true ]; then
		# Use $3 folder path
		pfbfolder="${max}/"
	else
		pfbfolder="${pfbdeny}"
	fi

	counto="$(grep -c ^ "${pfbfolder}${alias}.txt")"
	"${pathaggregate}" "${pfbfolder}${alias}.txt" > "${tempfile}" && mv -f "${tempfile}" "${pfbfolder}${alias}.txt"

	countf="$(grep -c ^ "${pfbfolder}${alias}.txt")"
	if [ "${counto}" != "${countf}" ]; then
		echo; echo '  Aggregation Stats:'
		echo '  ------------------'
		printf "%-10s %-10s \n" '  Original' 'Final'
		echo '  ------------------'
		printf "%-10s %-10s \n" "  ${counto}" "${countf}"
		echo '  ------------------'
	fi
}


# ADR-11: Union a set of already-effective member files into ONE deduped + CIDR-
# aggregated alias file, plus a never-empty '-f' consumer file. Type-AGNOSTIC: it is
# handed a plain list of member-file paths (one per line) and does not care which
# action class (Deny/Permit/Match/Native) they belong to -- the per-type membership
# is decided in PHP (pfb_aggregate_member_list) by the Phase-3 caller.
#
# Reuses the existing aggregation primitive (${pathaggregate} = iprange, the same
# binary cidr_aggregate() shells out to) -- NO new aggregation algorithm. iprange is
# set-exact (minimal CIDR cover equal to the union; never adds an address), so the
# union cannot widen the set.
#
# Positional args (read directly, not via the global $alias/$max slots):
#   $2 family       : 'v4' | 'v6'   (informational; iprange handles either family)
#   $3 memberlist   : path to a file listing member files, one path per line
#   $4 aggout       : path to write the aggregate alias file (the urltable content)
#   $5 consumerout  : path to write the never-empty '-f' consumer file
#
# mtime-gate (Phase 1 strategy): rebuild only when a listed member file is newer than
# the existing aggregate output -- otherwise the prior aggregate is current, so skip
# the cat|sort -u|iprange entirely. The consumer file must also already exist and be
# non-empty, else we always (re)build to honour the never-empty contract.
pfb_aggregate() {
	agg_family="${2}"
	agg_memberlist="${3}"
	agg_out="${4}"
	agg_consumer="${5}"
	# CIDR Aggregation (the global enable_agg setting) state, passed by the PHP caller as
	# 'on'/'off'. When 'on', every member feed already ran through cidr_aggregate during
	# processing, so the members are individually CIDR-collapsed -- the union then needs only a
	# sort -u (the union's iprange would do marginal cross-member merges only). See the build
	# branch below.
	agg_collapsed="${6:-off}"

	# v4 aggregation CIDR-collapses the union through iprange (below) ONLY when CIDR Aggregation
	# is off (raw members); v6 never uses iprange (IPv4-only), and v4 with CIDR Aggregation on
	# skips it too -- so require iprange only for the v4 + agg-off case.
	if [ "${agg_family}" != 'v6' ] && [ "${agg_collapsed}" != 'on' ] && [ ! -x "${pathaggregate}" ]; then
		log="Application [ iprange ] Not found. Cannot proceed."
		echo "${log}" | tee -a "${errorlog}"
		return
	fi

	if [ -z "${agg_memberlist}" ] || [ -z "${agg_out}" ] || [ -z "${agg_consumer}" ]; then
		log="aggregate [ ${agg_family} ]: missing memberlist/output path argument."
		echo "${log}" | tee -a "${errorlog}"
		return
	fi
	if [ ! -f "${agg_memberlist}" ]; then
		log="aggregate [ ${agg_family} ]: member list [ ${agg_memberlist} ] not found."
		echo "${log}" | tee -a "${errorlog}"
		return
	fi

	# Snapshot (beside the aggregate) of the member SET that produced the current ${agg_out}.
	# The gate must rebuild not only when a member is NEWER but also when the member set
	# CHANGED -- a feed removed/added, or the union emptied -- else a shrink would leave stale
	# content forever. PHP rewrites ${agg_memberlist} every pass (so its mtime is useless), so
	# we compare its CONTENT (the sorted member paths) against this snapshot.
	agg_setsnap="${agg_out}.members"

	# Skip the rebuild only when the aggregate + consumer already exist, the member set is
	# UNCHANGED since the last build, AND no listed member is newer than the aggregate output.
	if [ -f "${agg_out}" ] && [ -s "${agg_consumer}" ] && [ -f "${agg_setsnap}" ] && \
	   cmp -s "${agg_memberlist}" "${agg_setsnap}"; then
		agg_stale=''
		while IFS= read -r agg_member; do
			[ -z "${agg_member}" ] && continue
			# POSIX sh has no '-nt'; `find <member> -newer <out>` prints the member iff its
			# mtime is strictly newer than the aggregate output's.
			if [ -n "$(find "${agg_member}" -newer "${agg_out}" 2>/dev/null)" ]; then
				agg_stale=1
				break
			fi
		done < "${agg_memberlist}"
		if [ -z "${agg_stale}" ]; then
			echo "aggregate [ ${agg_family} ]: member set unchanged, no member newer than [ ${agg_out} ], skipping rebuild."
			return
		fi
	fi

	# Concatenate every existing member file, then dedup (sort -u) into the temp file.
	: > "${tempfile}"
	while IFS= read -r agg_member; do
		[ -z "${agg_member}" ] && continue
		[ -f "${agg_member}" ] && cat "${agg_member}" >> "${tempfile}"
	done < "${agg_memberlist}"
	LC_ALL=C sort -u "${tempfile}" > "${dedupfile}"

	# CIDR-collapse the deduped union into a temp, then mv into place only on success -- so a
	# failure in ANY branch (iprange error, or a write/copy failure) cannot clobber a previously
	# valid aggregate (a direct '>' redirect would truncate ${agg_out} before the producer ran).
	# iprange is IPv4-ONLY: given IPv6 it truncates each address at the first ':' and reads the
	# leading hextet as a decimal, emitting bogus 0.0.x.y entries -- so ONLY v4 is passed through
	# it (mirroring the per-alias path, which gates cidr_aggregate to _v4 in pfblockerng.inc). For
	# v6 the deduped sort -u union IS the result: set-correct, just not minimal-CIDR-collapsed --
	# exactly how every individual v6 alias is already kept.
	#
	# v4 ALSO takes that sort -u path when CIDR Aggregation is on (agg_collapsed='on'): every
	# member already ran through cidr_aggregate, so the union's iprange would only do marginal
	# cross-member merges -- not worth a redundant pass over the whole (possibly huge) union. The
	# sort -u union is set-correct (the same addresses), just not cross-feed minimal-collapsed. With
	# CIDR Aggregation off the members are raw, so v4 still collapses the union through iprange.
	# An empty union writes an empty aggregate (the never-empty consumer placeholder is below).
	agg_tmp="${agg_out}.tmp"
	if [ ! -s "${dedupfile}" ]; then
		: > "${agg_tmp}"
	elif [ "${agg_family}" = 'v6' ] || [ "${agg_collapsed}" = 'on' ]; then
		cp -f "${dedupfile}" "${agg_tmp}"
	else
		"${pathaggregate}" "${dedupfile}" > "${agg_tmp}"
	fi
	agg_rc="$?"
	if [ "${agg_rc}" -ne 0 ] || ! mv -f "${agg_tmp}" "${agg_out}"; then
		rm -f "${agg_tmp}"
		log="aggregate [ ${agg_family} ]: build of [ ${agg_out} ] failed; keeping existing."
		echo "${log}" | tee -a "${errorlog}"
		return
	fi

	# Never-empty '-f' consumer file: mirror the aggregate, but substitute a single
	# '#'-comment placeholder line when the union is empty so a downstream '-f'
	# consumer (ADR-12) never trips empty-file validation.
	if [ -s "${agg_out}" ]; then
		cp -f "${agg_out}" "${agg_consumer}"
	else
		echo '#' > "${agg_consumer}"
	fi

	# Record the member set that produced this aggregate so the NEXT pass's gate can detect a
	# membership change (shrink/grow/empty), not just a newer member. Only reached on a real
	# (re)build -- a skipped pass returns above, an iprange failure returns without touching it.
	cp -f "${agg_memberlist}" "${agg_setsnap}"

	aggin="$(grep -c ^ "${dedupfile}" 2>/dev/null)"
	aggfinal="$(grep -c ^ "${agg_out}" 2>/dev/null)"
	echo "aggregate [ ${agg_family} ]: union ${aggin} -> ${aggfinal} CIDRs -> ${agg_out}"
}


# Function to remove duplicate entries in each list individually.
duplicate() {
	if [ ! -x "${pathgrepcidr}" ]; then
		log="Application [ grepcidr ] Not found. Cannot proceed."
		echo "${log}" | tee -a "${errorlog}"
		return
	fi

	# "Original" in the stats below is the size ENTERING de-duplication -- i.e. the CIDR-aggregated
	# feed when aggregation ran, not the raw download. Capture it before the cross-feed grepcidr
	# prune mutates .txt, and persist it beside the feed so closingprocess() can sum the aggregated
	# originals for the FINAL Processing report.
	counto="$(grep -c ^ "${pfbdeny}${alias}.txt")"
	echo "${counto}" > "${pfborig}${alias}.aggcount"

	dupcheck=1
	# Check if masterfile is empty
	hcheck="$(grep -cv ^$ "${masterfile}")"; if [ "${hcheck}" -eq 0 ]; then dupcheck=0; fi
	# Check if alias exists in masterfile
	lcheck="$(grep -m1 "${alias}" "${masterfile}")"; if [ -z "${lcheck}" ]; then dupcheck=0; fi
	# Check for single alias in masterfile
	aliaslist="$(cut -d ' ' -f1 "${masterfile}" | LC_ALL=C sort -u)"; if [ "${alias}" = "${aliaslist}" ]; then hcheck=0; fi

	# Only execute if 'Alias' exists in masterfile
	if [ "${dupcheck}" -eq 1 ]; then
		# Grep alias with a trailing space character. Anchored (^) -- an
		# unanchored pattern over-matches a shorter alias that is a SUFFIX of
		# another (e.g. "Ads_v4" inside "BadAds_v4"), pulling the sibling's
		# masterfile row into the removal set and silently dropping it
		# (issue #714). Masterfile rows always start with the alias.
		grep "^${alias}[[:space:]]" "${masterfile}" > "${tempfile}"
		# #713: gate the publish on awk's own exit status (awk has no "empty
		# result = rc 1" quirk -- non-zero is a real error) so a failed dedup
		# can't truncate masterfile via an unconditional mv.
		awk 'FNR==NR{a[$0];next}!($0 in a)' "${tempfile}" "${masterfile}" > "${tempfile2}" && mv -f "${tempfile2}" "${masterfile}"
		cut -d ' ' -f2 "${masterfile}" > "${mastercat}"
	fi

	# Don't execute when only a single 'Alias' exists in masterfile
	if [ ! "${hcheck}" -eq 0 ]; then
		LC_ALL=C sort -u "${pfbdeny}${alias}.txt" > "${tempfile}"; mv -f "${tempfile}" "${pfbdeny}${alias}.txt"

		# #713: gate the publish on grepcidr's exit status -- rc 0 (matches removed)
		# and rc 1 (everything pruned, a LEGITIMATE empty result) both replace the
		# list; rc >= 2 is a real grepcidr error, so keep the previous list intact
		# (no truncation via an unconditional mv) and warn instead.
		"${pathgrepcidr}" -vf "${mastercat}" "${pfbdeny}${alias}.txt" > "${tempfile}"
		grc=$?
		if [ "${grc}" -lt 2 ]; then
			mv -f "${tempfile}" "${pfbdeny}${alias}.txt"
		else
			rm -f "${tempfile}"
			log="grepcidr error (rc=${grc}) de-duplicating [ ${alias} ]; keeping previous list"
			echo "${log}" | tee -a "${errorlog}"
		fi
	fi

	sed -e 's/^/'"$alias"' /' "${pfbdeny}${alias}.txt" >> "${masterfile}"
	cut -d ' ' -f2 "${masterfile}" > "${mastercat}"

	countm="$(grep -c "${alias}" "${masterfile}")"
	countf="$(grep -c ^ "${pfbdeny}${alias}.txt")"

	if [ "${countm}" -eq "${countf}" ]; then
		sanity='Pass'
	else
		sanity=' ==> FAILED <== '
	fi

	echo '  ------------------------------'
	printf "%-10s %-10s %-10s\n" '  Original' 'Master' 'Final'
	echo '  ------------------------------'
	printf "%-10s %-10s %-10s %-10s\n" "  ${counto}" "${countm}" "${countf}" " [ ${sanity} ]"
	echo '  -----------------------------------------------------------------'

	emptyfiles # Call emptyfiles function
}



# ADR-06: dnsbl_scrub (build-time within/cross-feed De-Duplication + user-
# whitelist removal + TOP1M removal) and domaintldpy (sort -u dedup + subdomain
# COLLAPSE via ggrep -vF dnsbl_tld_remove + pfb_py_count write) have been REMOVED.
# They were build-time list optimisations the Python plugin no longer needs: the
# dict load dedups keys for free, a redundant sub-domain is matched by its parent
# zone, and the user whitelist + TOP1M are applied at QUERY TIME via the whiteDB.
# The Python build (pfb_unbound.py) owns this and emits pfb_py_count itself; PHP
# hands it the per-feed raw via pfblockerng.inc pfb_unbound_python_sources().


# Function to compare previous and current DNSBL Unbound conf file, and create Add/Remove files for unbound-control cmds


# Function to convert Domains/ASs to its respective IP addresses
whoisconvert() {

	vtype="${max}"
	# One entry per line so the loop below can iterate via a here-doc + `read`
	# instead of an unquoted `for` over the value (which would re-split each
	# entry on IFS).
	custom_list="$(echo "${dedup}" | tr ',' '\n')"

	if [ "${vtype}" = '_v4' ]; then
		_type=A
	else
		_type=AAAA
	fi

	# Backup previous orig file
	if [ -e "${pfborig}${alias}.orig" ]; then
		mv "${pfborig}${alias}.orig" "${pfborig}${alias}.bk"
	fi

	echo
	# ${found} ACCUMULATES across the loop: it is initialised false here and only
	# ever set true on a successful entry, NEVER reset false inside the loop. So
	# after the loop found=true iff AT LEAST ONE entry resolved (keep the data
	# collected from the successful entries) and false iff nothing did (restore
	# the .bk). Resetting it per-iteration would make it reflect only the LAST
	# entry, discarding good data from earlier entries when the last one fails
	# (issue #714).
	found=false

	# Iterate via a here-doc so the loop body stays in THIS shell (it sets the
	# ${found} flag the restore logic below reads); skip blank entries.
	while IFS= read -r host; do
		[ -z "${host}" ] && continue
		# Determine if host is a Domain or an AS: a domain contains a dot.
		case "${host}" in
		*.*)
			printf '  Collecting host IP: %s' "${host}"
			# Capture the lookup output + its OWN exit code first (a pipe's $?
			# would reflect sed's status, not host's, hiding a failed lookup) --
			# then keep only the "has (IPv6) address" lines so a failure message
			# (e.g. "Host x not found: 3(NXDOMAIN)") can never be captured as
			# data (issue #714). Mirrors the ASN branch below.
			hostout="$("${pathhost}" -t "${_type}" "${host}")"
			hostrc=$?
			if [ "${hostrc}" -eq 0 ]; then
				hostips="$(echo "${hostout}" | grep -E 'has( IPv6)? address' | sed 's/^.* //')"
			else
				hostips=''
			fi

			if [ -n "${hostips}" ]; then
				found=true
				echo "### Domain: ${host} ###" >> "${pfborig}${alias}.orig"
				echo "${hostips}" >> "${pfborig}${alias}.orig"
				echo "... completed"
			else
				printf "... Failed to resolve host [ %s ]" "${host}"
				touch "${pfborig}${alias}.fail"
			fi
			;;
		*)
			# Download IPinfo asn databases on first use.
			if [ ! -f "${pathasncsv}" ]; then
				printf 'Downloading [ IPinfo databases ] [ %s ]' "${now}"
				/usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php asn_shell
				printf "... completed"
			fi

			# Exit if asn.csv is not found
			if [ ! -f "${pathasncsv}" ]; then
				log="Database ASN [ asn.csv ] not found. Register for IPinfo Token."
				echo "${log}" | tee -a "${errorlog}"
			else
				asn="$(echo "${host}" | tr -d 'AaSs')"
				printf '  Collecting ASN: AS%s' "${asn}"
				# An AS number is digits only; drop anything else so the value
				# spliced into the grep below is a literal, not a live pattern.
				case "${asn}" in
					''|*[!0-9]*)
						printf "... Invalid ASN [ %s ]" "${host}"
						touch "${pfborig}${alias}.fail"
						continue
						;;
				esac
				grep -F ",AS${asn}," "${pathasncsv}" | cut -d ',' -f1-2 | tr ',' '-' > "${pfborig}${alias}.wk"

				# Collect only IPv4 or IPv6
				if [ "${vtype}" = '_v4' ]; then
					grep -v ':' "${pfborig}${alias}.wk" > "${pfborig}${alias}.orig"
				else
					grep -v '\.' "${pfborig}${alias}.wk" > "${pfborig}${alias}.orig"
				fi
			fi

			if [ -s "${pfborig}${alias}.orig" ]; then
				found=true
			else
				printf "... Failed to collect ASN"
				touch "${pfborig}${alias}.fail"
			fi
			rm -f "${pfborig}${alias}.wk"
			;;
		esac
	done <<EOF
${custom_list}
EOF

	# Restore previous orig file
	if [ "${found}" = false ]; then
		if [ -e "${pfborig}${alias}.bk" ]; then
			echo "... Restoring previous data"
			mv "${pfborig}${alias}.bk" "${pfborig}${alias}.orig"
		else
			echo "... Creating empty file"
			echo > "${pfborig}${alias}.orig"
		fi
	else
		if [ -e "${pfborig}${alias}.bk" ]; then
			rm -f "${pfborig}${alias}.bk"
		fi
	fi
}


# Function to convert IP to ASN
iptoasn() {

	if [ ! -x "${pathgeoip}" ]; then
		log="Application [ mmdblookup ] Not found, cannot proceed. [ ${now} ]"
		echo "${log}" | tee -a "${errorlog}"
		echo ""
		return
	fi

        # Download IPinfo asn databases on first use.
        if [ ! -f "${pathasndat}" ]; then
                echo "Downloading [ IPinfo databases ] [ ${now} ]" >> "${extraslog}" 
                /usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php asn
        fi

	# Exit if asn.mmdb is not found
	if [ ! -f "${pathasndat}" ]; then
		log="Database ASN [ asn.mmdb ] not found. Register for IPinfo Token."
		echo "${log}" | tee -a "${errorlog}"
		echo ""
		return
	fi 
	
	ip="${alias}"
	asn="$(${pathgeoip} -f "${pathasndat}" -i "${ip}" 2>&1 | tr -d '"{},' | grep -v '^[[:space:]]*$' | cut -d '<' -f1 | tr -s ' ' | tr '\n' '|' | sed -e 's/: |/: /g' -e 's/asn:/ ASN:/g')"

	# $asn is the lookup result string, not a filename: test its contents with
	# -n, not the file-exists test -s (issue #28).
	if [ -n "${asn}" ]; then
		echo "${asn}"
	else
		echo ""
	fi
}


# Function to convert IPinfo ASN.csv to pfblockerng_asn.txt ASN Lookup Table
asn_table() {

	if [ -f "${pathasncsv}" ]; then
		tail -n +2 "${pathasncsv}" | cut -d ',' -f3-4 | cut -c 3- | sort -nu | tr -d '"' | sed -e 's/,/ [ /g' -e 's/$/ ]/g' -e 's/^/AS/' > "${pathasntable}"
		echo "ASN Lookup Table has been updated [ ${now} ]" >> "${extraslog}"
	fi
}


# Function to check for Reputation application dependencies.
reputation_depends() {
	if [ ! -x "${pathgeoip}" ]; then
		log="Application [ mmdblookup ] Not found, cannot proceed. [ ${now} ]"
		echo "${log}" | tee -a "${errorlog}"
		return
	fi

	# Download MaxMind GeoLite2-Country.mmdb on first install.
	if [ ! -f "${pathgeoipdat}" ]; then
		echo "Downloading [ MaxMind GeoLite2-Country.mmdb ] [ ${now} ]" >> "${geoiplog}"
		/usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php bu
	fi

	# Exit if GeoLite2-Country.mmdb is not found
	if [ ! -f "${pathgeoipdat}" ]; then
		log="Database GeoIP [ GeoLite2-Country.mmdb ] not found. Reputation function terminated."
		echo "${log}" | tee -a "${errorlog}"
		return
	fi

	# Clear variables and tempfiles
	count=0; countb=0; countm=0; counts=0; countr=0
}


# Reputation function to condense an IP range if a 'Max' amount of IP addresses are found in a /24 range per individual list.
reputation_max() {
	LC_ALL=C sort -u "${pfbdeny}${alias}.txt" > "${tempfile}"
	data="$(cut -d '.' -f 1-3 "${tempfile}" | awk -v max="${max}" '{a[$0]++}END{for(i in a){if(a[i] > max){print i}}}')" 

	# Classify repeat offenders by Country code
	if [ -n "${data}" ]; then
		# Iterate the octet prefixes via a here-doc (no IFS re-splitting) so the
		# loop body stays in THIS shell -- it accumulates ${count}/${countr} and
		# appends to ${dupfile}/${matchfile}. Validate each to digits/dots and
		# skip a malformed token.
		while IFS= read -r ip; do
			pfb_is_octet_prefix "${ip}" || continue
			ccheck="$(${pathgeoip} -f "${pathgeoipdat}" -i "${ip}.1" country iso_code 2>&1 | grep -v 'Could\|Got\|^$' | cut -d '"' -f2)"
			# A failed GeoIP lookup yields an empty ${ccheck}; an unquoted *${ccheck}*
			# case pattern would collapse to '**' and match every ${cc}, wrongly
			# classifying the IP as a country match. Treat unknown as not-in-${cc}
			# (the block path, mirroring the default branch below).
			if [ -z "${ccheck}" ]; then
				count="$((count + 1))"
				echo "${ip}." >> "${dupfile}"
				continue
			fi
			case "${cc}" in
				*"${ccheck}"*)
					countr="$((countr + 1))"
					if [ "${ccwhite}" = 'match' ] || [ "${ccblack}" = 'match' ]; then
						echo "${ip}." >> "${matchfile}"
					fi
					;;
				*)
					count="$((count + 1))"
					echo "${ip}." >> "${dupfile}"
					;;
			esac
		done <<EOF
${data}
EOF
	else
		countr=0; count=0
	fi

	# Collect match file details
	if [ -s "${matchfile}" ] && [ "${dedup}" != 'on' ] && [ "${ccwhite}" = 'match' ]; then
		# Each matchfile line is a '10.0.0.'-style octet prefix. Read them
		# directly (no sed pre-escape, no IFS re-split), validate to digits/dots,
		# and build the anchored '^10\.0\.0\.' pattern via the shared helper so
		# only a literal prefix reaches grep.
		while IFS= read -r ip; do
			pfb_is_octet_prefix "${ip}" || continue
			grep "$(pfb_anchor_octet_pattern "${ip}")" "${tempfile}" >> "${tempfile2}"
		done < "${matchfile}"
		counts="$(grep -c ^ "${tempfile2}")"
		if [ "${ccwhite}" = 'match' ]; then
			sed 's/$/0\/24/' "${matchfile}" >> "${tempmatchfile}"
			sed 's/^/\!/' "${tempfile2}" >> "${tempmatchfile}"
		fi
	fi

	# If no matches found remove previous matchoutfile if exists.
	# Derive header from $alias (in scope), matching reputation_dmax/pmax; do not
	# rely on a stale $header global, and operate on the absolute ${pfbmatch}
	# path rather than a relative one (issue #27).
	header="${alias##*/}"; header="${header%%.*}"
	matchoutfile="match${header}.txt"
	if [ ! -s "${tempmatchfile}" ] && [ -f "${pfbmatch}${matchoutfile}" ]; then rm -f "${pfbmatch}${matchoutfile}"; fi
	# Move match file to the match folder by individual blocklist name
	if [ -s "${tempmatchfile}" ]; then mv -f "${tempmatchfile}" "${pfbmatch}${matchoutfile}"; fi

	# Find repeat offenders in each individual blocklist outfile
	if [ -s "${dupfile}" ]; then
		: > "${tempfile2}"
		# Each dupfile line is a '10.0.0.'-style octet prefix. Read them directly
		# (no sed pre-escape, no IFS re-split), validate to digits/dots, and build
		# the anchored '^10\.0\.0\.' pattern via the shared helper so only a
		# literal prefix reaches grep.
		while IFS= read -r ip; do
			pfb_is_octet_prefix "${ip}" || continue
			grep "$(pfb_anchor_octet_pattern "${ip}")" "${tempfile}" >> "${tempfile2}"
		done < "${dupfile}"
		countb="$(grep -c ^ "${tempfile2}")"

		if [ "${ccblack}" = 'block' ]; then
			# #713: gate the publish on awk's own exit status (awk has no "empty
			# result = rc 1" quirk -- non-zero is a real error) so a failed dedup
			# can't truncate the live deny list via a direct redirect; write to a
			# sibling temp and publish only on success.
			awk 'FNR==NR{a[$0];next}!($0 in a)' "${tempfile2}" "${tempfile}" > "${pfbdeny}${alias}.txt.tmp" && mv -f "${pfbdeny}${alias}.txt.tmp" "${pfbdeny}${alias}.txt"
			sed 's/$/0\/24/' "${dupfile}" >> "${pfbdeny}${alias}.txt"
		elif [ "${ccblack}" = 'match' ]; then
			sed 's/$/0\/24/' "${dupfile}" >> "${tempmatchfile}"
			sed 's/^/\!/' "${tempfile2}" >> "${tempmatchfile}"
		fi
	fi

	if [ "${count}" -gt 0 ]; then
		echo; echo "  Reputation (Max=${max}) - Range(s)"
		tr '\n' '|' < "${dupfile}"; echo
		LC_ALL=C sort -u "${pfbdeny}${alias}.txt" > "${tempfile}"; mv -f "${tempfile}" "${pfbdeny}${alias}.txt"
	fi

	if [ "${count}" -gt 0 ] || [ "${countr}" -gt 0 ]; then
		echo; echo '  Reputation -Max Stats'
		echo '  ------------------------------'
		printf "%-17s %-10s\n" '  Blacklisted' 'Match'
		printf "%-8s %-8s %-8s %-8s\n" '  Ranges' 'IPs' 'Ranges' 'IPs'
		echo '  ------------------------------'
		printf "%-8s %-8s %-8s %-8s\n" "  ${count}" "${countb}" "${countr}" "${counts}"
		echo
	fi
}


# Reputation function 'dMax' utilizing MaxMind GeoIP Country code.
reputation_dmax() {
	echo; echo '===[ Reputation - dMax ]======================================'
	echo; echo "  Querying for repeat offenders ( dMax=${max} ) [ ${now} ]"
	data="$(find "${pfbdeny}"*.txt ! -name 'pfB*.txt' ! -name '*_v6.txt' -type f | xargs cut -d '.' -f 1-3 | \
		awk -v max="${max}" '{a[$0]++}END{for(i in a){if(a[i] > max){print i}}}' | grep -v "^${ip_placeholder3}$")"

	# Classify repeat offenders by Country code
	if [ -n "${data}" ]; then
		echo '  Classifying repeat offenders by GeoIP'
		# Iterate the octet prefixes via a here-doc (no IFS re-splitting) so the
		# loop body stays in THIS shell -- it accumulates ${count}/${countr} and
		# appends to ${dupfile}/${matchfile}. Validate each to digits/dots and
		# skip a malformed token.
		while IFS= read -r ip; do
			pfb_is_octet_prefix "${ip}" || continue
			ccheck="$(${pathgeoip} -f "${pathgeoipdat}" -i "${ip}.1" country iso_code 2>&1 | grep -v 'Could\|Got\|^$' | cut -d '"' -f2)"
			# A failed GeoIP lookup yields an empty ${ccheck}; an unquoted *${ccheck}*
			# case pattern would collapse to '**' and match every ${cc}, wrongly
			# classifying the IP as a country match. Treat unknown as not-in-${cc}
			# (the block path, mirroring the default branch below).
			if [ -z "${ccheck}" ]; then
				count="$((count + 1))"
				echo "${ip}." >> "${dupfile}"
				continue
			fi
			case "${cc}" in
				*"${ccheck}"*)
					countr="$((countr + 1))"
					if [ "${ccwhite}" = 'match' ] || [ "${ccblack}" = 'match' ]; then
						echo "${ip}." >> "${matchfile}"
					fi
					;;
				*)
					count="$((count + 1))"
					echo "${ip}." >> "${dupfile}"
					;;
			esac
		done <<EOF
${data}
EOF
	else
		countr=0; count=0
	fi

	if [ "${ccwhite}" = 'match' ] && [ -s "${matchfile}" ]; then
		echo '  Processing [ Match ] IPs'
		# Each matchfile line is a '10.0.0.'-style octet prefix. Read them
		# directly (no sed pre-escape, no IFS re-split), validate to digits/dots,
		# and build the anchored '^10\.0\.0\.' pattern via the shared helper so
		# only a literal prefix reaches grep.
		while IFS= read -r ip; do
			pfb_is_octet_prefix "${ip}" || continue
			grep "$(pfb_anchor_octet_pattern "${ip}")" "${pfbdeny}"*.txt >> "${tempfile}"
		done < "${matchfile}"

		sed 's/$/0\/24/' "${matchfile}" >> "${tempmatchfile}"
		sed -e 's/.*://' -e 's/^/\!/' "${tempfile}" >> "${tempmatchfile}"
		mv -f "${tempmatchfile}" "${pfbmatch}${matchdedup}"
		countm="$(grep -c ^ "${tempfile}")"
		counts="$((countm + counts))"
	fi

	# Find repeat offenders in each individual blocklist outfile
	if [ "${count}" -gt 0 ]; then
		echo '  Processing [ Block ] IPs'

		# Each dupfile line is a '10.0.0.'-style octet prefix. Read them directly
		# from the file (no IFS re-split) so the body stays in THIS shell -- it
		# sets ${runonce} and appends to ${dedupfile}/${addfile}. Validate each to
		# digits/dots, then build the anchored '^10\.0\.0\.' pattern via the shared
		# helper so only a literal prefix reaches grep.
		while IFS= read -r ip; do
			pfb_is_octet_prefix "${ip}" || continue
			runonce=0; ii="$(pfb_anchor_octet_pattern "${ip}")"
			list="$(find "${pfbdeny}"*.txt ! -name 'pfB*.txt' ! -name '*_v6.txt' -type f | xargs grep -al "${ii}")"

			# Iterate the matched blocklist files via a here-doc (no IFS re-split)
			# so the inner body's ${runonce}/file accumulation stays in THIS shell.
			while IFS= read -r blfile; do
				[ -z "${blfile}" ] && continue
				header="${blfile##*/}"; header="${header%%.*}"
				grep "${ii}" "${blfile}" > "${tempfile}"

				if [ "${ccblack}" = 'block' ]; then
					# #713: gate the publish on awk's own exit status (awk has no "empty
					# result = rc 1" quirk -- non-zero is a real error) so a failed dedup
					# can't truncate this blocklist via an unconditional mv.
					awk 'FNR==NR{a[$0];next}!($0 in a)' "${tempfile}" "${blfile}" > "${tempfile2}" && mv -f "${tempfile2}" "${blfile}"
					if [ "${runonce}" -eq 0 ]; then
						echo "${ip}0/24" >> "${blfile}"
						echo "${header}" "${ip}" >> "${dedupfile}"
						echo "${header}" "${ip}0/24" >> "${addfile}"
						runonce=1
					else
						echo "${header}" "${ip}" >> "${dedupfile}"
					fi
				else
					if [ "${runonce}" -eq 0 ]; then
						matchoutfile="match${header}.txt"
						echo "${ip}0/24" >> "${pfbmatch}${matchoutfile}"
						sed 's/^/\!/' "${tempfile}" >> "${pfbmatch}${matchoutfile}"
						countm="$(grep -c ^ "${pfbmatch}${matchoutfile}")"
						counts="$((countm + counts))"
						runonce=1
					fi
				fi
			done <<EOF
${list}
EOF
		done < "${dupfile}"

		# Remove repeat offenders in masterfiles
		echo '  Removing   [ Block ] IPs'
		: > "${tempfile}"
		# Each dedupfile line is '<alias> 10.0.0.'. Anchor it at column 0 and escape
		# the prefix's dots (via pfb_anchor_octet_pattern; the alias field is \w-only,
		# so escaping the dots is sufficient) so the removal grep matches ONLY this
		# alias's own rows in that /24. An unanchored grep -F over-matched a SIBLING
		# alias whose name ends with this one's (e.g. row 'XMYLIST 1.2.3.9' contains
		# the substring 'MYLIST 1.2.3.'), silently dropping its masterfile entry (#730).
		while IFS= read -r ips; do
			[ -z "${ips}" ] && continue
			grep "$(pfb_anchor_octet_pattern "${ips}")" "${masterfile}" >> "${tempfile}"
		done < "${dedupfile}"
		countb="$(grep -c ^ "${tempfile}")"
		# #713: gate the publish on awk's own exit status (awk has no "empty
		# result = rc 1" quirk -- non-zero is a real error) so a failed dedup
		# can't truncate masterfile via an unconditional mv.
		awk 'FNR==NR{a[$0];next}!($0 in a)' "${tempfile}" "${masterfile}" > "${tempfile2}" && mv -f "${tempfile2}" "${masterfile}"
		cat "${addfile}" >> "${masterfile}"
		cut -d ' ' -f2 "${masterfile}" > "${mastercat}"

		echo; echo '  Removed the following IP ranges:'
		sed -e 's/^.* //' -e 's/0\/24//' "${addfile}" | tr '\n' '|'; echo
	fi

	if [ "${count}" -gt 0 ] || [ "${countr}" -gt 0 ]; then
		echo; echo '  Reputation - dMax Stats'
		echo '  ------------------------------'
		printf "%-17s %-10s\n" '  Blacklisted' 'Match'
		printf "%-8s %-8s %-8s %-8s\n" '  Ranges' 'IPs' 'Ranges' 'IPs'
		echo '  ------------------------------'
		printf "%-8s %-8s %-8s %-8s\n" "  ${count}" "${countb}" "${countr}" "${counts}"

		emptyfiles # Call emptyfiles function
	else
		echo '  Reputation -dMax ( None )'
	fi
}


# Reputation function 'pMax'. (No Country code exclusions)
reputation_pmax(){
	echo; echo; echo '===[ Reputation - pMax ]======================================'
	echo; echo "  Querying for repeat offenders ( pMax=${max} ) [ ${now} ]"
	data="$(find "${pfbdeny}"*.txt ! -name 'pfB*.txt' ! -name '*_v6.txt' -type f | xargs cut -d '.' -f 1-3 |
		awk -v max="${max}" '{a[$0]++}END{for(i in a){if(a[i] > max){print i}}}' | grep -v "^${ip_placeholder3}$")"

	if [ -n "${data}" ]; then
		# Find repeat offenders in each individual blocklist outfile
		echo '  Processing [ Block ] IPs'
		count=0

		# Iterate the octet prefixes via a here-doc (no IFS re-splitting) so the
		# loop body stays in THIS shell -- it accumulates ${count} and appends to
		# ${dedupfile}/${addfile}. Validate each to digits/dots, then build the
		# anchored '^10\.0\.0\.' pattern via the shared helper so only a literal
		# prefix reaches grep.
		while IFS= read -r ip; do
			pfb_is_octet_prefix "${ip}" || continue
			count="$((count + 1))"
			runonce=0; ii="$(pfb_anchor_octet_pattern "${ip}.")"
			list="$(find "${pfbdeny}"*.txt ! -name 'pfB*.txt' ! -name '*_v6.txt' -type f | xargs grep -al "${ii}")"

			# Iterate the matched blocklist files via a here-doc (no IFS re-split)
			# so the inner body's ${runonce}/file accumulation stays in THIS shell.
			while IFS= read -r blfile; do
				[ -z "${blfile}" ] && continue
				header="${blfile##*/}"; header="${header%%.*}"
				grep "${ii}" "${blfile}" > "${tempfile}"
				# #713: gate the publish on awk's own exit status (awk has no "empty
				# result = rc 1" quirk -- non-zero is a real error) so a failed dedup
				# can't truncate this blocklist via an unconditional mv.
				awk 'FNR==NR{a[$0];next}!($0 in a)' "${tempfile}" "${blfile}" > "${tempfile2}" && mv -f "${tempfile2}" "${blfile}"

				if [ "${runonce}" -eq 0 ]; then
					echo "${ip}.0/24" >> "${blfile}"
					echo "${header}" "${ip}." >> "${dedupfile}"
					echo "${header}" "${ip}.0/24" >> "${addfile}"
					runonce=1
				else
					echo "${header}" "${ip}." >> "${dedupfile}"
				fi
			done <<EOF
${list}
EOF
		done <<EOF
${data}
EOF

		# Remove repeat offenders in masterfile
		echo '  Removing   [ Block ] IPs'
		: > "${tempfile}"
		# Each dedupfile line is '<alias> 10.0.0.'. Anchor it at column 0 and escape
		# the prefix's dots (via pfb_anchor_octet_pattern; the alias field is \w-only,
		# so escaping the dots is sufficient) so the removal grep matches ONLY this
		# alias's own rows in that /24. An unanchored grep -F over-matched a SIBLING
		# alias whose name ends with this one's (e.g. row 'XMYLIST 1.2.3.9' contains
		# the substring 'MYLIST 1.2.3.'), silently dropping its masterfile entry (#730).
		while IFS= read -r ips; do
			[ -z "${ips}" ] && continue
			grep "$(pfb_anchor_octet_pattern "${ips}")" "${masterfile}" >> "${tempfile}"
		done < "${dedupfile}"
		countb="$(grep -c ^ "${tempfile}")"
		# #713: gate the publish on awk's own exit status (awk has no "empty
		# result = rc 1" quirk -- non-zero is a real error) so a failed dedup
		# can't truncate masterfile via an unconditional mv.
		awk 'FNR==NR{a[$0];next}!($0 in a)' "${tempfile}" "${masterfile}" > "${tempfile2}" && mv -f "${tempfile2}" "${masterfile}"
		cat "${addfile}" >> "${masterfile}"
		cut -d ' ' -f2 "${masterfile}" > "${mastercat}"

		echo; echo '  Removed the following IP ranges:'
		sed -e 's/^.* //' -e 's/0\/24//' "${addfile}" | tr '\n' '|'; echo

		echo; echo '  Reputation - pMax Stats'
		echo '  ----------------'
		printf "%-8s %-8s\n" '  Ranges' 'IPs'
		echo '  ----------------'
		printf "%-8s %-8s\n" "  ${count}" "${countb}"

		emptyfiles # Call emptyfiles function
	else
		echo '  Reputation -pMax ( None )'
	fi
}


# Function to split ET Pro IPREP into category files and compile selected blocked categories into outfile.
processet() {
	if [ -s "${pfborig}${alias}.orig" ]; then
		# Remove previous ET IPRep files
		[ -d "${etdir}" ] && [ "$(ls -A "${etdir}")" ] && rm -r "${etdir}/ET_"*
		: > "${tempfile}"; : > "${tempfile2}"

		# ET CSV format (IP, Category, Score)
		echo; echo; echo 'Compiling ET IPREP IQRisk based upon user selected categories'

		category=1
		etcat='ET_Cnc ET_Bot ET_Spam ET_Drop ET_Spywarecnc ET_Onlinegaming ET_Drivebysrc ET_Cat8 ET_Chatserver ET_Tornode
			ET_Cat11 ET_Cat12 ET_Compromised ET_Cat14 ET_P2P ET_Proxy ET_Ipcheck ET_Cat18 ET_Utility ET_DDostarget
			ET_Scanner ET_Cat22 ET_Brute ET_Fakeav ET_Dyndns ET_Undesireable ET_Abusedtld ET_Selfsignedssl ET_Blackhole ET_RAS
			ET_P2Pcnc ET_Cat32 ET_Parking ET_VPN ET_Exesource ET_Cat36 ET_Mobilecnc ET_Mobilespyware ET_Skypenode
			ET_Bitcoin ET_DDosattack'

		for file in ${etcat}; do

			case "${category}" in

				8|11|12|14|18|22|32|36)
					# Some ET categories are not in use (For future use)
					;;
				*)
					grep ",${category}," "${pfborig}${alias}.orig" | cut -d',' -f1 > "${etdir}/${file}.txt"
					;;
			esac
			category="$((category + 1))"
		done

		data="$(ls "${etdir}" | sed 's/\.txt//')"
		printf "%-10s %-25s\n" '  Action' 'Category'
		echo '-------------------------------------------'

		for list in ${data}; do
			# etblock/etmatch are ", "-separated token lists (see the sed transform
			# above); pad both sides with the delimiter and anchor on it so a token
			# only matches its OWN whole entry -- a bare "*$list*" substring glob
			# would let e.g. a selected ET_P2Pcnc also match list=ET_P2P (issue #713
			# bug 6). The padded 'x' sentinel (no selection) still matches nothing
			# real, since no category is literally named 'x'.
			case ", ${etblock}, " in
				*", ${list}, "*)
					printf "%-10s %-25s\n" '  Block: ' "${list}"
					cat "${etdir}/${list}.txt" >> "${tempfile}"
					;;
			esac
			case ", ${etmatch}, " in
				*", ${list}, "*)
					printf "%-10s %-25s\n" '  Match: ' "${list}"
					cat "${etdir}/${list}.txt" >> "${tempfile2}"
					;;
			esac
		done
		echo '-------------------------------------------'

		if [ -f "${tempfile}" ]; then mv -f "${tempfile}" "${pfborig}${alias}.orig"; fi
		if [ "${etmatch}" != 'x' ]; then mv -f "${tempfile2}" "${pfbmatch}/ETMatch.txt"; fi
		counto="$(cat "${etdir}"/ET_* | grep -cv '^#\|^$')"; countf="$(grep -cv "^${ip_placeholder2}$" "${pfborig}${alias}.orig")"
		echo; echo "All ET Folder count [ ${counto} ]  Final count [ ${countf} ]"
	else
		echo; echo 'No ET .orig File Found!'
	fi
}


# Function to extract IP addresses from XLSX files.
processxlsx() {
	if [ ! -x "${pathtar}" ]; then
		log='Application [ TAR ] Not found, cannot proceed.'
		echo "${log}" | tee -a "${errorlog}"
		return
	fi

	if [ -s "${pfborig}${alias}.raw" ]; then
		"${pathtar}" -xf "${pfborig}${alias}.raw" -C "${tmpxlsx}"
		"${pathtar}" -xOf "${tmpxlsx}"*.[xX][lL][sS][xX] "xl/sharedStrings.xml" | \
			grep -aoEw "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)" | LC_ALL=C sort -u > "${pfborig}${alias}.orig"
		rm -r "${tmpxlsx}"*

		countf="$(grep -cv "^${ip_placeholder2}$" "${pfborig}${alias}.orig")"
		echo; echo "Final count [ ${countf} ]"
	else
		echo 'XLSX download file missing'
		echo " [ ${alias} ] XLSX download file missing [ ${now} ]" >> "${errorlog}"
	fi
}


# Function to report final pfBlockerNG statistics.
closingprocess() {
	counto=0
	echo; echo '===[ FINAL Processing ]====================================='; echo
	if [ -d "${pfborig}" ] && [ "$(ls -A "${pfborig}")" ]; then
		# Sum the per-feed aggregated "Original" counts written by duplicate() -- these reflect the
		# CIDR-aggregated input when aggregation ran. Fall back to the raw *_v4.orig total when no
		# sidecars exist (de-duplication disabled, so duplicate() never ran).
		counto="$(find "${pfborig}"*_v4.aggcount 2>/dev/null | xargs cat 2>/dev/null | awk '{s += $1} END {print s + 0}')"
		if [ "${counto}" -eq 0 ]; then
			counto="$(find "${pfborig}"*_v4.orig 2>/dev/null | xargs cat | grep -cv '^#\|^$')"
		fi
	fi

	# Execute when 'de-duplication' is enabled
	if [ "${alias}" = 'on' ]; then
		LC_ALL=C sort -o "${masterfile}" "${masterfile}"
		sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n "${mastercat}" > "${tempfile}"; mv -f "${tempfile}" "${mastercat}"

		echo "   [ Original IP count   ]  [ ${counto} ]"
		countm="$(grep -c ^ "${masterfile}")"
		echo; echo "   [ Final IP Count  ]  [ ${countm} ]"; echo

		s1="$(grep -cv "^${ip_placeholder2}$" "${mastercat}")"
		s2="$(find "${pfbdeny}"*.txt ! -name '*_v6.txt' -type f 2>/dev/null | xargs cat | grep -cv "^${ip_placeholder2}$")"
		s3="$(sort "${mastercat}" | uniq -d | tail -30)"
		s4="$(find "${pfbdeny}"*.txt ! -name '*_v6.txt' -type f 2>/dev/null | xargs cat | sort | uniq -d | tail -30 | grep -v "^${ip_placeholder2}$")"
	else
		echo "   [ Original IP count   ]  [ ${counto} ]"
	fi

	if [ -d "${pfbpermit}" ] && [ "$(ls -A "${pfbpermit}")" ]; then
		echo; echo '===[ Permit List IP Counts ]========================='; echo
		wc -l "${pfbpermit}"*.txt 2>/dev/null | sort -n -r
	fi
	if [ -d "${pfbmatch}" ] && [ "$(ls -A "${pfbmatch}")" ]; then
		echo; echo '===[ Match List IP Counts ]=========================='; echo
		wc -l "${pfbmatch}"*.txt 2>/dev/null | sort -n -r
	fi
	if [ -d "${pfbdeny}" ] && [ "$(ls -A "${pfbdeny}")" ]; then
		echo; echo '===[ Deny List IP Counts ]==========================='; echo
		wc -l "${pfbdeny}"*.txt 2>/dev/null | sort -n -r
	fi
	if [ -d "${pfbnative}" ] && [ "$(ls -A "${pfbnative}")" ]; then
		echo; echo '===[ Native List IP Counts ] ==================================='; echo
		wc -l "${pfbnative}"*.txt 2>/dev/null | sort -n -r
	fi
	if [ -d "${pfbdeny}" ] && [ "$(ls -A "${pfbdeny}")" ]; then
		emptylists="$(grep "^${ip_placeholder2}$" "${pfbdeny}"*.txt | cut -d ':' -f1 | sed -e 's/^.*[a-zA-Z]\///')"
		if [ -n "${emptylists}" ]; then
			echo; echo "====================[ Empty Lists w/${ip_placeholder} ]=================="; echo
			for list in ${emptylists}; do
				echo "${list}"
			done
		fi
	fi
	if [ -d "${pfbdomain}" ] && [ "$(ls -A "${pfbdomain}")" ]; then
		echo; echo '===[ DNSBL Domain/IP Counts ] ==================================='; echo
		wc -l "${pfbdomain}"* 2>/dev/null | sort -n -r
	fi
	if [ -d "${pfborig}" ] && [ "$(ls -A "${pfborig}")" ]; then
		echo; echo '====================[ IPv4/6 Last Updated List Summary ]=============='; echo
		pfb_list_orig_by_mtime "${pfborig}"
	fi
	if [ -d "${pfbdomainorig}" ] && [ "$(ls -A "${pfbdomainorig}")" ]; then
		echo; echo '====================[ DNSBL Last Updated List Summary ]=============='; echo
		pfb_list_orig_by_mtime "${pfbdomainorig}"
	fi

	# Execute when 'de-duplication' is enabled
	if [ "${alias}" = 'on' ]; then
		echo '==============================================================='; echo
		if [ "${s1}" = "${s2}" ]; then
			echo 'Database Sanity check [  PASSED  ]'
		else
			echo 'Database Sanity check [  FAILED  ] ** These two counts should match! **'
			echo '------------'
			echo "Masterfile Count    [ ${s1} ]"
			echo "Deny folder Count   [ ${s2} ]"; echo
			echo 'Duplication sanity check (Pass=No IPs reported)'
		fi
		echo '------------------------'
		echo 'Masterfile/Deny folder uniq check'
		if [ -n "${s3}" ]; then echo "${s3}"; fi
		echo 'Deny folder/Masterfile uniq check'
		if [ -n "${s4}" ]; then echo "${s4}"; fi
		echo; echo 'Sync check (Pass=No IPs reported)'
		echo '----------'
	fi

	echo; echo 'Alias table IP Counts'; echo '-----------------------------'
	wc -l "${pfsensealias}"pfB_*.txt 2>/dev/null | sort -n -r

	echo; echo 'pfSense Table Stats'; echo '-------------------'
	"${pathpfctl}" -s memory | grep 'table-entries'
	pfctlcount="$(${pathpfctl} -vvsTables | awk '/Addresses/ {s+=$2}; END {print s}')"
	echo "Table Usage Count         ${pfctlcount}"
}

# When sourced for unit testing (PFB_SOURCED=1) stop here: only the function
# definitions above are wanted, not the init/dispatch below. `return` is valid at
# the top level of a sourced script and is never reached on direct execution
# (PFB_SOURCED is unset, so the && short-circuits).
[ -n "${PFB_SOURCED:-}" ] && return 0 2>/dev/null

# Call appropriate processes using script argument $1.
case "${1}" in
	_*)
		case "${1}" in *_255*) process255 ;; esac
		case "${1}" in *_agg*) cidr_aggregate ;; esac
		case "${1}" in *_rep*) reputation_depends; reputation_max ;; esac
		case "${1}" in *_dup*) duplicate ;; esac
		;;
	continent)
		duplicate
		;;
	cidr_aggregate)
		agg_folder=true
		cidr_aggregate
		;;
	aggregate)
		# ADR-11: pfblockerng.sh aggregate <family> <memberlist> <aggout> <consumerout>
		pfb_aggregate "$@"
		;;
	whoisconvert)
		whoisconvert
		;;
	iptoasn)
		iptoasn
		;;
	asn_table)
		asn_table
		;;
	suppress)
		suppress
		;;
	dmax)
		reputation_depends
		reputation_dmax
		;;
	pmax)
		reputation_depends
		reputation_pmax
		;;
	et)
		processet
		;;
	xlsx)
		processxlsx
		;;
	remove)
		remove
		;;
	aliastables)
		aliastables
		;;
	dnsbl_cache)
		# #468: DNSBL python-integration cache. $2 = stage | save | restore.
		dnsbl_cache "${2}"
		;;
	pfb_compress)
		# #468: single-sourced archive compression for callers (e.g. PHP
		# pfb_aliastables). Args after the action: <base> <files...> (the helper
		# appends .zst/.bz2 and picks the codec).
		shift
		pfb_archive_compress "$@"
		;;
	dnsbl-control)
		# PFBL-03: root-only DNSBL-control CLI. Forwards the operator's command to the
		# PHP writer, which validates it and writes it to the local privileged command
		# channel consumed by pfb_unbound.py. The arguments ride as their own positional
		# parameters (no URL/shell interpolation); the writer re-validates each.
		# Usage: pfblockerng dnsbl-control disable [sec] | enable |
		#        addbypass <ip> [sec] | removebypass <ip>
		shift
		/usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php dnsbl-control "$@"
		exitnow "$?"
		;;
	closing)
		emptyfiles
		closingprocess
		;;
	*)
		;;
esac
exitnow
