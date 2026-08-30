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

# issue #2851: normalize a STORED nested-pass timeout into the seconds the re-entry seam
# may use. Accepts whole seconds inside the same 60..7200 window pfblockerng.inc's
# pfb_reentry_timeout() accepts, and resolves everything else -- absent, empty,
# non-numeric, signed, padded, zero, negative, out-of-range, 64-bit-overflowing -- to the
# same finite 1800-second default, so a stored value can neither weaken the bound nor
# leave timeout(1) an empty duration (issue #2488's degradation class). Defined above the
# init block on purpose: sh executes top to bottom, and the init block below calls this.
# `test -ge/-le` compares DECIMAL (POSIX), so a hand-edited '0060' is sixty seconds here
# exactly as in PHP; arithmetic expansion would have read it as octal forty-eight.
pfb_reentry_timeout() {
	_pfbrt=1800
	case "${1:-}" in
	''|*[!0-9]*) : ;;
	*)	if [ "${1}" -ge 60 ] 2>/dev/null && [ "${1}" -le 7200 ] 2>/dev/null; then
			_pfbrt="${1}"
		fi
		;;
	esac
	printf '%s\n' "${_pfbrt}"
}

# read_xml_tag.sh's xmllint --xpath appends one separator newline. Keep all reader bytes
# visible, strip that one terminator, and preserve embedded or additional newlines so the
# strict resolver still rejects them.
pfb_reentry_timeout_from_reader() {
	_pfbrt_raw="$("$@"; printf x)"
	_pfbrt_raw="${_pfbrt_raw%x}"
	case "${_pfbrt_raw}" in
	*'
')	_pfbrt_raw="${_pfbrt_raw%?}" ;;
	esac
	pfb_reentry_timeout "${_pfbrt_raw}"
	unset _pfbrt_raw
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
	pathtimeout=/usr/bin/timeout
	pathtar=/usr/bin/tar
	pathpfctl=/sbin/pfctl
	pathphp=/usr/local/bin/php
	# issue #2016: the nested re-entry target and its budget (seconds). pfb_reentry()
	# floors an empty/non-numeric/zero value to its own default, so a degraded value can
	# never restore an unbounded wait.
	pathpfbphp=/usr/local/www/pfblockerng/pfblockerng.php
	# issue #2851: the operator's budget (General -> Advanced, 'Nested pass timeout'),
	# normalized to the accepted window here -- the boundary where the stored value enters
	# this process -- exactly as pfb_reentry_budget() normalizes it in PHP.
	pfbreentrytimeout="$(pfb_reentry_timeout_from_reader /usr/local/sbin/read_xml_tag.sh string installedpackages/pfblockerng/config/pfb_reentry_timeout)"

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
	# ADR-06: pfbdnsblsuppression / pfbalexa (legacy TOP1M whitelist) removed
	# (only used by the dropped dnsbl_scrub build-time whitelist/TOP1M removal;
	# now applied at query time).
	masterfile=/var/db/pfblockerng/masterfile
	mastercat=/var/db/pfblockerng/mastercat
	# issue #1084: pristine post-preprocessing feed snapshots (recompute memberlist inputs).
	pfbsnap=/var/db/pfblockerng/snapshot/
	geoiplog=/var/log/pfblockerng/geoip.log
	errorlog=/var/log/pfblockerng/error.log
	extraslog=/var/log/pfblockerng/extras.log

	# Folder Locations
	etdir=/var/db/pfblockerng/ET
	pfbdb=/var/db/pfblockerng/
	pfbdeny=/var/db/pfblockerng/deny/
	pfborig=/var/db/pfblockerng/original/
	pfbmatch=/var/db/pfblockerng/match/
	# issue #1250: machine-generated match artifacts, kept out of pfbmatch so a
	# user-chosen Match-list header can never collide with them.
	pfbmatchgen=/var/db/pfblockerng/match/generated/
	pfbpermit=/var/db/pfblockerng/permit/
	pfbnative=/var/db/pfblockerng/native/
	pfsensealias=/var/db/aliastables/
	pfbdomain=/var/db/pfblockerng/dnsbl/
	pfbdomainorig=/var/db/pfblockerng/dnsblorig/

	# issue #1250: repeat offenders in the selected/exempt (ccwhite=match)
	# countries, consolidated into one file
	matchexemptfile=pfB_Match_Exempt_v4.txt

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
	if [ ! -d "${pfbmatchgen}" ]; then mkdir "${pfbmatchgen}"; fi
	if [ ! -d "${pfbsnap}" ]; then mkdir "${pfbsnap}"; fi
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


# Token-shape guards for feed-derived list data spliced into `grep` patterns (anchored
# octet-prefix matches like `^10\.0\.0\.`). Previously only the literal dot was escaped, so
# any other regex metacharacter stayed live -- yielding an over-broad/incorrect match or an
# expensive pattern. Each guard passes only when the token is built solely from its allowed
# characters (digits, dots, and -- for CIDR -- a slash); a failing token is dropped by its
# caller (`continue`), never matched. Reject '' explicitly: `case ''` would match
# `*[!set]*`'s negation as "no disallowed char present" and pass.

# An octet prefix: one or more dot-separated decimal octets, digits and dots
# only (e.g. '10' or '10.0.0'). No anchors, no slash.
pfb_is_octet_prefix() {
	case "${1}" in
		''|*[!0-9.]*) return 1 ;;
		*) return 0 ;;
	esac
}

# A CIDR token: digits/dots, then EXACTLY one '/', then a non-empty numeric mask
# (e.g. '10.0.0.1/32'). suppress() (ADR-53) uses this to pre-filter the
# suppression list -- always mask-annotated (pfblockerng_ip.php's validation)
# -- before it reaches iprange: a bare IP, an empty mask ('10.0.0.1/'), or a
# double slash ('10.0.0.1//32') is rejected here and skipped.
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

# An IPv4 host-OR-CIDR token: either a bare host (digits/dots only, e.g.
# '203.0.113.5') or a CIDR (digits/dots, EXACTLY one '/', non-empty numeric
# mask, e.g. '10.9.8.0/24'). Unlike pfb_is_cidr_token (which REQUIRES the
# mask), member/deny-list lines are a mix of bare hosts and CIDRs. suppress()
# (ADR-53) uses this to pre-filter the deny member file before it reaches
# iprange: iprange treats anything of the wrong shape as a HOSTNAME and
# DNS-resolves it (rc=0, no opt-out flag) rather than rejecting it.
pfb_is_ip_or_cidr_token() {
	case "${1}" in
		''|*[!0-9./]*|*/*/*|/*|*/) return 1 ;;
	esac
	case "${1}" in
		*/*)
			case "${1##*/}" in
				''|*[!0-9]*) return 1 ;;  # mask must be non-empty digits
			esac
			;;
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


# DNSBL python-integration cache (#468). On a RAM-disk /var (use_mfs_tmpvar) the chroot is
# wiped on reboot, so DNSBL comes up dead; this keeps it alive across reboot with PURE FILE
# OPS (no reload/restart), kept SEPARATE from the IP aliastables flow above (different
# lifecycles). stage = copy the SHIPPED set (PFB_PY_SHIPPED) from /usr/local into the chroot
# (re-run on every save/restore, never restored stale); teardown = remove the SHIPPED set;
# save = stage then archive the
# GENERATED set plus exact TOP1M detector sidecars; restore = boot earlyshellcmd, untar
# the cached files THEN stage. Naming contract: a new generated file MUST keep the
# pfb_unbound*/pfb_py_* prefix; a new shipped file goes in PFB_PY_SHIPPED (the port's plist
# is GENERATED from the stagedir, so packaging needs nothing) -- dnsbl_psl rides
# PFB_PY_SHIPPED with the same source/chroot basename like every other entry; no
# NAME-MAPPED shipped file (source basename != chroot basename) remains (issue #1541
# retired the last one, dnsbl_tld). Order matters: a module goes
# BEFORE the file that imports it, so a
# load racing the staging loop never sees the importer without its dependency.
dnsbl_cache() {
	# Overridable for unit tests; default to the live locations.
	pfbchroot="${pfbchroot:-/var/unbound}"
	pfbpkgdir="${pfbpkgdir:-/usr/local/pkg/pfblockerng}"
	pfbdb="${pfbdb:-/var/db/pfblockerng}"
	dnsblarchive="${dnsblarchive:-/usr/local/etc/pfb_dnsbl_cache.tar}"
	pathtar="${pathtar:-/usr/bin/tar}"

	# The shipped (static) DNSBL Python files + their launcher -- the ONE definition of the set.
	PFB_PY_SHIPPED='dnsbl_psl pfb_dnsbl_regex_rules.py pfb_unbound.py pfb_unbound_include.inc pfb_py_hsts.txt pfb_python.sh'

	dnsbl_cache_stage() {
		mkdir -p "${pfbchroot}"
		chown -f unbound:unbound "${pfbchroot}"
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
	dnsbl_cache_teardown() {
		for _f in ${PFB_PY_SHIPPED}; do
			rm -f "${pfbchroot}/${_f}"
		done
	}

	case "${1}" in
		stage)
			dnsbl_cache_stage
			;;
		teardown)
			dnsbl_cache_teardown
			;;
		save)
			dnsbl_cache_stage
			# Archive the generated chroot set plus exact TOP1M detector sidecars,
			# EXCLUDING shipped files (PFB_PY_SHIPPED) -- those are re-staged from
			# /usr/local on restore, so archiving them would reinstate stale code (e.g.
			# pfb_py_hsts.txt matches the pfb_py_* glob but is shipped, not generated).
			set --
			for _g in "${pfbchroot}"/pfb_unbound* "${pfbchroot}"/pfb_py_*; do
				[ -e "${_g}" ] || continue
				_skip=''
				case "${_g}" in
					"${pfbchroot}"/pfb_py_raw.stage.*|"${pfbchroot}"/pfb_py_sources.lock) _skip=1 ;;
				esac
				for _s in ${PFB_PY_SHIPPED}; do
					[ "${_g}" = "${pfbchroot}/${_s}" ] && _skip=1 && break
				done
				[ -z "${_skip}" ] && set -- "$@" "${_g}"
			done
			# issue #1542: preserve only the TOP1M detector baseline sidecars;
			# transient and unrelated /var/db/pfblockerng files stay out.
			_top1m_base="${pfbdb%/}/top-1m.csv.zip"
			for _s in orig xxhash128 md5 source orig.etag orig.lastmod; do
				_f="${_top1m_base}.${_s}"
				[ -f "${_f}" ] && set -- "$@" "${_f}"
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
	# issue #1172: rc-checked truncate-create (see pfb_recompute()'s 'true >'
	# rationale) -- abort before the #713 publish gate instead of falling through.
	if ! true > "${dedupfile}"; then
		log="process255 [ ${alias} ]: cannot create [ ${dedupfile} ]; aborting."
		echo "${log}" | tee -a "${errorlog}"
		return
	fi
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

# Process to remove suppressed entries. Set-subtracts every suppression entry
# from the deny member file via `iprange --except` (ADR-53): a single call
# performs exact CIDR set subtraction and publishes the minimal covering-CIDR
# remainder, so a suppressed host is carved out of ANY containing entry (not
# just the exact /24 the old grep -F explode required) -- with no per-hole
# dedup bookkeeping, since iprange subtracts every hole in one pass.
suppress() {
	if [ ! -x "${pathaggregate}" ]; then
		log="Application [ iprange ] Not found. Cannot proceed."
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

			if [ -n "${alias}" ]; then
				countg="$(grep -c ^ "${pfbfolder}${alias}.txt")"

				# Strict-shape pre-filter on BOTH inputs before either reaches iprange
				# (ADR-53 §1.2): a malformed token is NOT rejected by iprange -- it is
				# silently treated as a HOSTNAME and DNS-resolved (rc=0, no opt-out
				# flag), so anything not a bare IPv4 host or IPv4 CIDR must never
				# reach it. The suppression list is user free-text; the member file
				# is already-sanitised feed data, filtered again here as
				# defense-in-depth, not because it is expected to need it.
				if ! true > "${dupfile}"; then
					log=" Suppression ${alias}: cannot create [ ${dupfile} ]; aborting suppression pass, keeping unsuppressed list."
					echo "${log}" | tee -a "${errorlog}"
					return
				fi
				while IFS= read -r ip; do
					if pfb_is_cidr_token "${ip}"; then
						echo "${ip}" >> "${dupfile}"
					elif [ -n "${ip}" ]; then
						log=" Suppression ${alias}: dropping malformed suppression entry [ ${ip} ]"
						echo "${log}" | tee -a "${errorlog}"
					fi
				done <<EOF
${data}
EOF

				# Member-file pre-filter: ONE grep -E pass, not a pure-shell
				# `while read` loop over the whole deny member file -- measured
				# ~10s at 200k lines for the loop vs ~0.04s for grep (~250x), and
				# a single grep is also immune to the classic "last line dropped
				# when the file lacks a trailing newline" while-read trap. The
				# ERE reproduces pfb_is_ip_or_cidr_token() EXACTLY: digits/dots
				# only, at most one '/', a non-empty digits-only mask when
				# present, never a leading or trailing '/' -- do not tighten this
				# to a stricter dotted-quad pattern, the function itself is lax.
				grep -E '^[0-9.]+(/[0-9]+)?$' "${pfbfolder}${alias}.txt" > "${dedupfile}"
				countd="$(grep -c ^ "${dedupfile}")"
				if [ "${countd}" -lt "${countg}" ]; then
					log=" Suppression ${alias}: dropped $((countg - countd)) malformed member-file line(s) before iprange"
					echo "${log}" | tee -a "${errorlog}"
				fi

				# iprange --except merges the files before it (ipset A, here the
				# member file) and removes every IP found in the files after it
				# (here the suppression file), printing the minimal covering-CIDR
				# remainder. rc=0 is success -- INCLUDING a legitimately-empty
				# result (everything suppressed; iprange has no grepcidr-style
				# "rc=1 = empty" quirk to special-case). Any other rc is a real
				# error (e.g. a missing/unloadable file): keep the previous list
				# intact and log, mirroring the #713 fail-safe pattern.
				"${pathaggregate}" "${dedupfile}" --except "${dupfile}" > "${tempfile2}"
				irc=$?
				if [ "${irc}" -eq 0 ]; then
					mv -f "${tempfile2}" "${pfbfolder}${alias}.txt"
				else
					rm -f "${tempfile2}"
					log="iprange error (rc=${irc}) suppressing [ ${alias} ]; keeping previous list"
					echo "${log}" | tee -a "${errorlog}"
				fi

				# Update masterfiles. Don't execute if duplication process is disabled
				if [ "${dedup}" = 'on' ]; then
					# Don't execute if alias doesn't exist in masterfile
					lcheck="$(grep -m1 "${alias}" "${masterfile}")"

					if [ -n "${lcheck}" ]; then
						# Replace masterfile with changes to list. Anchored (^) --
						# see remove()'s sibling grep for the suffix-over-match
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
				printf "%-20s %-10s %-10s %-10s\n" "${alias}" "${countg}" "${countx}" "${countk}"
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


# ADR-11: Union a set of already-effective member files into ONE deduped + CIDR-aggregated
# alias file, plus a never-empty '-f' consumer file. Type-AGNOSTIC (handed a plain list of
# member-file paths; per-type membership is decided in PHP by pfb_aggregate_member_list).
# Reuses the existing aggregation primitive (${pathaggregate} = iprange, set-exact: minimal
# CIDR cover equal to the union, never adds an address) -- NO new aggregation algorithm.
# Args: $2 family ('v4'|'v6', informational), $3 memberlist (member-file-list path), $4
# aggout (aggregate alias output), $5 consumerout (never-empty '-f' consumer output).
# mtime-gate: rebuild only when a listed member file is newer than the existing aggregate
# output; the consumer file must also already exist and be non-empty, else always rebuild.
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
	if ! true > "${tempfile}"; then
		log="aggregate [ ${agg_family} ]: cannot create [ ${tempfile} ]; failed; keeping existing."
		echo "${log}" | tee -a "${errorlog}"
		return
	fi
	while IFS= read -r agg_member; do
		[ -z "${agg_member}" ] && continue
		# issue #1263: awk 1 supplies a record terminator cat doesn't -- an
		# unterminated member no longer welds onto the next member's first line.
		[ -f "${agg_member}" ] && awk 1 "${agg_member}" >> "${tempfile}"
	done < "${agg_memberlist}"
	if ! LC_ALL=C sort -u "${tempfile}" > "${dedupfile}"; then
		log="aggregate [ ${agg_family} ]: union sort of [ ${tempfile} ] failed; keeping existing."
		echo "${log}" | tee -a "${errorlog}"
		return
	fi

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
		true > "${agg_tmp}"
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


# issue #1084: single-pass batch recompute -- cross-feed v4/v6-Deny dedup +
# v4 dMax/pMax reputation, replacing duplicate()/reputation_dmax()'s masterfile
# surgery and dmax/pmax's incremental per-file mutation for the CALLERS the
# .inc matrix (pfb_ip_recompute_matrix()) routes through it.
#
# Args (mirrors pfb_aggregate's memberlist-file convention):
#   $2 family      'v4' | 'v6' -- gates the reputation stage (v4-only) and
#                  selects which masterfile rows this pass owns (alias suffix
#                  "_${family}", e.g. "_v4"/"_v6").
#   $3 memberlist  Path to a file listing PRISTINE per-feed snapshot paths,
#                  one per line, in PRIORITY order (highest priority first).
#                  CONTRACT: a snapshot is whatever a per-feed file looked
#                  like right after preprocessing (post _255/_agg/_rep) --
#                  recompute never reads its own prior output. The alias is
#                  derived from the snapshot basename exactly as existing
#                  code derives a header from a file name: strip the
#                  directory, then strip from the first '.' onward (e.g.
#                  ".../FeedA_v4.orig" ->
#                  "FeedA_v4"). The memberlist MUST list every currently
#                  configured snapshot for THIS family -- an alias absent
#                  from the list is treated as removed: its masterfile rows
#                  and deny file are not carried forward by this pass (a
#                  feed removal or priority reorder is simply "recompute
#                  with the updated memberlist").
#   $4 countsfile  Output path for the per-alias row-count artifact ("alias
#                  count" lines, one per memberlist alias including 0),
#                  rendered at pass end by pfb_recompute_render_stats() as
#                  the per-feed update-log stats table (issue #1174).
#   $5 dedup       'on' | 'off'. 'on' runs the cumulative grepcidr
#                  containment prune (Stage A) and emits masterfile/
#                  mastercat; 'off' plain-copies every snapshot (overlaps
#                  across feeds are retained -- matches today's dedup-off
#                  double-counting in dMax/pMax) and skips masterfile.
#   $6 repmode     'off' | 'dmax' | 'pmax' -- v4-only; ignored for v6.
#   $7 max         dMax/pMax member-per-/24 threshold (repmode != 'off').
#   $8 cc          dMax only: comma-separated country-code list, matched
#                  against each offender /24's GeoIP country (below, $rec_cc).
#   $9 ccwhite     dMax only: 'match' | anything else.
#  $10 ccblack     dMax only: 'block' | 'match' | anything else.
#
# Pipeline (sequential, temp files, no pipes; LC_ALL=C inline per ADR-26):
#   A cumulative dedup -- for each snapshot in priority order: plain copy
#     when dedup=off OR the cumulative pattern set is still empty; else
#     `grepcidr -vf cumulative snapshot` (containment-aware, the #713 rc
#     gate: rc 0/1 publish, rc>=2 aborts the WHOLE pass, prior artifacts
#     untouched). Ownership is decided by loop order (memberlist priority).
#   B reputation decision (v4 + dmax/pmax only) -- a hashmap awk counts rows
#     per /24 prefix straight over the owned files (placeholder excluded);
#     offender prefixes are classified into an actionmap (dMax: today's
#     GeoIP loop verbatim, over just the offenders; a missing mmdblookup/db
#     bails like reputation_depends. pMax: every offender is block, no
#     GeoIP). An EMPTY actionmap -- repmode=off, every v6 pass, no
#     offenders, or GeoIP unavailable -- makes reputation a no-op.
#   C emit. Actionmap EMPTY (the common case): each owned file is
#     blank-filtered and sorted straight into its "<denydir><alias>.txt.new"
#     sibling -- no class-wide sort of any kind. Actionmap non-empty:
#     offender-/24 rows are diverted out of each owned file into one tagged
#     side set, ONE small sort makes it prefix-contiguous, and a windowed
#     awk drops block-mode offenders' member rows and emits ONE collapsed
#     "x.y.z.0/24" row owned by the HIGHEST-PRIORITY alias among that
#     window's members (a documented delta from today's incidental glob-
#     order attribution); match-mode offenders pass their rows through and
#     additionally emit pfB_Match_Rep_<alias>.txt (ccblack=match) / the single
#     pfB_Match_Exempt_v4.txt file (ccwhite=match, cc-list hits only -- mirrors today's
#     asymmetric gate). Survivors/collapsed rows are reinjected into their
#     owners' keep sets, then the per-alias emit runs identically to the
#     direct path -- reputation cost scales with offender rows, not class
#     size. Either path appends masterfile.new rows (dedup=on only --
#     pre-seeded with the LIVE masterfile minus every row whose alias
#     carries this pass's family suffix, so a second family's rows survive
#     a family-scoped recompute untouched) and the per-alias counts lines;
#     mastercat.new is cut from the completed masterfile.new.
#   swap -- every artifact above is written as a ".new" sibling of its live
#     path. Every mv is rc-checked, in sequence: a stage BEFORE the swap
#     failing logs, cleans up whatever ".new" siblings this pass already
#     wrote, and returns non-zero WITHOUT starting the swap; a mv WITHIN the
#     swap failing logs the artifact and returns non-zero WITHOUT rollback --
#     earlier moves in that same sequence may already be live, so the family
#     can stay mixed until the next successful pass.
#
# Callers (pfblockerng.inc's pfb_ip_recompute_matrix()): invoke once per
# family after per-feed preprocessing. recompute does not refill an empty
# deny file with the placeholder -- an alias with zero surviving rows still
# gets an empty ".txt.new" so the closing verb's emptyfiles() call can find
# and refill it.
pfb_recompute() {
	rec_family="${2}"
	rec_memberlist="${3}"
	rec_countsfile="${4}"
	rec_dedup="${5:-off}"
	rec_repmode="${6:-off}"
	rec_max="${7:-0}"
	rec_cc="${8:-}"
	# The legacy verbs' top-level init case-folds ccwhite/ccblack (never cc
	# itself) -- match it, or a capitalized config value silently disables
	# the dMax match/exempt branches below (both compare against 'match').
	rec_ccwhite="$(echo "${9:-off}" | tr '[:upper:]' '[:lower:]')"
	rec_ccblack="$(echo "${10:-off}" | tr '[:upper:]' '[:lower:]')"

	if [ -z "${rec_family}" ] || [ -z "${rec_memberlist}" ] || [ -z "${rec_countsfile}" ]; then
		log="recompute: missing family/memberlist/countsfile argument."
		echo "${log}" | tee -a "${errorlog}"
		return 1
	fi
	if [ ! -f "${rec_memberlist}" ]; then
		log="recompute [ ${rec_family} ]: member list [ ${rec_memberlist} ] not found."
		echo "${log}" | tee -a "${errorlog}"
		return 1
	fi
	if [ "${rec_dedup}" = 'on' ] && [ ! -x "${pathgrepcidr}" ]; then
		log="Application [ grepcidr ] Not found. Cannot proceed."
		echo "${log}" | tee -a "${errorlog}"
		return 1
	fi

	rec_scratch="${tmpdir}/pfb_recompute_${rec_family}"
	rm -rf "${rec_scratch}"
	mkdir -p "${rec_scratch}/owned"
	if [ ! -d "${rec_scratch}/owned" ]; then
		log="recompute [ ${rec_family} ]: could not create scratch dir [ ${rec_scratch} ]."
		echo "${log}" | tee -a "${errorlog}"
		return 1
	fi

	rec_cumulative="${rec_scratch}/cumulative"
	rec_priority="${rec_scratch}/priority"
	rec_matchexemptfile="${matchexemptfile:-pfB_Match_Exempt_v4.txt}"
	true > "${rec_cumulative}"
	true > "${rec_priority}"

	# Stage A: cumulative containment-aware dedup (or plain copy when
	# dedup=off), in memberlist/priority order. Ownership = loop order.
	rec_prio=0
	while IFS= read -r rec_snap; do
		[ -z "${rec_snap}" ] && continue
		rec_alias="${rec_snap##*/}"; rec_alias="${rec_alias%%.*}"
		if [ ! -f "${rec_snap}" ]; then
			# issue #1084: a dangling memberlist entry must never silently drop this
			# alias's masterfile rows while its live deny file keeps serving them --
			# self-heal from the live file (seed-snapshot's own upgrade fallback).
			rec_livefallback="${pfbdeny}${rec_alias}.txt"
			if [ -f "${rec_livefallback}" ]; then
				log="recompute [ ${rec_family} ]: snapshot missing for [ ${rec_alias} ]; falling back to the live deny file"
				echo "${log}" | tee -a "${errorlog}"
				rec_snap="${rec_livefallback}"
			else
				log="recompute [ ${rec_family} ]: snapshot missing for [ ${rec_alias} ] and no live deny file to fall back to; skipping"
				echo "${log}" | tee -a "${errorlog}"
				continue
			fi
		fi
		rec_prio=$((rec_prio + 1))
		echo "${rec_alias} ${rec_prio}" >> "${rec_priority}"
		rec_ownedfile="${rec_scratch}/owned/${rec_alias}.txt"

		if [ "${rec_dedup}" != 'on' ] || [ ! -s "${rec_cumulative}" ]; then
			if ! cp -f "${rec_snap}" "${rec_ownedfile}"; then
				log="recompute [ ${rec_family} ]: could not copy snapshot for [ ${rec_alias} ]; aborting pass, cleaning up partial artifacts"
				echo "${log}" | tee -a "${errorlog}"
				pfb_recompute_clean_new
				return 1
			fi
		else
			"${pathgrepcidr}" -vf "${rec_cumulative}" "${rec_snap}" > "${rec_ownedfile}"
			rec_grc=$?
			if [ "${rec_grc}" -ge 2 ]; then
				log="recompute [ ${rec_family} ]: grepcidr error (rc=${rec_grc}) de-duplicating [ ${rec_alias} ]; aborting pass, keeping previous artifacts"
				echo "${log}" | tee -a "${errorlog}"
				return 1
			fi
		fi

		if [ "${rec_dedup}" = 'on' ]; then
			# issue #1084/#1279: blank/whitespace-filtered -- an unfiltered blank
			# OR whitespace-only line still gives the cumulative nonzero size (the
			# `-s` guard above no longer sees it as empty), so a later alias hits
			# grepcidr with a pattern-free file, which prints NOTHING for -vf (not
			# "keep everything"): it would wipe every row of every lower-priority
			# feed sharing this pass.
			# issue #1929: a total-range row (0.0.0.0/0, ::/0) as a -vf pattern
			# MATCHES everything -- the same silent wipe -- so keep it out of the
			# cumulative stream; it still ships in this alias's own deny file.
			if ! LC_ALL=C awk -v allnetflag="${rec_scratch}/allnet" '
				{ sub(/\r$/, "") }
				!NF { next }
				$1 == "0.0.0.0/0" || $1 == "::/0" { print > allnetflag; next }
				{ print }' "${rec_ownedfile}" >> "${rec_cumulative}"; then
				log="recompute [ ${rec_family} ]: could not extend cumulative dedup stream for [ ${rec_alias} ]; aborting pass, cleaning up partial artifacts"
				echo "${log}" | tee -a "${errorlog}"
				pfb_recompute_clean_new
				return 1
			fi
			if [ -s "${rec_scratch}/allnet" ]; then
				log="recompute [ ${rec_family} ]: dropped total-range row(s) from [ ${rec_alias} ] before cumulative dedup (a 0.0.0.0/0 or ::/0 pattern would empty every lower-priority alias)"
				echo "${log}" | tee -a "${errorlog}"
				rm -f "${rec_scratch}/allnet"
			fi
		fi
	done < "${rec_memberlist}"

	# masterfile.new is pre-seeded with the live masterfile minus this
	# family's own rows (a sibling family's rows, from a separate per-family
	# recompute call, survive untouched) -- only when dedup=on.
	rec_masterfile_new="${masterfile}.new"
	rec_mastercat_new="${mastercat}.new"
	if [ "${rec_dedup}" = 'on' ]; then
		if [ -f "${masterfile}" ]; then
			awk -v suf="_${rec_family}" '{
				al = $1
				if (length(al) >= length(suf) && substr(al, length(al) - length(suf) + 1) == suf) next
				print
			}' "${masterfile}" > "${rec_masterfile_new}"
		else
			true > "${rec_masterfile_new}"
		fi
		rec_rc=$?
		if [ "${rec_rc}" -ne 0 ]; then
			log="recompute [ ${rec_family} ]: masterfile strip pass failed; aborting pass, cleaning up partial artifacts"
			echo "${log}" | tee -a "${errorlog}"
			pfb_recompute_clean_new
			return 1
		fi
	fi

	# 'true >' (a regular built-in), never ': >': a redirection error on a
	# special built-in exits non-interactive ash/dash entirely (POSIX XCU
	# 2.8.1), skipping the cleanup path below.
	rec_countsfile_new="${rec_countsfile}.new"
	while IFS=' ' read -r rec_alias _; do
		if ! true > "${pfbdeny}${rec_alias}.txt.new"; then
			log="recompute [ ${rec_family} ]: cannot create [ ${rec_alias}.txt.new ]; aborting pass, cleaning up partial artifacts"
			echo "${log}" | tee -a "${errorlog}"
			pfb_recompute_clean_new
			return 1
		fi
	done < "${rec_priority}"

	if ! true > "${rec_countsfile_new}"; then
		log="recompute [ ${rec_family} ]: cannot create countsfile staging; aborting pass, cleaning up partial artifacts"
		echo "${log}" | tee -a "${errorlog}"
		pfb_recompute_clean_new
		return 1
	fi

	# issue #1084 review: clear stale match-reputation ".new" debris (a CRASHED
	# prior pass, or a window-awk failure mid-write) BEFORE this pass runs -- else
	# it can survive to be wrongly promoted by a LATER pass that never actually
	# recomputed reputation for that alias.
	pfb_recompute_clean_rep_new
	rm -f "${pfbmatchgen}${rec_matchexemptfile}.new"

	rec_do_rep=0
	if [ "${rec_family}" = 'v4' ]; then
		case "${rec_repmode}" in
			dmax|pmax) rec_do_rep=1 ;;
		esac
	fi

	# Reputation decision first: offender detect + GeoIP classify need only
	# the owned files (a hashmap count -- never a sorted stream). An EMPTY
	# actionmap (no offenders, or GeoIP unavailable) makes reputation a
	# no-op, so that pass takes the same direct path as repmode=off.
	rec_actionmap="${rec_scratch}/actionmap"
	true > "${rec_actionmap}"
	if [ "${rec_do_rep}" -eq 1 ]; then
		if ! pfb_recompute_rep_actionmap; then
			pfb_recompute_clean_new
			return 1
		fi
	fi

	if [ -s "${rec_actionmap}" ]; then
		# Offenders exist: rows in offender /24s are diverted, windowed and
		# reinjected; every other row still rides the direct path.
		if ! pfb_recompute_rep_subset; then
			pfb_recompute_clean_new
			return 1
		fi
	else
		# The owned files already ARE the final per-alias partition -- emit
		# each directly (blank-filter + per-alias sort into the .txt.new
		# sibling); no class-wide sort of any kind.
		while IFS=' ' read -r rec_alias _; do
			rec_ownedfile="${rec_scratch}/owned/${rec_alias}.txt"
			if [ -f "${rec_ownedfile}" ]; then
				LC_ALL=C awk '{ sub(/\r$/, "") } NF' "${rec_ownedfile}" > "${rec_scratch}/direct"
				rec_rc=$?
				if [ "${rec_rc}" -eq 0 ]; then
					pfb_recompute_emit_alias "${rec_alias}" "${rec_scratch}/direct"
					rec_rc=$?
				fi
			else
				echo "${rec_alias} 0" >> "${rec_countsfile_new}"
				rec_rc=0
			fi
			if [ "${rec_rc}" -ne 0 ]; then
				log="recompute [ ${rec_family} ]: direct emit failed for [ ${rec_alias} ]; aborting pass, cleaning up partial artifacts"
				echo "${log}" | tee -a "${errorlog}"
				pfb_recompute_clean_new
				return 1
			fi
		done < "${rec_priority}"
	fi

	pfb_recompute_finish
	rec_rc=$?
	[ "${rec_rc}" -eq 0 ] && pfb_recompute_render_stats
	return "${rec_rc}"
}

# One alias's final emit: per-alias sort into the .txt.new sibling, masterfile
# row append (dedup=on), and the counts line. grep -c ^ counts an unterminated
# final line (wc -l undercounts; grepcidr/cp both preserve one).
pfb_recompute_emit_alias() { # $1 alias  $2 blank-free source file
	# issue #1084 review: -u -- a within-feed repeat (never pruned by the cross-feed
	# grepcidr containment, which only strips rows already owned by an EARLIER feed)
	# must still collapse to one row here, exactly like the retired duplicate()'s own
	# per-feed `sort -u`.
	LC_ALL=C sort -u "$2" > "${pfbdeny}$1.txt.new" || return 1
	if [ "${rec_dedup}" = 'on' ]; then
		awk -v a="$1" '{ print a " " $0 }' "${pfbdeny}$1.txt.new" >> "${rec_masterfile_new}" || return 1
	fi
	echo "$1 $(grep -c ^ "${pfbdeny}$1.txt.new")" >> "${rec_countsfile_new}"
}

# The recompute .new-sibling cleanup after a mid-emit failure: every artifact
# this pass may already have written, so an abort leaves the live files whole.
pfb_recompute_clean_new() {
	while IFS=' ' read -r rec_alias _; do
		rm -f "${pfbdeny}${rec_alias}.txt.new"
	done < "${rec_priority}"
	rm -f "${rec_masterfile_new}" "${rec_mastercat_new}" "${rec_countsfile_new}"
	pfb_recompute_clean_rep_new
}

# Same cleanup for the per-alias reputation artifacts' .new siblings (dMax emits
# them into matchgendir); the consolidated exempt file's .new stays caller-owned.
pfb_recompute_clean_rep_new() {
	[ -n "${pfbmatchgen:-}" ] || return 0
	while IFS=' ' read -r rec_alias _; do
		rm -f "${pfbmatchgen}pfB_Match_Rep_${rec_alias}.txt.new"
	done < "${rec_priority}"
}

# Offender detect + classify into rec_actionmap ("<prefix> <action>" rows).
# Detection is a hashmap count straight over the owned files -- no stream, no
# sort. Placeholder prefix excluded, same as reputation_pmax()'s class-wide scan.
pfb_recompute_rep_actionmap() {
	set --
	while IFS=' ' read -r rec_alias _; do
		# issue #1084 review: Continent/Uber (pfB_*) aliases never contribute to the
		# offender count -- legacy duplicate()/pmax excluded them the same way
		# (`find ! -name 'pfB*.txt'`).
		case "${rec_alias}" in pfB*) continue ;; esac
		rec_ownedfile="${rec_scratch}/owned/${rec_alias}.txt"
		[ -f "${rec_ownedfile}" ] && set -- "$@" "${rec_ownedfile}"
	done < "${rec_priority}"

	rec_offenders="${rec_scratch}/offenders"
	true > "${rec_offenders}"
	if [ "$#" -gt 0 ]; then
		awk -v max="${rec_max}" -v ph="${ip_placeholder3}" '
			{
				n = split($1, o, ".")
				if (n < 3) next
				pfx = o[1] "." o[2] "." o[3]
				if (pfx == ph) next
				cnt[pfx]++
			}
			END { for (p in cnt) if (cnt[p] > max) print p }
		' "$@" > "${rec_offenders}"
		rec_rc=$?
		if [ "${rec_rc}" -ne 0 ]; then
			log="recompute [ ${rec_family} ]: offender-detect pass failed; aborting pass"
			echo "${log}" | tee -a "${errorlog}"
			return 1
		fi
	fi

	{
		# C2 classify: dMax reuses reputation_max()'s GeoIP-classify loop shape
		# verbatim over just the offenders; a missing mmdblookup/db bails like
		# reputation_depends -- the actionmap stays empty and the pass rides
		# the direct path. pMax is unconditionally block-only.
		rec_geoip_ok=1
		if [ "${rec_repmode}" = 'dmax' ] && [ -s "${rec_offenders}" ]; then
			if [ ! -x "${pathgeoip}" ] || [ ! -f "${pathgeoipdat}" ]; then
				reputation_depends
			fi
			if [ ! -x "${pathgeoip}" ] || [ ! -f "${pathgeoipdat}" ]; then
				rec_geoip_ok=0
			fi
		fi

		if [ -s "${rec_offenders}" ]; then
			if [ "${rec_repmode}" = 'pmax' ]; then
				while IFS= read -r rec_pfx; do
					pfb_is_octet_prefix "${rec_pfx}" || continue
					echo "${rec_pfx} block" >> "${rec_actionmap}"
				done < "${rec_offenders}"
			elif [ "${rec_geoip_ok}" -eq 1 ]; then
				while IFS= read -r rec_pfx; do
					pfb_is_octet_prefix "${rec_pfx}" || continue
					rec_ccheck="$(${pathgeoip} -f "${pathgeoipdat}" -i "${rec_pfx}.1" country iso_code 2>&1 | grep -v 'Could\|Got\|^$' | cut -d '"' -f2)"
					if [ -z "${rec_ccheck}" ]; then
						if [ "${rec_ccblack}" = 'block' ]; then
							echo "${rec_pfx} block" >> "${rec_actionmap}"
						elif [ "${rec_ccblack}" = 'match' ]; then
							echo "${rec_pfx} matchdup" >> "${rec_actionmap}"
						fi
						continue
					fi
					case "${rec_cc}" in
						*"${rec_ccheck}"*)
							if [ "${rec_ccwhite}" = 'match' ] || [ "${rec_ccblack}" = 'match' ]; then
								echo "${rec_pfx} matchexempt" >> "${rec_actionmap}"
							fi
							;;
						*)
							if [ "${rec_ccblack}" = 'block' ]; then
								echo "${rec_pfx} block" >> "${rec_actionmap}"
							elif [ "${rec_ccblack}" = 'match' ]; then
								echo "${rec_pfx} matchdup" >> "${rec_actionmap}"
							fi
							;;
					esac
				done < "${rec_offenders}"
			fi
		fi
	}
	return 0
}

# The offender-subset reputation path: divert offender-/24 rows out of each
# owned file, window ONLY that (small) subset with the priority-attribution
# awk, reinject the survivors/collapsed rows, then emit per alias exactly
# like the direct path. Cost scales with offender rows, not class size.
pfb_recompute_rep_subset() {
	rec_matchexemptcidr="${rec_scratch}/matchexempt_cidr"
	rec_matchexemptmembers="${rec_scratch}/matchexempt_members"
	true > "${rec_matchexemptcidr}"
	true > "${rec_matchexemptmembers}"

	# Divert: blank-free keep file per alias; offender-prefix rows go to the
	# tagged side set instead.
	rec_side="${rec_scratch}/side"
	true > "${rec_side}"
	mkdir -p "${rec_scratch}/keep"
	while IFS=' ' read -r rec_alias _; do
		rec_ownedfile="${rec_scratch}/owned/${rec_alias}.txt"
		[ -f "${rec_ownedfile}" ] || continue
		# issue #1084 review: a Continent/Uber (pfB_*) alias rides reputation
		# untouched -- never diverted/windowed, same class exclusion as detection.
		case "${rec_alias}" in
			pfB*)
				LC_ALL=C awk '{ sub(/\r$/, "") } NF' "${rec_ownedfile}" > "${rec_scratch}/keep/${rec_alias}.keep"
				continue
				;;
		esac
		LC_ALL=C awk -v a="${rec_alias}" -v actionfile="${rec_actionmap}" -v side="${rec_side}" '
			BEGIN {
				while ((getline line < actionfile) > 0) {
					split(line, f, " "); act[f[1]] = 1
				}
				close(actionfile)
			}
			{ sub(/\r$/, "") }
			NF == 0 { next }
			{
				n = split($1, o, ".")
				pfx = (n >= 3) ? o[1] "." o[2] "." o[3] : ""
				if (pfx in act) { print $0 " " a >> side; next }
				print
			}
		' "${rec_ownedfile}" > "${rec_scratch}/keep/${rec_alias}.keep"
		rec_rc=$?
		if [ "${rec_rc}" -ne 0 ]; then
			log="recompute [ ${rec_family} ]: offender divert failed for [ ${rec_alias} ]; aborting pass"
			echo "${log}" | tee -a "${errorlog}"
			return 1
		fi
	done < "${rec_priority}"

	# The window awk needs prefix-contiguous input: one small sort over the
	# diverted rows only.
	rec_side_sorted="${rec_scratch}/side_sorted"
	LC_ALL=C sort -t ' ' -k1,1 "${rec_side}" > "${rec_side_sorted}"
	rec_rc=$?
	if [ "${rec_rc}" -ne 0 ]; then
		log="recompute [ ${rec_family} ]: offender-subset sort failed; aborting pass"
		echo "${log}" | tee -a "${errorlog}"
		return 1
	fi

	# pfB_Match_Rep_<alias>.txt is a dMax-owned artifact; start every candidate
	# fresh so the window awk's append-only writes never carry stale content.
	if [ "${rec_repmode}" = 'dmax' ]; then
		pfb_recompute_clean_rep_new
	fi

	# Window pass over the diverted subset: block-mode offenders collapse to
	# one /24 owned by the highest-priority member alias; match modes emit
	# their files and pass the rows through.
	rec_new_stream="${rec_scratch}/new_stream"
	true > "${rec_new_stream}"
	awk -v actionfile="${rec_actionmap}" -v priofile="${rec_priority}" \
			-v newstream="${rec_new_stream}" -v matchgendir="${pfbmatchgen}" \
			-v mexcidr="${rec_matchexemptcidr}" -v mexmem="${rec_matchexemptmembers}" '
			BEGIN {
				while ((getline line < actionfile) > 0) {
					split(line, f, " "); act[f[1]] = f[2]
				}
				close(actionfile)
				while ((getline line < priofile) > 0) {
					split(line, f, " "); prio[f[1]] = f[2]
				}
				close(priofile)
				curpfx = ""
				wincount = 0
			}
			function flush(   a, best, bestprio, i, curact, mfile) {
				if (curpfx == "") return
				curact = act[curpfx]
				if (curact == "block") {
					best = ""; bestprio = 2000000000
					for (a in winaliases) {
						if ((a in prio) && prio[a] + 0 < bestprio) { bestprio = prio[a] + 0; best = a }
					}
					if (best == "") { for (a in winaliases) { best = a; break } }
					print curpfx ".0/24 " best >> newstream
				} else {
					for (i = 1; i <= wincount; i++) print winrows[i] >> newstream
					if (curact == "matchdup") {
						for (a in winaliases) {
							mfile = matchgendir "pfB_Match_Rep_" a ".txt.new"
							print curpfx ".0/24" >> mfile
							for (i = 1; i <= wincount; i++) {
								if (winalias[i] == a) print "!" winip[i] >> mfile
							}
							close(mfile)
						}
					} else if (curact == "matchexempt") {
						print curpfx ".0/24" >> mexcidr
						for (i = 1; i <= wincount; i++) print "!" winip[i] >> mexmem
					}
				}
				wincount = 0
				delete winaliases; delete winrows; delete winip; delete winalias
			}
			{
				if ($0 == "") next
				n = split($1, o, ".")
				pfx = (n >= 3) ? o[1] "." o[2] "." o[3] : ""
				if (pfx != curpfx) { flush(); curpfx = pfx }
				wincount++
				winrows[wincount] = $0
				winip[wincount] = $1
				winalias[wincount] = $2
				winaliases[$2] = 1
			}
			END { flush() }
		' "${rec_side_sorted}"
	rec_rc=$?
	if [ "${rec_rc}" -ne 0 ]; then
		log="recompute [ ${rec_family} ]: reputation-apply pass failed; aborting pass"
		echo "${log}" | tee -a "${errorlog}"
		return 1
	fi

	# Reinject the window's survivors/collapsed rows into their owners' keep
	# files (alias-sorted first, so close() discipline caps open handles).
	rec_reinject="${rec_scratch}/reinject"
	LC_ALL=C sort -t ' ' -k2,2 -s "${rec_new_stream}" > "${rec_reinject}"
	rec_rc=$?
	if [ "${rec_rc}" -ne 0 ]; then
		log="recompute [ ${rec_family} ]: reinject sort failed; aborting pass"
		echo "${log}" | tee -a "${errorlog}"
		return 1
	fi
	awk -v keepdir="${rec_scratch}/keep" '
		{
			f = keepdir "/" $2 ".keep"
			if (f != cur) { if (cur != "") close(cur); cur = f }
			print $1 >> f
		}
	' "${rec_reinject}"
	rec_rc=$?
	if [ "${rec_rc}" -ne 0 ]; then
		log="recompute [ ${rec_family} ]: reinject pass failed; aborting pass, cleaning up partial artifacts"
		echo "${log}" | tee -a "${errorlog}"
		pfb_recompute_clean_new
		return 1
	fi

	# Final emit per alias from the keep files -- identical to the direct path.
	while IFS=' ' read -r rec_alias _; do
		rec_keep="${rec_scratch}/keep/${rec_alias}.keep"
		if [ -f "${rec_keep}" ]; then
			pfb_recompute_emit_alias "${rec_alias}" "${rec_keep}"
			rec_rc=$?
		else
			echo "${rec_alias} 0" >> "${rec_countsfile_new}"
			rec_rc=0
		fi
		if [ "${rec_rc}" -ne 0 ]; then
			log="recompute [ ${rec_family} ]: emit pass failed for [ ${rec_alias} ]; aborting pass, cleaning up partial artifacts"
			echo "${log}" | tee -a "${errorlog}"
			pfb_recompute_clean_new
			return 1
		fi
	done < "${rec_priority}"
	return 0
}

# One rc-checked swap move: a mid-swap failure cannot be rolled back (earlier
# moves in the same pass may already be live), so this only logs the
# offending artifact and lets the caller abort further swapping.
pfb_recompute_swap_mv() { # $1 src  $2 dst  $3 artifact label for the log
	if ! mv -f "$1" "$2"; then
		log="recompute [ ${rec_family} ]: swap failed moving [ $3 ] into place -- family may be partially swapped until the next successful pass"
		echo "${log}" | tee -a "${errorlog}"
		return 1
	fi
}

# The shared recompute artifact tail: mastercat derivation + the rc-checked
# per-file ".new" swap sequence, used by both the direct and offender-subset
# paths.
pfb_recompute_finish() {
	# mastercat derives from the COMPLETED masterfile.new (today's exact
	# derivation, both families' rows) -- masterfile.new always exists when
	# dedup=on, so the swap below can never hit a missing .new sibling.
	if [ "${rec_dedup}" = 'on' ]; then
		cut -d ' ' -f2 "${rec_masterfile_new}" > "${rec_mastercat_new}"
		rec_rc=$?
		if [ "${rec_rc}" -ne 0 ]; then
			log="recompute [ ${rec_family} ]: mastercat derivation failed; aborting pass, cleaning up partial artifacts"
			echo "${log}" | tee -a "${errorlog}"
			pfb_recompute_clean_new
			return 1
		fi
	fi

	# The consolidated exempt-country match file: gated on ccwhite='match'
	# ALONE (mirrors reputation_max()'s own asymmetric gate), even though a
	# 'matchexempt' action can also be reached via ccblack='match'.
	if [ "${rec_repmode}" = 'dmax' ] && [ "${rec_ccwhite}" = 'match' ] && [ -s "${rec_matchexemptcidr}" ]; then
		rec_matchexemptfile_new="${pfbmatchgen}${rec_matchexemptfile}.new"
		cat "${rec_matchexemptcidr}" > "${rec_matchexemptfile_new}"
		cat "${rec_matchexemptmembers}" >> "${rec_matchexemptfile_new}"
	fi

	# Swap: each artifact's ".new" sibling is moved into place in sequence,
	# rc-checked -- a failure here cannot be rolled back (earlier moves in
	# this loop may already be live), so it only logs the failing artifact
	# and aborts; the family may be mixed until the next successful pass.
	while IFS=' ' read -r rec_alias _; do
		pfb_recompute_swap_mv "${pfbdeny}${rec_alias}.txt.new" "${pfbdeny}${rec_alias}.txt" "${rec_alias}.txt.new" || return 1
	done < "${rec_priority}"

	if [ "${rec_dedup}" = 'on' ]; then
		pfb_recompute_swap_mv "${rec_masterfile_new}" "${masterfile}" 'masterfile.new' || return 1
		pfb_recompute_swap_mv "${rec_mastercat_new}" "${mastercat}" 'mastercat.new' || return 1
	fi

	pfb_recompute_swap_mv "${rec_countsfile_new}" "${rec_countsfile}" 'countsfile.new' || return 1

	if [ "${rec_do_rep}" -eq 1 ] && [ "${rec_repmode}" = 'dmax' ]; then
		if [ "${rec_geoip_ok:-1}" -eq 1 ]; then
			# GeoIP ran (or there were no offenders to classify) -- a missing ".new"
			# genuinely means "no reputation match for this alias this pass", so
			# reconciling away a stale live file here is correct, not destructive.
			while IFS=' ' read -r rec_alias _; do
				if [ -f "${pfbmatchgen}pfB_Match_Rep_${rec_alias}.txt.new" ]; then
					pfb_recompute_swap_mv "${pfbmatchgen}pfB_Match_Rep_${rec_alias}.txt.new" "${pfbmatchgen}pfB_Match_Rep_${rec_alias}.txt" "pfB_Match_Rep_${rec_alias}.txt.new" || return 1
				else
					rm -f "${pfbmatchgen}pfB_Match_Rep_${rec_alias}.txt"
				fi
			done < "${rec_priority}"
			if [ -f "${pfbmatchgen}${rec_matchexemptfile}.new" ]; then
				pfb_recompute_swap_mv "${pfbmatchgen}${rec_matchexemptfile}.new" "${pfbmatchgen}${rec_matchexemptfile}" "${rec_matchexemptfile}.new" || return 1
			elif [ "${rec_ccwhite}" = 'match' ]; then
				rm -f "${pfbmatchgen}${rec_matchexemptfile}"
			fi
		else
			log="recompute [ ${rec_family} ]: GeoIP unavailable this pass -- keeping previous reputation match artifacts"
			echo "${log}" | tee -a "${errorlog}"
		fi
	fi

	echo "recompute [ ${rec_family} ]: ${rec_prio} feed(s) processed."
}

# issue #1174: renders the .counts artifact as a per-feed Original/Final table
# on stdout (pre-suppression, like the retired duplicate() table) -- the PHP
# caller already pipes recompute's stdout into the update log.
pfb_recompute_render_stats() {
	[ -f "${rec_countsfile}" ] || return 0

	echo
	echo "===[ Recompute Stats [ ${rec_family} ] ]====================="
	echo '  ------------------------------------------------------'
	printf '%-36s %-10s %-10s\n' '  Alias' 'Original' 'Final'
	echo '  ------------------------------------------------------'
	while IFS=' ' read -r rec_alias rec_countf; do
		[ -z "${rec_alias}" ] && continue
		if [ -f "${pfborig}${rec_alias}.aggcount" ]; then
			rec_orig="$(cat "${pfborig}${rec_alias}.aggcount")"
		elif [ -f "${pfborig}${rec_alias}.orig" ]; then
			rec_orig="$(grep -cv '^#\|^$' "${pfborig}${rec_alias}.orig")"
		else
			rec_orig='?'
		fi
		printf '%-36s %-10s %-10s\n' "  ${rec_alias}" "${rec_orig}" "${rec_countf}"
	done < "${rec_countsfile}"
	echo '  ------------------------------------------------------'
	return 0
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


# issue #2016: the ONE seam every blocking nested pfblockerng.php re-entry goes through.
pfb_reentry() {
	# issue #2488: start AT the default and take the configured value only once it is
	# proven positive-integral, so no input can produce an empty or non-numeric duration
	# (which is how an AND-list bound degrades into an unbounded wait).
	_pfbre_tmo=1800
	case "${pfbreentrytimeout:-}" in
	''|*[!0-9]*) : ;;
	*) [ "${pfbreentrytimeout}" -gt 0 ] 2>/dev/null && _pfbre_tmo="${pfbreentrytimeout}" ;;
	esac
	# Default (reaper) mode -- a hung download pass must die as a whole tree; --foreground
	# would orphan a blocked fetch (docs/misc/external-process-waits.md).
	"${pathtimeout}" -s TERM -k 5 "${_pfbre_tmo}" "${pathphp}" "${pathpfbphp}" "$@"
	_pfbre_rc=$?
	if [ "${_pfbre_rc}" -eq 124 ]; then
		echo "Nested pfblockerng.php [ ${1} ] TIMED OUT after ${_pfbre_tmo}s and was killed" \
			| tee -a "${errorlog}"
	fi
	return "${_pfbre_rc}"
}


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
			hostout="$("${pathtimeout}" -s TERM -k 5 30 "${pathhost}" -t "${_type}" "${host}")"
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
			asnok=false
			# Download IPinfo asn databases on first use.
			if [ ! -f "${pathasncsv}" ]; then
				printf 'Downloading [ IPinfo databases ] [ %s ]' "${now}"
				pfb_reentry asn_shell scheduled
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

				# Collect only IPv4 or IPv6 for THIS entry, appending like the
				# domain branch (issue #1075: a `>` here truncated .orig, so each
				# ASN entry clobbered everything collected before it). grep exits
				# 0 iff it appended at least one line.
				if [ "${vtype}" = '_v4' ]; then
					grep -v ':' "${pfborig}${alias}.wk" >> "${pfborig}${alias}.orig" && asnok=true
				else
					grep -v '\.' "${pfborig}${alias}.wk" >> "${pfborig}${alias}.orig" && asnok=true
				fi
			fi

			if [ "${asnok}" = true ]; then
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
                pfb_reentry asn
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
		pfb_reentry bu scheduled
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
	# Derive header from $alias (mirrors reputation_pmax()); operate on the
	# absolute ${pfbmatchgen} path, not a relative one (issue #27).
	header="${alias##*/}"; header="${header%%.*}"
	matchoutfile="pfB_Match_Rep_${header}.txt"
	if [ ! -s "${tempmatchfile}" ] && [ -f "${pfbmatchgen}${matchoutfile}" ]; then rm -f "${pfbmatchgen}${matchoutfile}"; fi
	# Move match file to the match folder by individual blocklist name
	if [ -s "${tempmatchfile}" ]; then mv -f "${tempmatchfile}" "${pfbmatchgen}${matchoutfile}"; fi

	# Find repeat offenders in each individual blocklist outfile
	if [ -s "${dupfile}" ]; then
		if ! true > "${tempfile2}"; then
			log="reputation_max [ ${alias} ]: cannot create [ ${tempfile2} ]; aborting, keeping existing list."
			echo "${log}" | tee -a "${errorlog}"
			return
		fi
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
		if ! true > "${tempfile}"; then
			log="reputation_pmax: cannot create [ ${tempfile} ]; aborting, keeping existing masterfile."
			echo "${log}" | tee -a "${errorlog}"
			return
		fi
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
		# issue #1263: awk 1 guarantees masterfile stays newline-terminated --
		# cat would silently inherit addfile's bare tail if it lacked one.
		awk 1 "${addfile}" >> "${masterfile}"
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


# One failure exit for every writing step of an ET pass: $1 names the step, so an
# operator reads which one failed rather than a bare status. $2 is that status.
pfb_et_abort() {
	echo 'ET processing failed'
	echo " [ ${alias} ] ET processing failed at ${1}, exit ${2}; aborting ET processing [ ${now} ]" >> "${errorlog}"
}


# A candidate may be empty only when it is not replacing a non-empty live list.
# Every non-empty row must be one IPv4 literal; this also rejects binary
# diagnostics, BOMs, NUL-bearing rows, ranges, and CIDRs.
pfb_et_output_valid() {
	if [ ! -s "${1}" ]; then
		[ ! -s "${2}" ]
		return
	fi
	LC_ALL=C awk -F. '
		NF != 4 { exit 1 }
		{
			for (i = 1; i <= 4; i++) {
				if ($i !~ /^[0-9]+$/ || $i > 255) {
					exit 1
				}
			}
		}
	' "${1}"
}


# Function to split ET Pro IPREP into category files and compile selected blocked categories into outfile.
#
# issue #2683: the exit contract pfb_download() gates on. A failing status is
# returned verbatim rather than collapsed to 1, so a child killed at issue
# #2658's extraction ceiling reaches the caller as the 153 that names it.
processet() {
	etsource="${pfborig}${alias}.raw"
	if [ -s "${etsource}" ]; then
		# Remove previous ET IPRep files
		[ -d "${etdir}" ] && [ "$(ls -A "${etdir}")" ] && rm -r "${etdir}/ET_"*
		etgrep="${tempfile}.grep"
		etsplit="${tempfile}.split"
		if ! true > "${tempfile}" || ! true > "${tempfile2}" ||
			! true > "${etgrep}" || ! true > "${etsplit}"; then
			log="processet [ ${alias} ]: cannot create ET scratch file(s); aborting ET processing."
			echo "${log}" | tee -a "${errorlog}"
			return 1
		fi

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
					# grep rc 1 is a legitimate empty category. Its hard errors must
					# remain observable, so cut runs only after grep's status is saved.
					grep ",${category}," "${etsource}" > "${etgrep}"
					etrc=$?
					case "${etrc}" in
						0|1)
							cut -d',' -f1 "${etgrep}" > "${etsplit}" || { etrc=$?; pfb_et_abort "the ${file} split" "${etrc}"; return "${etrc}"; }
							pfb_et_output_valid "${etsplit}" '' || { etrc=$?; pfb_et_abort "the ${file} split validation" "${etrc}"; return "${etrc}"; }
							mv -f "${etsplit}" "${etdir}/${file}.txt" || { etrc=$?; pfb_et_abort "the ${file} split publish" "${etrc}"; return "${etrc}"; }
							;;
						*)
							pfb_et_abort "the ${file} category scan" "${etrc}"
							return "${etrc}"
							;;
					esac
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
					# issue #1263: awk 1 supplies a record terminator cat doesn't --
					# a category file no longer welds onto the next one accumulated.
					# Both accumulations stay on ONE line: pfblockerng_cat_weld_more_spec.sh
					# extracts each statement by line number and evals it.
					awk 1 "${etdir}/${list}.txt" >> "${tempfile}" || { etrc=$?; pfb_et_abort "the ${list} block accumulation" "${etrc}"; return "${etrc}"; }
					;;
			esac
			case ", ${etmatch}, " in
				*", ${list}, "*)
					printf "%-10s %-25s\n" '  Match: ' "${list}"
					awk 1 "${etdir}/${list}.txt" >> "${tempfile2}" || { etrc=$?; pfb_et_abort "the ${list} match accumulation" "${etrc}"; return "${etrc}"; }
					;;
			esac
		done
		echo '-------------------------------------------'

		if [ -f "${tempfile}" ]; then
			pfb_et_output_valid "${tempfile}" "${pfborig}${alias}.orig" || { etrc=$?; pfb_et_abort 'the block validation' "${etrc}"; return "${etrc}"; }
		fi
		if [ "${etmatch}" != 'x' ]; then
			pfb_et_output_valid "${tempfile2}" "${pfbmatchgen}pfB_Match_ET_v4.txt" || { etrc=$?; pfb_et_abort 'the match validation' "${etrc}"; return "${etrc}"; }
		fi
		if [ -f "${tempfile}" ]; then
			mv -f "${tempfile}" "${pfborig}${alias}.orig" || { etrc=$?; pfb_et_abort 'the block publish' "${etrc}"; return "${etrc}"; }
		fi
		if [ "${etmatch}" != 'x' ]; then
			mv -f "${tempfile2}" "${pfbmatchgen}pfB_Match_ET_v4.txt" || { etrc=$?; pfb_et_abort 'the match publish' "${etrc}"; return "${etrc}"; }
		fi
		# issue #1263: awk 1 supplies a record terminator cat doesn't -- an
		# unterminated ET_* file no longer welds its last row onto the next file's first.
		counto="$(awk 1 "${etdir}"/ET_* | grep -cv '^#\|^$')"; countf="$(grep -cv "^${ip_placeholder2}$" "${pfborig}${alias}.orig")"
		echo; echo "All ET Folder count [ ${counto} ]  Final count [ ${countf} ]"
		return 0
	else
		echo; echo 'No staged ET source file found!'
		echo " [ ${alias} ] No staged ET source file found; aborting ET processing [ ${now} ]" >> "${errorlog}"
		return 1
	fi
}


# Function to extract IP addresses from XLSX files.
#
# issue #2666: the exit contract pfb_download() gates on. A failing status is
# returned verbatim rather than collapsed to 1, so a child killed at issue
# #2658's extraction ceiling reaches the caller as the 153 that names it.
#
# issue #2682: an extraction that parses but yields no address is part of that
# contract -- it refuses the refresh instead of publishing an empty feed.
#
# issue #2684: the shared-strings part is streamed, not written to a file. It is
# XML, so it expands by two orders of magnitude past the workbook carrying it --
# 4,181,827 bytes from a 20,897-byte workbook on the fixture in
# tests/shell/pfblockerng_processxlsx_stream_spec.sh, and 10,083,388 from 49,160
# on a real ZIP-in-ZIP workbook -- while ${tmpdir} is a RAM disk on a default
# use_mfs_tmpvar install.
processxlsx() {
	if [ ! -x "${pathtar}" ]; then
		log='Application [ TAR ] Not found, cannot proceed.'
		echo "${log}" | tee -a "${errorlog}"
		return 1
	fi

	if [ ! -s "${pfborig}${alias}.raw" ]; then
		echo 'XLSX download file missing'
		echo " [ ${alias} ] XLSX download file missing [ ${now} ]" >> "${errorlog}"
		return 1
	fi

	# A SIBLING of the extraction target, never a file inside it: the container is
	# untrusted, and a member landing on this path would hand a remote feed the
	# status the publish gate below reads. ${tmpxlsx} is "${tmpdir}/xlsx/", so this
	# is "${tmpdir}/xlsx.rc" -- still inside the run's own 0700 mktemp directory.
	xlsxtarrc="${tmpxlsx%/}.rc"
	xlsxstage="${pfborig}${alias}.orig.tmp"

	# Only ONE status may be lost to the pipe, and neither of the two that decide
	# the feed is expendable: POSIX sh has no `pipefail` (and `set -o pipefail` is
	# not an option here -- `set` is a special builtin, so an option a base system
	# does not support aborts the whole script rather than failing one command).
	# So `grep` is the pipeline's LAST stage, which keeps its no-match exit 1
	# (issue #2682) as the pipeline's own status, and tar's status is stashed to a
	# file. Nothing can pre-seed that stash: it is not a path any container member
	# can reach, and ${tmpdir} is a fresh 0700 mktemp directory every run.
	# `set --` names ONE workbook: the glob splats into tar's argument list, where
	# every match after the first is a member selector, not a second archive.
	"${pathtar}" -xf "${pfborig}${alias}.raw" -C "${tmpxlsx}" &&
		set -- "${tmpxlsx}"*.[xX][lL][sS][xX] &&
		{ "${pathtar}" -xOf "$1" "xl/sharedStrings.xml" || echo "$?" > "${xlsxtarrc}"; } |
			grep -aoEw "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)" > "${xlsxstage}"
	xlsxrc=$?
	# tar's stashed status is read only when `grep` ran to completion -- exit 0 or
	# its no-match 1 -- and BEFORE the publish: a partial read still emits an
	# address for `grep` to match, so publishing would be issue #2666's defect
	# again, a truncated feed reported as a success. Above 1 the pipeline's own
	# status stands, because tar cannot be the cause: its only output is the pipe,
	# and RLIMIT_FSIZE does not bound a pipe write, so issue #2658's ceiling can
	# only kill the stage that writes a FILE. tar merely dies of EPIPE behind it,
	# and reading that over the 153 would cost pfb_extract_cap_note() the one
	# value it keys on to tell the operator "too large".
	if [ "${xlsxrc}" -le 1 ] && [ -s "${xlsxtarrc}" ]; then
		xlsxrc="$(cat "${xlsxtarrc}")"
	fi
	# `chmod` before the rename because published feeds have unprivileged readers
	# and a rename would hand the file the run's umask (as pfb_stage_publish()).
	# (POSIX permits sort -o's file among its inputs.)
	if [ "${xlsxrc}" -eq 0 ]; then
		LC_ALL=C sort -u -o "${xlsxstage}" "${xlsxstage}" &&
			chmod 644 "${xlsxstage}" &&
			mv -f "${xlsxstage}" "${pfborig}${alias}.orig"
		xlsxrc=$?
	fi
	rm -rf "${tmpxlsx}"* "${xlsxtarrc}"

	if [ "${xlsxrc}" -ne 0 ]; then
		# -rf, not -f: crash-leftover DIRECTORY debris here would otherwise survive
		# every later run and keep refusing the feed.
		rm -rf "${xlsxstage}"
		echo 'XLSX processing failed'
		echo " [ ${alias} ] XLSX processing failed, exit ${xlsxrc}; keeping existing [ ${now} ]" >> "${errorlog}"
		return "${xlsxrc}"
	fi

	countf="$(grep -cv "^${ip_placeholder2}$" "${pfborig}${alias}.orig")"
	echo; echo "Final count [ ${countf} ]"
	return 0
}


# Function to report final pfBlockerNG statistics.
closingprocess() {
	counto=0
	echo; echo '===[ FINAL Processing ]====================================='; echo
	if [ -d "${pfborig}" ] && [ "$(ls -A "${pfborig}")" ]; then
		# Sum the per-feed aggregated "Original" counts written by pfb_ip_recompute_write_snapshot()
		# (pfblockerng.inc) -- these reflect the CIDR-aggregated input when aggregation ran. Fall back
		# to the raw *_v4.orig total when no sidecars exist (no snapshot was ever written this pass).
		# issue #1263: awk 1 (not cat) supplies a missing record terminator --
		# a welded pair of unterminated counts would otherwise concatenate
		# digits (e.g. "100" + "200" -> "100200") instead of summing to 300.
		counto="$(find "${pfborig}"*_v4.aggcount 2>/dev/null | xargs awk 1 2>/dev/null | awk '{s += $1} END {print s + 0}')"
		if [ "${counto}" -eq 0 ]; then
			counto="$(find "${pfborig}"*_v4.orig 2>/dev/null | xargs awk 1 | grep -cv '^#\|^$')"
		fi
	fi

	# Execute when 'de-duplication' is enabled
	if [ "${alias}" = 'on' ]; then
		LC_ALL=C sort -o "${masterfile}" "${masterfile}"
		sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n "${mastercat}" > "${tempfile}"; mv -f "${tempfile}" "${mastercat}"

		echo "   [ Original IP count   ]  [ ${counto} ]"
		countm="$(grep -c ^ "${masterfile}")"
		echo; echo "   [ Final IP Count  ]  [ ${countm} ]"; echo

		# issue #1084 review: mastercat (s1/s3) now carries BOTH families' rows
		# (v6 Deny joined cross-list dedup) -- the deny-folder re-scan (s2/s4) must
		# include v6 Deny files too, else the family mismatch alone fails sanity.
		s1="$(grep -cv "^${ip_placeholder2}$" "${mastercat}")"
		# issue #1263: awk 1 -- an unterminated deny file no longer welds into its neighbour.
		s2="$(find "${pfbdeny}"*.txt -type f 2>/dev/null | xargs awk 1 | grep -cv "^${ip_placeholder2}$")"
		s3="$(LC_ALL=C sort "${mastercat}" | LC_ALL=C uniq -d | tail -30)"
		s4="$(find "${pfbdeny}"*.txt -type f 2>/dev/null | xargs awk 1 | LC_ALL=C sort | LC_ALL=C uniq -d | tail -30 | grep -v "^${ip_placeholder2}$")"
	else
		echo "   [ Original IP count   ]  [ ${counto} ]"
	fi

	if [ -d "${pfbpermit}" ] && [ "$(ls -A "${pfbpermit}")" ]; then
		echo; echo '===[ Permit List IP Counts ]========================='; echo
		wc -l "${pfbpermit}"*.txt 2>/dev/null | sort -n -r
	fi
	# issue #1250: key on the .txt files themselves -- `ls -A "${pfbmatch}"` is now always
	# non-empty (the generated/ subdir always exists), and `wc -l` emits a "total" line
	# even when every glob is unmatched. The generated artifacts still belong in this count.
	if [ -n "$(ls -A "${pfbmatch}"*.txt "${pfbmatchgen}"*.txt 2>/dev/null)" ]; then
		echo; echo '===[ Match List IP Counts ]=========================='; echo
		wc -l "${pfbmatch}"*.txt "${pfbmatchgen}"*.txt 2>/dev/null | sort -n -r
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
		# grep only prefixes matches with "path:" when given >=2 file args; a deny glob that
		# resolves to exactly one file then returns the bare match (the placeholder IP) and
		# `cut -d ':' -f1` picks that up instead of the filename. The appended /dev/null forces
		# a second (never-matching) file arg so the prefix -- and the filename -- always shows,
		# same idiom as issue #833's PHP-side fix (#842). See issue #844.
		emptylists="$(grep "^${ip_placeholder2}$" "${pfbdeny}"*.txt /dev/null | cut -d ':' -f1 | sed -e 's/^.*[a-zA-Z]\///')"
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
		;;
	cidr_aggregate)
		agg_folder=true
		cidr_aggregate
		;;
	aggregate)
		# ADR-11: pfblockerng.sh aggregate <family> <memberlist> <aggout> <consumerout>
		pfb_aggregate "$@"
		;;
	recompute)
		# issue #1084: pfblockerng.sh recompute <family> <memberlist> <countsfile>
		#              <dedup> <repmode> <max> <cc> <ccwhite> <ccblack>
		pfb_recompute "$@"
		exitnow "$?"
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
	pmax)
		reputation_depends
		reputation_pmax
		;;
	et)
		# issue #2683: same wiring as the `xlsx` arm below.
		processet
		exitnow "$?"
		;;
	xlsx)
		# issue #2666: the tail's bare `exitnow` defaults to 0, so the status has to
		# be threaded through here (as `recompute` does).
		processxlsx
		exitnow "$?"
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
		pfb_reentry dnsbl-control "$@"
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
