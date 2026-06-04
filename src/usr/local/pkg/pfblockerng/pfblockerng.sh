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
}

# Top-level initialisation. Guarded so the script can be sourced for unit tests
# (PFB_SOURCED=1) to exercise the functions below in isolation without running
# any of this; the executable path runs it because PFB_SOURCED is unset. The
# function definitions further down are always defined on source.
if [ -z "${PFB_SOURCED:-}" ]; then
	now=$(/bin/date +%m/%d/%y' '%T)

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
	aliasarchive="/usr/local/etc/aliastables.tar.bz2"
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
	tmpxlsx=/tmp/xlsx/
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

	# Create a private per-run temp directory (sets tempfile, tempfile2, ...).
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
	if [ ! -d "${tmpxlsx}" ]; then mkdir "${tmpxlsx}"; fi

	if [ ! -f "${masterfile}" ]; then touch "${masterfile}"; fi
	if [ ! -f "${mastercat}" ]; then touch "${mastercat}"; fi
fi


# Remove the private per-run temp directory before exiting (issue #30).
exitnow() {
	rm -rf "${tmpdir}"
	exit
}


# Function to restore IP aliastables and DNSBL database from archive on reboot. ( Ramdisk installations only )
aliastables() {
	if [ "${USE_MFS_TMPVAR}" -gt 0 ] || [ "${DISK_TYPE}" = 'md' ]; then
		if [ ! -d '/var/unbound' ]; then
			mkdir '/var/unbound'
			chown -f unbound:unbound /var/unbound
			chgrp -f unbound /var/unbound
		fi
		[ -f "${aliasarchive}" ] && cd / && /usr/bin/tar -Pxvf "${aliasarchive}"
	fi
}


# Function to write IP Placeholder IP to 'empty' final blocklist files.
emptyfiles() {
	emptyfiles="$(find ${pfbdeny}*.txt -size 0 2>/dev/null)"
	for i in ${emptyfiles}; do
		echo "${ip_placeholder}" > "${i}";
	done
}


# Function to remove lists from masterfiles and delete associated files.
remove() {
	echo; echo
	for i in ${cc}; do
		header="${i%*,}"
		if [ ! -z "${header}" ]; then
			# Make sure that alias exists in masterfile before removal.
			query="${header} "
			masterchk="$(grep -m1 "${query}" "${masterfile}")"

			if [ ! -z "${masterchk}" ]; then
				# Grep header with a trailing space character
				grep "${header}[[:space:]]" "${masterfile}" > "${tempfile}"
				awk 'FNR==NR{a[$0];next}!($0 in a)' "${tempfile}" "${masterfile}" > "${tempfile2}"; mv -f "${tempfile2}" "${masterfile}"
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

	if [ ! -z "${data255}" ]; then
		cp "${pfbdeny}${alias}.txt" "${tempfile}"

		for ip in ${data255}; do
			ii="$(echo "^${ip}." | sed 's/\./\\\./g')"
			grep "${ii}" "${tempfile}" >> "${dedupfile}"
		done

		awk 'FNR==NR{a[$0];next}!($0 in a)' "${dedupfile}" "${tempfile}" > "${pfbdeny}${alias}.txt"
		for ip in ${data255}; do echo "${ip}.0/24" >> "${pfbdeny}${alias}.txt"; done
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
		data="$(sort -u "${pfbsuppression}")"

		if [ ! -z "${data}" ] && [ ! -z "${alias}" ]; then
			if [ "${alias}" = 'suppressheader' ]; then
				echo; echo '===[ Suppression Stats ]==================================='; echo
				printf "%-20s %-10s %-10s %-10s\n" 'List' 'Pre' 'Suppress' 'Master'
				echo '-----------------------------------------------------------'
				return
			fi

			pfbfolder="${max}/"
			counter=0; : > "${dupfile}"

			if [ ! -z "${alias}" ]; then
				countg="$(grep -c ^ "${pfbfolder}${alias}.txt")"
				cp "${pfbfolder}${alias}.txt" "${tempfile}"

				for ip in ${data}; do
					found=''; dcheck='';
					mask="${ip##*/}"
					iptrim="${ip%.*}"
					ip="${ip%%/*}"
					found="$(grep -m1 "${iptrim}.0/24" "${tempfile}")"

					# If a suppression is '/32' and a blocklist has a full '/24' block, execute the following.
					if [ ! -z "${found}" ] && [ "${mask}" -eq 32 ]; then
						echo " Suppression ${alias}: ${iptrim}.0/24 (Excluding: ${ip}/32)"
						octet4="${ip##*.}"
						dcheck="$(grep "${iptrim}.0/24" "${dupfile}")"

						if [ -z "${dcheck}" ]; then
							echo "${iptrim}.0/24" >> "${dupfile}"
							counter="$((counter + 1))"

							# Add individual IP addresses from range excluding suppressed IP
							for i in $(/usr/bin/jot 255); do
								if [ "${i}" != "${octet4}" ]; then
									echo "${iptrim}.${i}" >> "${tempfile}"
									counter="$((counter + 1))"
								fi
							done
						fi
					fi
				done

				if [ -s "${dupfile}" ]; then
					# Remove '/24' suppressed ranges
					awk 'FNR==NR{a[$0];next}!($0 in a)' "${dupfile}" "${tempfile}" > "${tempfile2}"; mv -f "${tempfile2}" "${tempfile}"
				fi

				# Remove all other suppressions from list
				"${pathgrepcidr}" -vf "${pfbsuppression}" "${tempfile}" > "${pfbfolder}${alias}.txt"

				# Update masterfiles. Don't execute if duplication process is disabled
				if [ "${dedup}" = 'on' ]; then
					# Don't execute if alias doesn't exist in masterfile
					lcheck="$(grep -m1 "${alias}" "${masterfile}")"

					if [ ! -z "${lcheck}" ]; then
						# Replace masterfile with changes to list.
						grep "${alias}[[:space:]]" "${masterfile}" > "${tempfile}"
						awk 'FNR==NR{a[$0];next}!($0 in a)' "${tempfile}" "${masterfile}" > "${tempfile2}"
						mv -f "${tempfile2}" "${masterfile}"
						sed -e 's/^/'"$alias"' /' "${pfbfolder}${alias}.txt" >> "${masterfile}"
						cut -d ' ' -f2 "${masterfile}" > "${mastercat}"
					fi
				fi

				countk="$(grep -c ^ ${masterfile})"
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


# Function to remove duplicate entries in each list individually.
duplicate() {
	if [ ! -x "${pathgrepcidr}" ]; then
		log="Application [ grepcidr ] Not found. Cannot proceed."
		echo "${log}" | tee -a "${errorlog}"
		return
	fi

	dupcheck=1
	# Check if masterfile is empty
	hcheck="$(grep -cv ^$ ${masterfile})"; if [ "${hcheck}" -eq 0 ]; then dupcheck=0; fi
	# Check if alias exists in masterfile
	lcheck="$(grep -m1 "${alias}" "${masterfile}")"; if [ -z "${lcheck}" ]; then dupcheck=0; fi
	# Check for single alias in masterfile
	aliaslist="$(cut -d ' ' -f1 ${masterfile} | sort -u)"; if [ "${alias}" = "${aliaslist}" ]; then hcheck=0; fi

	# Only execute if 'Alias' exists in masterfile
	if [ "${dupcheck}" -eq 1 ]; then
		# Grep alias with a trailing space character
		grep "${alias}[[:space:]]" "${masterfile}" > "${tempfile}"
		awk 'FNR==NR{a[$0];next}!($0 in a)' "${tempfile}" "${masterfile}" > "${tempfile2}"; mv -f "${tempfile2}" "${masterfile}"
		cut -d ' ' -f2 "${masterfile}" > "${mastercat}"
	fi

	# Don't execute when only a single 'Alias' exists in masterfile
	if [ ! "${hcheck}" -eq 0 ]; then
		sort -u "${pfbdeny}${alias}.txt" > "${tempfile}"; mv -f "${tempfile}" "${pfbdeny}${alias}.txt"
		"${pathgrepcidr}" -vf "${mastercat}" "${pfbdeny}${alias}.txt" > "${tempfile}"; mv -f "${tempfile}" "${pfbdeny}${alias}.txt"
	fi

	sed -e 's/^/'"$alias"' /' "${pfbdeny}${alias}.txt" >> "${masterfile}"
	cut -d ' ' -f2 "${masterfile}" > "${mastercat}"

	counto="$(grep -cv '^#\|^$' "${pfborig}${alias}.orig")"
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
	custom_list="$(echo "${dedup}" | tr ',' ' ')"

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
	found=false

	for host in ${custom_list}; do
		# Determine if host is a Domain or an AS
		host_check="$(echo "${host}" | grep '\.')"
		if [ ! -z "${host_check}" ]; then
			found=true
			printf '  Collecting host IP: %s' "${host}"
			echo "### Domain: ${host} ###" >> "${pfborig}${alias}.orig"
			"${pathhost}" -t "${_type}" "${host}" | sed 's/^.* //' >> "${pfborig}${alias}.orig"
			echo "... completed"
		else
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
				grep ",AS${asn}," "${pathasncsv}" | cut -d ',' -f1-2 | tr ',' '-' > "${pfborig}${alias}.wk"

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
				found=false
			fi
			rm -f "${pfborig}${alias}.wk"
		fi
	done

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
	asn="$(${pathgeoip} -f ${pathasndat} -i "${ip}" 2>&1 | tr -d '"{},' | grep -v '^[[:space:]]*$' | cut -d '<' -f1 | tr -s ' ' | tr '\n' '|' | sed -e 's/: |/: /g' -e 's/asn:/ ASN:/g')"

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
		tail +2 "${pathasncsv}" | cut -d ',' -f3-4 | cut -c 3- | sort -nu | tr -d '"' | sed -e 's/,/ [ /g' -e 's/$/ ]/g' -e 's/^/AS/' > "${pathasntable}"
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
	sort -u "${pfbdeny}${alias}.txt" > "${tempfile}"
	data="$(cut -d '.' -f 1-3 "${tempfile}" | awk -v max="${max}" '{a[$0]++}END{for(i in a){if(a[i] > max){print i}}}')" 

	# Classify repeat offenders by Country code
	if [ ! -z "${data}" ]; then
		for ip in ${data}; do
			ccheck="$(${pathgeoip} -f ${pathgeoipdat} -i "${ip}.1" country iso_code 2>&1 | grep -v 'Could\|Got\|^$' | cut -d '"' -f2)"
			case "${cc}" in
				*$ccheck*)
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
		done
	else
		countr=0; count=0
	fi

	# Collect match file details
	if [ -s "${matchfile}" ] && [ "${dedup}" != 'on' ] && [ "${ccwhite}" = 'match' ]; then
		mon="$(sed -e 's/^/^/' -e 's/\./\\\./g' "${matchfile}")"
		for ip in ${mon}; do
			grep "${ip}" "${tempfile}" >> "${tempfile2}"
		done
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
	header="$(echo "${alias##*/}" | cut -d '.' -f1)"
	matchoutfile="match${header}.txt"
	if [ ! -s "${tempmatchfile}" ] && [ -f "${pfbmatch}${matchoutfile}" ]; then rm -f "${pfbmatch}${matchoutfile}"; fi
	# Move match file to the match folder by individual blocklist name
	if [ -s "${tempmatchfile}" ]; then mv -f "${tempmatchfile}" "${pfbmatch}${matchoutfile}"; fi

	# Find repeat offenders in each individual blocklist outfile
	if [ -s "${dupfile}" ]; then
		: > "${tempfile2}"
		dup="$(sed -e 's/^/^/' -e 's/\./\\\./g' "${dupfile}")"
		for ip in ${dup}; do
			grep "${ip}" "${tempfile}" >> "${tempfile2}"
		done
		countb="$(grep -c ^ "${tempfile2}")"

		if [ "${ccblack}" = 'block' ]; then
			awk 'FNR==NR{a[$0];next}!($0 in a)' "${tempfile2}" "${tempfile}" > "${pfbdeny}${alias}.txt"
			sed 's/$/0\/24/' "${dupfile}" >> "${pfbdeny}${alias}.txt"
		elif [ "${ccblack}" = 'match' ]; then
			sed 's/$/0\/24/' "${dupfile}" >> "${tempmatchfile}"
			sed 's/^/\!/' "${tempfile2}" >> "${tempmatchfile}"
		else
			:
		fi
	fi

	if [ "${count}" -gt 0 ]; then
		echo; echo "  Reputation (Max=${max}) - Range(s)"
		tr '\n' '|' < "${dupfile}"; echo
		sort -u "${pfbdeny}${alias}.txt" > "${tempfile}"; mv -f "${tempfile}" "${pfbdeny}${alias}.txt"
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
	data="$(find ${pfbdeny}*.txt ! -name 'pfB*.txt' ! -name '*_v6.txt' -type f | xargs cut -d '.' -f 1-3 | \
		awk -v max="${max}" '{a[$0]++}END{for(i in a){if(a[i] > max){print i}}}' | grep -v "^${ip_placeholder3}$")"

	# Classify repeat offenders by Country code
	if [ ! -z "${data}" ]; then
		echo '  Classifying repeat offenders by GeoIP'
		for ip in ${data}; do
			ccheck="$(${pathgeoip} -f ${pathgeoipdat} -i "${ip}.1" country iso_code 2>&1 | grep -v 'Could\|Got\|^$' | cut -d '"' -f2)"
			case "${cc}" in
				*$ccheck*)
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
		done
	else
		countr=0; count=0
	fi

	if [ "${ccwhite}" = 'match' ] && [ -s "${matchfile}" ]; then
		echo '  Processing [ Match ] IPs'
		match="$(sed -e 's/^/^/' -e 's/\./\\\./g' "${matchfile}")"

		for mfile in ${match}; do
			grep "${mfile}" "${pfbdeny}"*.txt >> "${tempfile}"
		done

		sed 's/$/0\/24/' "${matchfile}" >> "${tempmatchfile}"
		sed -e 's/.*://' -e 's/^/\!/' "${tempfile}" >> "${tempmatchfile}"
		mv -f "${tempmatchfile}" "${pfbmatch}${matchdedup}"
		countm="$(grep -c ^ "${tempfile}")"
		counts="$((countm + counts))"
	fi

	# Find repeat offenders in each individual blocklist outfile
	if [ "${count}" -gt 0 ]; then
		echo '  Processing [ Block ] IPs'
		dup="$(cat "${dupfile}")"

		for ip in ${dup}; do
			runonce=0; ii="$(echo "^${ip}" | sed 's/\./\\\./g')"
			list="$(find ${pfbdeny}*.txt ! -name 'pfB*.txt' ! -name '*_v6.txt' -type f | xargs grep -al "${ii}")"

			for blfile in ${list}; do
				header="$(echo "${blfile##*/}" | cut -d '.' -f1)"
				grep "${ii}" "${blfile}" > "${tempfile}"

				if [ "${ccblack}" = 'block' ]; then
					awk 'FNR==NR{a[$0];next}!($0 in a)' "${tempfile}" "${blfile}" > "${tempfile2}"; mv -f "${tempfile2}" "${blfile}"
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
			done
		done

		# Remove repeat offenders in masterfiles
		echo '  Removing   [ Block ] IPs'
		: > "${tempfile}"; : > "${tempfile2}"
		sed 's/\./\\\./g' "${dedupfile}" > "${tempfile2}"
		while IFS=' ' read -r ips; do grep "${ips}" "${masterfile}" >> "${tempfile}"; done < "${tempfile2}"
		countb="$(grep -c ^ "${tempfile}")"
		awk 'FNR==NR{a[$0];next}!($0 in a)' "${tempfile}" "${masterfile}" > "${tempfile2}"; mv -f "${tempfile2}" "${masterfile}"
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
	data="$(find ${pfbdeny}*.txt ! -name 'pfB*.txt' ! -name '*_v6.txt' -type f | xargs cut -d '.' -f 1-3 |
		awk -v max="${max}" '{a[$0]++}END{for(i in a){if(a[i] > max){print i}}}' | grep -v "^${ip_placeholder3}$")"

	if [ ! -z "${data}" ]; then
		# Find repeat offenders in each individual blocklist outfile
		echo '  Processing [ Block ] IPs'
		count=0

		for ip in ${data}; do
			count="$((count + 1))"
			runonce=0; ii="$(echo "^${ip}." | sed 's/\./\\\./g')"
			list="$(find ${pfbdeny}*.txt ! -name 'pfB*.txt' ! -name '*_v6.txt' -type f | xargs grep -al "${ii}")"

			for blfile in ${list}; do
				header="$(echo "${blfile##*/}" | cut -d '.' -f1)"
				grep "${ii}" "${blfile}" > "${tempfile}"
				awk 'FNR==NR{a[$0];next}!($0 in a)' "${tempfile}" "${blfile}" > "${tempfile2}"; mv -f "${tempfile2}" "${blfile}"

				if [ "${runonce}" -eq 0 ]; then
					echo "${ip}.0/24" >> "${blfile}"
					echo "${header}" "${ip}." >> "${dedupfile}"
					echo "${header}" "${ip}.0/24" >> "${addfile}"
					runonce=1
				else
					echo "${header}" "${ip}." >> "${dedupfile}"
				fi
			done
		done

		# Remove repeat offenders in masterfile
		echo '  Removing   [ Block ] IPs'
		: > "${tempfile}"; : > "${tempfile2}"
		sed 's/\./\\\./g' "${dedupfile}" > "${tempfile2}"
		while IFS=' ' read -r ips; do grep "${ips}" "${masterfile}" >> "${tempfile}"; done < "${tempfile2}"
		countb="$(grep -c ^ "${tempfile}")"
		awk 'FNR==NR{a[$0];next}!($0 in a)' "${tempfile}" "${masterfile}" > "${tempfile2}"; mv -f "${tempfile2}" "${masterfile}"
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
		[ -d "${etdir}" ] && [ "$(ls -A ${etdir})" ] && rm -r "${etdir}/ET_"*
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

		data="$(ls ${etdir} | sed 's/\.txt//')"
		printf "%-10s %-25s\n" '  Action' 'Category'
		echo '-------------------------------------------'

		for list in ${data}; do
			case "${etblock}" in
				*$list*)
					printf "%-10s %-25s\n" '  Block: ' "${list}"
					cat "${etdir}/${list}.txt" >> "${tempfile}"
					;;
			esac
			case "${etmatch}" in
				*$list*)
					printf "%-10s %-25s\n" '  Match: ' "${list}"
					cat "${etdir}/${list}.txt" >> "${tempfile2}"
					;;
			esac
		done
		echo '-------------------------------------------'

		if [ -f "${tempfile}" ]; then mv -f "${tempfile}" "${pfborig}${alias}.orig"; fi
		if [ "${etmatch}" != 'x' ]; then mv -f "${tempfile2}" "${pfbmatch}/ETMatch.txt"; fi
		counto="$(cat ${etdir}/ET_* | grep -cv '^#\|^$')"; countf="$(grep -cv "^${ip_placeholder2}$" "${pfborig}${alias}.orig")"
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
			grep -aoEw "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)" | sort -u > "${pfborig}${alias}.orig"
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
	if [ -d "${pfborig}" ] && [ "$(ls -A ${pfborig})" ]; then
		counto="$(find ${pfborig}*_v4.orig 2>/dev/null | xargs cat | grep -cv '^#\|^$')"
	fi

	# Execute when 'de-duplication' is enabled
	if [ "${alias}" = 'on' ]; then
		sort -o "${masterfile}" "${masterfile}"
		sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n "${mastercat}" > "${tempfile}"; mv -f "${tempfile}" "${mastercat}"

		echo "   [ Original IP count   ]  [ ${counto} ]"
		countm="$(grep -c ^ ${masterfile})"
		echo; echo "   [ Final IP Count  ]  [ ${countm} ]"; echo

		s1="$(grep -cv "^${ip_placeholder2}$" "${mastercat}")"
		s2="$(find ${pfbdeny}*.txt ! -name '*_v6.txt' -type f 2>/dev/null | xargs cat | grep -cv "^${ip_placeholder2}$")"
		s3="$(sort "${mastercat}" | uniq -d | tail -30)"
		s4="$(find ${pfbdeny}*.txt ! -name '*_v6.txt' -type f 2>/dev/null | xargs cat | sort | uniq -d | tail -30 | grep -v "^${ip_placeholder2}$")"
	else
		echo "   [ Original IP count   ]  [ ${counto} ]"
	fi

	if [ -d "${pfbpermit}" ] && [ "$(ls -A ${pfbpermit})" ]; then
		echo; echo '===[ Permit List IP Counts ]========================='; echo
		wc -l "${pfbpermit}"*.txt 2>/dev/null | sort -n -r
	fi
	if [ -d "${pfbmatch}" ] && [ "$(ls -A ${pfbmatch})" ]; then
		echo; echo '===[ Match List IP Counts ]=========================='; echo
		wc -l "${pfbmatch}"*.txt 2>/dev/null | sort -n -r
	fi
	if [ -d "${pfbdeny}" ] && [ "$(ls -A ${pfbdeny})" ]; then
		echo; echo '===[ Deny List IP Counts ]==========================='; echo
		wc -l "${pfbdeny}"*.txt 2>/dev/null | sort -n -r
	fi
	if [ -d "${pfbnative}" ] && [ "$(ls -A ${pfbnative})" ]; then
		echo; echo '===[ Native List IP Counts ] ==================================='; echo
		wc -l "${pfbnative}"*.txt 2>/dev/null | sort -n -r
	fi
	if [ -d "${pfbdeny}" ] && [ "$(ls -A ${pfbdeny})" ]; then
		emptylists="$(grep "^${ip_placeholder2}$" ${pfbdeny}*.txt | cut -d ':' -f1 | sed -e 's/^.*[a-zA-Z]\///')"
		if [ ! -z "${emptylists}" ]; then
			echo; echo "====================[ Empty Lists w/${ip_placeholder} ]=================="; echo
			for list in ${emptylists}; do
				echo "${list}"
			done
		fi
	fi
	if [ -d "${pfbdomain}" ] && [ "$(ls -A ${pfbdomain})" ]; then
		echo; echo '===[ DNSBL Domain/IP Counts ] ==================================='; echo
		wc -l "${pfbdomain}"* 2>/dev/null | sort -n -r
	fi
	if [ -d "${pfborig}" ] && [ "$(ls -A ${pfborig})" ]; then
		echo; echo '====================[ IPv4/6 Last Updated List Summary ]=============='; echo
		ls -lahtr "${pfborig}"*.orig | sed -e 's/\/.*\// /' -e 's/.orig//' | awk -v OFS='\t' '{print $6" "$7,$8,$9}'
	fi
	if [ -d "${pfbdomainorig}" ] && [ "$(ls -A ${pfbdomainorig})" ]; then
		echo; echo '====================[ DNSBL Last Updated List Summary ]=============='; echo
		ls -lahtr "${pfbdomainorig}"*.orig | sed -e 's/\/.*\// /' -e 's/.orig//' | awk -v OFS='\t' '{print $6" "$7,$8,$9}'
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
		if [ ! -z "${s3}" ]; then echo "${s3}"; fi
		echo 'Deny folder/Masterfile uniq check'
		if [ ! -z "${s4}" ]; then echo "${s4}"; fi
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
		if [ "$(echo "${1}" | grep -c '_255')" -gt 0 ]; then process255; fi
		if [ "$(echo "${1}" | grep -c '_agg')" -gt 0 ]; then cidr_aggregate; fi
		if [ "$(echo "${1}" | grep -c '_rep')" -gt 0 ]; then reputation_depends; reputation_max; fi
		if [ "$(echo "${1}" | grep -c '_dup')" -gt 0 ]; then duplicate; fi
		;;
	continent)
		duplicate
		;;
	cidr_aggregate)
		agg_folder=true
		cidr_aggregate
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
	closing)
		emptyfiles
		closingprocess
		;;
	*)
		;;
esac
exitnow
