#!/bin/sh
# Fake pfctl for tests/php/PfbRemoveStatesTest.php.
#
# pfb_remove_states() (and its pfb_filterrules() helper) reach pfctl exclusively
# through $pfb['pfctl'], in four invocation shapes. This stub answers each from
# env-configured canned data so the REAL function runs off-appliance:
#
#   pfctl -vvsr                   -> cat "$PFB_FAKE_RULES"   (pfb_filterrules)
#   pfctl -s state                -> cat "$PFB_FAKE_STATES"  (caller redirects to states_tmp)
#   pfctl -t <table> -T test <ip> -> "1/1 addresses match." when <ip> is listed in
#                                    PFB_FAKE_MATCH (space-separated), else "0/1 ..."
#   pfctl -k <ip> [-k <ip>]       -> append the argv to "$PFB_FAKE_KILL_LOG" and print pfctl's
#                                    "killed N states ..." on stderr. Every canned state counts
#                                    as a flow TO the victim: the one-host form (states FROM
#                                    <ip>) kills 0; the two-host form kills PFB_FAKE_KILLED
#                                    (default 0), or 0 when the hosts' address families
#                                    differ (pfctl skips such a destination).
#
# Anything else fails loud: the test drove an invocation this stub does not model.

case "$1" in
	-vvsr)
		cat "${PFB_FAKE_RULES}"
		;;
	-s)
		cat "${PFB_FAKE_STATES}"
		;;
	-t)
		# argv: -t <table> -T test <ip>
		ip="$5"
		# shellcheck disable=SC2086 # PFB_FAKE_MATCH is a deliberate space-separated word list
		for m in ${PFB_FAKE_MATCH}; do
			if [ "${m}" = "${ip}" ]; then
				echo "1/1 addresses match."
				exit 0
			fi
		done
		echo "0/1 addresses match."
		;;
	-k)
		echo "$*" >> "${PFB_FAKE_KILL_LOG}"
		killed=0
		if [ "$#" -eq 4 ]; then
			case "$2" in *:*) src_af=6 ;; *) src_af=4 ;; esac
			case "$4" in *:*) dst_af=6 ;; *) dst_af=4 ;; esac
			[ "${src_af}" = "${dst_af}" ] && killed="${PFB_FAKE_KILLED:-0}"
		fi
		echo "killed ${killed} states from 1 sources and 0 destinations" >&2
		;;
	*)
		echo "fake_pfctl: unexpected invocation: $*" >&2
		exit 64
		;;
esac
