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
#   pfctl -k <ip> [-k <ip>]       -> append the argv to "$PFB_FAKE_KILL_LOG"
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
		;;
	*)
		echo "fake_pfctl: unexpected invocation: $*" >&2
		exit 64
		;;
esac
