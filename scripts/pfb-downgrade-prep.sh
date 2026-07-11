#!/bin/sh
# pfb-downgrade-prep.sh — prepare a pfBlockerNG 4.0.x install for a downgrade to a
# pre-4.0.x release, so rolling the package back is clean.
#
# Dev/ops-only tool: NOT shipped in the package (release archives are src/ only).
# Copy it to the appliance and run it there as root, BEFORE the `pkg` downgrade.
#
#   scp scripts/pfb-downgrade-prep.sh root@<box>:/tmp/
#   ssh root@<box> 'sh /tmp/pfb-downgrade-prep.sh'
#   ssh root@<box> 'pkg delete pfSense-pkg-pfBlockerNG-devel && pkg install <older>'
#
# It reverses the two 4.0.x changes a pre-4.0.x release cannot cope with and that do
# NOT self-heal:
#
#   1. Custom list pre/post scripts relocated into list_scripts/ on upgrade — a
#      pre-4.0.x release resolves list scripts against the package ROOT only, so a
#      moved script silently stops running. They are moved back to the root.
#   2. The ADR-43 scheduled-tick cron entry (`pfblockerng.php cron-tick`, or the
#      legacy `pfblockerng.php tick` on an older build -- issue #1204) is removed, so
#      the downgraded release re-establishes its own schedule on its next sync instead
#      of leaving an orphan tick cron behind that it has no verb to run.
#
# Everything else the upgrade changed is already downgrade-safe: new-in-4.0.x config
# keys are ignored by an older release (inert, preserved for roll-forward), and the
# .md5 -> .xxhash128 feed sidecars and the .tar.bz2 -> .tar.zst MFS archive self-heal
# on the next feed update / rebuild.
#
# Idempotent: a second run restores nothing (scripts already at the root) and reports
# the tick cron already gone.
#
# Tests: tests/shell/pfb_downgrade_prep_spec.sh (shellspec — the file-move logic and
# the shipped-name gate) and tests/smoke/test_downgrade_prepare.py (the live tool
# end-to-end on a real VM).

# Paths are env-overridable so the pure functions are unit-testable off-appliance.
PFB_PKGDIR="${PFB_PKGDIR:-/usr/local/pkg/pfblockerng}"
PFB_LISTDIR="${PFB_LISTDIR:-${PFB_PKGDIR}/list_scripts}"
PFB_PFSSH="${PFB_PFSSH:-/usr/local/sbin/pfSsh.php}"

# The {ip,dnsbl}_{pre,post}_*.{sh,py} name space, enumerated (POSIX sh has no brace
# glob). Single source of truth for what a "list script" is.
PFB_LIST_SCRIPT_GLOBS='ip_pre_*.sh ip_pre_*.py ip_post_*.sh ip_post_*.py dnsbl_pre_*.sh dnsbl_pre_*.py dnsbl_post_*.sh dnsbl_post_*.py'

# pfb_is_shipped_list_script <path>
# Exit 0 iff the basename is a SHIPPED list script that must NOT be moved to the
# package root (moving a shipped file would leave a stray duplicate the downgrade's
# `pkg delete` cannot account for). pfBlockerNG ships only the AWS region wrappers
# and aws_region_prefixes.sh in list_scripts/, so a name gate is sufficient and needs
# no pkg query.
#
# This gate is a NAME SNAPSHOT of the shipped list_scripts/ contents. Two consequences,
# both accepted for a dev/ops tool:
#   - A user script named exactly like a shipped wrapper (ip_pre_AWS_*.sh) is treated
#     as shipped and left in place — the shipped namespace is reserved.
#   - If a FUTURE release ships a new list script under a different name, this gate
#     would move it to the root. MAINTENANCE: keep the patterns below in sync with the
#     shipped src/usr/local/pkg/pfblockerng/list_scripts/ contents, and run the tool
#     version that matches the pfBlockerNG version installed on the box.
pfb_is_shipped_list_script() {
	case "$(basename "$1")" in
		ip_pre_AWS_*.sh|aws_region_prefixes.sh) return 0 ;;
		*) return 1 ;;
	esac
}

# pfb_restore_list_scripts
# Move a user's custom list scripts from list_scripts/ back to the package root,
# skipping shipped scripts and never clobbering a same-named file already at the root.
# Prints the number restored to stdout; diagnostics go to stderr. Returns non-zero if
# any `mv` failed (so the caller can surface a partial failure), zero otherwise. A
# deliberate no-clobber skip is NOT a failure.
pfb_restore_list_scripts() {
	_restored=0
	_rc=0
	[ -d "$PFB_LISTDIR" ] || { echo "$_restored"; return 0; }
	# shellcheck disable=SC2086  # deliberate word-split: PFB_LIST_SCRIPT_GLOBS is a list of patterns.
	for _glob in $PFB_LIST_SCRIPT_GLOBS; do
		# $_glob is unquoted on purpose so the shell expands the wildcard; a
		# non-matching pattern stays literal and is skipped by the -f test.
		# shellcheck disable=SC2086  # deliberate glob expansion of the pattern.
		for _src in "$PFB_LISTDIR"/$_glob; do
			[ -f "$_src" ] || continue
			if pfb_is_shipped_list_script "$_src"; then
				continue
			fi
			_dest="${PFB_PKGDIR}/$(basename "$_src")"
			if [ -e "$_dest" ]; then
				echo "pfb-downgrade-prep: not overwriting existing ${_dest}; left $(basename "$_src") in list_scripts/" >&2
				continue
			fi
			if mv "$_src" "$_dest"; then
				chmod 0755 "$_dest" 2>/dev/null
				_restored=$((_restored + 1))
			else
				echo "pfb-downgrade-prep: failed to move ${_src} -> ${_dest}" >&2
				_rc=1
			fi
		done
	done
	echo "$_restored"
	return "$_rc"
}

# pfb_remove_tick_cron
# Remove the ADR-43 scheduled-tick cron entry via pfSsh.php, which calls the shipped
# install_cron_job() so config.xml + the live crontab are rewritten cleanly. Checks
# BOTH the current `pfblockerng.php cron-tick` verb and the legacy pre-#1204
# `pfblockerng.php tick` verb -- install_cron_job() matches by SUBSTRING and 'tick'
# does not match 'cron-tick', so each needs its own needle. Prints "removed" /
# "absent" to stdout; returns non-zero (and prints to stderr) if pfSsh.php is
# unavailable.
pfb_remove_tick_cron() {
	if [ ! -f "$PFB_PFSSH" ]; then
		echo "pfb-downgrade-prep: pfSsh.php not found at ${PFB_PFSSH}; cannot remove the tick cron" >&2
		return 2
	fi
	# Heredoc is quoted ('PHP') so the shell passes the PHP through verbatim. The
	# trailing `exec`/`exit` are pfSsh.php's run-buffer / quit protocol, not PHP.
	# Bounded with timeout(1): pfSsh.php loads AND LOCKS the config, so a concurrent
	# holder (a sync in progress, a GUI save) could otherwise block us indefinitely.
	_out=$(timeout 120 "$PFB_PFSSH" <<'PHP'
$present = FALSE;
foreach (config_get_path('cron/item', array()) as $i) {
	$cmd = $i['command'] ?? '';
	if (strpos($cmd, 'pfblockerng.php cron-tick') !== FALSE || strpos($cmd, 'pfblockerng.php tick') !== FALSE) {
		$present = TRUE;
		break;
	}
}
if ($present) {
	install_cron_job('pfblockerng.php cron-tick', FALSE);
	install_cron_job('pfblockerng.php tick', FALSE);
	echo "PFB_TICK_REMOVED\n";
} else { echo "PFB_TICK_ABSENT\n"; }
exec
exit
PHP
	)
	_tick_rc=$?
	if [ "$_tick_rc" -eq 124 ]; then
		echo "pfb-downgrade-prep: pfSsh.php timed out removing the tick cron (config locked by another process?)" >&2
		return 1
	fi
	case "$_out" in
		*PFB_TICK_REMOVED*) echo removed ; return 0 ;;
		*PFB_TICK_ABSENT*)  echo absent  ; return 0 ;;
		*)
			echo "pfb-downgrade-prep: unexpected pfSsh.php output while removing the tick cron: ${_out}" >&2
			return 1
			;;
	esac
}

# pfb_downgrade_prep_main — orchestrate both reversals and report.
# Returns non-zero if EITHER reversal failed, so an operator chaining this with the
# downgrade (`sh pfb-downgrade-prep.sh && pkg delete ... && pkg install <older>`) does
# NOT proceed on a silent failure (e.g. a tick cron that was never removed).
pfb_downgrade_prep_main() {
	if [ "$(id -u 2>/dev/null)" != '0' ]; then
		echo "pfb-downgrade-prep: must run as root (it moves package files and edits config.xml)" >&2
		return 1
	fi

	_rc=0
	_restored=$(pfb_restore_list_scripts) || _rc=1
	if _tick=$(pfb_remove_tick_cron); then
		:
	else
		_tick='ERROR (see stderr)'
		_rc=1
	fi

	echo "pfBlockerNG downgrade preparation:"
	echo "  Custom list scripts restored to package root: ${_restored}"
	echo "  ADR-43 tick cron entry: ${_tick}"
	return "$_rc"
}

# Run main only when executed directly; a shellspec source sets PFB_DOWNGRADE_PREP_SOURCED
# to load the functions in isolation without running anything.
if [ -z "${PFB_DOWNGRADE_PREP_SOURCED:-}" ]; then
	pfb_downgrade_prep_main "$@"
fi
