<?php
/*
 * pfblockerng_hook_edit.inc
 *
 * part of pfSense (https://www.pfsense.org)
 * Copyright (c) 2015-2026 Rubicon Communications, LLC (Netgate)
 * Copyright (c) 2015-2024 BBcan177@gmail.com
 * All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// DESTRUCTIVE HOOK-SCRIPT OPERATIONS -- included by pfblockerng_edit_hooks.php ONLY.
//
// The read-only hook helpers (pfb_hook_scripts(), pfb_hook_editor_path(),
// pfb_hook_editor_lang_for(), ...) live in pfblockerng.inc / pfblockerng_extra.inc
// because the runner, the Hooks tab and the editor all need them. This file is
// separate on purpose: pfblockerng.inc pulls extra.inc into essentially every page
// of the package -- the dashboard, the alerts page, even the firewall_aliases_edit
// config hook -- and a root-privileged unlink() has no business being in scope
// there. Keeping it in a file that exactly one privilege-gated page includes makes
// "only the Edit Hooks page can delete a hook" a property of where the code EXISTS,
// not of who remembered to check.
//
// That containment is enforced mechanically, not by convention:
// tests/php/HookEditFileContainmentTest.php fails if any file other than
// pfblockerng_edit_hooks.php includes this one.
//
// The gates inside the function are NOT made redundant by that placement -- they are
// defence in depth behind it, and each is load-bearing on its own.

/*
 * issue #1871: remove a hook script on behalf of the Edit Hooks page.
 *
 * The Web UI could create and save hook scripts but never delete one, so a typo in
 * the Name field at creation time was unrecoverable without shell access. This is a
 * root-privileged file removal driven by a GUI request, so it deletes NOTHING it has
 * not first cleared through pfb_hook_script_valid() -- the same allow-list the picker
 * offers from, the save handler accepts, and the runner executes. That single gate
 * covers every hostile shape at once: a traversal or absolute path fails its bare-
 * basename check, and a non-hook file, a wrong Pre/Post, or a symlink whose real path
 * leaves the hook directory all fail pfb_hook_scripts()' membership test.
 *
 * Returns TRUE only when a file was actually removed, so a double submit reports
 * failure on the second pass rather than a phantom success.
 */
function pfb_hook_editor_delete(string $script, string $when, ?string $dir = null): bool
{
	// GATE 1 -- PRIVILEGE, asserted here and not only at the page.
	//
	// This performs a root-privileged unlink(), and it lives in a file that
	// pfblockerng.inc pulls into essentially every page of the package -- the
	// alerts page, the dashboard, even the firewall_aliases_edit config hook all
	// have this function in scope. The Edit Hooks page's own isAllowedPage() gate
	// protects that page, not this operation: nothing stops a future caller
	// elsewhere from invoking the helper with no gate at all. Re-asserting the
	// same privilege the hook editor demands (diag_command.php -- the
	// shell-equivalent trust class, ADR-12) makes the authorization a property of
	// the DELETION rather than of one call site.
	//
	// function_exists() keeps the helper testable off-appliance, where the pfSense
	// core function is supplied by tests/php/pfsense_doubles.php.
	if (function_exists('isAllowedPage') && !isAllowedPage('diag_command.php')) {
		return FALSE;
	}

	// GATE 2 -- the shared allow-list: a bare basename, named hook_<when>_*.{sh,py},
	// actually present in the hook directory, with symlinks that resolve outside it
	// already excluded by pfb_hook_scripts()' containment check.
	if (!pfb_hook_script_valid($script, $when, $dir)) {
		return FALSE;
	}

	// GATE 3 -- resolve the directory here rather than trusting a path handed back
	// from elsewhere, so every check below is anchored to a canonical root.
	$real_dir = realpath($dir ?? PFB_HOOK_SCRIPT_DIR);
	if ($real_dir === FALSE || !is_dir($real_dir)) {
		return FALSE;
	}
	$entry = $real_dir . '/' . $script;

	// GATE 4 -- the ORIGINAL path. The entry must sit DIRECTLY in the hook
	// directory under exactly the name given. basename() equality inside
	// pfb_hook_script_valid() already rejected separators; this re-derives the
	// same fact from the composed path, so a future change to either helper cannot
	// quietly widen what this one deletes.
	if (dirname($entry) !== $real_dir || basename($entry) !== $script) {
		return FALSE;
	}

	// GATE 5 -- the entry exists, as a regular file or a symlink to one.
	if (!is_link($entry) && !is_file($entry)) {
		return FALSE;
	}

	// GATE 6 -- the TRUE RESOLVED path. A symlink is removable only when what it
	// points at is ALSO inside the hook directory. unlink() drops the link rather
	// than the target either way, so this is defence in depth over GATE 2 -- but
	// refusing is the right default: "delete a hook" must never become a request
	// that even names something outside the hook directory.
	if (is_link($entry)) {
		$resolved = realpath($entry);
		if ($resolved === FALSE || dirname($resolved) !== $real_dir) {
			return FALSE;
		}
	}

	// GATE 7 -- permission. unlink() needs write+execute on the DIRECTORY, not on
	// the file, so checking the directory turns an unexplained failure into an
	// honest one the page can report.
	if (!is_writable($real_dir)) {
		return FALSE;
	}

	// Remove the DIRECTORY ENTRY the admin named, never what it resolves to: for a
	// symlink inside the directory, unlinking the resolved realpath would delete a
	// DIFFERENT hook (a post row removing a pre file) while the UI reported success,
	// because the dangling link stops being listed either way.
	$removed = @unlink($entry);

	// Audit trail. pfb_run_hooks() logs every hook it refuses to execute; a
	// destructive root-privileged removal deserves at least the same, and a silent
	// FALSE gives an operator investigating a vanished hook nothing to go on. Level
	// 2 (error) for a refusal, level 1 for the removal itself.
	pfb_logger(
		$removed
			? "[ pfB Hook ] deleted {$when} hook script '{$script}' from {$real_dir}\n"
			: "[ pfB Hook ] failed to delete {$when} hook script '{$script}' from {$real_dir}\n",
		$removed ? 1 : 2
	);
	return $removed;
}
