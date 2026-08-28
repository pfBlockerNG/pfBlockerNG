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
// The gates inside the function are defence in depth BEHIND that placement, and the
// honest description of them is that GATE 1 (privilege) and the unlink-the-named-entry
// rule are the two that individually change behaviour today: delete either and a test
// fails. GATE 2 (the shared allow-list) establishes most of what GATES 3-7 then
// re-derive, so each of those can be removed in isolation with the suite still green,
// and GATE 7 (writability) rarely fires on-box at all because the caller is root, for
// whom is_writable() on a read-only directory is still TRUE.
//
// They stay regardless. Each one re-derives from a canonical root a fact some OTHER
// helper currently guarantees, so a future change to pfb_hook_scripts() or
// pfb_hook_editor_path() cannot silently widen what this function will delete. That is
// a real property, and it is a different claim from "every gate is individually
// load-bearing" -- which mutation testing disproves.

/** Check access before invoking the request callbacks or touching request data. */
function pfb_edit_hooks_controller(bool $allowed, callable $post, callable $get, ?string $dir = null): array
{
	$redirect = pfb_edit_hooks_access($allowed);
	if ($redirect !== NULL) {
		return pfb_edit_hooks_default_state($redirect);
	}

	return pfb_edit_hooks_request((array) $post(), (array) $get(), $dir);
}

/** Shared Edit Hooks request path; returns state plus a PRG redirect when complete. */
function pfb_edit_hooks_request(array $post, array $get, ?string $dir = null): array
{
	$state = pfb_edit_hooks_default_state();
	if (!$post) {
		if (isset($get['saved'])) {
			$state['notice'] = gettext('Hook script saved.');
		} elseif (!empty($get['deleted'])) {
			$state['notice'] = gettext('Hook script deleted.');
		}
	}

	if ($post) {
		if (isset($post['pfb_eh_create'])) {
			$post_when = (string) ($post['pfb_eh_new_when'] ?? '');
			$post_core = (string) ($post['pfb_eh_new_core'] ?? '');
			$post_lang = (string) ($post['pfb_eh_new_lang'] ?? '');
			$filename = pfb_hook_editor_compose_filename($post_when, $post_core, $post_lang);
			$path = ($filename !== NULL) ? pfb_hook_editor_path($filename, $dir) : NULL;
			if ($filename === NULL || $path === NULL) {
				$state['errors'][] = gettext('Invalid new-hook fields: When must be Pre/Post, Name must be letters, digits, and underscores only, and Language must be Shell or Python.');
			} else {
				$handle = @fopen($path, 'x');
				if ($handle === FALSE) {
					$state['errors'][] = gettext('A hook script with that composed name already exists, or the hook-script directory is not writable -- pick a different Name.');
				} else {
					$template = pfb_hook_editor_template($post_when, $post_lang);
					$written = @fwrite($handle, $template);
					@fclose($handle);
					if ($written !== strlen($template) || !@chmod($path, 0700)) {
						@unlink($path);
						$state['errors'][] = gettext('Failed to write the hook script file -- check that the hook-script directory is writable.');
					} else {
						$state['redirect'] = '/pfblockerng/pfblockerng_edit_hooks.php?' . http_build_query(['when' => $post_when, 'script' => $filename]);
						return $state;
					}
				}
			}
			$state['new_core'] = $post_core;
			$state['new_lang'] = $post_lang === 'py' ? 'py' : 'sh';
			$state['new_when'] = $post_when;
			$state['sel_when'] = (string) ($post['pfb_eh_cur_when'] ?? '');
			$state['sel_script'] = (string) ($post['pfb_eh_cur_script'] ?? '');
			$state['content'] = pfb_sanitize_text_area((string) ($post['pfb_eh_content'] ?? ''));
		} elseif (isset($post['pfb_eh_delete']) && $post['pfb_eh_delete'] !== '') {
			$post_when = (string) ($post['pfb_eh_del_when'] ?? '');
			$post_script = (string) ($post['pfb_eh_del_script'] ?? '');
			if (pfb_hook_editor_delete($post_script, $post_when, $dir)) {
				$state['redirect'] = '/pfblockerng/pfblockerng_edit_hooks.php?' . http_build_query(['deleted' => $post_script]);
				return $state;
			}
			$state['errors'][] = gettext('That hook script could not be deleted -- reload the page and try again (it may already be gone, or the hook-script directory may not be writable).');
			$state['sel_when'] = (string) ($post['pfb_eh_cur_when'] ?? '');
			$state['sel_script'] = (string) ($post['pfb_eh_cur_script'] ?? '');
			$state['content'] = pfb_sanitize_text_area((string) ($post['pfb_eh_content'] ?? ''));
		} elseif (isset($post['pfb_eh_save'])) {
			$post_when = (string) ($post['pfb_eh_cur_when'] ?? '');
			$post_script = (string) ($post['pfb_eh_cur_script'] ?? '');
			$post_content = pfb_sanitize_text_area((string) ($post['pfb_eh_content'] ?? ''));
			if (!pfb_hook_script_valid($post_script, $post_when, $dir)) {
				$state['errors'][] = gettext('Select a valid, existing hook script for this Pre/Post before saving (load it from the picker above first).');
			} else {
				$path = pfb_hook_editor_path($post_script, $dir);
				if ($path === NULL || !is_file($path)) {
					$state['errors'][] = gettext('The selected hook script could not be resolved on disk.');
				} else {
					$tmp = @tempnam(dirname($path), '.pfbeh_');
					$written = $tmp !== FALSE ? @file_put_contents($tmp, $post_content) : FALSE;
					if ($tmp === FALSE || $written !== strlen($post_content) || !@chmod($tmp, 0700) || !@rename($tmp, $path)) {
						if ($tmp !== FALSE) {
							@unlink($tmp);
						}
						$state['errors'][] = gettext('Failed to save the hook script file -- check that the hook-script directory is writable.');
					} else {
						$state['redirect'] = '/pfblockerng/pfblockerng_edit_hooks.php?' . http_build_query(['when' => $post_when, 'script' => $post_script, 'saved' => '1']);
						return $state;
					}
				}
			}
			$state['sel_when'] = $post_when;
			$state['sel_script'] = $post_script;
			$state['content'] = $post_content;
		}
	} elseif (isset($get['when'], $get['script'])) {
		$get_when = (string) $get['when'];
		$get_script = (string) $get['script'];
		if (pfb_hook_script_valid($get_script, $get_when, $dir)) {
			$path = pfb_hook_editor_path($get_script, $dir);
			$body = ($path !== NULL && is_file($path)) ? @file_get_contents($path) : FALSE;
			if ($body === FALSE) {
				$state['errors'][] = gettext('Failed to read the selected hook script.');
			} elseif (!mb_check_encoding($body, 'UTF-8')) {
				$state['errors'][] = gettext('The selected hook script file is not valid UTF-8 -- fix it on disk before editing it here (loading it into this editor would corrupt invalid byte sequences on display).');
			} else {
				$state['sel_when'] = $get_when;
				$state['sel_script'] = $get_script;
				$state['content'] = $body;
			}
		} else {
			$state['errors'][] = gettext('That script is not a valid hook file for the selected Pre/Post.');
		}
	}

	return $state;
}

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
	// This page-only helper performs a root-privileged unlink(). The Edit Hooks
	// controller checks the page privilege too, but a future caller could invoke
	// this destructive operation without that controller. Re-asserting the same
	// privilege the hook editor demands (diag_command.php -- the
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
	// Line breaks are folded out of the name before it reaches the log: a filename
	// carrying one would otherwise let a forged line be written into the package log,
	// which is read by operators investigating exactly this kind of event. Creating
	// such a name needs root shell access (the GUI create flow composes [A-Za-z0-9_]
	// only), so this is cheap insurance rather than a reachable hole.
	$logged = str_replace(["\r", "\n"], ' ', $script);
	pfb_logger(
		$removed
			? "[ pfB Hook ] deleted {$when} hook script '{$logged}' from {$real_dir}\n"
			: "[ pfB Hook ] failed to delete {$when} hook script '{$logged}' from {$real_dir}\n",
		$removed ? 1 : 2
	);
	return $removed;
}
