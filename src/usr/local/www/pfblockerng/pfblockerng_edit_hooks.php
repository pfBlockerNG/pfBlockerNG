<?php
/*
 * pfblockerng_edit_hooks.php
 *
 * part of pfSense (https://www.pfsense.org)
 * Copyright (c) 2016-2026 Rubicon Communications, LLC (Netgate)
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

// issue #1669: this page lets a
// gated admin AUTHOR hook-script file content from the GUI -- a reversal of the
// original ADR-12 decision that hook content is picked, never typed/edited, in the web
// UI (pfblockerng_hooks.php remains pick-only and untouched). The reversal is safe
// ONLY because of the privilege gate below: everyone who can reach this page already
// holds root-equivalent access via pfSense Diagnostics > Command Prompt / Edit File
// (isAllowedPage('diag_command.php')), so this page adds NO new capability and NO
// privilege escalation over what that admin already has.
//
// DELIBERATE OMISSION: this page is intentionally NOT added to
// $priv_list['page-firewall-pfblockerng']['match'] in
// src/etc/inc/priv/pfblockerng.priv.inc (pinned by
// EditHooksPageWiringTest::testPrivIncDoesNotMatchThisPage()). Only 'page-all' / a full
// admin passes pfSense's own FRAMEWORK page guard (no match entry -> no scoped
// pfBlockerNG-page privilege can ever route a request to this URL through the
// framework at all). That keeps the ADR-12 addendum's picker-trust-boundary guarantee
// intact: a user holding only the ordinary pfBlockerNG page privileges must stay unable
// to author or edit hook content -- they can still PICK a vetted file on the Hooks tab,
// nothing here changes that. The isAllowedPage() check immediately below is the SECOND,
// LOAD-BEARING gate (mirrors pfblockerng_software.php's SECONDARY PRIVILEGE GATE,
// issue #485): it is what actually decides who may render or save on this page, and it
// covers the GET render path and BOTH POST actions with a single check.

require_once('guiconfig.inc');
require_once('globals.inc');
require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');

global $pfb;
pfb_global();

// issue #1669: General-settings toggle gating the CodeMirror 6
// live-highlight overlay for the #pfb_hook_editor_content field below (same toggle,
// same PfbConfig/PfbLenient idiom, as pfblockerng_dnsbl.php's $pfb_syntaxhl_on --
// registered in the general section, default on, rendered by pfblockerng_general.php).
$pfb_syntaxhl_on = (PfbConfig::read('pfb_syntax_highlight') === PfbLenient::On);

// SECONDARY PRIVILEGE GATE (issue #1669 Part B / ADR-12 addendum). Placed
// immediately after the includes -- before any request superglobal is read -- so
// this ONE check guards the picker/render path AND the create/save POST handlers
// below. Use
// isAllowedPage(), NOT userHasPrivilege() with a raw priv id: isAllowedPage() honours
// the admin (uid 0) short-circuit AND the 'page-all' wildcard match, whereas
// userHasPrivilege() does an exact priv-id membership test that would wrongly exclude
// a page-all admin (who lacks the literal 'page-diagnostics-command' priv) -- that
// would lock admins out. pfSense match-based privilege is OR across groups, so this
// extra AND-requirement can only be enforced by an explicit in-page check.
if (!isAllowedPage('diag_command.php')) {
	header('Location: /index.php');
	exit;
}

$input_errors = array();

// The currently loaded/edited script, and its content -- populated below from either
// a successful GET picker load or a re-rendered failed POST (so the user's in-progress
// edit is never silently dropped on a validation error).
$pfb_eh_sel_when   = '';
$pfb_eh_sel_script = '';
$pfb_eh_content    = '';

// Create-flow field echo -- only re-populated on a failed create POST, so the user
// doesn't have to retype Name/Language after fixing a validation error.
$pfb_eh_new_core_val = '';
$pfb_eh_new_lang_val = 'sh';

if ($_POST) {
	if (isset($_POST['pfb_eh_create'])) {
		// Create flow (issue #1669 design comment): the user supplies only When/Name
		// core/Language -- the server COMPOSES the filename. pfb_hook_editor_compose_filename()
		// is the single source of truth for every validation decision here; this
		// handler never inlines a regex or a naming rule of its own.
		$post_when = (string) ($_POST['pfb_eh_new_when'] ?? '');
		$post_core = (string) ($_POST['pfb_eh_new_core'] ?? '');
		$post_lang = (string) ($_POST['pfb_eh_new_lang'] ?? '');

		$filename = pfb_hook_editor_compose_filename($post_when, $post_core, $post_lang);
		$path     = ($filename !== NULL) ? pfb_hook_editor_path($filename) : NULL;

		if ($filename === NULL || $path === NULL) {
			$input_errors[] = gettext('Invalid new-hook fields: When must be Pre/Post, Name must be letters, ' .
				'digits, and underscores only, and Language must be Shell or Python.');
		} else {
			// Mode 0700: the runner execs the vetted script directly under timeout(1)
			// via its own shebang (pfb_run_hooks()), so a freshly created file must be
			// executable to ever actually run -- but the runner always execs as root,
			// and pfb_hook_scripts() has no is_executable filter, so nothing else on
			// the system needs the group/other bits; owner-only is least privilege.
			//
			// 'x' mode: atomic create-exclusive open -- fails outright if the target
			// already exists, closing the TOCTOU race a separate file_exists() check
			// followed by a plain write left open: two concurrent creates racing the
			// same composed name could otherwise both pass the existence check and one
			// clobber the other.
			$pfb_eh_new_handle = @fopen($path, 'x');
			if ($pfb_eh_new_handle === FALSE) {
				// fopen(..., 'x') returns FALSE
				// for EVERY failure reason (name collision, unwritable directory, etc.) --
				// the prior message named only the collision case, which misled an admin
				// hitting a permissions problem into repeatedly retyping a "different Name"
				// that would never help.
				$input_errors[] = gettext('A hook script with that composed name already exists, or the ' .
					'hook-script directory is not writable -- pick a different Name.');
			} else {
				$pfb_eh_new_template = pfb_hook_editor_template($post_when, $post_lang);
				$pfb_eh_new_written  = @fwrite($pfb_eh_new_handle, $pfb_eh_new_template);
				@fclose($pfb_eh_new_handle);
				if ($pfb_eh_new_written !== strlen($pfb_eh_new_template) || !@chmod($path, 0700)) {
					// Partial/failed write or chmod -- never leave a half-written file
					// behind for a later create attempt (with a different name) to trip
					// over, or for the picker to ever list.
					@unlink($path);
					$input_errors[] = gettext('Failed to write the hook script file -- check that the ' .
						'hook-script directory is writable.');
				} else {
					// PRG: redirect straight into the picker-load state for the new file so
					// the admin lands in the editor, ready to fill in the hello-world stub.
					header('Location: /pfblockerng/pfblockerng_edit_hooks.php?' .
						http_build_query(array('when' => $post_when, 'script' => $filename)));
					exit;
				}
			}
		}

		// Preserve the create-flow fields the user typed so a validation error doesn't
		// silently clear the form.
		$pfb_eh_sel_when     = $post_when;
		$pfb_eh_content      = '';
		$pfb_eh_new_core_val = $post_core;
		$pfb_eh_new_lang_val = ($post_lang === 'py') ? 'py' : 'sh';
	} elseif (isset($_POST['pfb_eh_save'])) {
		// Save flow: edit the CONTENT of an EXISTING, already-vetted script only --
		// this never creates a new file. pfb_hook_script_valid() is the same allow-list
		// gate the Hooks tab's save handler and the runner itself use, so a stale pick
		// or a crafted POST can never write outside a file the picker already offers.
		$post_when    = (string) ($_POST['pfb_eh_cur_when'] ?? '');
		$post_script  = (string) ($_POST['pfb_eh_cur_script'] ?? '');
		// issue #1734: shared persist-boundary sanitizer (#1723), run at INGESTION.
		// Its leading CRLF/CR -> LF fold is load-bearing: HTML5 makes the browser submit
		// a <textarea> as CRLF, and a saved "#!/bin/sh\r" shebang execs the nonexistent
		// path "/bin/sh\r" (ENOENT) -- the hook then silently never fires again. A
		// literal control byte must be written as an escape (\033); issue #1728.
		$post_content = pfb_sanitize_text_area((string) ($_POST['pfb_eh_content'] ?? ''));

		if (!pfb_hook_script_valid($post_script, $post_when)) {
			$input_errors[] = gettext('Select a valid, existing hook script for this Pre/Post before saving ' .
				'(load it from the picker above first).');
		} else {
			$path = pfb_hook_editor_path($post_script);
			if ($path === NULL || !is_file($path)) {
				$input_errors[] = gettext('The selected hook script could not be resolved on disk.');
			} else {
				// pfb_run_hooks() may exec
				// this exact file as root concurrently with a save -- an in-place
				// truncate-and-write straight to the live target leaves a window where a
				// concurrent reader/exec sees an empty or partial script. Stage to a temp
				// file in the SAME directory (same idiom as pfb_utf16_transcode_file() /
				// pfb_apply_publish() in pfblockerng.inc), verify the full byte count
				// landed, chmod, then rename() over the target -- rename() is atomic on
				// the same filesystem, so a concurrent exec always observes either the
				// old or the new content in full, never a partial write.
				$pfb_eh_tmp = @tempnam(dirname($path), '.pfbeh_');
				$pfb_eh_written = ($pfb_eh_tmp !== FALSE) ? @file_put_contents($pfb_eh_tmp, $post_content) : FALSE;
				if (
					$pfb_eh_tmp === FALSE ||
					$pfb_eh_written !== strlen($post_content) ||
					!@chmod($pfb_eh_tmp, 0700) ||
					!@rename($pfb_eh_tmp, $path)
				) {
					if ($pfb_eh_tmp !== FALSE) {
						@unlink($pfb_eh_tmp);
					}
					$input_errors[] = gettext('Failed to save the hook script file -- check that the ' .
						'hook-script directory is writable.');
				} else {
					header('Location: /pfblockerng/pfblockerng_edit_hooks.php?' .
						http_build_query(array('when' => $post_when, 'script' => $post_script, 'saved' => '1')));
					exit;
				}
			}
		}

		// Re-render the sanitized content so a validation/write error doesn't lose the
		// user's in-progress work -- it is what a retry would persist, so echoing the
		// raw typed bytes back would misreport what Save is about to write.
		$pfb_eh_sel_when   = $post_when;
		$pfb_eh_sel_script = $post_script;
		$pfb_eh_content    = $post_content;
	}
}

// GET picker load -- reached on a plain click from the picker links below, or via the
// PRG redirect right after a successful create/save. $_GET['script'] is NEVER treated
// as a path: pfb_hook_script_valid() checks it against pfb_hook_scripts()'s own
// allow-list (an exact basename match against what is actually on disk for this
// Pre/Post) before pfb_hook_editor_path() resolves it and anything is read.
if (!$_POST && isset($_GET['when'], $_GET['script'])) {
	$get_when   = (string) $_GET['when'];
	$get_script = (string) $_GET['script'];
	if (pfb_hook_script_valid($get_script, $get_when)) {
		$path = pfb_hook_editor_path($get_script);
		$body = ($path !== NULL && is_file($path)) ? @file_get_contents($path) : FALSE;
		if ($body === FALSE) {
			$input_errors[] = gettext('Failed to read the selected hook script.');
		} elseif (!mb_check_encoding($body, 'UTF-8')) {
			// htmlspecialchars(ENT_SUBSTITUTE)
			// (used by Form_Textarea::_getInput() at render) silently replaces every
			// invalid byte with U+FFFD -- loading an invalid-UTF-8 file into this editor
			// would corrupt it, and re-saving would persist that corruption to disk.
			// Refuse to populate the editor for this load; leaving $pfb_eh_sel_script
			// empty also disables the Save path (pfb_hook_script_valid('', ...) fails),
			// so there is nothing to click that could write the corrupted view back.
			$input_errors[] = gettext('The selected hook script file is not valid UTF-8 -- fix it on disk before ' .
				'editing it here (loading it into this editor would corrupt invalid byte sequences on display).');
		} else {
			$pfb_eh_sel_when   = $get_when;
			$pfb_eh_sel_script = $get_script;
			$pfb_eh_content    = $body;
		}
	} else {
		$input_errors[] = gettext('That script is not a valid hook file for the selected Pre/Post.');
	}
}

// issue #1669: the CM6 editor mode -- follows the loaded script's own
// extension (pfb_eh_sel_script, populated by the picker/create-redirect above), falling
// back to the create-flow's typed Language choice (pfb_eh_new_lang_val) when nothing is
// loaded yet.
$pfb_eh_lang = pfb_hook_editor_lang_for($pfb_eh_sel_script, $pfb_eh_new_lang_val);

$pgtitle = array(gettext('Firewall'), gettext('pfBlockerNG'), gettext('Update'), gettext('Edit Hooks'));
$pglinks = array('', '/pfblockerng/pfblockerng_general.php', '/pfblockerng/pfblockerng_update.php', '@self');
$shortcut_section = 'pfblockerng';
include_once('head.inc');

if ($input_errors) {
	print_input_errors($input_errors);
}
if (!$_POST && isset($_GET['saved'])) {
	print_info_box(gettext('Hook script saved.'), 'success');
}

// Define default Alerts Tab href link (Top row)
$get_req = pfb_alerts_default_page();

$tab_array	= array();
$tab_array[]	= array(gettext('General'),	FALSE,	'/pfblockerng/pfblockerng_general.php');
$tab_array[]	= array(gettext('IP'),		FALSE,	'/pfblockerng/pfblockerng_ip.php');
$tab_array[]	= array(gettext('DNSBL'),	FALSE,	'/pfblockerng/pfblockerng_dnsbl.php');
$tab_array[]	= array(gettext('Update'),	TRUE,	'/pfblockerng/pfblockerng_update.php');
$tab_array[]	= array(gettext('Reports'),	FALSE,	"/pfblockerng/pfblockerng_alerts.php{$get_req}");
$tab_array[]	= array(gettext('Feeds'),	FALSE,	'/pfblockerng/pfblockerng_feeds.php');
$tab_array[]	= array(gettext('Logs'),	FALSE,	'/pfblockerng/pfblockerng_log.php');
$tab_array[]	= array(gettext('Sync'),	FALSE,	'/pfblockerng/pfblockerng_sync.php');
pfb_software_add_tab($tab_array);
display_top_tabs($tab_array, TRUE);

// Update sub-tabs: Run, Hooks (picker), and this page (Edit Hooks) -- directly after
// Hooks (issue #1669 Part B design comment). Every page that declares this row
// re-declares it in full with its OWN tab marked active (pfblockerng_update.php,
// pfblockerng_hooks.php, and this page); see EditHooksPageWiringTest for the coverage
// pin across all three.
$tab_array_sub	= array();
$tab_array_sub[]	= array(gettext('Run'),		FALSE,	'/pfblockerng/pfblockerng_update.php');
$tab_array_sub[]	= array(gettext('Hooks'),	FALSE,	'/pfblockerng/pfblockerng_hooks.php');
$tab_array_sub[]	= array(gettext('Edit Hooks'),	TRUE,	'/pfblockerng/pfblockerng_edit_hooks.php');
display_top_tabs($tab_array_sub, TRUE);
pfb_print_pending_changes_box();

// Warning banner -- mirrors diag_command.php's own manual advanced-users callout
// (print_callout(..., 'danger', 'Advanced Users Only')). diag_command.php's priv also
// carries a '##|*WARN=standard-warning-root' metadata tag, but that tag is consumed by
// pfSense's priv-registration machinery for pages that ARE listed in $priv_list -- this
// page deliberately is not (see the top-of-file comment), so that generic mechanism
// never fires here and would give a false sense of coverage. This explicit callout is
// the load-bearing equivalent, not a decoration.
print_callout(
	gettext('The capabilities offered here can be dangerous. No support is available. Scripts you ' .
		'create or edit on this page run as ROOT during every pfBlockerNG update pass -- the same ' .
		'trust class as pfSense Diagnostics > Command Prompt / Edit File. Use them at your own risk!'),
	'danger',
	gettext('Advanced Users Only')
);

$form = new Form(FALSE);

// --- Picker: existing hook scripts, grouped by Pre/Post -------------------------
$section = new Form_Section('Load an Existing Hook Script');
$section->addInput(new Form_StaticText(
	'About',
	'<small>' . gettext('Click a script below to load it into the editor. Only files already present ' .
		'in the hook-script folder are listed here -- the same picker model as the Hooks tab.') . '</small>'
));

foreach (array('pre' => gettext('Pre'), 'post' => gettext('Post')) as $pfb_eh_when_key => $pfb_eh_when_label) {
	// pfb_hook_scripts() is the SAME allow-list function the Hooks tab picker and the
	// runner use -- basenames only, never a path.
	$pfb_eh_scripts = pfb_hook_scripts($pfb_eh_when_key);
	if (empty($pfb_eh_scripts)) {
		$pfb_eh_list_html = '<em>' . gettext('(none yet)') . '</em>';
	} else {
		$pfb_eh_links = array();
		foreach ($pfb_eh_scripts as $pfb_eh_script_name) {
			$pfb_eh_href = '/pfblockerng/pfblockerng_edit_hooks.php?' .
				http_build_query(array('when' => $pfb_eh_when_key, 'script' => $pfb_eh_script_name));
			$pfb_eh_is_active = ($pfb_eh_sel_when === $pfb_eh_when_key && $pfb_eh_sel_script === $pfb_eh_script_name);
			$pfb_eh_links[] = '<a href="' . htmlspecialchars($pfb_eh_href) . '"' .
				($pfb_eh_is_active ? ' class="text-bold"' : '') . '>' .
				htmlspecialchars($pfb_eh_script_name) . '</a>';
		}
		$pfb_eh_list_html = implode('&emsp;', $pfb_eh_links);
	}
	$section->addInput(new Form_StaticText($pfb_eh_when_label, $pfb_eh_list_html));
}
$form->add($section);

// --- Create a new hook script ----------------------------------------------------
$section = new Form_Section('Create a New Hook Script');
$section->addInput(new Form_StaticText(
	'About',
	'<small>' . gettext('The server composes the filename as <code>hook_&lt;when&gt;_&lt;name&gt;.&lt;ext&gt;</code> ' .
		'-- you never type a path or a full filename. Creation is rejected if that exact file already exists.') . '</small>'
));

$pfb_eh_new_when_val = ($pfb_eh_sel_when === 'pre' || $pfb_eh_sel_when === 'post') ? $pfb_eh_sel_when : 'post';
$group = new Form_Group('New Hook');
$group->add(new Form_Select(
	'pfb_eh_new_when',
	NULL,
	$pfb_eh_new_when_val,
	array('pre' => gettext('Pre'), 'post' => gettext('Post'))
))->setHelp('When')->setWidth(2);
$group->add(new Form_Input(
	'pfb_eh_new_core',
	NULL,
	'text',
	// RAW value: Form_Input::_getInput() already HTML-escapes it at render
	// -- escaping it again at the page
	// level would double-escape it.
	$pfb_eh_new_core_val,
	array('placeholder' => 'name_core')
))->setHelp('Name (letters, digits, underscore only)')->setWidth(4);
$group->add(new Form_Select(
	'pfb_eh_new_lang',
	NULL,
	$pfb_eh_new_lang_val,
	array('sh' => gettext('Shell (.sh)'), 'py' => gettext('Python (.py)'))
))->setHelp('Language')->setWidth(2);
$section->add($group);

// Named pfb_eh_create directly: a clicked
// <button type="submit" name="pfb_eh_create"> is included in the browser's OWN POST
// natively -- exactly what isset($_POST['pfb_eh_create']) above keys on -- so no
// click-handler JS is needed to make this submit as the create action.
$pfb_eh_create_btn = new Form_Button(
	'pfb_eh_create',
	gettext('Create'),
	NULL,
	'fa-solid fa-plus'
);
$pfb_eh_create_btn->removeClass('btn-primary')->addClass('btn-success btn-xs');
$group = new Form_Group(NULL);
$group->add(new Form_StaticText(NULL, $pfb_eh_create_btn));
$section->add($group);
$form->add($section);

// --- Editor -----------------------------------------------------------------------
// B2 (issue #1669) mounts CodeMirror 6 on the #pfb_hook_editor_content textarea in
// place, gated by the same pfb_syntax_highlight toggle the DNSBL regex field uses,
// falling back to this plain textarea when the toggle is off -- this element's id is
// the stable seam that slice targets. The 'When'/'Script' hidden fields identify which
// on-disk file Save writes to; they are ALWAYS re-validated server-side
// (pfb_hook_script_valid()) regardless of what a crafted POST claims.
$section = new Form_Section('Editor');
$pfb_eh_loaded_label = ($pfb_eh_sel_script !== '')
	? sprintf(gettext('Editing <strong>%1$s</strong> (%2$s)'), htmlspecialchars($pfb_eh_sel_script), htmlspecialchars($pfb_eh_sel_when))
	: gettext('Load an existing script above, or create a new one, to start editing.');
$section->addInput(new Form_StaticText('Now editing', $pfb_eh_loaded_label));

// RAW values: Form_Element/Form_Input already HTML-escape every attribute at
// render -- escaping them again at the
// page level would double-escape them.
$form->addGlobal(new Form_Input('pfb_eh_cur_when', 'pfb_eh_cur_when', 'hidden', $pfb_eh_sel_when));
$form->addGlobal(new Form_Input('pfb_eh_cur_script', 'pfb_eh_cur_script', 'hidden', $pfb_eh_sel_script));

$pfb_eh_textarea = new Form_Textarea(
	'pfb_eh_content',
	NULL,
	// Displayed/re-loaded verbatim here -- the save handler's sanitization
	// (pfb_sanitize_text_area(): line endings to LF, control characters other than tab
	// stripped, each line right-stripped) happens later, on $_POST, not to this
	// loaded value. Passed RAW: Form_Textarea::_getInput() already HTML-escapes the
	// value exactly once at render (verified against pfSense master and
	// RELENG_2_7_2), so escaping it again here would double-escape it: the browser
	// decodes only ONE layer, leaving mangled entities (e.g. "&quot;") in what the
	// user sees and re-saves.
	$pfb_eh_content
);
$pfb_eh_textarea->setAttribute('id', 'pfb_hook_editor_content');
$pfb_eh_textarea->removeClass('form-control')
	->addClass('row-fluid col-sm-12')
	->setAttribute('columns', '90')
	->setAttribute('rows', '20')
	->setAttribute('wrap', 'off')
	->setAttribute('spellcheck', 'false')
	->setAttribute('style', 'background:#fafafa; width: 100%; font-family: monospace;')
	->setHelp(gettext('Saved as typed, except line endings are normalized to LF, trailing whitespace is ' .
		'stripped from each line, and control characters other than tab are removed -- write a literal ' .
		'control byte as an escape (e.g. \\033) instead.'));
$section->addInput($pfb_eh_textarea);

// Named pfb_eh_save directly -- same native-submit reasoning as the Create button
// above.
$pfb_eh_save_btn = new Form_Button(
	'pfb_eh_save',
	gettext('Save'),
	NULL,
	'fa-solid fa-floppy-disk'
);
$pfb_eh_save_btn->removeClass('btn-primary')->addClass('btn-primary btn-xs');
$group = new Form_Group(NULL);
$group->add(new Form_StaticText(NULL, $pfb_eh_save_btn));
$section->add($group);
$form->add($section);

print($form);
?>
<?php if ($pfb_syntaxhl_on): ?>
<!-- issue #1669: live syntax highlighting for the pfb_eh_content field -->
<script src="vendor/codemirror/cm-hooks.min.js?v=<?=pfb_file_mtime('/usr/local/www/pfblockerng/vendor/codemirror/cm-hooks.min.js')?>"></script>
<?php endif; ?>
<script type="text/javascript">
//<![CDATA[
events.push(function() {
<?php if ($pfb_syntaxhl_on): ?>
	// issue #1669: progressively enhance pfb_eh_content into a
	// CodeMirror 6 live-highlight editor (python or shell mode, per $pfb_eh_lang).
	// window.pfbHooksCM is the global the vendored bundle exposes (IIFE
	// --global-name=pfbHooksCM); fromTextarea() hides the textarea, mounts the editor
	// before it, and keeps name/value synced so the save handler's $_POST read is
	// unaffected.
	var pfbHookEditorEl = document.getElementById('pfb_hook_editor_content');
	if (pfbHookEditorEl && window.pfbHooksCM) {
		window.pfbHooksCM.fromTextarea(pfbHookEditorEl, '<?=$pfb_eh_lang?>');
	}
<?php endif; ?>
});
//]]>
</script>
<?php
include('foot.inc');
?>
