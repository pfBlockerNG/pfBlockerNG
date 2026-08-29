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
// nothing here changes that. The controller call immediately below is the SECOND,
// LOAD-BEARING gate (mirrors pfblockerng_software.php's secondary privilege gate,
// issue #485): it decides who may render or save this page, redirects denied requests,
// and invokes the request callbacks only when access is allowed.

require_once('guiconfig.inc');
require_once('globals.inc');
$pfb_eh_pkg = '/usr/local/pkg/pfblockerng/pfblockerng.inc';
if (!file_exists($pfb_eh_pkg)) {
	$pfb_eh_pkg = dirname(__DIR__, 2) . '/pkg/pfblockerng/pfblockerng.inc';
}
require_once($pfb_eh_pkg);
// Destructive hook-script operations, deliberately NOT in the package-wide includes:
// this file is included by THIS PAGE ONLY, so a root-privileged unlink() is never in
// scope on a page that has no business holding one. Containment is pinned by
// tests/php/HookEditFileContainmentTest.php.
$pfb_eh_hook_edit = '/usr/local/pkg/pfblockerng/pfblockerng_hook_edit.inc';
if (!file_exists($pfb_eh_hook_edit)) {
	$pfb_eh_hook_edit = dirname(__DIR__, 2) . '/pkg/pfblockerng/pfblockerng_hook_edit.inc';
}
require_once($pfb_eh_hook_edit);

global $pfb;
pfb_global();

// issue #1669: General-settings toggle gating the CodeMirror 6
// live-highlight overlay for the #pfb_hook_editor_content field below (same toggle,
// same pfb_editor_enabled() accessor, as pfblockerng_dnsbl.php's $pfb_syntaxhl_on --
// registered in the general section, default on, rendered by pfblockerng_general.php).
$pfb_syntaxhl_on = pfb_editor_enabled();

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
$input_errors = array();

// The currently loaded/edited script, and its content -- populated below from either
// a successful GET picker load or a re-rendered failed POST (so the user's in-progress
// edit is never silently dropped on a validation error).
$pfb_eh_sel_when   = '';
$pfb_eh_sel_script = '';
$pfb_eh_content    = '';

// Create-flow field echo -- only re-populated on a failed create POST, so the user
// doesn't have to retype When/Name/Language after fixing a validation error.
$pfb_eh_new_core_val  = '';
$pfb_eh_new_lang_val  = 'sh';
$pfb_eh_new_when_echo = '';

$pfb_eh_state = pfb_edit_hooks_controller(
	isAllowedPage('diag_command.php'),
	static fn (): array => $_POST,
	static fn (): array => $_GET
);
$input_errors = $pfb_eh_state['errors'];
$pfb_eh_sel_when = $pfb_eh_state['sel_when'];
$pfb_eh_sel_script = $pfb_eh_state['sel_script'];
$pfb_eh_content = $pfb_eh_state['content'];
$pfb_eh_new_core_val = $pfb_eh_state['new_core'];
$pfb_eh_new_lang_val = $pfb_eh_state['new_lang'];
$pfb_eh_new_when_echo = $pfb_eh_state['new_when'];
if ($pfb_eh_state['redirect'] !== NULL) {
	header('Location: ' . $pfb_eh_state['redirect']);
	exit;
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
if ($pfb_eh_state['notice'] !== NULL) {
	print_info_box($pfb_eh_state['notice'], 'success');
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
$tab_array_sub = pfb_edit_hooks_tabs('edit');
display_top_tabs($tab_array_sub, TRUE);
pfb_print_pending_changes_box();

// Warning banner -- mirrors diag_command.php's own manual advanced-users callout
// (print_callout(..., 'danger', 'Advanced Users Only')). diag_command.php's priv also
// carries a '##|*WARN=standard-warning-root' metadata tag, but that tag is consumed by
// pfSense's priv-registration machinery for pages that ARE listed in $priv_list -- this
// page deliberately is not (see the top-of-file comment), so that generic mechanism
// never fires here and would give a false sense of coverage. This explicit callout is
// the load-bearing equivalent, not a decoration.
$pfb_eh_warning = pfb_edit_hooks_warning();
print_callout(
	$pfb_eh_warning['message'],
	$pfb_eh_warning['style'],
	$pfb_eh_warning['title']
);

$form = new Form(FALSE);

// --- Picker: existing hook scripts, grouped by Pre/Post -------------------------
$section = new Form_Section('Load an Existing Hook Script');
$section->addInput(new Form_StaticText(
	'About',
	'<small>' . gettext('Use the pencil to load a script into the editor, or the trash can to delete it. ' .
		'Only files already present in the hook-script folder are listed here -- the same picker model ' .
		'as the Hooks tab.') . '</small>'
));

// issue #1871: one table per Pre/Post instead of a run of inline links, matching the
// row-with-actions pattern the IP/DNSBL group lists already use (pfblockerng_category.php).
// The name is a plain cell and the actions are explicit buttons, so "load" is no longer
// hidden behind clicking the name -- and there is somewhere for delete to live, which the
// page previously had no way to offer at all.
foreach (array('pre' => gettext('Pre'), 'post' => gettext('Post')) as $pfb_eh_when_key => $pfb_eh_when_label) {
	// pfb_hook_scripts() is the SAME allow-list function the Hooks tab picker, the
	// delete handler and the runner use -- basenames only, never a path.
	$pfb_eh_scripts = pfb_hook_scripts($pfb_eh_when_key);

	$pfb_eh_rows = '';
	foreach ($pfb_eh_scripts as $pfb_eh_script_name) {
		$pfb_eh_href = '/pfblockerng/pfblockerng_edit_hooks.php?' .
			http_build_query(array('when' => $pfb_eh_when_key, 'script' => $pfb_eh_script_name));
		$pfb_eh_is_active = ($pfb_eh_sel_when === $pfb_eh_when_key && $pfb_eh_sel_script === $pfb_eh_script_name);
		$pfb_eh_lang_label = str_ends_with($pfb_eh_script_name, '.py') ? gettext('Python') : gettext('Shell');

		// filemtime() is read through the allow-list-resolved path, never a composed
		// one; an unresolvable entry simply reports no timestamp.
		$pfb_eh_path = pfb_hook_editor_path($pfb_eh_script_name);
		$pfb_eh_mtime = ($pfb_eh_path !== NULL) ? @filemtime($pfb_eh_path) : FALSE;
		$pfb_eh_mtime_label = ($pfb_eh_mtime !== FALSE) ? date('Y-m-d H:i', $pfb_eh_mtime) : '';

		$pfb_eh_safe_name = htmlspecialchars($pfb_eh_script_name, ENT_QUOTES);
		$pfb_eh_rows .= '<tr data-pfb-hook="' . $pfb_eh_safe_name . '">'
			. '<td' . ($pfb_eh_is_active ? ' class="text-bold"' : '') . '>' . htmlspecialchars($pfb_eh_script_name) . '</td>'
			. '<td>' . htmlspecialchars($pfb_eh_lang_label) . '</td>'
			. '<td>' . htmlspecialchars($pfb_eh_mtime_label) . '</td>'
			. '<td>'
			. '<a href="' . htmlspecialchars($pfb_eh_href) . '" title="' . gettext('Load this script into the editor') . '">'
			. '<i class="fa-solid fa-pencil" alt="edit"></i></a>'
			. '&emsp;'
			. '<i class="fa-solid fa-trash-can icon-pointer no-confirm"'
			. ' title="' . gettext('Delete this hook script') . '"'
			. ' onclick="pfb_eh_delete_hook(\'' . htmlspecialchars($pfb_eh_when_key, ENT_QUOTES) . '\', \''
			. htmlspecialchars(addslashes($pfb_eh_script_name), ENT_QUOTES) . '\');"></i>'
			. '</td></tr>';
	}
	if ($pfb_eh_rows === '') {
		$pfb_eh_rows = '<tr><td colspan="4"><em>' . gettext('(none yet)') . '</em></td></tr>';
	}

	$pfb_eh_table = '<table class="table table-striped table-hover table-condensed"'
		. ' data-pfb-hook-table="' . htmlspecialchars($pfb_eh_when_key, ENT_QUOTES) . '">'
		. '<thead><tr>'
		. '<th>' . gettext('Script') . '</th>'
		. '<th>' . gettext('Language') . '</th>'
		. '<th>' . gettext('Modified') . '</th>'
		. '<th>' . gettext('Actions') . '</th>'
		. '</tr></thead><tbody>' . $pfb_eh_rows . '</tbody></table>';

	$section->addInput(new Form_StaticText($pfb_eh_when_label, $pfb_eh_table));
}
$form->add($section);

// issue #1871: the delete flow's POST fields. Populated by pfb_eh_delete_hook() below
// and re-validated server-side against the allow-list regardless of what they claim.
$form->addGlobal(new Form_Input('pfb_eh_del_when', 'pfb_eh_del_when', 'hidden', ''));
$form->addGlobal(new Form_Input('pfb_eh_del_script', 'pfb_eh_del_script', 'hidden', ''));
$form->addGlobal(new Form_Input('pfb_eh_delete', 'pfb_eh_delete', 'hidden', ''));

// --- Create a new hook script ----------------------------------------------------
$section = new Form_Section('Create a New Hook Script');
$section->addInput(new Form_StaticText(
	'About',
	'<small>' . gettext('The server composes the filename as <code>hook_&lt;when&gt;_&lt;name&gt;.&lt;ext&gt;</code> ' .
		'-- you never type a path or a full filename. Creation is rejected if that exact file already exists.') . '</small>'
));

// The typed create-When echo (failed create) wins over the loaded script's own
// when; a fresh render follows the loaded script, defaulting to 'post'.
$pfb_eh_new_when_val = ($pfb_eh_new_when_echo === 'pre' || $pfb_eh_new_when_echo === 'post') ? $pfb_eh_new_when_echo
	: (($pfb_eh_sel_when === 'pre' || $pfb_eh_sel_when === 'post') ? $pfb_eh_sel_when : 'post');
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
	pfb_edit_hooks_form_value($pfb_eh_new_core_val),
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
	pfb_edit_hooks_submit_field('create'),
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
$form->addGlobal(new Form_Input('pfb_eh_cur_when', 'pfb_eh_cur_when', 'hidden', pfb_edit_hooks_form_value($pfb_eh_sel_when)));
$form->addGlobal(new Form_Input('pfb_eh_cur_script', 'pfb_eh_cur_script', 'hidden', pfb_edit_hooks_form_value($pfb_eh_sel_script)));

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
	pfb_edit_hooks_form_value($pfb_eh_content)
);
$pfb_eh_textarea->setAttribute('id', 'pfb_hook_editor_content');
$pfb_eh_textarea->removeClass('form-control')
	->addClass('row-fluid col-sm-12')
	->setAttribute('columns', '90')
	->setAttribute('rows', '20')
	->setAttribute('wrap', 'off')
	->setAttribute('spellcheck', 'false')
	->setAttribute('style', 'width: 100%; font-family: monospace;')
	->setHelp(gettext('Saved as typed, except line endings are normalized to LF, trailing whitespace is ' .
		'stripped from each line, and control characters other than tab are removed -- write a literal ' .
		'control byte as an escape (e.g. \\033) instead.'));
$section->addInput($pfb_eh_textarea);

// Named pfb_eh_save directly -- same native-submit reasoning as the Create button
// above.
$pfb_eh_save_btn = new Form_Button(
	pfb_edit_hooks_submit_field('save'),
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
<?php $pfb_hooks_editor = pfb_hooks_editor_render($pfb_syntaxhl_on, $pfb_eh_lang); ?>
<?=$pfb_hooks_editor['asset']?>
<script type="text/javascript">
//<![CDATA[
// issue #1871: deleting a hook script is irreversible from the UI (the file is
// unlinked, not moved aside), so it goes behind a confirmation naming the script.
// Dismissing the dialog leaves everything untouched -- nothing is written until the
// submit below, and the server re-validates the name against the shared allow-list
// regardless of what these fields carry.
function pfb_eh_delete_hook(when, script) {
	if (!confirm('Delete hook script "' + script + '"? This cannot be undone.')) {
		return;
	}
	$('#pfb_eh_del_when').val(when);
	$('#pfb_eh_del_script').val(script);
	$('#pfb_eh_delete').val('1');
	$('#pfb_eh_del_when').closest('form').submit();
}

events.push(function() {
<?=$pfb_hooks_editor['mount']?>
});
//]]>
</script>
<?php
include('foot.inc');
?>
