<?php
/*
 * pfblockerng_group_policy.php
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
 *
 * ============================================================================
 * ADR-55 UI REFERENCE IMPLEMENTATION (Phase 3 splices this into src/).
 * Authoritative design target — adapt mechanically to drift, never redesign
 * silently (divergences go in the phase handoff).
 *
 * Helper contracts consumed (defined by ADR-55 Phases 1-2):
 *   pfb_cg_all(): array                    — all Client Group rows (rowid-keyed)
 *   pfb_cg_delete(int $rowid): void        — remove a CG (+ its pfB_CG alias on next sync)
 *   pfb_cg_set_enabled(int $rowid, string $state): void   — 'Enabled'|'Disabled'
 *   pfb_cg_rule_counts(): array            — ['total' => int, 'per_cg' => [name => int]]
 * Pattern source: pfblockerng_category.php (panel/table/AJAX quick-edit/delete).
 * ============================================================================
 */

require_once('guiconfig.inc');
require_once('globals.inc');
require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');

global $pfb;
pfb_global();

$action = '';
$rowid = 0;

if (isset($_GET['savemsg']) && !empty($_GET['savemsg'])) {
	$savemsg = htmlspecialchars($_GET['savemsg']);
}

if (isset($_POST)) {
	if (isset($_POST['rowid']) && !empty($_POST['rowid'])) {
		$temp_value = pfb_filter($_POST['rowid'], PFB_FILTER_NUM, 'Group Policy');
		if (!empty($temp_value) || $_POST['rowid'] == 0) {
			$rowid = $temp_value ?: 0;
		}
	}
	if (isset($_POST['postdata']) && !empty($_POST['postdata'])) {
		parse_str($_POST['postdata'], $post_data);
	}
	if (isset($_POST['act']) && !empty($_POST['act'])) {
		if ($_POST['act'] == 'del') {
			$action = 'del';
		} elseif ($_POST['act'] == 'update') {
			$action = 'update';
		}
	}
}

$rowdata = pfb_cg_all();

// Delete a Client Group
if ($action == 'del' && isset($rowdata[$rowid])) {
	$name = $rowdata[$rowid]['name'];
	pfb_cg_delete($rowid);
	write_config("pfBlockerNG: Deleted Client Group [ {$name} ]");
	pfb_mark_pending_changes();	// alias/rule removal applies on the next Update
	header("Location: /pfblockerng/pfblockerng_group_policy.php?savemsg=" . urlencode("Client Group [ {$name} ] deleted"));
	exit;
}

// AJAX quick-edit save ('enabled' per-row selects, mirroring pfblockerng_category.php)
if ($action == 'update') {
	$input_errors = array();
	$enabled_values = array('Enabled', 'Disabled');

	if (!empty($post_data) && is_array($post_data)) {
		foreach ($post_data as $key => $value) {
			if (strpos($key, '-') === FALSE) {
				continue;
			}
			$k_field = explode('-', $key);
			if (count($k_field) != 2 || $k_field[0] != 'enabled') {
				$input_errors[] = 'Failed Variable: ' . htmlspecialchars($key);
				continue;
			}

			$temp_value = pfb_filter($k_field[1], PFB_FILTER_NUM, 'Group Policy');
			if (empty($temp_value) && $k_field[1] != 0) {
				$input_errors[] = 'Failed Rowid: ' . htmlspecialchars($k_field[1]);
				continue;
			}
			$q_rowid = $temp_value ?: 0;

			if (!in_array($value, $enabled_values)) {
				$input_errors[] = 'Failed Enabled: ' . htmlspecialchars($value);
				continue;
			}

			if (isset($rowdata[$q_rowid])) {
				pfb_cg_set_enabled($q_rowid, $value);
			}
		}
	}

	if (!$input_errors) {
		write_config('pfBlockerNG: Saved Client Group state settings');
		pfb_mark_pending_changes();	// applies on the next Update, not on save
	} else {
		print(json_encode($input_errors));
	}
	exit;
}

$pgtitle = array(gettext('Firewall'), gettext('pfBlockerNG'), gettext('Group Policy'));
include_once('head.inc');

// Top tab row (Group Policy sits after Feeds — the ADR-55 tab sweep)
$get_req = pfb_alerts_default_page();

$tab_array	= array();
$tab_array[]	= array(gettext('General'),	FALSE,	'/pfblockerng/pfblockerng_general.php');
$tab_array[]	= array(gettext('IP'),		FALSE,	'/pfblockerng/pfblockerng_ip.php');
$tab_array[]	= array(gettext('DNSBL'),	FALSE,	'/pfblockerng/pfblockerng_dnsbl.php');
$tab_array[]	= array(gettext('Update'),	FALSE,	'/pfblockerng/pfblockerng_update.php');
$tab_array[]	= array(gettext('Reports'),	FALSE,	"/pfblockerng/pfblockerng_alerts.php{$get_req}");
$tab_array[]	= array(gettext('Feeds'),	FALSE,	'/pfblockerng/pfblockerng_feeds.php');
$tab_array[]	= array(gettext('Group Policy'), TRUE,	'/pfblockerng/pfblockerng_group_policy.php');
$tab_array[]	= array(gettext('Logs'),	FALSE,	'/pfblockerng/pfblockerng_log.php');
$tab_array[]	= array(gettext('Sync'),	FALSE,	'/pfblockerng/pfblockerng_sync.php');
pfb_software_add_tab($tab_array);
display_top_tabs($tab_array, TRUE);
pfb_print_pending_changes_box();

if (isset($savemsg)) {
	print_info_box($savemsg, 'success');
}

print_info_box(gettext('Client Groups apply Feed Group actions to specific source networks. '
	. 'A Feed Group without any Client Group policy behaves exactly as before.'), 'info', 'close');

$rule_counts = pfb_cg_rule_counts();
?>
<form action="pfblockerng_group_policy.php" method="post" name="iform" id="iform">
<div id="savemsg_json" class="alert" role="alert"></div>
<input type="hidden" name="rowid" id="rowid" value="">
<input type="hidden" name="act" id="act" value="">

<div class="panel panel-default">
	<div class="panel-heading">
		<h2 class="panel-title"><?=gettext('Client Groups Summary')?></h2>
	</div>
	<div id="pfb_gp_table" class="panel-body">
		<div class="table-responsive">
		<table class="table table-striped table-hover table-compact sortable-theme-bootstrap table-rowdblclickedit" data-sortable>
			<thead>
				<tr id="pfb_header">
					<th><?=gettext('Name');?></th>
					<th><?=gettext('Description');?></th>
					<th><?=gettext('Members');?></th>
					<th><?=gettext('Policies');?></th>
					<th><?=gettext('Enabled');?></th>
					<th><!----- Buttons -----></th>
				</tr>
			</thead>
			<tbody>

				<?php if (!empty($rowdata)):
					foreach ($rowdata as $r_id => $row):

					$addr_count	= count(array_filter(explode("\n", pfbng_text_area_decode($row['addresses'] ?? '', TRUE, FALSE))));
					$alias_count	= is_array($row['aliases'] ?? NULL) ? count($row['aliases']) : 0;
					$bind_count	= is_array($row['binding'] ?? NULL) ? count($row['binding']) : 0;
				?>

				<tr style="vertical-align: top" id="pfb_gp_r<?=$r_id;?>">
					<td>
					<?php
						$row['name'] = htmlspecialchars($row['name']);
						if (strlen($row['name']) >= 20) {
							print ("<p title=\"{$row['name']}\">" . substr($row['name'], 0, 15) . '...</p>');
						} else {
							print ($row['name']);
						}
					?>
					</td>

					<td>
					<?php
						$row['description'] = htmlspecialchars($row['description'] ?? '');
						if (strlen($row['description']) >= 20) {
							print ("<p title=\"{$row['description']}\">" . substr($row['description'], 0, 15) . '...</p>');
						} else {
							print ($row['description']);
						}
					?>
					</td>

					<td>
						<?=$addr_count?> <?=gettext('addresses')?>, <?=$alias_count?> <?=gettext('aliases')?>
					</td>

					<td>
						<?php if ($bind_count > 0): ?>
							<?=$bind_count?> (<?=htmlspecialchars((string)($rule_counts['per_cg'][$row['name']] ?? 0))?> <?=gettext('rules')?>)
						<?php else: ?>
							&mdash;
						<?php endif; ?>
					</td>

					<td>
					<?php
						$selectadd = new Form_Select(
								'enabled-' . $r_id,
								'Enabled',
								(($row['enabled'] ?? '') == 'on') ? 'Enabled' : 'Disabled',
								[ 'Enabled' => 'Enabled', 'Disabled' => 'Disabled' ]
						);
						$selectadd->setWidth(8)->setAttribute('style', 'width: auto');
						print ($selectadd);
					?>
					</td>

					<td>
						<a href="/pfblockerng/pfblockerng_group_policy_edit.php?rowid=<?=$r_id?>">
							<i class="fa-solid fa-pencil" alt="edit"></i>
						</a>
						<i class="fa-solid fa-trash-can icon-pointer no-confirm"
							title="<?=gettext('Delete selected entry') . ' [ ' . $row['name'] .' ] ?' ?>"
							onclick="$('#rowid').val('<?=$r_id?>');$('#act').val('del');pfb_rownamedelete();">
						</i>
					</td>
				</tr>
					<?php endforeach; ?>
				<?php else: $r_id = -1; ?>

				<tr>
					<td>
						No Client Groups are defined.
						<br />Click <strong>Add</strong> to define a new Client Group.
					</td>
				</tr>
				<?php endif; ?>
			</tbody>
		</table>
		</div>
	</div>
	<nav class="action-buttons">
		<a href="/pfblockerng/pfblockerng_group_policy_edit.php?rowid=<?=$r_id +1?>" class="btn btn-sm btn-success">
			<i class="fa-solid fa-plus icon-embed-btn"></i>
			<?=gettext('Add')?>
		</a>
		<button class="btn btn-sm btn-primary" type="button" id="btnsave" title="Save the Enabled state settings">
			<i class="fa-solid fa-save icon-embed-btn"></i>
			<?=gettext('Save')?>
		</button>&emsp;
	</nav>
</div>

<?php
print_callout('<p><strong>Setting changes are applied via CRON or \'Force Update|Reload\' only!</strong><br /><br />'
		. 'Client Group policies generate <strong>' . htmlspecialchars((string)$rule_counts['total'])
		. '</strong> firewall auto-rules in total (each policy adds rules scoped to its Client Group).</p>');
?>
</form>

<script type="text/javascript">
//<![CDATA[

function pfb_rownamedelete() {
	if (confirm('Delete selected entry?')) {
		$('form').submit();
	}
}

events.push(function() {

	function save_new_changes() {
		var postdata = $('#iform').serialize();

		if (confirm("<?=gettext('Save the Enabled state changes?')?>")) {

			ajaxRequest = $.ajax(
				{
					type: 'post',
					url: '/pfblockerng/pfblockerng_group_policy.php',
					data: {
						rowid: '0',
						act: 'update',
						postdata: postdata
					}
				}
			);

			ajaxRequest.done(function (response, textStatus, jqXHR) {
				if (response == '') {
					$('form').submit();
				} else {
					$('#savemsg_json').show();
					$('#savemsg_json').addClass("alert-danger")
					var json = new Object;
					json = jQuery.parseJSON(response)
					output = 'Could not save, Errors Found:<br />';
					$.each(json, function(key, value) {
						output += value + "<br />"
					});
					$('#savemsg_json').html(output);
					var scrollToEl = document.getElementById('topmenu');
					scrollToEl.scrollIntoView(true);
				}
			});
		}
	}

	$('#savemsg_json').hide();
	$('#btnsave').click(function() {
		save_new_changes();
		$('#savemsg_json').hide();
	});
});

//]]>
</script>
<script src="pfBlockerNG.js" type="text/javascript"></script>
<?php include('foot.inc');?>
