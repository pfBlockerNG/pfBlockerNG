<?php
/*
 * pfblockerng_category.php
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

require_once('guiconfig.inc');
require_once('globals.inc');
require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');

global $pfb;
pfb_global();

$action = $gtype = '';
$post_type_valid = FALSE;
$rowdata = array();
$rowid = 0;

if (isset($_GET)) {
	if (isset($_GET['savemsg']) && !empty($_GET['savemsg'])) {
		$savemsg = htmlspecialchars($_GET['savemsg']);
	}
	if (isset($_GET['rowid']) && !empty($_GET['rowid'])) {
		$temp_value = pfb_filter($_GET['rowid'], PFB_FILTER_NUM, 'Category');
                if (!empty($temp_value)) {
			$rowid = $temp_value ?: 0;
		}
	}
	if (isset($_GET['type']) && !empty($_GET['type'])) {
		$temp_value = pfb_filter($_GET['type'], PFB_FILTER_HTML, 'Category');
		if (in_array($temp_value, array('ipv4', 'ipv6', 'geoip', 'dnsbl'))) {
			$gtype = $temp_value;
		}
	}
}

if (isset($_POST)) {
	if (isset($_POST['savemsg']) && !empty($_POST['savemsg'])) {
		$savemsg = htmlspecialchars($_POST['savemsg']);
	}
	if (isset($_POST['rowid']) && !empty($_POST['rowid'])) {
		$temp_value = pfb_filter($_POST['rowid'], PFB_FILTER_NUM, 'Category');
		if (!empty($temp_value)) {
			$rowid = $temp_value ?: 0;
		}
	}
	$post_type_valid = isset($_POST['type']) && is_string($_POST['type']) && in_array($_POST['type'], array('ipv4', 'ipv6', 'geoip', 'dnsbl'), TRUE);
	if ($post_type_valid) {
		$gtype = $_POST['type'];
	}

	// AJAX request
	if (isset($_POST['postdata']) && !empty($_POST['postdata'])) {
		parse_str($_POST['postdata'], $post_data);
	}
	if (isset($_POST['ids']) && !empty($_POST['ids'])) {
		parse_str($_POST['ids'], $post_ids);
	}
	if (isset($_POST['act']) && !empty($_POST['act'])) {
		if ($_POST['act'] == 'del') {
			$action = 'del';
		} elseif ($_POST['act'] == 'update') {
			$action = 'update';
		}
	}
}

if (!empty($action) && !$post_type_valid) {
	print(json_encode(array('Failed Type')));
	exit;
}

// Set 'active' GUI Tabs
$active = array('ip' => FALSE, 'ipv4' => FALSE, 'ipv6' => FALSE, 'dnsbl' => FALSE, 'geoip' => FALSE);

// Default so $conf_type is defined on every path. The GeoIP case below doesn't set it;
// it is only ever used under the `$type != 'GeoIP'` guard, where the switch always sets it.
$conf_type = '';

switch ($gtype) {
	case 'ipv4':
		$type		= 'IPv4';
		$conf_type	= 'pfblockernglistsv4';
		$active		= array('ip' => TRUE, 'ipv4' => TRUE, 'ipv6' => FALSE, 'dnsbl' => FALSE, 'geoip' => FALSE);
		break;
	case 'ipv6':
		$type		= 'IPv6';
		$conf_type	= 'pfblockernglistsv6';
		$active		= array('ip' => TRUE, 'ipv4' => FALSE, 'ipv6' => TRUE, 'dnsbl' => FALSE, 'geoip' => FALSE);
		break;
	case 'geoip':
		$type		= 'GeoIP';
		$active		= array('ip' => TRUE, 'ipv4' => FALSE, 'ipv6' => FALSE, 'dnsbl' => FALSE, 'geoip' => TRUE);
		break;
	case 'dnsbl':
	default:
		$gtype		= 'dnsbl';
		$type		= 'DNSBL Groups';
		$conf_type	= 'pfblockerngdnsbl';
		$active		= array('ip' => FALSE, 'ipv4' => FALSE, 'ipv6' => FALSE, 'dnsbl' => TRUE, 'geoip' => FALSE);
		break;
}

// Collect rowdata
if ($type != 'GeoIP') {
	$rowdata_path = "installedpackages/{$conf_type}/config";
	$rowdata = config_get_path($rowdata_path, []);
} else {

	// Collect GeoIP rowdata
	foreach ($pfb['continents'] as $continent => $pfb_alias) {
		$continent_config = config_get_path('installedpackages/pfblockerng' . strtolower(str_replace(' ', '', $continent)) . '/config', [[
			'action' => 'Disabled',
			'cron' => 'Never',
			'aliaslog' => 'enabled'
		]]);

		if (!is_array($continent_config[0])) {
			$continent_config[0] = array();
		}
		$continent_config[0]['aliasname']		= $continent;
		$continent_config[0]['filename']		= str_replace(' ', '_', $continent);
		$continent_config[0]['description']		= "GeoIP {$continent}";
		$rowdata = array_merge($rowdata, $continent_config);
	}
}

// Remove any empty '<config></config>' XML tags
if (isset($rowdata[0]) && empty($rowdata[0])) {
	unset($rowdata[0]);
	$rowdata = array_values($rowdata);
	if (isset($rowdata_path)) {
		config_set_path($rowdata_path, $rowdata);
	}
	write_config("pfBlockerNG: Removed empty rowdata", FALSE);
}

if (!empty($action) && isset($gtype) && isset($rowid)) {

	switch ($action) {
		case 'del':
			// Delete Table row (via POST)
			$name = pfb_filter($rowdata[$rowid]['aliasname'], PFB_FILTER_WORD, 'Category');
			if (!empty($name) && isset($rowdata[$rowid])) {
				// issue #1014/#1019/#2060: close the deleted alias's alias-pass-managed
				// ledger entries (download, script) before the row config node is gone.
				pfb_sync_status_close_removed_alias($gtype, $name, $pfb['dbdir']);
				unset($rowdata[$rowid]);
				if (isset($rowdata_path)) {
					config_del_path("{$rowdata_path}/{$rowid}");
				}
				write_config("pfBlockerNG: Removed [ {$type} | {$name} ]", FALSE);
				pfb_mark_pending_changes();	// applies on the next Update, not on save
				$savemsg = "Removed [ Type: {$type}, Name: {$name} ]";
			} else {
				$savemsg = "Could not delete [ Type: {$type}, Name: {$name} ], not found";
			}
			header("Location: /pfblockerng/pfblockerng_category.php?type={$gtype}&savemsg={$savemsg}");
			exit;

		case 'update':
			// issue #1496: reads at 251/286/300 hit undefined on normal AJAX
			// act=update/reorder flows with no init (the old idiom was a no-op).
			// No isset($input_errors) consumer downstream -- safe unconditional init.
			$input_errors = array();
			if (is_array($rowdata)) {
				$cron_values = array(	'Never',
							'01hour',
							'02hours',
							'03hours',
							'04hours',
							'06hours',
							'08hours',
							'12hours',
							'EveryDay',
							'Weekly'
							);

				$aliaslog_values = array('enabled',
							'disabled',
							'disabled_log',
							'nxdomain_log',	// issue #31: NXDOMAIN logging
							'nxdomain'	// issue #31: NXDOMAIN no logging
							);

				// Parse POST and save new values
				if (!empty($post_data) && is_array($post_data)) {
					foreach ($post_data as $key => $value) {
						if (strpos($key, '-') !== FALSE) {
							$k_field = explode('-', $key);

							if (count($k_field) != 2) {
								$input_errors[] = "Failed too many fields: " . htmlspecialchars($key);
							}

							// Validate Variable names
							if (in_array($k_field[0], array('action', 'cron', 'aliaslog', 'logging'))) {
								$variable = $k_field[0];
							} else {
								$input_errors[] = "Failed Variable: " . htmlspecialchars($k_field[0]);
								// issue #1496: mirrors the sibling continue below (!is_string($value))
								// -- without it, switch ($variable) runs with $variable undefined on
								// an invalid prefix, producing a warning plus a second garbled error.
								continue;
							}

							// Validate Rowid
							$temp_value = pfb_filter($k_field[1], PFB_FILTER_NUM, 'Category');
							if (!empty($temp_value) || $k_field[1] == 0) {
								$rowid = $temp_value ?: 0;
							} else {
								$input_errors[] = "Failed Rowid: " . htmlspecialchars($k_field[1]);
							}
							if (!is_string($value)) {
								$input_errors[] = 'Failed Value';
								continue;
							}

							switch ($variable) {
								case 'action':
									if (!pfb_group_action_valid($value, $gtype)) {
										$input_errors[] = "Failed Action: " . htmlspecialchars($value);
									}
									break;
								case 'cron':
									if (!in_array($value, $cron_values)) {
										$input_errors[] = "Failed Cron: " . htmlspecialchars($value);
									}
									break;
								case 'aliaslog':
								case 'logging':
									if (!in_array($value, $aliaslog_values)) {
										$input_errors[] = "Failed Aliaslog: " . htmlspecialchars($value);
									}
									break;
								default:
									$input_errors[] = "Failed variable name: " . htmlspecialchars($variable);
							}

							if (!$input_errors) {
								if ($gtype != 'geoip') {
									$rowdata[$rowid][$variable] = pfb_filter($value, PFB_FILTER_HTML, 'Category');
									if (isset($rowdata_path)) {
										config_set_path("{$rowdata_path}/{$rowid}/{$variable}", $rowdata[$rowid][$variable]);
									}
								} else {
									$continent = pfb_filter(strtolower(str_replace(' ', '', $rowdata[$rowid]['aliasname'])), PFB_FILTER_HTML, 'Category');

									config_set_path("installedpackages/pfblockerng{$continent}/config/0/{$variable}", pfb_filter($value, PFB_FILTER_HTML, 'Category'));
								}
							}
						}
					}
				}

				// Save new Table order format (via AJAX)
				if (!empty($post_ids['ids']) && is_array($post_ids['ids'])) {
					$new_rows = array();
					foreach ($post_ids['ids'] as $key => $value) {

						$temp_value = pfb_filter($key, PFB_FILTER_NUM, 'Category');
						if (!empty($temp_value) || $key == 0) {
							$key = $temp_value ?: 0;
						} else {
							$input_errors[] = "IDS Failed " . htmlspecialchars($key);
						}

						$temp_value = pfb_filter(str_replace('r', '', $value), PFB_FILTER_NUM, 'Category');
						if (!empty($temp_value) || $value == 'r0') {
							$rowid = $temp_value ?: 0;
						} else {
							$input_errors[] = "IDS Failed Rowid: " . htmlspecialchars($value);
						}

						if (!$input_errors) {
							$new_rows[$key] = $rowdata[$rowid];
						}
					}

					if (!$input_errors) {
						$rowdata = $new_rows;
						if (isset($rowdata_path)) {
							config_set_path($rowdata_path, $rowdata);
						}
					}
				}

				// Save postdata and Table re-ordering
				if (!$input_errors) {
					write_config("pfBlockerNG: Saved page order format/settings for [ {$type} ]", FALSE);
					pfb_mark_pending_changes();	// applies on the next Update, not on save
				} else {
					// return errors to AJAX request
					print(json_encode($input_errors));
				}
			}
	}
	exit;
}

$pgtype = 'IP';
$pg_url = '/pfblockerng/pfblockerng_category.php?type=ipv4';

if ($gtype == 'dnsbl') {
	$pgtype = 'DNSBL';
	$pg_url = '/pfblockerng/pfblockerng_dnsbl.php';
}

$pgtitle = array(gettext('Firewall'), gettext('pfBlockerNG'), gettext($pgtype), gettext($type));
$pglinks = array('', '/pfblockerng/pfblockerng_general.php', "{$pg_url}", '@self');
$shortcut_section = 'pfblockerng';

include_once('head.inc');

// Define default Alerts Tab href link (Top row)
$get_req = pfb_alerts_default_page();

$tab_array	= array();
$tab_array[]	= array(gettext('General'),	FALSE,			'/pfblockerng/pfblockerng_general.php');
$tab_array[]	= array(gettext('IP'),		$active['ip'],		'/pfblockerng/pfblockerng_ip.php');
$tab_array[]	= array(gettext('DNSBL'),	$active['dnsbl'],	'/pfblockerng/pfblockerng_dnsbl.php');
$tab_array[]	= array(gettext('Update'),	FALSE,			'/pfblockerng/pfblockerng_update.php');
$tab_array[]	= array(gettext('Reports'),	FALSE,			"/pfblockerng/pfblockerng_alerts.php{$get_req}");
$tab_array[]	= array(gettext('Feeds'),	FALSE,			'/pfblockerng/pfblockerng_feeds.php');
$tab_array[]	= array(gettext('Logs'),	FALSE,			'/pfblockerng/pfblockerng_log.php');
$tab_array[]	= array(gettext('Sync'),	FALSE,			'/pfblockerng/pfblockerng_sync.php');
pfb_software_add_tab($tab_array);
display_top_tabs($tab_array, TRUE);

$tab_array = array();

if ($gtype == 'ipv4' || $gtype == 'ipv6' || $gtype == 'geoip') {
	$tab_array[]	= array(gettext('IPv4'),	$active['ipv4'],	'/pfblockerng/pfblockerng_category.php?type=ipv4');
	$tab_array[]	= array(gettext('IPv6'),	$active['ipv6'],	'/pfblockerng/pfblockerng_category.php?type=ipv6');
	$tab_array[]	= array(gettext('GeoIP'),	$active['geoip'],	'/pfblockerng/pfblockerng_category.php?type=geoip');
	$tab_array[]	= array(gettext('Reputation'),	FALSE,			'/pfblockerng/pfblockerng_reputation.php');
}
else {
	$tab_array[]	= array(gettext('DNSBL Groups'),	$active['dnsbl'],	'/pfblockerng/pfblockerng_category.php?type=dnsbl');
	$tab_array[]	= array(gettext('DNSBL Category'),	FALSE,			'/pfblockerng/pfblockerng_blacklist.php');
	$tab_array[]	= array(gettext('DNSBL SafeSearch'),	FALSE,			'/pfblockerng/pfblockerng_safesearch.php');
}
display_top_tabs($tab_array, TRUE);
pfb_print_pending_changes_box();

if (isset($savemsg)) {
	print_info_box($savemsg, 'success');
}

?>
<form action="pfblockerng_category.php" method="post" name="iform" id="iform">
<div id="savemsg_json" class="alert" role="alert"></div>
<input id="type" name="type" type="hidden" value="<?=$gtype?>"/>
<input type="hidden" name="rowid" id="rowid" value="">
<input type="hidden" name="act" id="act" value="">

<div class="panel panel-default">
	<div class="panel-heading">
		<?php if ($gtype != 'geoip'):
			$pageid = 'pfb_table'; ?>

			<h2 class="panel-title"><?=gettext("{$type} Summary &emsp;&emsp;(Drag to change order)")?></h2>
		<?php else:
			$pageid = 'pfb_table_geoip'; ?>

			<h2 class="panel-title"><?=gettext("{$type} Summary")?></h2>
		<?php endif; ?>
	</div>
	<div id="<?=$pageid;?>" class="panel-body">

		<?php
			// issue #1497: read at 565, reachable only when $gtype == 'geoip' (same
			// guard as below) -- but that guard is far enough away, across a table
			// render loop, that PHPStan can't correlate the two.
			$maxmind_verify = FALSE;
			// Maxmind credential verification
			if ($gtype == 'geoip') {
				$maxmind_verify = TRUE;
				$mmsg = pfb_maxmind_credential_notice($pfb['maxmind_key'], $pfb['maxmind_account']);
				if ($mmsg !== '') {
					$maxmind_verify = FALSE;
					print_callout('<p><strong>' . $mmsg . '</strong><br />'
						. '<a href="/pfblockerng/pfblockerng_ip.php">IP tab &mdash; MaxMind GeoIP configuration</a></p>', 'warning', '');
				}
			}
		?>

		<div class="table-responsive">
		<table id="<?=$pageid;?>" class="table table-striped table-hover table-compact sortable-theme-bootstrap table-rowdblclickedit" data-sortable>
			<thead>
				<tr id="pfb_header">
					<th><?=gettext('Name');?></th>
					<th><?=gettext('Description');?></th>
					<th><?=gettext('Action');?></th>
					<?php if ($gtype != 'geoip'): ?>
					<th><?=gettext('Frequency');?></th>
					<?php endif; ?>
					<?php if ($gtype == 'dnsbl'): ?>
						<th><?=gettext('Logging/Blocking Mode');?></th>
					<?php else: ?>
						<th><?=gettext('Logging');?></th>
					<?php endif; ?>
					<th><!----- Buttons -----></th>
					<?php if ($gtype != 'geoip'): ?>
					<th><!----- Reorder -----></th>
					<?php endif; ?>
				</tr>
			</thead>
			<tbody>

				<?php
				// issue #1497: read at 594 ($r_id +1, the "Add" link). Both branches
				// below provably assign it (foreach over a proven non-empty $rowdata,
				// or the else's explicit -1); this default changes nothing at runtime.
				$r_id = -1;
				if (!empty($rowdata) && !empty($rowdata[0])):
					foreach ($rowdata as $r_id => $row): ?>

				<tr style="vertical-align: top"<?php if ($gtype != 'geoip'): ?> class="sortable"<?php endif; ?> id="pfb_r<?=$r_id;?>">
					<td>
					<?php
						$aliasname_raw = $row['aliasname'];
						$row['aliasname'] = htmlspecialchars($aliasname_raw);
						if (mb_strlen($aliasname_raw, 'UTF-8') >= 20) {
							print ("<p title=\"{$row['aliasname']}\">" . htmlspecialchars(mb_substr($aliasname_raw, 0, 15, 'UTF-8')) . '...</p>');
						} else {
							print ($row['aliasname']);
						}
					?>
					</td>

					<td>
					<?php
						$description_raw = $row['description'];
						$row['description'] = htmlspecialchars($description_raw);
						if (mb_strlen($description_raw, 'UTF-8') >= 20) {
							print ("<p title=\"{$row['description']}\">" . htmlspecialchars(mb_substr($description_raw, 0, 15, 'UTF-8')) . '...</p>');
						} else {
							print ($row['description']);
						}
					?>
					</td>

					<td>
					<?php
						if ($gtype == 'ipv4' || $gtype == 'ipv6' || $gtype == 'geoip') {
							$list_array = array(	'Disabled' => 'Disabled', 'Deny_Inbound' => 'Deny Inbound',
										'Deny_Outbound' => 'Deny Outbound', 'Deny_Both' => 'Deny Both',
										'Permit_Inbound' => 'Permit Inbound', 'Permit_Outbound' => 'Permit Outbound',
										'Permit_Both' => 'Permit Both', 'Match_Inbound' => 'Match Inbound',
										'Match_Outbound' => 'Match Outbound', 'Match_Both' => 'Match Both',
										'Alias_Deny' => 'Alias Deny', 'Alias_Permit' => 'Alias Permit',
										'Alias_Match' => 'Alias Match', 'Alias_Native' => 'Alias Native' );
						} else {
							$list_array = array(	'Disabled' => 'Disabled', 'unbound' => 'Unbound' );
						}
						if (!pfb_group_action_valid($rowdata[$r_id]['action'] ?? NULL, $gtype)) {
							$rowdata[$r_id]['action'] = 'Disabled';
						}

						$selectadd = new Form_Select(
								'action-' . $r_id,
								'List Action',
								$rowdata[$r_id]['action'],
								$list_array
						);
						$selectadd->setWidth(8)->setAttribute('style', 'width: auto');
						print ($selectadd);
					?>
					</td>

					<?php if ($gtype != 'geoip'): ?>

					<td>
					<?php
						$selectadd = new Form_Select(
								'cron-' . $r_id,
								'Update Frequency',
								$rowdata[$r_id]['cron'],
								[	'Never' => 'Never', '01hour' => 'Every hour', '02hours' => 'Every 2 hours',
									'03hours' => 'Every 3 hours', '04hours' => 'Every 4 hours',
									'06hours' => 'Every 6 hours', '08hours' => 'Every 8 hours',
									'12hours' => 'Every 12 hours', 'EveryDay' => 'Once a day',
									'Weekly' => 'Weekly'
								]
						);
						$selectadd->setWidth(8)->setAttribute('style', 'width: auto');
						print ($selectadd);
					?>
					</td>

					<?php endif; ?>

					<td>
					<?php
						if ($gtype == 'ipv4' || $gtype == 'ipv6' || $gtype == 'geoip') {
							$field = 'aliaslog-' . $r_id;
							$logtype = $rowdata[$r_id]['aliaslog'];
						} else {
							$field = 'logging-' . $r_id;
							$logtype = $rowdata[$r_id]['logging'];
						}

						$log_error = '';
						if ($gtype == 'dnsbl') {
							$log_options = ['enabled'	=> 'DNSBL WebServer/VIP',
									'disabled_log'	=> 'Null Blocking (logging)',
									'disabled'	=> 'Null Blocking (no logging)',
									'nxdomain_log'	=> 'NXDOMAIN (logging)',
									'nxdomain'	=> 'NXDOMAIN (no logging)'];

							// Global DNSBL Logging/Blocking mode
							if (!empty($pfb['dnsbl_global_log'])) {
								$logtype		= $pfb['dnsbl_global_log'];
								$log_options[$logtype]	= "{$log_options[$logtype]} (Global)";
							}
						}
						else {
							$log_options = [ 'enabled' => 'Enabled', 'disabled' => 'Disabled' ];
						}

						$selectadd = new Form_Select(
								$field,
								'Logging/Blocking Mode',
								$logtype,
								$log_options
						);
						$selectadd->setWidth(8)->setAttribute('style', 'width: auto')
							  ->setHelp($log_error);
						print ($selectadd);
					?>
					</td>

					<td>
					<?php if ($gtype != 'geoip'): ?>
						<a href="/pfblockerng/pfblockerng_category_edit.php?type=<?=$gtype?>&rowid=<?=$r_id?>">
							<i class="fa-solid fa-pencil" alt="edit"></i>
						</a>
						<i class="fa-solid fa-trash-can icon-pointer no-confirm"
							title="<?=gettext('Delete selected entry') . ' [ ' . $row['aliasname'] .' ] ?' ?>"
							onclick="$('#rowid').val('<?=$r_id?>');$('#act').val('del');pfb_rownamedelete();">
						</i>

						<?php
							// Add href anchor link to CustomList if defined
							if (!empty($rowdata[$r_id]['custom'])):
						?>

							<a href="/pfblockerng/pfblockerng_category_edit.php?type=<?=$gtype?>&rowid=<?=$r_id?>#Customlist"
								title="Quick link to Custom List">
								<i class="fa-solid fa-anchor" alt="edit"></i>
								</a>
							<?php endif; ?>

						<?php
							if ($gtype == 'dnsbl' && isset($row['order']) && $row['order'] == 'primary'):
						?>
							<i class="fa-regular fa-square-check" style="cursor: default" title="DNSBL Primary Group order defined"></i>
							<?php endif; ?>

					<?php elseif ($maxmind_verify && file_exists("/usr/local/www/pfblockerng/pfblockerng_{$row['filename']}.php")): ?>
						<a href="/pfblockerng/pfblockerng_<?=$row['filename'];?>.php">
							<i class="fa-solid fa-pencil" alt="edit"></i>
						</a>
					<?php endif; ?>

					</td>
				</tr>
					<?php endforeach; ?>
				<?php else: $r_id = -1; ?>

				<tr>
					<td>
						No Alias/Groups are defined.
						<br />Click <strong>Add</strong> to define a new Alias/Group.
						<br /><br /><strong>Note</strong>: Pre-defined Alias/Groups are available in the Feeds Tab.
					</td>
				</tr>
				<?php endif; ?>
			</tbody>
		</table>
		</div>
	</div>
	<nav class="action-buttons">
		<?php if ($gtype != 'geoip'): ?>
		<a href="/pfblockerng/pfblockerng_category_edit.php?type=<?=$gtype?>&rowid=<?=$r_id +1?>" class="btn btn-sm btn-success">
			<i class="fa-solid fa-plus icon-embed-btn"></i>
			<?=gettext('Add')?>
		</a>
		<?php endif; ?>
		<button class="btn btn-sm btn-primary" type="button" id="btnsave" title="Save the page 'Order' format">
			<i class="fa-solid fa-save icon-embed-btn"></i>
			<?=gettext('Save')?>
		</button>&emsp;
	</nav>
</div>

<?php
if ($gtype == 'geoip') {
	print_callout('GeoIP database GeoLite2 distributed under the Creative Commons Attribution-ShareAlike 4.0 International License by:
			<a target="_blank" rel="noopener noreferrer" href="https://www.maxmind.com">MaxMind Inc.</a><br /><br />
			The GeoIP database is automatically updated each day at a random hour.<br /><br />

			<span class="text-danger"><strong>Note:&emsp;</strong></span>
			pfSense by default implicitly blocks all unsolicited inbound traffic to the WAN interface.<br />
			Therefore adding GeoIP based firewall rules to the WAN will <strong>not</strong> provide any benefit, unless there are
			open WAN ports.<br /><br />
			Its also <strong>not</strong> recommended to block the "world", instead consider rules to "Permit" traffic to/from
			selected Countries only.<br />
			Also consider protecting just the specific open WAN ports and its just as important to protect the outbound LAN traffic.<br /><br />
			Country ISOs can also be defined in the IPv4/6 Tabs (Refer to blue infoblocks for more details)<br /><br />
			MaxMind Account ID and License Key are configured on the
			<a href="/pfblockerng/pfblockerng_ip.php">IP tab</a>
			(MaxMind GeoIP configuration).<br /><br />
			<strong>Setting changes are applied via CRON or \'Force Update|Reload\' only!</strong></p>');
}
elseif ($gtype == 'dnsbl') {
	print_callout('<p><strong>Setting changes are applied via CRON or \'Force Update|Reload\' only!</strong><br /><br />
			DNSBL Category feeds are processed first, followed by the DNSBL Groups.<br />
			DNSBL Groups can be prioritized first, by selecting the \'Group Order\' option.</p>');
}
else {
	print_callout('<p><strong>Setting changes are applied via CRON or \'Force Update|Reload\' only!</strong></p>');
}
?>
</form>

<script type="text/javascript">
//<![CDATA[

var pagetype = null;
// ADR-63: mirrors system/webgui/roworderdragging -- OFF (default) keeps drag
// enabled alongside anchor-click; ON restricts reordering to anchor-click only.
var pfb_drag_enabled = <?=config_path_enabled('system/webgui', 'roworderdragging') ? 'false' : 'true';?>;

function pfb_rownamedelete() {
	if (confirm('Delete selected entry?')) {
		$('form').submit();
	}
}

events.push(function() {

	function save_new_changes() {
		var gtype = "<?=$gtype?>";
		if ($('#pfb_table table tbody').length == 0) {
			var ids = '';
		} else {
			var ids = pfb_reorder_read_order('#pfb_table table tbody', 'tr.sortable');
		}
		var postdata = $('#iform').serialize();

		if (confirm("<?=gettext("Save settings and/or page 'Order' changes?")?>")) {

			ajaxRequest = $.ajax(
				{
					type: 'post',
					url: '/pfblockerng/pfblockerng_category.php',
					data: {
						rowid: '0',
						act: 'update',
						type: gtype,
						ids: ids,
						postdata: postdata
					}
				}
			);

			// Deal with the results of the above ajax call
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

	// Move line (User mouse drag) + anchor-click (issue #1147); drag stays
	// gated by pfb_drag_enabled (system/webgui/roworderdragging).
	pfb_reorder_init('#pfb_table table tbody', 'tr.sortable', null, pfb_drag_enabled);

	$('#savemsg_json').hide();
	$('#btnsave').click(function() {
		save_new_changes();
		$('#savemsg_json').hide();
	});
});

//]]>
</script>
<?=pfb_category_js_asset_render()?>
<?php include('foot.inc');?>
