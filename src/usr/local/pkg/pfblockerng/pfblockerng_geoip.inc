<?php
/*
 * pfblockerng_geoip.inc
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

// Function to process Continent txt files and create Country ISO files and to Generate GUI PHP files.
function pfblockerng_get_countries($output_root = '/usr/local/www/pfblockerng') {
	global $g, $pfb;
	if (!is_dir($output_root) && !@mkdir($output_root, 0755, TRUE)) {
		return FALSE;
	}
	$output_ok = TRUE;

	$coptions4 = $coptions6 = array();
	$options4 = $options6 = '';

	$geoip_files = array (	'Africa'		=> "{$pfb['ccdir']}/Africa_v4.txt",
				'Antarctica'		=> "{$pfb['ccdir']}/Antarctica_v4.txt",
				'Asia'			=> "{$pfb['ccdir']}/Asia_v4.txt",
				'Europe'		=> "{$pfb['ccdir']}/Europe_v4.txt",
				'North America'		=> "{$pfb['ccdir']}/North_America_v4.txt",
				'Oceania'		=> "{$pfb['ccdir']}/Oceania_v4.txt",
				'South America'		=> "{$pfb['ccdir']}/South_America_v4.txt",
				'Proxy and Satellite'	=> "{$pfb['ccdir']}/Proxy_and_Satellite_v4.txt",
				'Top Spammers'		=> "{$pfb['ccdir']}/Top_Spammers_v4.info"
				);

	// Collect data to generate new continent PHP files.
	$log = " Creating pfBlockerNG Continent PHP files\n";
	pfb_logger("{$log}", 4);

	$roptions4 = array();

	foreach ($geoip_files as $cont => $file) {
		$continent = $continent_en = '';

		// issue #1507: $ftotal4/$ftotal6 are assigned only when a continent has
		// data -- reset per continent so a data-less one renders 0, not the
		// previous continent's count.
		$ftotal4 = $ftotal6 = 0;

		// Process the following for IPv4 and IPv6
		foreach (array('4', '6') as $type) {

			$cont_length = strlen($cont);
			if ($cont_length < 8) {
				$tab = "\t\t\t";
			} elseif ($cont_length < 19) {
				$tab = "\t\t";
			} else {
				$tab = "\t";
			}

			$log = " IPv{$type} {$cont}{$tab}\n";
			pfb_logger("{$log}", 4);

			if ($type == '6') {
				$file = str_replace('v4', 'v6', $file);
			}

			// issue #1261: NULL (read failure) -> 0, matching the exec()-era `?: 0`
			// fallback (a legitimately-empty file also yields 0).
			$lastline		= pfb_count_lines($file) ?? 0;
			$pfb['complete']	= FALSE;
			$linenum		= 1;
			$total			= 0;
			// $country/$isocode are carried across lines and read in the
			// `$pfb['complete']` flush block below; default them so they are
			// always defined (the flush only runs after a header has set them).
			$country		= '';
			$isocode		= '';

			if (($handle = @fopen("{$file}", 'r')) !== FALSE) {
				while (($line = @fgets($handle)) !== FALSE) {

					$line = trim($line);
					if (str_starts_with($line, '#')) {
						if ($pfb['complete']) {
							if (file_exists("{$pfb['ccdir']}/{$isocode}_v{$type}.txt")) {

								${'coptions' . $type}[] = "{$country}|\"{$isocode}\" => \"{$country} {$isocode} ({$total})\"";

								// Only collect IPv4 for Reputation Tab
								if ($type == '4' && strpos($isocode, '_rep') === FALSE) {
									$roptions4[] = "{$country}|\"{$isocode}\" => \"{$country} {$isocode} ({$total})\"";
								}
							}

							// Clear variables and restart Continent collection process
							$total = 0;
							$pfb['complete'] = FALSE;
						}

						if (strpos($line, 'Continent IPv') !== FALSE) {
							$continent = trim(str_replace(':', '', strstr($line, ':', FALSE)));
						}
						if (strpos($line, 'Continent en:') !== FALSE) {
							$continent_en = trim(str_replace(':', '', strstr($line, ':', FALSE)));
						}
						if (strpos($line, 'Country: ') !== FALSE) {
							$country = str_replace('# Country: ', '', $line);
						}
						if (strpos($line, 'ISO Code: ') !== FALSE) {
							$isocode = str_replace('# ISO Code: ', '', $line);

							// Remove previous ISO file
							if ($cont != 'Top Spammers') {
								unlink_if_exists("{$pfb['ccdir']}/{$isocode}_v{$type}.txt");
							}
						}

						// Create placeholder for null ISO Data or 'undefined ISO Represented'
						if (strpos($line, 'Total Networks: 0') !== FALSE || strpos($line, 'Total Networks: NA') !== FALSE) {
							if (!empty(pfb_filter($isocode, PFB_FILTER_WORD, 'php'))) {
									$output_ok = @file_put_contents("{$pfb['ccdir']}/{$isocode}_v{$type}.txt", '', LOCK_EX) !== FALSE
										&& $output_ok;
							}
							$pfb['complete'] = TRUE;
						}
					}

					elseif (!str_starts_with($line, '#')) {
						if (!empty(pfb_filter($isocode, PFB_FILTER_WORD, 'php'))) {
							if ($cont == 'Top Spammers') {
								// issue #1261: display-only total -- NULL (read failure) -> 0.
								$total = pfb_count_lines("{$pfb['ccdir']}/{$isocode}_v{$type}.txt") ?? 0;
							} else {
								$total++;
								if (!empty($line)) {
									$output_ok = @file_put_contents(
										"{$pfb['ccdir']}/{$isocode}_v{$type}.txt", "{$line}\n", FILE_APPEND | LOCK_EX
									) !== FALSE && $output_ok;
								}
							}
						}
						$pfb['complete'] = TRUE;
					}

					// Save last EOF ISO IP data
					if ($linenum == $lastline) {
						if (!empty(pfb_filter($isocode, PFB_FILTER_WORD, 'php'))) {
							// Create placeholder for null ISO Data or 'undefined ISO Represented'
							if (strpos($line, 'Total Networks: 0') !== FALSE || strpos($line, 'Total Networks: NA') !== FALSE) {
								$output_ok = @file_put_contents("{$pfb['ccdir']}/{$isocode}_v{$type}.txt", '', LOCK_EX) !== FALSE
									&& $output_ok;
							}

							if (file_exists("{$pfb['ccdir']}/{$isocode}_v{$type}.txt")) {
								${'coptions' . $type}[] = "{$country}|\"{$isocode}\" => \"{$country} {$isocode} ({$total})\"";

								if ($type == '4' && strpos($isocode, '_rep') === FALSE) {
									$roptions4[] = "{$country}|\"{$isocode}\" => \"{$country} {$isocode} ({$total})\"";
								}
							}
						}
					}
					$linenum++;
				}
			}

			if ($handle) {
				@fclose($handle);
			}

			if (empty($continent)) {
				pfb_logger("Continent data [ {$cont} ] not found\n", 4);
				continue;
			}

			// Sort IP Countries alphabetically and build PHP drop-down lists for Continent tabs
			if (!empty(${'coptions' . $type})) {
				if ($cont != 'Top Spammers') {
					sort(${'coptions' . $type}, SORT_STRING);
				}
				${'ftotal' . $type} = count(${'coptions' . $type});
				$count = 1;
				${'options' . $type} = '';

				foreach (${'coptions' . $type} as $option) {

					// Remove prefixed Country string (Used to sort array)
					$option = ltrim(strstr($option, '|', FALSE), '|');

					if ($count == 1) {
						${'options' . $type} .= "\t{$option},\n";
						$count++;
						continue;
					}
					if (${'ftotal' . $type} == $count) {
						${'options' . $type} .= "\t\t{$option}\n\t";
					} else {
						${'options' . $type} .= "\t\t{$option},\n";
					}
					$count++;
				}
			}
			unset(${'coptions' . $type});
		}

		// #1493 defect 2: the heredoc below reads $options4/$options6 once per
		// continent, but the per-continent tail unconditionally unsets them
		// below -- a continent whose coptions4/6 stayed empty (fopen failure,
		// or genuinely no data) never re-enters the guarded block above to
		// reassign them, so anything after the first continent needs this fill.
		$options4 ??= ''; // @phpstan-ignore nullCoalesce.variable (dynamic ${'options4'} unset at the previous continent's tail is invisible to PHPStan)
		$options6 ??= ''; // @phpstan-ignore nullCoalesce.variable (dynamic ${'options6'} unset at the previous continent's tail is invisible to PHPStan)

$php_data = <<<EOF
<?php
/*
 * pfblockerng_{$continent_en}.php
 *
 * part of pfSense (https://www.pfsense.org)
 * Copyright (c) 2016-2026 Rubicon Communications, LLC (Netgate)
 * Copyright (c) 2015-2024 BBcan177@gmail.com
 * All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the \"License\");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an \"AS IS\" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

require_once('guiconfig.inc');
require_once('globals.inc');
require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');

global \$pfb;
pfb_global();

\$continent			= "{$continent}";	// Continent name (Locale specific)
\$continent_en			= "{$continent_en}";	// Continent name (English)
\$options_countries4		= array({$options4});
\$options_countries6		= array({$options6});
\$options_countries4_cnt	= "{$ftotal4}";
\$options_countries6_cnt	= "{$ftotal6}";

EOF;
$php_data .= <<<'EOF'

$options_action			= [	'Disabled' => 'Disabled', 'Deny_Inbound' => 'Deny Inbound', 'Deny_Outbound' => 'Deny Outbound',
					'Deny_Both' => 'Deny Both', 'Permit_Inbound' => 'Permit Inbound', 'Permit_Outbound' => 'Permit Outbound',
					'Permit_Both' => 'Permit Both', 'Match_Inbound' => 'Match Inbound', 'Match_Outbound' => 'Match Outbound',
					'Match_Both' => 'Match Both', 'Alias_Deny' => 'Alias Deny', 'Alias_Permit' => 'Alias Permit',
					'Alias_Match' => 'Alias Match', 'Alias_Native' => 'Alias Native' ];

$options_aliaslog		= [	'enabled' => 'Enabled', 'disabled' => 'Disabled' ];

// Collect all pfSense 'Port' Aliases (+ address-bearing types for Custom Source/Destination)
$pfb_ac_lists			= pfb_alias_autocomplete_lists(config_get_path('aliases/alias', []));
$options_aliasports_in		= $options_aliasports_out	= $pfb_ac_lists['ports'];
$options_aliasaddr_in		= $options_aliasaddr_out	= $pfb_ac_lists['networks'];
$ports_list			= implode(',', array_keys($pfb_ac_lists['ports']));
$networks_list			= implode(',', array_keys($pfb_ac_lists['networks']));

$options_autoproto_in		= $options_autoproto_out	= get_ipprotocols();
$options_agateway_in		= $options_agateway_out		= pfb_get_gateways();

$continent_display		= str_replace('_', ' ', "{$continent}");				// Continent name displayed on page
$conf_type			= 'pfblockerng' . strtolower(str_replace('_', '', $continent_en));	// XML config location

$pfb['geoipconfig'] = config_get_path("installedpackages/{$conf_type}/config/0", []);

$active[$continent_display]	= TRUE;

foreach (array('Top Spammers', 'Africa', 'Antarctica', 'Asia', 'Europe', 'North America', 'Oceania', 'South America', 'Proxy and Satellite') as $tab_active) {
        if (!isset($active[$tab_active])) {
                $active[$tab_active] = FALSE;
        }
}

$pconfig = array();
$pconfig['countries4']		= explode(',', $pfb['geoipconfig']['countries4'] ?? '');
$pconfig['countries6']		= explode(',', $pfb['geoipconfig']['countries6'] ?? '');
$pconfig['action'] = pfb_group_action_valid($pfb['geoipconfig']['action'] ?? NULL, 'geoip') ? $pfb['geoipconfig']['action'] : 'Disabled';
$pconfig['aliaslog']		= $pfb['geoipconfig']['aliaslog']			?: 'enabled';

$pconfig['autoaddrnot_in']	= $pfb['geoipconfig']['autoaddrnot_in'];
$pconfig['autoports_in']	= $pfb['geoipconfig']['autoports_in'];
$pconfig['aliasports_in']	= $pfb['geoipconfig']['aliasports_in'];
$pconfig['autoaddr_in']		= $pfb['geoipconfig']['autoaddr_in'];
$pconfig['autonot_in']		= $pfb['geoipconfig']['autonot_in'];
$pconfig['aliasaddr_in']	= $pfb['geoipconfig']['aliasaddr_in'];
$pconfig['autoproto_in']	= $pfb['geoipconfig']['autoproto_in'];
$pconfig['agateway_in']		= $pfb['geoipconfig']['agateway_in'];

$pconfig['autoaddrnot_out']	= $pfb['geoipconfig']['autoaddrnot_out'];
$pconfig['autoports_out']	= $pfb['geoipconfig']['autoports_out'];
$pconfig['aliasports_out']	= $pfb['geoipconfig']['aliasports_out'];
$pconfig['autoaddr_out']	= $pfb['geoipconfig']['autoaddr_out'];
$pconfig['autonot_out']		= $pfb['geoipconfig']['autonot_out'];
$pconfig['aliasaddr_out']	= $pfb['geoipconfig']['aliasaddr_out'];
$pconfig['autoproto_out']	= $pfb['geoipconfig']['autoproto_out'];
$pconfig['agateway_out']	= $pfb['geoipconfig']['agateway_out'];

// Validate input fields and save
if ($_POST) {
	if (isset($_POST['save'])) {

		if (isset($input_errors)) {
			unset($input_errors);
		}

		// Validate Select field options
		$select_options = array(	'action'		=> 'Disabled',
						'aliaslog'		=> 'enabled',
						'aliasports_in'		=> '',
						'aliasports_out'	=> '',
						'aliasaddr_in'		=> '',
						'aliasaddr_out'		=> '',
						'autoproto_in'		=> 'any',
						'autoproto_out'		=> 'any',
						'agateway_in'		=> 'default',
						'agateway_out'		=> 'default',
						);

		foreach ($select_options as $s_option => $s_default) {
			if (!isset($_POST[$s_option])) {
				// do nothing
			}
			elseif (is_array($_POST[$s_option])) {
				$_POST[$s_option] = $s_default;
			}
			elseif (!array_key_exists($_POST[$s_option], ${"options_$s_option"})) {
				$_POST[$s_option] = $s_default;
			}
		}

		// Validate Select field (array) options
		$select_options = array(	'countries4'	=> '',
						'countries6'	=> ''
						);

		foreach ($select_options as $s_option => $s_default) {
			if (!isset($_POST[$s_option])) {
				// do nothing
			}
			elseif (is_array($_POST[$s_option])) {
				foreach ($_POST[$s_option] as $post_option) {
					if (!array_key_exists($post_option, ${"options_$s_option"})) {
						$_POST[$s_option] = $s_default;
						break;
					}
				}
			}
			elseif (!array_key_exists($_POST[$s_option], ${"options_$s_option"})) {
				$_POST[$s_option] = $s_default;
			}
		}

		// Validate Adv. In/Outbound firewall rules settings (issue #676, sibling of #636).
		// Existence + type are resolved from the configuration (pfb_alias_type), NOT is_alias()
		// (empty $aliastable cache here) nor alias_get_type() (reserved system tables would
		// wrongly pass) — see pfb_adv_alias_field_errors().
		// Append (not array_merge): $input_errors is left unset until the first error so the
		// later isset($input_errors) checks hold — appending auto-vivifies only on a real error.
		foreach (pfb_adv_alias_field_errors($_POST) as $pfb_alias_error) {
			$input_errors[] = $pfb_alias_error;
		}

		// Validate Adv. firewall rule 'Protocol' setting
		if (!empty($_POST['autoports_in']) || !empty($_POST['autoaddr_in'])) {
			if (empty($_POST['autoproto_in']) || $_POST['autoproto_in'] == 'any') {
				$input_errors[] = "Settings: Protocol setting cannot be set to 'Any' with Advanced Inbound firewall rule settings.";
			}
		}
		if (!empty($_POST['autoports_out']) || !empty($_POST['autoaddr_out'])) {
			if (empty($_POST['autoproto_out']) || $_POST['autoproto_out'] == 'any') {
				$input_errors[] = "Settings: Protocol setting cannot be set to 'Any' with Advanced Outbound firewall rule settings.";
			}
		}

		// Validate if any Countries (v4/v6) are defined when Action is enabled.
		if ($_POST['action'] != 'Disabled' && !isset($_POST['countries4']) && !isset($_POST['countries6'])) {
			$input_errors[] = "No Countries defined!";
		}

		// Avoid creating a permit rule on WAN with 'any'
		if ($_POST['action'] == 'Permit_Inbound' || $_POST['action'] == 'Permit_Both') {
			$pfb_warning = FALSE;
			if ($_POST['autoproto_in'] == '' || $_POST['autoproto_in'] == 'any') {
				$pfb_warning = TRUE;
				$input_errors[] = "Warning: When using an Action setting of 'Permit Inbound or Permit Both',"
					. " you must configure the 'Advanced Inbound Custom Protocol' setting. The current setting of 'Any' is not allowed.";
			}
			if ($_POST['aliasports_in'] == '' && $_POST['aliasaddr_in'] == '') {
				$pfb_warning = TRUE;
				$input_errors[] = "Warning:  When using an Action setting of 'Permit Inbound or Permit Both',"
					. " you must configure at least one of 'Advanced Inbound Custom Port/Destination' settings.";
			}
			if ($pfb_warning) {
				$input_errors[] = '';
				$input_errors[] = '===> WARNING <===';
				$input_errors[] = "Improper Permit rules on the WAN can catastrophically impact the security of your network!";
			}
		}

		if (!$input_errors) {

			$pfb['geoipconfig']['countries4']		= implode(',', (array)$_POST['countries4'])		?: '';
			$pfb['geoipconfig']['countries6']		= implode(',', (array)$_POST['countries6'])		?: '';
			$pfb['geoipconfig']['action']			= $_POST['action']					?: '';
			$pfb['geoipconfig']['aliaslog']			= $_POST['aliaslog']					?: '';

			$pfb['geoipconfig']['autoaddrnot_in']		= pfb_filter($_POST['autoaddrnot_in'], PFB_FILTER_ON_OFF, 'Geoip');
			$pfb['geoipconfig']['autoports_in']		= pfb_filter($_POST['autoports_in'], PFB_FILTER_ON_OFF, 'Geoip');
			$pfb['geoipconfig']['aliasports_in']		= $_POST['aliasports_in']				?: '';
			$pfb['geoipconfig']['autoaddr_in']		= pfb_filter($_POST['autoaddr_in'], PFB_FILTER_ON_OFF, 'Geoip');
			$pfb['geoipconfig']['autonot_in']		= pfb_filter($_POST['autonot_in'], PFB_FILTER_ON_OFF, 'Geoip');
			$pfb['geoipconfig']['aliasaddr_in']		= $_POST['aliasaddr_in']				?: '';
			$pfb['geoipconfig']['autoproto_in']		= $_POST['autoproto_in']				?: 'any';
			$pfb['geoipconfig']['agateway_in']		= $_POST['agateway_in']					?: '';

			$pfb['geoipconfig']['autoaddrnot_out']		= pfb_filter($_POST['autoaddrnot_out'], PFB_FILTER_ON_OFF, 'Geoip');
			$pfb['geoipconfig']['autoports_out']		= pfb_filter($_POST['autoports_out'], PFB_FILTER_ON_OFF, 'Geoip');
			$pfb['geoipconfig']['aliasports_out']		= $_POST['aliasports_out']				?: '';
			$pfb['geoipconfig']['autoaddr_out']		= pfb_filter($_POST['autoaddr_out'], PFB_FILTER_ON_OFF, 'Geoip');
			$pfb['geoipconfig']['autonot_out']		= pfb_filter($_POST['autonot_out'], PFB_FILTER_ON_OFF, 'Geoip');
			$pfb['geoipconfig']['aliasaddr_out']		= $_POST['aliasaddr_out']				?: '';
			$pfb['geoipconfig']['autoproto_out']		= $_POST['autoproto_out']				?: 'any';
			$pfb['geoipconfig']['agateway_out']		= $_POST['agateway_out']				?: '';

			config_set_path("installedpackages/{$conf_type}/config/0", $pfb['geoipconfig']);
			write_config("[pfBlockerNG] save GeoIP [ {$continent_display} ] settings");
			pfb_mark_pending_changes();	// applies on the next Update, not on save
			header("Location: /pfblockerng/pfblockerng_{$continent_en}.php");
			exit;
		}
		else {
			$pconfig = $_POST;	// Restore failed user-entered data
		}
	}
}

$pgtitle = array(gettext('Firewall'), gettext('pfBlockerNG'), gettext('IP'), gettext('GeoIP'), $continent_display);
$pglinks = array( '', '/pfblockerng/pfblockerng_general.php', '/pfblockerng/pfblockerng_ip.php',
		'/pfblockerng/pfblockerng_category.php?type=geoip', '@self');
$shortcut_section = 'pfblockerng';

include_once('head.inc');

if ($input_errors) {
	print_input_errors($input_errors);
}

// Define default Alerts Tab href link (Top row)
$get_req = pfb_alerts_default_page();

$tab_array	= array();
$tab_array[]	= array(gettext('General'),		FALSE,	'/pfblockerng/pfblockerng_general.php');
$tab_array[]	= array(gettext('IP'),			TRUE,	'/pfblockerng/pfblockerng_ip.php');
$tab_array[]	= array(gettext('DNSBL'),		FALSE,	'/pfblockerng/pfblockerng_dnsbl.php');
$tab_array[]	= array(gettext('Update'),		FALSE,	'/pfblockerng/pfblockerng_update.php');
$tab_array[]	= array(gettext('Reports'),		FALSE,	"/pfblockerng/pfblockerng_alerts.php{$get_req}");
$tab_array[]	= array(gettext('Feeds'),		FALSE,	'/pfblockerng/pfblockerng_feeds.php');
$tab_array[]	= array(gettext('Logs'),		FALSE,	'/pfblockerng/pfblockerng_log.php');
$tab_array[]	= array(gettext('Sync'),		FALSE,	'/pfblockerng/pfblockerng_sync.php');
pfb_software_add_tab($tab_array);
display_top_tabs($tab_array, TRUE);

$tab_array	= array();
$tab_array[]	= array(gettext('GeoIP'),		FALSE,						'/pfblockerng/pfblockerng_category.php?type=geoip');
$tab_array[]	= array(gettext('Top Spammers'),	$active['Top Spammers']		?: FALSE,	'/pfblockerng/pfblockerng_Top_Spammers.php');
$tab_array[]	= array(gettext('Africa'),		$active['Africa']		?: FALSE,	'/pfblockerng/pfblockerng_Africa.php');
$tab_array[]	= array(gettext('Antarctica'),		$active['Antarctica']		?: FALSE,	'/pfblockerng/pfblockerng_Antarctica.php');
$tab_array[]	= array(gettext('Asia'),		$active['Asia']			?: FALSE,	'/pfblockerng/pfblockerng_Asia.php');
$tab_array[]	= array(gettext('Europe'),		$active['Europe']		?: FALSE,	'/pfblockerng/pfblockerng_Europe.php');
$tab_array[]	= array(gettext('North America'),	$active['North America']	?: FALSE,	'/pfblockerng/pfblockerng_North_America.php');
$tab_array[]	= array(gettext('Oceania'),		$active['Oceania']		?: FALSE,	'/pfblockerng/pfblockerng_Oceania.php');
$tab_array[]	= array(gettext('South America'),	$active['South America']	?: FALSE,	'/pfblockerng/pfblockerng_South_America.php');
$tab_array[]	= array(gettext('Proxy and Satellite'),	$active['Proxy and Satellite']	?: FALSE,	'/pfblockerng/pfblockerng_Proxy_and_Satellite.php');
display_top_tabs($tab_array, TRUE);
pfb_print_pending_changes_box();

$form = new Form('Save');

$section = new Form_Section("Continent - {$continent_display}");
$section->addInput(new Form_StaticText(
	'Links',
	'<small>'
	. '<a href="/firewall_aliases.php" target="_blank" rel="noopener noreferrer">Firewall Alias</a>&emsp;'
	. '<a href="/firewall_rules.php" target="_blank" rel="noopener noreferrer">Firewall Rules</a>&emsp;'
	. '<a href="/status_logs_filter.php" target="_blank" rel="noopener noreferrer">Firewall Logs</a></small>'
));

$section->addInput(new Form_StaticText(
	'NOTES:',
	'GeoIP data by MaxMind Inc. - GeoLite2<br />'
	. 'MaxMind credentials are configured on the <a href="/pfblockerng/pfblockerng_ip.php">IP tab</a> (MaxMind GeoIP configuration).<br />'
	. 'Click here for IMPORTANT info&emsp;-->&emsp;'
	. pfb_geoip_doc_link()

	. '<hr style="height: 1px; border: none; background-color: #d6d6d6;"/>'

	. '<div id="Txtfld" tabindex="1" class="bg-info">'
	. 'pfSense by default implicitly blocks all unsolicited inbound traffic to the WAN interface.<br />'
	. 'Therefore adding GeoIP based firewall rules to the WAN will <strong>not</strong> provide any benefit, unless there are open WAN ports.<br /><br />'
	. 'It\'s also <strong>not</strong> recommended to block the \'world\', instead consider rules to \'Permit\' traffic from selected Countries only.<br />'
	. 'Also consider protecting just the specific open WAN ports and it\'s just as important to protect the outbound LAN traffic.<br /><br />'

	. 'GeoIP ISOs can also be configured in the pfBlockerNG IPv4/IPv6 Alias(es) Source Definitions (Format: GeoIP)'
	. '</div>'

	. '<hr style="height: 1px; border: none; background-color: #d6d6d6;"/>'

	. '&emsp;Use &emsp;<strong>CTRL+CLICK</strong>&emsp;to&emsp;<strong>select/unselect</strong>&emsp; the IPv4/6 Countries below as required.'
));

// Maxmind credential verification
$mmsg = pfb_maxmind_credential_notice($pfb['maxmind_key'], $pfb['maxmind_account']);
if ($mmsg !== '') {
	print_callout('<p><strong>' . $mmsg . '</strong><br />'
		. '<a href="/pfblockerng/pfblockerng_ip.php">IP tab &mdash; MaxMind GeoIP configuration</a></p>', 'danger', '');
}

$group = new Form_Group('');
$group->add(new Form_Select(
	'countries4',
	NULL,
	$pconfig['countries4'],
	$options_countries4,
	TRUE
))->setHelp('&emsp;IPv4 countries')->setAttribute('size', $options_countries4_cnt)
  ->setAttribute('style', 'overflow: auto;');

$group->add(new Form_Select(
	'countries6',
	NULL,
	$pconfig['countries6'],
	$options_countries6,
	TRUE
))->setHelp('&emsp;IPv6 countries')->setAttribute('size', $options_countries6_cnt)
  ->setAttribute('style', 'overflow: auto;');

$section->add($group);
$form->add($section);

$action_txt = "Default: <strong>Disabled</strong>
		<br />For Non-Alias type rules you must define the appropriate <strong>Firewall 'Auto' Rule Order</strong> option.
		<br />Click here for more info\xe2\x80\x83-->
		<div class=\"infoblock alert-info clearfix\">
			Select the <strong>Action</strong> for Firewall Rules on lists you have selected.<br /><br />

			<strong><u>'Disabled' Rules:</u></strong> Disables selection and does nothing to selected Alias.<br /><br />

			<strong><u>'Deny' Rules:</u></strong><br />
			'Deny' rules create high priority 'block' or 'reject' rules on the stated interfaces. They don't change the 'pass' rules on other
			interfaces. Typical uses of 'Deny' rules are:<br />
				<ul>
					<li><strong>Deny Both</strong> -
						blocks all traffic in both directions, if the source or destination IP is in the block list
					</li>
					<li><strong>Deny Inbound/Deny Outbound</strong> -
						blocks all traffic in one direction <u>unless</u> it is part of a session started by
						traffic sent in the other direction. Does not affect traffic in the other direction.
					</li>
					<li>One way 'Deny' rules can be used to selectively block <u>unsolicited</u> incoming
						(new session) packets in one direction, while still allowing <u>deliberate</u> outgoing
						sessions to be created in the other direction.
					</li>
				</ul>

			<strong><u>'Permit' Rules:</u></strong><br />
			'Permit' rules create high priority 'pass' rules on the stated interfaces. They are the opposite of Deny rules, and don't create
			any 'blocking' effect anywhere. They have priority over all Deny rules. Typical uses of 'Permit' rules are:<br />
				<ul>
					<li><strong>To ensure</strong> that traffic to/from the listed IPs will <u>always</u> be allowed in the
						stated directions. They override <u>almost all other</u> Firewall rules on the stated interfaces.
					</li>
					<li><strong>To act as a whitelist</strong> for Deny rule exceptions, for example if a large IP range
						or pre-created blocklist blocks a few IPs that should be accessible.
					</li>
				</ul>

			<strong><u>'Match' Rules:</u></strong><br />
			'Match' or 'Log' only the traffic on the stated interfaces. This does not Block or Reject. It just Logs the traffic.
			<ul>
				<li><strong>Match Both</strong> - Matches all traffic in both directions,
					if the source or destination IP is in the list.
				</li>
				<li><strong>Match Inbound/Match Outbound</strong> - Matches all traffic in one direction only.
				</li>
			</ul>

			<strong><u>'Alias' Rules:</u></strong><br />
			<strong>'Alias'</strong> rules create an <a href=\"/firewall_aliases.php\">alias</a> for the list (and do nothing else).
			This enables a pfBlockerNG list to be used by name, in any firewall rule or pfSense function, as desired.
				<ul>
					<li><strong>Options - Alias Deny,&nbsp; Alias Permit,&nbsp; Alias Match,&nbsp; Alias Native</strong></li>
					<li>'Alias Deny' can use De-Duplication and Reputation Processes if configured.</li>
					<li>'Alias Permit' and 'Alias Match' will be saved in the Same folder as the other Permit/Match Auto-Rules</li>
					<li>'Alias Native' lists are kept in their Native format without any modifications.</li></ul>

			<span class=\"text-danger\">Note: </span><ul>
				When manually creating 'Alias' type firewall rules; <strong>Do not add</strong> (pfB_) to the
				start of the rule description, use (pfb_) (Lowercase prefix). Manually created 'Alias' rules with 'pfB_' in the
				description will be auto-removed by package when 'Auto' rules are defined.</ul>
		</div>";

$section->addInput(new Form_Select(
	'action',
	'List Action',
	$pconfig['action'],
	$options_action
))->setHelp($action_txt);

$section->addInput(new Form_Select(
	'aliaslog',
	'Enable Logging',
	$pconfig['aliaslog'],
	$options_aliaslog
))->setHelp("Default: <strong>Enable</strong><br />
	Select - Logging to Status: System Logs: FIREWALL ( Log )<br />
	This can be overriden by the 'Force Global IP Logging' option on the IP Tab.");

// Print Advanced Firewall Rule Settings (Inbound and Outbound) section
foreach (array( 'In' => 'Source', 'Out' => 'Destination') as $adv_mode => $adv_type) {

	$advmode = strtolower($adv_mode);

	$section = new Form_Section("Advanced {$adv_mode}bound Firewall Rule Settings", "adv{$advmode}boundsettings", COLLAPSIBLE|SEC_CLOSED);
	$section->addInput(new Form_StaticText(
		NULL,
		"<span class=\"text-danger\">Note:</span>&nbsp; In general, Auto-Rules are created as follows:<br />
			<dl class=\"dl-horizontal\">
				<dt>{$adv_mode}bound</dt><dd>'any' port, 'any' protocol, 'any' destination and 'any' gateway</dd>
			</dl>
			Configuring the Adv. {$adv_mode}bound Rule settings, will allow for more customization of the {$adv_mode}bound Auto-Rules."));

	$section->addInput(new Form_Checkbox(
		'autoaddrnot_' . $advmode,
		"Invert {$adv_type}",
		NULL,
		pfb_cfg_toggle_read($pconfig['autoaddrnot_' . $advmode]) === PfbToggle::On,
		'on'
	))->setHelp("Option to invert the sense of the match. ie - Not (!) {$adv_type} Address(es)");

	$group = new Form_Group("Custom DST Port");
	$group->add(new Form_Checkbox(
		'autoports_' . $advmode,
		'Custom DST Port',
		NULL,
		pfb_cfg_toggle_read($pconfig['autoports_' . $advmode]) === PfbToggle::On,
		'on'
	))->setHelp('Enable')
	  ->setWidth(2);

	$group->add(new Form_Input(
		'aliasports_' . $advmode,
		'Custom Port',
		'text',
		$pconfig["aliasports_{$advmode}"]
	))->setHelp("<a target=\"_blank\" href=\"/firewall_aliases.php?tab=port\">Click Here to add/edit Aliases</a>
			Do not manually enter port numbers.<br />Do not use 'pfB_' in the Port Alias name."
	)->setWidth(8);
	$section->add($group);

	if ($adv_type == 'Source') {
		$custom_location = 'Destination';
	} else {
		$custom_location = 'Source';
	}

	$group = new Form_Group("Custom {$custom_location}");
	$group->add(new Form_Checkbox(
		'autoaddr_' . $advmode,
		"Custom {$custom_location}",
		NULL,
		pfb_cfg_toggle_read($pconfig["autoaddr_{$advmode}"]) === PfbToggle::On,
		'on'
	))->setHelp('Enable')->setWidth(1);

	$group->add(new Form_Checkbox(
		'autonot_' . $advmode,
		NULL,
		NULL,
		pfb_cfg_toggle_read($pconfig["autonot_{$advmode}"]) === PfbToggle::On,
		'on'
	))->setHelp('Invert')->setWidth(1);

	$group->add(new Form_Input(
		'aliasaddr_' . $advmode,
		"Custom {$custom_location}",
		'text',
		$pconfig['aliasaddr_' . $advmode]
	))->sethelp('<a target="_blank" rel="noopener noreferrer" href="/firewall_aliases.php?tab=ip">Click Here to add/edit Aliases</a>'
		. 'Do not manually enter Addresses(es).<br />Do not use \'pfB_\' in the address-type (Host/Network/URL/URL Table) Alias name.<br />'
		. "Select 'invert' to invert the sense of the match. ie - Not (!) {$custom_location} Address(es)"
	)->setWidth(8);
	$section->add($group);

	$group = new Form_Group('Custom Protocol');
	$group->add(new Form_Select(
		'autoproto_' . $advmode,
		NULL,
		$pconfig['autoproto_' . $advmode],
		$options_autoproto_in
	))->setHelp("<strong>Default: any</strong><br />Select the Protocol used for {$adv_mode}bound Firewall Rule(s).<br />
		<span class=\"text-danger\">Note:</span>&nbsp;Do not use 'Any' with Adv. {$adv_mode}bound Rules as it will bypass these settings!");
	$section->add($group);

	$group = new Form_Group('Custom Gateway');
	$group->add(new Form_Select(
		'agateway_' . $advmode,
		NULL,
		$pconfig['agateway_' . $advmode],
		$options_agateway_in
	))->setHelp("Select alternate Gateway or keep 'default' setting.");

	$section->add($group);
	$form->add($section);
}

print($form);
print_callout('<p><strong>Setting changes are applied via CRON or \'Force Update|Reload\' only!</strong></p>');
?>

<script type="text/javascript">
//<![CDATA[

var pagetype = 'advanced';

// Auto-Complete for Adv. In/Out Address Select boxes
var plist = "<?=$ports_list?>";
var portsarray = plist.split(',');
var nlist = "<?=$networks_list?>";
var networksarray = nlist.split(',');

// Disable GeoIP/ASN Autocomplete as not required for the GeoIP Continent pages
var geoiparray = 'disabled';

events.push(function() {
	// Scroll to top of page and set focus to "Note" text.
	$('body').scrollTop(0);
	$('#Txtfld').focus();
});

//]]
</script>
<?=pfb_geoip_js_asset_render()?>
<?php include('foot.inc');?>

EOF;
		// Update each Continent PHP file.
		if (!empty(pfb_filter($continent_en, PFB_FILTER_WORD, 'php'))) {
			$output_ok = @file_put_contents(
				"{$output_root}/pfblockerng_{$continent_en}.php", $php_data, LOCK_EX
			) !== FALSE && $output_ok;
		}

		// Unset Arrays
		unset(${'options4'}, ${'options6'}, $php_data);

	}	// End foreach 'Six Continents and Proxy/Satellite' update PHP script builder process

	// Sort Countries IPv4 alphabetically and build XML <option> data for Reputation tab (IPv6 not used by ET IQRisk)

	sort($roptions4, SORT_STRING);
	$eoa = count($roptions4);
	$et_options = '';
	$count = 1;

	foreach ($roptions4 as $option4) {

		// Remove prefixed Country string (Used to sort array)
		$option4 = ltrim(strstr($option4, '|', FALSE), '|');

		if ($count == 1) {
			$et_options .= "\t{$option4},\n";
			$count++;
			continue;
		}
		if ($eoa == $count) {
			$et_options .= "\t\t{$option4}\n\t";
		} else {
			$et_options .= "\t\t{$option4},\n";
		}
		$count++;
	}

	//Build Reputation Tab
	$output_ok = pfb_build_reputation_tab($et_options, $output_root) && $output_ok;

	$log = "Country Code Update Ended\n\n";
	pfb_logger("{$log}", 4);

	// Unset arrays
	unset($roptions4, $et_options);
	return $output_ok;
}


// Update pfBlockerNG_Reputation.php file with Country Code changes
function pfb_build_reputation_tab($et_options='', $output_root = '/usr/local/www/pfblockerng') {

	$php_rep = <<<'EOF'
<?php
/*
 * pfblockerng_reputation.php
 *
 * part of pfSense (https://www.pfsense.org)
 * Copyright (c) 2016-2026 Rubicon Communications, LLC (Netgate)
 * Copyright (c) 2015-2024 BBcan177@gmail.com
 * All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the \"License\");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an \"AS IS\" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

require_once('guiconfig.inc');
require_once('globals.inc');
require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');

global $pfb;
pfb_global();

$pfb['repconfig'] = PfbConfig::readSection('installedpackages/pfblockerngreputation/config/0');

$pconfig = array();
$pconfig['enable_rep']		= $pfb['repconfig']['enable_rep'];
$pconfig['p24_max_var']		= $pfb['repconfig']['p24_max_var'];
$pconfig['enable_pdup']		= $pfb['repconfig']['enable_pdup'];
$pconfig['p24_pmax_var']	= $pfb['repconfig']['p24_pmax_var'];
$pconfig['enable_dedup']	= $pfb['repconfig']['enable_dedup'];
$pconfig['p24_dmax_var']	= $pfb['repconfig']['p24_dmax_var'];
$pconfig['ccwhite']		= $pfb['repconfig']['ccwhite'];
$pconfig['ccblack']		= $pfb['repconfig']['ccblack'];
$pconfig['ccexclude']		= explode(',', $pfb['repconfig']['ccexclude'] ?? '');
$pconfig['et_header']		= $pfb['repconfig']['et_header'];
$pconfig['etblock']		= explode(',', $pfb['repconfig']['etblock'] ?? '');
$pconfig['etmatch']		= explode(',', $pfb['repconfig']['etmatch'] ?? '');


// Select field options
$options_p24_max_var		= [ '5' => '5', '10' => '10', '15' => '15', '20' => '20', '25' => '25', '50' => '50' ];
$options_p24_pmax_var		= [ '50' => '50', '25' => '25', '20' => '20', '15' => '15', '10' => '10', '5' => '5' ];
$options_p24_dmax_var		= [ '5' => '5', '10' => '10', '15' => '15', '20' => '20', '25' => '25', '50' => '50' ];
$options_ccwhite		= [ 'ignore' => 'Ignore', 'match' => 'Match' ];
$options_ccblack		= [ 'block' => 'Block', 'match' => 'Match' ];

EOF;
	if (!empty($et_options)) {
		$php_rep .= <<<EOF
\$options_ccexclude	= array($et_options);

EOF;
	} else {
		$php_rep .= <<<'EOF'
$options_ccexclude	= array();

EOF;
	}

	$php_rep .= <<<'EOF'

$options_et_categories		= [	'ET_Cnc'		=> 'ET CNC',
					'ET_Bot'		=> 'ET BOT',
					'ET_Spam'		=> 'ET SPAM',
					'ET_Drop'		=> 'ET DROP',
					'ET_Spywarecnc'		=> 'ET Spyware CNC',
					'ET_Onlinegaming'	=> 'ET Online Gaming',
					'ET_Drivebysrc'		=> 'ET DrivebySRC',
					'ET_Chatserver'		=> 'ET Chat Server',
					'ET_Tornode'		=> 'ET TOR Node',
					'ET_Compromised'	=> 'ET Compromised',
					'ET_P2Pnode'		=> 'ET P2P Node',
					'ET_Proxy'		=> 'ET Proxy',
					'ET_Ipcheck'		=> 'ET IP Check',
					'ET_Utility'		=> 'ET Utility',
					'ET_DDostarget'		=> 'ET DDOS Target',
					'ET_Scanner'		=> 'ET Scanner',
					'ET_Brute'		=> 'ET Brute',
					'ET_Fakeav'		=> 'ET Fake AV',
					'ET_Dyndns'		=> 'ET DYN DNS',
					'ET_Undesireable'	=> 'ET Undersireable',
					'ET_Abusedtld'		=> 'ET Abuse TLD',
					'ET_Selfsignedssl'	=> 'ET SelfSigned SSL',
					'ET_Blackhole'		=> 'ET Blackhole',
					'ET_RAS'		=> 'ET RAS',
					'ET_P2Pcnc'		=> 'ET P2P CNC',
					'ET_Sharedhosting'	=> 'ET Shared Hosting',
					'ET_Parking'		=> 'ET Parking',
					'ET_VPN'		=> 'ET VPN',
					'ET_Exesource'		=> 'ET EXE Source',
					'ET_Mobilecnc'		=> 'ET Mobile CNC',
					'ET_Mobilespyware'	=> 'ET Mobile Spyware',
					'ET_Skypenode'		=> 'ET Skype Node',
					'ET_Bitcoin'		=> 'ET Bitcoin',
					'ET_DDosattacker'	=> 'ET DDOS Attacker'
					];

// Validate input fields and save
if ($_POST) {
	if (isset($_POST['save'])) {

		if (!empty($_POST['et_header']) && preg_match("/\W/", $_POST['et_header'])) {
			$input_errors[] = 'ET Header/Label Name: Name field cannot contain spaces, special or international characters.';
		}

		// Validate Select field options
		$select_options = array(	'p24_max_var'	=> '',
						'p24_pmax_var'	=> '',
						'p24_dmax_var'	=> '',
						'ccwhite'	=> '',
						'ccblack'	=> ''
					);

		foreach ($select_options as $s_option => $s_default) {
			if (!isset($_POST[$s_option])) {
				// do nothing
			}
			elseif (is_array($_POST[$s_option])) {
				$_POST[$s_option] = $s_default;
			}
			elseif (!array_key_exists($_POST[$s_option], ${"options_$s_option"})) {
				$_POST[$s_option] = $s_default;
			}
		}

		// Validate Select field (array) options
		$select_options = array(	'ccexclude'	=> '',
						'etblock'	=> '',
						'etmatch'	=> ''
					);

		foreach ($select_options as $s_option => $s_default) {

			// Array to validate against
			if ($s_option == 'ccexclude') {
				$query = $options_ccexclude;
			} else {
				$query = $options_et_categories;
			}

			if (is_array($_POST[$s_option])) {
				foreach ($_POST[$s_option] as $post_option) {
					if (!array_key_exists($post_option, $query)) {
						$_POST[$s_option] = $s_default;
						break;
					}
				}
			}
			elseif (!array_key_exists($_POST[$s_option], $query)) {
				$_POST[$s_option] = $s_default;
			}
		}

		if (!$input_errors) {

			$pfb['repconfig']['enable_rep']		= pfb_filter($_POST['enable_rep'], PFB_FILTER_ON_OFF, 'Rep');
			$pfb['repconfig']['p24_max_var']	= $_POST['p24_max_var']				?: '';
			$pfb['repconfig']['enable_pdup']	= pfb_filter($_POST['enable_pdup'], PFB_FILTER_ON_OFF, 'Rep');
			$pfb['repconfig']['p24_pmax_var']	= $_POST['p24_pmax_var']			?: '';
			$pfb['repconfig']['enable_dedup']	= pfb_filter($_POST['enable_dedup'], PFB_FILTER_ON_OFF, 'Rep');
			$pfb['repconfig']['p24_dmax_var']	= $_POST['p24_dmax_var']			?: '';
			$pfb['repconfig']['ccwhite']		= $_POST['ccwhite']				?: '';
			$pfb['repconfig']['ccblack']		= $_POST['ccblack']				?: '';
			$pfb['repconfig']['ccexclude']		= implode(',', (array)$_POST['ccexclude'])	?: '';
			$pfb['repconfig']['et_header']		= $_POST['et_header']				?: '';
			$pfb['repconfig']['etblock']		= implode(',', (array)$_POST['etblock'])	?: '';
			$pfb['repconfig']['etmatch']		= implode(',', (array)$_POST['etmatch'])	?: '';

			// Set flag to update ET IQRisk on next Cron|Force update|Force reload
			$pfb['repconfig']['et_update']	= 'enabled';

			PfbConfig::writeSection('installedpackages/pfblockerngreputation/config/0', $pfb['repconfig']);
			write_config('[pfBlockerNG] save Reputation settings');
			pfb_mark_pending_changes();	// applies on the next Update, not on save
			header('Location: /pfblockerng/pfblockerng_reputation.php');
			exit;
		}
		else {
			print_input_errors($input_errors);
			$pconfig = $_POST;	// Restore failed user-entered data
		}
	}
}

$pgtitle = array(gettext('Firewall'), gettext('pfBlockerNG'), gettext('IP'), gettext('Reputation'));
$pglinks = array('', '/pfblockerng/pfblockerng_general.php', '/pfblockerng/pfblockerng_ip.php', '@self');
$shortcut_section = 'pfblockerng';
include_once('head.inc');

// Define default Alerts Tab href link (Top row)
$get_req = pfb_alerts_default_page();

$tab_array	= array();
$tab_array[]	= array(gettext('General'),	FALSE,	'/pfblockerng/pfblockerng_general.php');
$tab_array[]	= array(gettext('IP'),		TRUE,	'/pfblockerng/pfblockerng_ip.php');
$tab_array[]	= array(gettext('DNSBL'),	FALSE,	'/pfblockerng/pfblockerng_dnsbl.php');
$tab_array[]	= array(gettext('Update'),	FALSE,	'/pfblockerng/pfblockerng_update.php');
$tab_array[]	= array(gettext('Reports'),	FALSE,	"/pfblockerng/pfblockerng_alerts.php{$get_req}");
$tab_array[]	= array(gettext('Feeds'),	FALSE,	'/pfblockerng/pfblockerng_feeds.php');
$tab_array[]	= array(gettext('Logs'),	FALSE,	'/pfblockerng/pfblockerng_log.php');
$tab_array[]	= array(gettext('Sync'),	FALSE,	'/pfblockerng/pfblockerng_sync.php');
pfb_software_add_tab($tab_array);
display_top_tabs($tab_array, TRUE);

$tab_array	= array();
$tab_array[]	= array(gettext('IPv4'),	FALSE,	'/pfblockerng/pfblockerng_category.php?type=ipv4');
$tab_array[]	= array(gettext('IPv6'),	FALSE,	'/pfblockerng/pfblockerng_category.php?type=ipv6');
$tab_array[]	= array(gettext('GeoIP'),       FALSE,	'/pfblockerng/pfblockerng_category.php?type=geoip');
$tab_array[]	= array(gettext('Reputation'),  TRUE,	'/pfblockerng/pfblockerng_reputation.php');
display_top_tabs($tab_array, TRUE);
pfb_print_pending_changes_box();

$form = new Form('Save');

$section = new Form_Section('IPv4 Reputation');
$section->addInput(new Form_StaticText(
	'Links',
	'<small>'
	. '<a href="/firewall_aliases.php" target="_blank" rel="noopener noreferrer">Firewall Alias</a>&emsp;'
	. '<a href="/firewall_rules.php" target="_blank" rel="noopener noreferrer">Firewall Rules</a>&emsp;'
	. '<a href="/status_logs_filter.php" target="_blank" rel="noopener noreferrer">Firewall Logs</a></small>'
));

$section->addInput(new Form_StaticText(
	'Why Reputation Matters',
	'By enabling <strong>Reputation</strong>, each Blocklist will be analyzed for repeat offenders in each IP range.'
	. '<div class="infoblock">'
	. '<ul>Example: &emsp;x.x.x.1, x.x.x.2, x.x.x.3, x.x.x.4, x.x.x.5<br />'
	. 'No. of <strong> repeat offending IPs </strong> [ &nbsp;<strong>5</strong>&nbsp; ], in a Blocklist within the same IP range.</ul>'
	. 'With <strong>Reputation</strong> enabled, these 5 IPs will be removed and a single<strong>x.x.x.0/24</strong> Block is used.<br />'
	. 'This will completely Block/Reject this particular range from your Firewall.<br /><br />'
	. 'Selecting Blocklists from various Threat Sources will help to highlight repeat offending IP ranges,<br />'
	. 'Its important to select a broad range of Blocklists that cover different types of malicious activity.<br /><br />'
	. 'You *may* experience some False Positives. Add any False Positive IPs manually to the<br />'
	. '<strong>IPv4 Suppression custom list</strong> or use the "+" suppression Icon in the Alerts TAB<br /><br />'
	. 'To help mitigate False Positives \'Countries\' can be <strong>Excluded</strong> from this process. (Refer to Country Code settings)'
	. '<br /><br />Enabling <strong>De-Duplication</strong> is highly recommended before utilizing <strong>Reputation</strong> processes.'
	. '</div>'
));
$form->add($section);

$section = new Form_Section('Individual List Reputation');
$section->addInput(new Form_Checkbox(
	'enable_rep',
	'Max',
	'Enable',
	pfb_cfg_toggle_read($pconfig['enable_rep']) === PfbToggle::On,
	'on'
))->setHelp('Enables search for repeat offenders in a /24 range on <strong>Each individual Blocklist</strong>');

$section->addInput(new Form_Select(
	'p24_max_var',
	'Max Setting',
	$pconfig['p24_max_var'],
	$options_p24_max_var
))->setHelp('Default: <strong>5</strong><br />Maximum number of repeat offenders allowed in a single IP range');
$form->add($section);

$section = new Form_Section('Collective List Reputation');
$section->addInput(new Form_StaticText(
	NULL,
	'Once all Blocklists are downloaded, these two additional processes <strong>[ pMax and dMax ]</strong><br />'
	. 'Can be used to further analyze for repeat offenders.'
	. '<div class="infoblock">'
	. '<ul>Analyzing all Blocklists as a whole:</ul>'
	. '<ul><strong>[ pMax ]</strong> will analyze for repeat offenders in each IP range but will not use the Country Exclusion.<br />'
	. 'Default is 50 IPs in any range. Having 50 repeat offenders IPs in any range will Block the entire range.<br /><br /></ul>'
	. '<ul><strong>[ dMax ]</strong> will analyze for repeat offenders in each IP range. Country Exclusions will be applied.<br />'
	. 'Default is 5 IPs in any range.</ul>'
	. 'Note: <strong>MAX</strong> performs on individual Blocklists, while <strong>pMAX / dMAX</strong>'
	. 'perform on all Lists together.'
	. '</div>'
));
EOF;
	$tab_only_line = "\t";
	$php_rep .= <<<EOF

{$tab_only_line}

EOF;
	$php_rep .= <<<'EOF'
$section->addInput(new Form_Checkbox(
	'enable_pdup',
	'pMAX',
	'Enable',
	pfb_cfg_toggle_read($pconfig['enable_pdup']) === PfbToggle::On,
	'on'
))->setHelp('Enables search for repeat offenders in All BlockLists, <strong>without</strong> Country Code Exclusion');

$section->addInput(new Form_Select(
	'p24_pmax_var',
	'pMax Setting',
	$pconfig['p24_pmax_var'],
	$options_p24_pmax_var
))->setHelp('Default: <strong>50</strong><br />Maximum number of repeat offenders');

$section->addInput(new Form_Checkbox(
	'enable_dedup',
	'dMAX',
	'Enable',
	pfb_cfg_toggle_read($pconfig['enable_dedup']) === PfbToggle::On,
	'on'
))->setHelp('Enables search for repeat offenders in All blocklists <strong>using</strong> Country Code Exclusion');

$section->addInput(new Form_Select(
	'p24_dmax_var',
	'dMax Setting',
	$pconfig['p24_dmax_var'],
	$options_p24_dmax_var
))->setHelp('Default: <strong>5</strong><br />Maximum number of repeat offenders');
$form->add($section);

$section = new Form_Section('Country Code Settings (max/dMax)');
$section->addInput(new Form_StaticText(
	NULL,
	'When performing queries for repeat offenders, you can choose to <strong>ignore</strong> repeat offenders in select'
	. 'Countries. The original blocklisted IPs remain intact. All other repeat offending Country ranges will be processed.'
	. '<div class="infoblock">'
	. 'Define repeat offending ranges [ <strong>Action</strong> ] Available settings are:<br />'
	. '<ul><strong>Ignore</strong>: Repeat offenders that are in the <strong>ccwhite</strong> category will be <strong>Ignored</strong> (Default)</ul>'
	. '<ul><strong>Block:</strong> Repeat offenders are set to Block the entire repeat offending range(s)</ul>'
	. '<ul><strong>Match:</strong> Repeat offenders are added to a <strong>Match</strong> List which can be used in a Floating Match rule<br />'
	. 'Selecting <strong>Match</strong> will consume more processing time, so only select this option if you enable rules for it.</ul>'
	. '\'<strong>ccwhite</strong>\' are Countries that are selected to be excluded from the repeat offenders search.<br />'
	. '\'<strong>ccblack</strong>\' are all other Countries that are not selected.<br /><br />'
	. 'To use <strong>Match</strong> Lists, Create a new \'Alias\''
	. 'and select one of the <strong>Action Match</strong> Formats and<br /> enter the <strong>Localfile</strong> as:'
	. '<ul>/var/db/pfblockerng/match/generated/pfB_Match_Exempt_v4.txt</ul><br />'
	. '<strong>These Country Code options are only available when the MaxMind key has been entered and MaxMind database has been downloaded and updated</strong>'
	. '</div>'
));

$section->addInput(new Form_Select(
	'ccwhite',
	'ccwhite Action:',
	$pconfig['ccwhite'],
	$options_ccwhite
))->setHelp('Default: <strong>Ignore</strong><br />Select the \'Action\' format for ccwhite');

$section->addInput(new Form_Select(
	'ccblack',
	'ccblack Action:',
	$pconfig['ccblack'],
	$options_ccblack
))->setHelp('Default: <strong>Block</strong><br />Select the \'Action\' format for ccblack');

EOF;
	if (!empty($et_options)) {
		$php_rep .= <<<EOF

\$section->addInput(new Form_Select(
	'ccexclude',
	'IPv4 Country Exclusion',
	\$pconfig['ccexclude'],
	array($et_options),
	TRUE
))->setHelp('Select Countries you want to <strong>Exclude</strong> from the Reputation Process.<br />
		<strong>Use CTRL&nbsp;+&nbsp;CLICK to select/unselect countries</strong>')
  ->setAttribute('size', '20')
  ->setAttribute('style', 'overflow: auto;');

EOF;
	}

	$php_rep .= <<<'EOF'
$form->add($section);

$section = new Form_Section('Proofpoint ET IQRISK IPv4 Reputation', 'Proofpointsettings', COLLAPSIBLE|SEC_CLOSED);
$section->addInput(new Form_StaticText(
	'Professional Subscription Blocklist',
	'<strong>Proofpoint ET IQRisk</strong> is a subscription based professional Reputation list.<br /><br />'
	. 'The URL must include the name <strong>iprepdata.txt</strong><br />'
	. 'ET IQRisk Blocklist URL must be entered in the IPv4 Lists Tab using the following example:'
	. '<ul>https://rules.emergingthreatspro.com/XXXXXXXXXXXXXXXX/reputation/iprepdata.txt.gz</ul>'
	. 'Select the <strong>Auto</strong> format. The URL should use the .gz File type.<br />'
	. 'Enter your "ETPRO" code in URL. Further information can be found @ '
	. '<a target="_blank" rel="noopener noreferrer" href="https://www.proofpoint.com/us/solutions/products/threat-intelligence">Proofpoint IQRisk</a><br /><br />'
	. 'To use <strong>Match</strong> Lists, Create a new Alias and select one of the <strong>'
	. 'Action Match</strong> Formats and <br />'
	. 'enter the <strong>Localfile</strong> as: <ul>/var/db/pfblockerng/match/generated/pfB_Match_ET_v4.txt</ul>'
	. 'ET IQRisk Individual Match Lists can be found in the following folder:<br />'
	. '<ul>/var/db/pfblockerng/ET</ul>'
));

$section->addInput(new Form_Input(
	'et_header',
	'Header/Label Name',
	'text',
	$pconfig['et_header'],
	['placeholder' => 'Enter the ET IQRisk Header Name']
))->setHelp('Enter the \'Header Name\' referenced in the IPv4 List TAB for ET IQRisk IPRep.<br />This will be used to improve the Alerts TAB reporting for ET IPRep.');

$section->addInput(new Form_Select(
	'etblock',
	'Block Categories',
	$pconfig['etblock'],
	$options_et_categories,
	TRUE
))->setHelp('Select Lists you want to BLOCK.<br /><strong>Use CTRL&nbsp;+&nbsp;CLICK to select/unselect Categories</strong>')
  ->setAttribute('size', '35')
  ->setAttribute('style', 'overflow: auto;');

$section->addInput(new Form_Select(
	'etmatch',
	'Match Categories',
	$pconfig['etmatch'],
	$options_et_categories,
	TRUE
))->setHelp('Select Lists you want to MATCH.<br /><strong>Use CTRL&nbsp;+&nbsp;CLICK to select/unselect Categories</strong>')
  ->setAttribute('size', '35')
  ->setAttribute('style', 'overflow: auto;');

$form->add($section);
print($form);
print_callout('<p><strong>Setting changes are applied via CRON or \'Force Update|Reload\' only!</strong></p>');
?>
<?php include('foot.inc');?>

EOF;

	if (!empty($et_options)) {
		$log = " pfBlockerNG Reputation Tab\n";
		pfb_logger("{$log}", 4);
	}

	// Save pfBlockerng_reputation.php file
	$output_ok = @file_put_contents("{$output_root}/pfblockerng_reputation.php", $php_rep, LOCK_EX) !== FALSE;
	unset($php_rep);
	return $output_ok;
}
?>
