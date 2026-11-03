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

/** Refresh legacy navigation without regenerating country data or populated page options. */
function pfb_geoip_refresh_navigation(string $output_root = '/usr/local/www/pfblockerng'): bool {
	$dnsbl_continent = "\n\$tab_array[]\t= array(gettext('DNSBL'),\t\tFALSE,\t'/pfblockerng/pfblockerng_dnsbl.php');\n";
	$dnsbl_reputation = "\n\$tab_array[]\t= array(gettext('DNSBL'),\tFALSE,\t'/pfblockerng/pfblockerng_dnsbl.php');\n";
	$pfbdns = "\$tab_array[]\t= array(gettext('pfB-DNS'),\tFALSE,\t'/pfblockerng/pfblockerng_dns.php');\n";
	$update_continent = "\$tab_array[]\t= array(gettext('Update'),\t\tFALSE,\t'/pfblockerng/pfblockerng_update.php');\n";
	$update_reputation = "\$tab_array[]\t= array(gettext('Update'),\tFALSE,\t'/pfblockerng/pfblockerng_update.php');\n";
	$dns_continent = "\n\$tab_array[]\t= array(gettext('DNS'),\t\t\tFALSE,\t'/pfblockerng/pfblockerng_dns_general.php');\n";
	$dns_reputation = "\n\$tab_array[]\t= array(gettext('DNS'),\t\tFALSE,\t'/pfblockerng/pfblockerng_dns_general.php');\n";
	// The unchanged Update row bounds the supported navigation layouts.
	$legacy = [
		$dnsbl_continent . $pfbdns . $update_continent,
		$dnsbl_reputation . $pfbdns . $update_reputation,
		$dnsbl_continent . $update_continent,
		$dnsbl_reputation . $update_reputation,
		str_replace('FALSE', 'false', $dnsbl_continent . $update_continent),
		str_replace('FALSE', 'false', $dnsbl_reputation . $update_reputation),
		str_replace('pfblockerng_dns_general.php', 'pfblockerng_dns.php', $dns_continent) . $update_continent,
		str_replace('pfblockerng_dns_general.php', 'pfblockerng_dns.php', $dns_reputation) . $update_reputation,
	];
	$current = [
		$dns_continent . $update_continent,
		$dns_reputation . $update_reputation,
		$dns_continent . $update_continent,
		$dns_reputation . $update_reputation,
		$dns_continent . str_replace('FALSE', 'false', $update_continent),
		$dns_reputation . str_replace('FALSE', 'false', $update_reputation),
		$dns_continent . $update_continent,
		$dns_reputation . $update_reputation,
	];
	$pages = [
		'Top_Spammers', 'Africa', 'Antarctica', 'Asia', 'Europe', 'North_America',
		'Oceania', 'South_America', 'Proxy_and_Satellite', 'reputation',
	];
	$success = TRUE;
	foreach ($pages as $page) {
		$path = "{$output_root}/pfblockerng_{$page}.php";
		if (is_link($path)) {
			$success = FALSE;
			continue;
		}
		if (!file_exists($path)) {
			continue;
		}
		if (!is_file($path)) {
			$success = FALSE;
			continue;
		}
		$content = @file_get_contents($path);
		$stat = @stat($path);
		if ($content === FALSE || $stat === FALSE) {
			$success = FALSE;
			continue;
		}
		$updated = str_replace($legacy, $current, $content, $matches);
		if ($matches === 0) {
			continue;
		}

		// Stage beside the page: tempnam() may fall back to another filesystem.
		$tmp = "{$output_root}/.pfbnav_" . bin2hex(random_bytes(8));
		$handle = @fopen($tmp, 'x');
		if ($handle === FALSE) {
			$success = FALSE;
			continue;
		}
		$ok = @chmod($tmp, 0600)
			&& @fwrite($handle, $updated) === strlen($updated)
			&& @fflush($handle) && @fsync($handle);
		$ok = @fclose($handle) && $ok;
		if ($ok) {
			$ok = (fileowner($tmp) === $stat['uid'] || @chown($tmp, $stat['uid']))
				&& (filegroup($tmp) === $stat['gid'] || @chgrp($tmp, $stat['gid']))
				&& @chmod($tmp, $stat['mode'] & 07777)
				&& @rename($tmp, $path);
		}
		if (!$ok) {
			@unlink($tmp);
			$success = FALSE;
		}
	}
	return $success;
}

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

		// #3066: this body must start at the "/*" -- prepending ANY line to it
		// (observed with tree-sitter-php 0.24.1, the grammar code-graph extraction
		// parses with) makes the grammar emit ERROR nodes here and drop the rest of
		// the file, so the "<?php" is concatenated on outside instead. Upstream
		// cause not isolated; tests/test_issue3066_php_grammar_parse.py is the guard.
$php_data = "<?php\n" . <<<EOF
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
$tab_array[]	= array(gettext('DNS'),			FALSE,	'/pfblockerng/pfblockerng_dns_general.php');
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
	. 'Guidelines: '
	. pfb_geoip_doc_link()

	. '<hr style="height: 1px; border: none; background-color: #d6d6d6;"/>'

	. '<div id="Txtfld" tabindex="1" class="bg-info">'
	. 'pfSense by default implicitly blocks all unsolicited inbound traffic to the WAN interface.<br />'
	. 'Therefore adding GeoIP based firewall rules to the WAN will <strong>not</strong> provide any benefit, unless there are open WAN ports.<br /><br />'
	. 'Do not block every country. Permit the countries you need, and also filter outbound LAN traffic, not only open WAN ports.<br /><br />'

	. 'GeoIP country codes can also be configured under <strong>Source Definitions</strong> on <strong>IPv4</strong> or <strong>IPv6</strong>, with <strong>Format</strong> set to <strong>GeoIP</strong>.'
	. '</div>'

	. '<hr style="height: 1px; border: none; background-color: #d6d6d6;"/>'

	. 'Use <code>Ctrl+click</code> to select or clear countries.'
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
		<p>For automatic rules, choose the appropriate <strong>Firewall 'Auto' Rule Order</strong> on <strong>IP</strong>.</p>
		Guidelines:
		<div class=\"infoblock alert-info clearfix\">
			<dl>
				<dt><strong>Disabled</strong></dt><dd>This list is not used.</dd>
				<dt>Automatic rules</dt><dd><strong>Deny Inbound</strong>, <strong>Deny Outbound</strong> and <strong>Deny Both</strong> create block rules;
					<strong>Permit Inbound</strong>, <strong>Permit Outbound</strong> and <strong>Permit Both</strong> create pass rules;
					<strong>Match Inbound</strong>, <strong>Match Outbound</strong> and <strong>Match Both</strong> match and log traffic without blocking it.
					Inbound rules match the list as the source address; outbound rules match it as the destination address.
					Both-direction actions create both rules.</dd>
				<dt>Aliases only</dt><dd><strong>Alias Deny</strong>, <strong>Alias Permit</strong>, <strong>Alias Match</strong> and <strong>Alias Native</strong>
					create an alias for use in your own rules. No automatic rule is added.</dd>
			</dl>
			<p><strong>Alias Deny</strong> can use <strong>De-Duplication</strong> and Reputation processing if configured.
				<strong>Alias Permit</strong> and <strong>Alias Match</strong> use the same folders as their automatic-rule counterparts.
				<strong>Alias Native</strong> keeps the original list format without modification.</p>
			<p>Deny rules do not change pass rules on other interfaces. A session started in the other direction can still pass.
				Permit rules provide exceptions to Deny rules on the selected interfaces.</p>
			<p>Start your own rule descriptions with <code>pfb_</code> so the widget counts them.
				Do not use <code>pfB_</code>; pfBlockerNG removes rules with that prefix.</p>
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
))->setHelp("Default: <strong>Enabled</strong><br />
	Log events under <strong>Status &gt; System Logs &gt; Firewall</strong>.<br />
	This can be overridden by <strong>Force Global IP Logging</strong> on <strong>IP</strong>.");

// Print Advanced Firewall Rule Settings (Inbound and Outbound) section
foreach (array( 'In' => 'Source', 'Out' => 'Destination') as $adv_mode => $adv_type) {

	$advmode = strtolower($adv_mode);

	$section = new Form_Section("Advanced {$adv_mode}bound Firewall Rule Settings", "adv{$advmode}boundsettings", COLLAPSIBLE|SEC_CLOSED);
	$section->addInput(new Form_StaticText(
		NULL,
		"<p>In general, Auto-Rules are created as follows:</p>
			<dl class=\"dl-horizontal\">
				<dt>{$adv_mode}bound</dt><dd>'any' port, 'any' protocol, 'any' destination and 'any' gateway</dd>
			</dl>
			<p>Use <strong>Advanced {$adv_mode}bound Firewall Rule Settings</strong> to customize these automatic rules.</p>"));

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
	))->setHelp("<a target=\"_blank\" rel=\"noopener noreferrer\" href=\"/firewall_aliases.php?tab=port\">Add or edit aliases</a><br />
			Do not enter port numbers directly.<br />Do not use <code>pfB_</code> in the port alias name."
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
	))->sethelp('<a target="_blank" rel="noopener noreferrer" href="/firewall_aliases.php?tab=ip">Add or edit aliases</a><br />'
		. 'Do not enter addresses directly.<br />Do not use <code>pfB_</code> in the address-type (Host/Network/URL/URL Table) alias name.<br />'
		. "Select <strong>Invert</strong> to match addresses outside the selected {$custom_location} alias."
	)->setWidth(8);
	$section->add($group);

	$group = new Form_Group('Custom Protocol');
	$group->add(new Form_Select(
		'autoproto_' . $advmode,
		NULL,
		$pconfig['autoproto_' . $advmode],
		$options_autoproto_in
	))->setHelp("Default: any<br />Choose <strong>Custom Protocol</strong> for {$adv_mode}bound automatic rules.<br />
		<span class=\"text-danger\"><strong>Warning:</strong></span> Leaving the protocol as any bypasses the other <strong>Advanced {$adv_mode}bound Firewall Rule Settings</strong>.");
	$section->add($group);

	$group = new Form_Group('Custom Gateway');
	$group->add(new Form_Select(
		'agateway_' . $advmode,
		NULL,
		$pconfig['agateway_' . $advmode],
		$options_agateway_in
	))->setHelp("Choose <strong>Custom Gateway</strong>, or keep the default.");

	$section->add($group);
	$form->add($section);
}

print($form);
print_callout('<p>Saved changes are applied automatically at a schedule check, normally within 15 minutes while pfBlockerNG is enabled. If an <strong>Automatic Apply Window</strong> is set on <strong>General</strong>, changes wait for that window. To apply them now, open <strong>Update</strong> and use <strong>Run Now</strong>.</p>');
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

			// Set flag to update ET IQRisk on the next update pass
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
$tab_array[]	= array(gettext('DNS'),		FALSE,	'/pfblockerng/pfblockerng_dns_general.php');
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
	'How Reputation works',
	'Reputation checks blocklists for repeat offenders in each IP range.'
	. '<div class="infoblock">'
	. '<p>For example, a list containing <code>x.x.x.1</code> through <code>x.x.x.5</code> has five listed addresses in the same range. '
	. 'Reputation can replace those addresses with a single <code>x.x.x.0/24</code> block.</p>'
	. '<p><span class="text-danger"><strong>Warning:</strong></span> This blocks the entire range, including addresses not originally listed, and can cause false positives.</p>'
	. '<p>Use a broad range of blocklists covering different types of malicious activity. '
	. 'It\'s important to review false positives: add those IPs to <strong>IPv4 Suppression</strong>, or use the <strong>+</strong> icon on <strong>Reports</strong> &gt; <strong>Alerts</strong>.</p>'
	. '<p>To exclude countries, use <strong>Country Code Settings (max/dMax)</strong>. '
	. 'Enable <strong>De-Duplication</strong> on <strong>IP</strong> before using Reputation processing.</p>'
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
	'<p>Across all blocklists:</p>'
	. '<div class="infoblock">'
	. '<ul>'
	. '<li><strong>pMAX</strong>: checks ranges without country exclusions. Default threshold: 50 addresses (<strong>pMax Setting</strong>).</li>'
	. '<li><strong>dMAX</strong>: checks ranges with country exclusions. Default threshold: 5 addresses (<strong>dMax Setting</strong>).</li>'
	. '</ul>'
	. '<p><strong>Max</strong> checks individual blocklists; <strong>pMAX</strong> and <strong>dMAX</strong> check them together.</p>'
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
	'<p>Choose how to handle repeat offenders in selected countries. '
	. 'Excluded countries keep their original listed addresses when <strong>Ignore</strong> is selected; all other countries are processed.</p>'
	. '<div class="infoblock">'
	. '<ul>'
	. '<li><strong>Ignore</strong>: keep the excluded country\'s original listed addresses.</li>'
	. '<li><strong>Block</strong>: block the matching range.</li>'
	. '<li><strong>Match</strong>: add the range to a Match list for use in your rules.</li>'
	. '</ul>'
	. '<p><strong>ccwhite Action:</strong> applies to countries selected under <strong>IPv4 Country Exclusion</strong> and defaults to <strong>Ignore</strong>. '
	. '<strong>ccblack Action:</strong> applies to all other countries and defaults to <strong>Block</strong>.</p>'
	. '<p>Selecting <strong>Match</strong> takes additional processing time; use it only if you create rules for the resulting list.</p>'
	. '<p>Create an alias and set <strong>List Action</strong> to <strong>Alias Match</strong>. Use this file as its <strong>Source</strong>:</p>'
	. '<p><code style="overflow-wrap:anywhere">/var/db/pfblockerng/match/generated/pfB_Match_Exempt_v4.txt</code></p>'
	. '<p><strong>Note:</strong> Country Code options require a MaxMind key and a downloaded, updated MaxMind database.</p>'
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
))->setHelp('Select countries to exclude from Reputation processing.<br />
		Use <code>Ctrl+click</code> to select or clear countries.')
  ->setAttribute('size', '20')
  ->setAttribute('style', 'overflow: auto;');

EOF;
	}

	$php_rep .= <<<'EOF'
$form->add($section);

$section = new Form_Section('Proofpoint ET IQRISK IPv4 Reputation', 'Proofpointsettings', COLLAPSIBLE|SEC_CLOSED);
$section->addInput(new Form_StaticText(
	'Professional Subscription Blocklist',
	'<p>Proofpoint ET IQRisk is a subscription-based reputation list.</p>'
	. '<p>The URL must include <code>iprepdata.txt</code>. Enter it as a <strong>Source</strong> on <strong>IPv4</strong>, for example:</p>'
	. '<p><code style="overflow-wrap:anywhere">https://rules.emergingthreatspro.com/XXXXXXXXXXXXXXXX/reputation/iprepdata.txt.gz</code></p>'
	. '<p>Set <strong>Format</strong> to <strong>Auto</strong> and use a <code>.gz</code> file. '
	. 'Replace <code>XXXXXXXXXXXXXXXX</code> with your ETPRO code. See '
	. '<a target="_blank" rel="noopener noreferrer" href="https://www.proofpoint.com/us/solutions/products/threat-intelligence">Proofpoint IQRisk</a> for details.</p>'
	. '<p>To use the Match list, create an alias with <strong>List Action</strong> set to <strong>Alias Match</strong> and this file as its <strong>Source</strong>:</p>'
	. '<p><code style="overflow-wrap:anywhere">/var/db/pfblockerng/match/generated/pfB_Match_ET_v4.txt</code></p>'
	. '<p>Individual ET IQRisk Match lists are stored in:</p>'
	. '<p><code style="overflow-wrap:anywhere">/var/db/pfblockerng/ET</code></p>'
));

$section->addInput(new Form_Input(
	'et_header',
	'Header/Label Name',
	'text',
	$pconfig['et_header'],
	['placeholder' => 'Enter the ET IQRisk Header Name']
))->setHelp('Enter the <strong>Header/Label</strong> used for ET IQRisk under <strong>Source Definitions</strong> on <strong>IPv4</strong>. This improves ET IQRisk reporting on <strong>Reports</strong> &gt; <strong>Alerts</strong>.');

$section->addInput(new Form_Select(
	'etblock',
	'Block Categories',
	$pconfig['etblock'],
	$options_et_categories,
	TRUE
))->setHelp('Select the lists to block. Use <code>Ctrl+click</code> to select or clear categories.')
  ->setAttribute('size', '35')
  ->setAttribute('style', 'overflow: auto;');

$section->addInput(new Form_Select(
	'etmatch',
	'Match Categories',
	$pconfig['etmatch'],
	$options_et_categories,
	TRUE
))->setHelp('Select the lists to match. Use <code>Ctrl+click</code> to select or clear categories.')
  ->setAttribute('size', '35')
  ->setAttribute('style', 'overflow: auto;');

$form->add($section);
print($form);
print_callout('<p>Saved changes are applied automatically at a schedule check, normally within 15 minutes while pfBlockerNG is enabled. If an <strong>Automatic Apply Window</strong> is set on <strong>General</strong>, changes wait for that window. To apply them now, open <strong>Update</strong> and use <strong>Run Now</strong>.</p>');
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
