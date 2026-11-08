<?php
/*
 * Shared Alerts Stats presentation.
 *
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

function pfb_stats_definitions(string $alert_view, $pfbchartcnt): array {
if ($alert_view == 'dnsbl_stat') {
$stats = array( 'dnsblchart'	=> array("DNSBL Event Timeline&emsp;<small>(Last <span id=\"range\">{$pfbchartcnt}</span> hours)</small>",'','', FALSE, ''),
		'dnsbldomain'	=> array('Top Blocked Domain',			'Found', 'Blocked Domain(s)',	TRUE, 'domain'),
		'dnsblevald'	=> array('Top Blocked Evaluated Domain (TLD)',	'Found', 'Blocked Domain(s)',	TRUE, 'domain'),
		'dnsblgptotal'	=> array('Top Group Count',			'Found', 'DNSBL Group(s)',	FALSE, ''),
		'dnsblgpblock'	=> array('Top Blocked Group',			'Found', 'DNSBL Group(s)',	FALSE, ''),
		'dnsblfeed'	=> array('Top Feed',				'Found', 'Feed(s)',		FALSE, ''),
		'dnsblip'	=> array('Top Source IP',			'Found', 'Source IP(s)',	FALSE, ''),
		'dnsblagent'	=> array('Blocking Type', 'Found',
					'Type(s)',		FALSE, ''),
		'dnsbltld'	=> array('Top TLD',				'Found', 'TLD(s)',		FALSE, ''),
		'dnsblwebtype'	=> array('Top Blocked Webpage Types',		'Found', 'Blocked Webpage Type(s)',	FALSE, ''),
		'dnsblmode'	=> array('Top DNSBL Modes',			'Found', 'Blocked DNSBL Mode(s)',	FALSE, ''),
		'dnsbldatehr'	=> array('Top Date/Hr',				'Found', 'Date/Hr segment(s)',		FALSE, ''),
		'dnsbldatehrmin'=> array('Top Date/Hr/Min',			'Found', 'Date/Hr/Min segment(s)',	FALSE, ''),
		'dnsbldate'	=> array('Top Date',				'Found', 'day(s) of logs',		FALSE, '') );
}
elseif ($alert_view == 'dnsbl_reply_stat') {
$stats = array( 'replychart'	=> array("Reply Event Timeline&emsp;<small>(Last <span id=\"range\">{$pfbchartcnt}</span> hours)</small>",'','', FALSE, ''),
			'replydomain'	=> array('Top Reply Domain',			'Found', 'Reply Domain(s)',	FALSE, 'domain'),
			'replytld'	=> array('Top Reply TLD',			'Found', 'Reply TLD(s)',	FALSE, ''),
			'replytld2'	=> array('Top Reply TLD 2nd level',		'Found', 'Reply TLD(s)',	FALSE, ''),
			'replytld3'	=> array('Top Reply TLD 3rd level',		'Found', 'Reply TLD(s)',	FALSE, ''),
			'replysrcip'	=> array('Top Reply SRC IP',			'Found', 'SRC IP(s)',		FALSE, ''),
			'replydstip'	=> array('Top Reply DST IP',			'Found', 'IP(s)',		FALSE, 'host'),
			'replysrcipd'	=> array('Top Reply SRC IP/Domain',		'Found', 'Domain/IP(s)',	FALSE, 'domain'),
			'replytype'	=> array('Top Reply Type',			'Found', 'Reply Type(s)',	FALSE, ''),
			'replyorec'	=> array('Top Reply Orig Record',		'Found', 'Reply Record(s)',	FALSE, ''),
			'replyrec'	=> array('Top Reply Record',			'Found', 'Reply Record(s)',	FALSE, ''),
			'replyttl'	=> array('Top Reply TTL',			'Found', 'Reply TTL(s)',	FALSE, ''),
			'replygeoip'	=> array('Top Reply GeoIP',			'Found', 'Reply GeoIP(s)',	FALSE, ''),
			'replydate'	=> array('Top Date',				'Found', 'day(s) of logs',	FALSE, ''));
}
else {
	$stats = array(	'ipchart'	=> array("IP Event Timeline&emsp;<small>(Last <span id=\"range\">{$pfbchartcnt}</span> hours)</small>",'','', FALSE, ''),
			'ipsrcipin'	=> array("Top SRC IP Inbound (by GeoIP)",	'Found', 'SRC IP(s)',		TRUE, 'host'),
			'ipsrcipout'	=> array("Top SRC IP Outbound (by GeoIP)",	'Found', 'SRC IP(s)',		TRUE, 'host'),
			'ipdstipin'	=> array("Top DST IP Inbound (by GeoIP)",	'Found', 'DST IP(s)',		TRUE, 'host'),
			'ipdstipout'	=> array("Top DST IP Outbound (by GeoIP)",	'Found', 'DST IP(s)',		TRUE, 'host'),
			'ipsrcport'	=> array("Top SRC Port (1-1024 only)",		'Found', 'SRC Port(s)',		FALSE, ''),
			'ipdstport'	=> array("Top DST Port",			'Found', 'DST Port(s)',		FALSE, ''),
			'ipgeoip'	=> array("Top GeoIP",				'Found', 'GeoIP(s)',		FALSE, ''),
			'ipasn'		=> array("Top ASN",				'Found', 'ASN(s)',		FALSE, ''),
			'ipaliasname'	=> array("Top Aliasname",			'Found', 'Aliasname(s)',	FALSE, ''),
			'ipfeed'	=> array("Top Feed",				'Found', 'Feed{s)',		FALSE, ''),
			'ipinterface'	=> array("Top Interface",			'Found', 'Interface(s)',	FALSE, ''),
			'ipprotocol'	=> array("Top Protocol",			'Found', 'Protocol(s)',		FALSE, ''),
			'ipdirection'	=> array("Top Direction",			'Found', 'Direction(s)',	FALSE, ''),
			'ipdate'	=> array("Top Date",				'Found', 'day(s) of logs',	FALSE, ''));
}
	return $stats;
}

function pfb_stats_pie(array $summary, int $topcount, string $stat_type): ?array {
	if (!$summary) {
		return NULL;
	}
	$colors = ['#2484c1', '#65a620', '#7b6888', '#a05d56', '#961a1a', '#d8d23a', '#e98125', '#d0743c', '#635222', '#6ada6a'];
	$summary = array_slice($summary, 0, 10, TRUE);
	uasort($summary, fn($a, $b) => $b <=> $a);
	$keys = array_keys($summary);
	$content = [];
	for ($i = 0; $i < 9; $i++) {
		if ($keys[$i] ?? NULL) {
			$content[] = ['label' => (string) $keys[$i], 'value' => $summary[$keys[$i]] == 0 ? 0.1 : (float) $summary[$keys[$i]], 'color' => $colors[$i]];
		}
	}
	$balance = $topcount - count($content);
	if ($balance > 0) {
		$content[] = ['label' => 'Other', 'value' => $balance, 'color' => $colors[9]];
	}
	return ['id' => 'pieChart_' . $stat_type, 'content' => $content];
}

function pfb_stats_panel(string $stat_type, array $stype, array $summary, $pfbmaxtable, array $local_hosts): array {
	$topcount = count($summary);
	$height = $topcount > 0 ? 390 : 30;
	$pie = pfb_stats_pie($summary, $topcount, $stat_type);
	ob_start();
?>
			<div class="pfb-stats-row">
			<div class="pfb-stats-col" style="height: <?=$height;?>px; overflow-y: scroll;">
			<table class="table table-responsive table-bordered table-striped table-hover table-compact sortable-theme-bootstrap" data-sortable>

				<thead>
					<tr>
						<th style="width: 10%;"><!--  Action buttons --></th>
						<th style="width: 10%; text-align: center;"><?=gettext("Count")?></th>

						<?php if ($stype[3]): ?>
						<th style="width: 2%; text-align: center;">
							<?php
							$column_title = 'GeoIP';
							if ($stat_type == 'dnsbldomain' || $stat_type == 'dnsblevald') {
								$column_title = 'Type';
							} elseif ($stat_type == 'replysrcipd') {
								$column_title = 'SRC IP';
							}
							?>
							<?=gettext($column_title);?></th>
						<?php endif; ?>

						<th><small><?=$stype[1] . "&emsp;[ {$topcount} ]&emsp;" . $stype[2]?></th>
					</tr>
				</thead>
				<tbody>
					<?php
					// issue #1495: default FALSE -- when the first non-chart stat category
					// has no data (routine on a fresh install), the block below never runs,
					// and $max_table_entries must still be defined for the tfoot check.
					$max_table_entries = FALSE;
					if (!empty($summary)) {

						$table_entries = 0;
						foreach ($summary as $data => $data_count) {

							if ($pfbmaxtable != 'max') {
								if ($table_entries > $pfbmaxtable) {
									$max_table_entries = TRUE;
									break;
								}
								$table_entries++;
							}

							$alert_event = $btnsubmit = $query_port = $hostname = '';
							$subdata = array();
							// issue #1069: NULL until a trusted-literal branch below opts the
							// final <td> out of escaping; otherwise it defaults to pfb_hsc($data).
							$data_disp = NULL;

							$filter_value = $data;
							if ($stat_type == 'dnsbltld' || $stat_type == 'replytld' ||
							    $stat_type == 'replytld2'|| $stat_type == 'replytld3' ) {
								$filter_value = "\.{$data}$";
							}
							elseif ($stat_type == 'ipsrcport' || $stat_type == 'ipdstport' ||
								$stat_type == 'replyorec' || $stat_type == 'replyrec') {
								$filter_value = "^{$data}$";
							}
							elseif ($stat_type == 'replyttl') {
								if (strlen($data) > 8) {
									$filter_value = "^15\d{6,10}";
								} else {
									$filter_value = "^{$data}$";
								}
							}
							elseif ($stat_type == 'ipasn') {
								if ($data == 'null') {
									continue;
								} elseif ($data != 'Unknown' && !ctype_digit($data)) { 
									if (strpos($data, '| ') !== FALSE) {
										$ex		= explode('| ', $data, 3);
										$filter_value	= $ex[1];
										$data		= "{$ex[1]} | {$ex[2]}";
									} else {
										$ex		= explode(' ', $data, 2);
										$filter_value	= $ex[0];
										$data		= "{$ex[0]} | {$ex[1]}";
									}
								}
							}
							elseif ($stat_type == 'dnsbldomain') {
								$split = strrpos($data, ',');
								$subdata = [substr($data, 0, $split), substr($data, $split + 1)];
								$filter_value = $subdata[0];
							}
							elseif ($stat_type == 'dnsblevald') {
								$subdata = explode(',', $data, 2);
								$filter_value = $subdata[1];
							}

							if ($stat_type != 'ipdirection') {
								// issue #1069: filter_value/data are log-derived -- HTML-encode
								// both attribute values.
								$btnsubmit = '<button type="submit" class="fa-solid fa-filter button-icon"'
										. " name=\"filterlogentries_submit_{$stat_type}\""
										. " id=\"filterlogentries_submit_{$stat_type}\""
										. " value=\"" . pfb_hsc($filter_value) . "\" title=\"Filter Alerts for [ "
										. pfb_hsc($data) . " ]\"></button>";
							}

							// Collect GeoIP or DNSBL Type classification
							if ($stype[3]) {
								if (empty($subdata)) {
									$subdata = explode(',', $data);
								}
								if ($stat_type == 'dnsblevald') {
									$data		= $subdata[1];
									$subdata[1]	= $subdata[0];
								}
								else {
									$data = $subdata[0];
								}

								// issue #1069: $data rides a URL query segment -- rawurlencode,
								// not HTML-encode.
								$alert_event = '<a class="fa-solid fa-info icon-pointer"'
										. ' title="Click for Threat Lookup." target="_blank" rel="noopener noreferrer"'
										. ' href="/pfblockerng/pfblockerng_threats.php?' . $stype[4] . '=' . rawurlencode($data) . '"></a>';
							}

							if ($stat_type == 'dnsbldatehr' || $stat_type == 'dnsbldatehrmin') {
								// ISO bucket key is 2 space-tokens (date, hour[:min]), not the
								// old 3-token "Mon D HH" shape -- label as "date (hour[:min])".
								// issue #1057: a truncated/corrupt key has no 2nd token.
								$d = explode (' ', $data);
								$data = isset($d[1]) ? "{$d[0]}&emsp;({$d[1]})" : $d[0];
								$data_disp = $data;	// program-generated date/hour token, trusted
							}

							if (!empty($data) && $data != 'Not available for HTTPS alerts') {

								// Report Local hostname if found
								if ($stat_type == 'ipsrcipout' || $stat_type == 'ipdstipin') {
									if (isset($local_hosts[$data])) {
										$hostname = "&emsp;<small>( " . pfb_hsc($local_hosts[$data]) . " )</small>";
									}
								}

								// Get external IP hostname and Resolved hostname
								elseif ($stat_type == 'ipsrcipin' || $stat_type == 'ipdstipout') {
									$hostname = pfb_stat_hostname_cell($subdata[2]);
								}
							}

							if ($stat_type == 'dnsblagent' && $data == 'Unknown') {
								$data = pfb_dnsbl_mechanism_labels()['enabled'];
								$data_disp = $data;	// literal, trusted
							}

							if ($stat_type == 'ipdstport') {
								// issue #1069: href segment rawurlencode'd; title HTML-encoded.
								$query_port = '&nbsp;<a class="fa-solid fa-search icon-pointer" target="_blank" rel="noopener noreferrer"'
										. ' href="/pfblockerng/pfblockerng_threats.php?port=' . rawurlencode($data)
										. '" title="Click for Threat Port Lookup [ ' . pfb_hsc($data) . ' ]"></a>';
							}

							elseif ($stat_type == 'ipdirection') {
								if ($data == 'in') {
									$data = 'Inbound packets';
								} else {
									$data = 'Outbound packets';
								}
								$data_disp = $data;	// literal, trusted
							}

							if (empty($data)) {
								$data = 'Unknown';
								$data_disp = $data;	// literal, trusted
							}

							$td_type = '';
							if ($stype[3]) {
								$td_type = "<td style=\"text-align: center;\">" . pfb_hsc($subdata[1]) . "</td>";
							}

							// issue #1069: everything NOT opted into a trusted literal above is
							// attacker-influenceable log/feed data -- HTML-encode it here.
							if ($data_disp === NULL) {
								$data_disp = pfb_hsc($data);
							}

							print ("<tr>
								<td style=\"text-align: center; white-space: nowrap;\">{$alert_event}{$query_port}{$btnsubmit}</td>
								<td style=\"text-align: right; padding-right: 15px;\">{$data_count}</td>
								{$td_type}
								<td style=\"white-space: nowrap;\">{$data_disp}{$hostname}</td></tr>");
						}
					}
					?>
				</tbody>
			</table>
			</div>

			<div class="pfb-stats-col" style="height: <?=$height;?>px;">
				<div id="pieChart_<?=$stat_type?>">

				</div>
			</div>
			</div><!-- /.pfb-stats-row -->

			<!-- Display max table extry limit, if found -->
			<?php if ($max_table_entries): ?>
			<div>
				&emsp;
				<span class="text-warning" style="font-size:12px; background-color: #424242;"
					title="Table limit reached! Change the limit in 'Alert Settings' on 'Reports'; a higher limit slows page refresh.">
					<small>Displaying [ <?= $pfbmaxtable; ?> ] entries.</small>
				</span>
			</div>
			<?php endif; ?>
<?php
	return ['id' => $stat_type, 'html' => (string) ob_get_clean(), 'pie' => $pie];
}

function pfb_stats_panels(array $definitions, array $summaries, array $hidden, $pfbmaxtable, array $local_hosts, array $ranges): array {
	global $pfb;
	$panels = [];
	foreach ($definitions as $id => $definition) {
		if (isset($hidden[$id]) || ($id === 'ipasn' && ($pfb['asn_reporting'] ?? 'disabled') === 'disabled')) {
			continue;
		}
		if (in_array($id, ['dnsblchart', 'replychart', 'ipchart'], TRUE)) {
			$html = '<div id="chart" class="d3-chart" style="overflow: hidden;"><div class="btn-group navbar-right" style="margin-right: 10px;"><ul class="navbar-nav"><a href="#" class="dropdown-toggle" data-toggle="dropdown" role="button" aria-expanded="false">Date Range <span class="caret"></span></a><ul class="dropdown-menu" role="menu" style="padding: 1px; font-size: smaller;">';
			foreach ($ranges as $range => $label) {
				$html .= '<li id="chartEvent" value="' . pfb_hsc((string) $range) . '"><a href="#" class="navlnk">' . pfb_hsc($label) . '</a></li>';
			}
			$panels[] = ['id' => $id, 'html' => $html . '</ul></ul></div></div>', 'pie' => NULL];
		} else {
			$panels[] = pfb_stats_panel($id, $definition, $summaries[$id] ?? [], $pfbmaxtable, $local_hosts);
		}
	}
	return $panels;
}
