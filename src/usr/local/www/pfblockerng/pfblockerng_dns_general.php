<?php
/*
 * pfblockerng_dns_general.php
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

$pconfig = array();
$pconfig['pfb_py_reply'] = PfbConfig::read('dnsbl/pfb_py_reply');
$pconfig['pfb_dns_listen_vip'] = PfbConfig::read('gen/pfb_dns_listen_vip');
$pconfig['pfb_dns_listen_vip_only'] = PfbConfig::read('gen/pfb_dns_listen_vip_only');
$pconfig['pfb_dns_listen_vip4'] = PfbConfig::read('gen/pfb_dns_listen_vip4') ?: 'none';
$pconfig['pfb_dns_listen_vip6'] = PfbConfig::read('gen/pfb_dns_listen_vip6') ?: 'none';
$pconfig['pfb_dns_listen_interface'] = PfbConfig::read('gen/pfb_dns_listen_interface');
$options_dns_listen_interface = array_merge(array('lo0' => 'Localhost'), pfb_build_if_list(FALSE, FALSE));
$options_dns_listen_vip4 = array_merge(pfb_get_vip_options(AF_INET), array('auto' => gettext('Create VIP automatically')));
$options_dns_listen_vip6 = array_merge(pfb_get_vip_options(AF_INET6), array('auto' => gettext('Create VIP automatically')));
$input_errors = array();

if ($_POST && isset($_POST['save'])) {
	foreach (array('pfb_dns_listen_vip4', 'pfb_dns_listen_vip6', 'pfb_dns_listen_interface') as $field) {
		$value = $_POST[$field] ?? '';
		if (!is_string($value)) {
			$input_errors[] = gettext('DNS General: invalid selection.');
			$value = '';
		}
		$pconfig[$field] = pfb_sanitize_text($value);
	}
	$pconfig['pfb_py_reply'] = pfb_filter($_POST['pfb_py_reply'] ?? '', PFB_FILTER_ON_OFF, 'dnsbl') ?: '';
	$pconfig['pfb_dns_listen_vip'] = pfb_filter($_POST['pfb_dns_listen_vip'] ?? '', PFB_FILTER_ON_OFF, 'gen') ?: '';
	$pconfig['pfb_dns_listen_vip_only'] = pfb_filter($_POST['pfb_dns_listen_vip_only'] ?? '', PFB_FILTER_ON_OFF, 'gen') ?: '';
	$pconfig['pfb_dns_listen_interface'] = pfb_filter($pconfig['pfb_dns_listen_interface'], PFB_FILTER_WORD, 'gen') ?: 'lo0';
	foreach (array('pfb_dns_listen_vip4' => $options_dns_listen_vip4, 'pfb_dns_listen_vip6' => $options_dns_listen_vip6,
		'pfb_dns_listen_interface' => $options_dns_listen_interface) as $field => $options) {
		if (!array_key_exists($pconfig[$field], $options)) {
			$input_errors[] = gettext('DNS General: select an available VIP and interface.');
		}
	}
	if (!$input_errors) {
		$pfb_config_lock = pfb_dns_config_lock();
		if ($pfb_config_lock === NULL) {
			$input_errors[] = gettext('DNS General: another save of the pfSense configuration is in progress, so these settings were not saved. Save again in a moment.');
		} else {
			try {
				$input_errors = pfb_validate_dns_listen_vip_only_post($pconfig);
				$pfb_written = FALSE;
				if (!$input_errors) {
					PfbConfig::write('dnsbl/pfb_py_reply', $pconfig['pfb_py_reply']);
					PfbConfig::write('gen/pfb_dns_listen_vip', $pconfig['pfb_dns_listen_vip']);
					PfbConfig::write('gen/pfb_dns_listen_vip_only', $pconfig['pfb_dns_listen_vip_only']);
					PfbConfig::write('gen/pfb_dns_listen_vip4', $pconfig['pfb_dns_listen_vip4'] === 'none' ? '' : $pconfig['pfb_dns_listen_vip4']);
					PfbConfig::write('gen/pfb_dns_listen_vip6', $pconfig['pfb_dns_listen_vip6'] === 'none' ? '' : $pconfig['pfb_dns_listen_vip6']);
					PfbConfig::write('gen/pfb_dns_listen_interface', $pconfig['pfb_dns_listen_interface']);
					// A refused advertisement write re-read config.xml: the page write would hide it behind a success.
					$pfb_written = pfb_dns_listen_vips_apply() ? write_config('[pfBlockerNG] save DNS General settings') : FALSE;
				}
			} finally {
				unlock($pfb_config_lock);
			}
			if ($pfb_written !== FALSE && $pfb_written !== -1) {
				pfb_mark_pending_changes();
				header('Location: /pfblockerng/pfblockerng_dns_general.php');
				exit;
			}
			if (!$input_errors) {
				$input_errors[] = gettext('DNS General: the configuration could not be written, so these settings were not saved. Save again in a moment.');
			}
		}
	}
}

$pgtitle = array(gettext('Firewall'), gettext('pfBlockerNG'), gettext('DNS'), gettext('General'));
$pglinks = array('', '/pfblockerng/pfblockerng_general.php', '/pfblockerng/pfblockerng_dns_general.php', '@self');
$shortcut_section = 'pfblockerng';
include_once('head.inc');
if ($input_errors) {
	print_input_errors($input_errors);
}
$get_req = pfb_alerts_default_page();
$tab_array = array();
$tab_array[] = array(gettext('General'), FALSE, '/pfblockerng/pfblockerng_general.php');
$tab_array[] = array(gettext('IP'), FALSE, '/pfblockerng/pfblockerng_ip.php');
$tab_array[] = array(gettext('DNS'), TRUE, '/pfblockerng/pfblockerng_dns_general.php');
$tab_array[] = array(gettext('Update'), FALSE, '/pfblockerng/pfblockerng_update.php');
$tab_array[] = array(gettext('Reports'), FALSE, "/pfblockerng/pfblockerng_alerts.php{$get_req}");
$tab_array[] = array(gettext('Feeds'), FALSE, '/pfblockerng/pfblockerng_feeds.php');
$tab_array[] = array(gettext('Logs'), FALSE, '/pfblockerng/pfblockerng_log.php');
$tab_array[] = array(gettext('Sync'), FALSE, '/pfblockerng/pfblockerng_sync.php');
pfb_software_add_tab($tab_array);
$tab_array[] = array(gettext('Wizard'), FALSE, '/wizard.php?xml=pfblockerng_wizard.xml');
display_top_tabs($tab_array, TRUE);
$tab_array = array();
$tab_array[] = array(gettext('General'), TRUE, '/pfblockerng/pfblockerng_dns_general.php');
$tab_array[] = array(gettext('pfB-DNS'), FALSE, '/pfblockerng/pfblockerng_dns.php');
$tab_array[] = array(gettext('DNSBL'), FALSE, '/pfblockerng/pfblockerng_dnsbl.php');
$tab_array[] = array(gettext('DNSBL Groups'), FALSE, '/pfblockerng/pfblockerng_category.php?type=dnsbl');
$tab_array[] = array(gettext('DNSBL Category'), FALSE, '/pfblockerng/pfblockerng_blacklist.php');
$tab_array[] = array(gettext('DNSBL SafeSearch'), FALSE, '/pfblockerng/pfblockerng_safesearch.php');
display_top_tabs($tab_array, TRUE);
pfb_print_pending_changes_box();

foreach (pfb_dns_listen_foreign_warnings() as $pfb_foreign_warning) {
	print_info_box($pfb_foreign_warning, 'warning', FALSE);
}

$form = new Form('Save DNS General settings');
$section = new Form_Section('DNS Reply Logging');
$section->addInput(new Form_Checkbox(
	'pfb_py_reply',
	gettext('DNS Reply Logging'),
	'Enable',
	pfb_dnsbl_toggle_enabled($pconfig['pfb_py_reply'] ?? NULL),
	'on'
))->setHelp('Log each DNS reply to the DNS Reply log (the client, the name asked, the reply type, TTL and answer, and the answer\'s country), '
		. 'which fills <strong>Reports</strong> &gt; <strong>DNS Reply</strong>.'
		. '<div class="infoblock">'
		. 'This one setting applies to both DNS modes. With DNSBL enabled, the DNSBL Python module logs the replies that were not blocked. '
		. 'With pfB-DNS enabled and DNSBL disabled, the pfB-DNS proxy logs every reply it forwards from the DNS Resolver, '
		. 'without loading any DNSBL feed or module. '
		. 'When <strong>DNS Reply Logging</strong> is disabled, no replies are logged.<br />'
		. 'The log lists the names each client looked up: keep this disabled where that must not be recorded.<br />'
		. 'Default: <strong>Enabled</strong>'
		. '</div>');
$form->add($section);

$section = new Form_Section('Resolver addresses');
$section->addInput(new Form_Checkbox(
	'pfb_dns_listen_vip',
	gettext('Resolver addresses'),
	'Enable',
	pfb_cfg_toggle_read($pconfig['pfb_dns_listen_vip'] ?? NULL) === PfbToggle::On,
	'on'
))->setAttribute('aria-label', gettext('Resolver addresses'))
  ->setHelp(gettext('Provide dedicated DNS service addresses, even when <strong>DNSBL</strong> and <strong>pfB-DNS</strong> are disabled.')
		. '<div class="infoblock"><p>' . gettext('The selected <strong>Resolver VIPs</strong> integrate with:') . '</p><ul>'
		. '<li>' . gettext('<strong>DNS Resolver</strong> — listening addresses.') . '</li>'
		. '<li>' . gettext('<strong>DHCPv4</strong> — advertised IPv4 DNS servers.') . '</li>'
		. '<li>' . gettext('<strong>DHCPv6</strong> — advertised IPv6 DNS servers.') . '</li>'
		. '<li>' . gettext('<strong>Router Advertisements</strong> — advertised IPv6 DNS servers.') . '</li>'
		. '</ul><p>' . gettext('Administrator-selected DNS servers are preserved. Page warnings identify affected DNS server lists.') . '</p>'
		. '<p>' . gettext('Default: <strong>Disabled</strong>') . '</p></div>');
$group = new Form_Group(gettext('Resolver VIPs'));
$group->add(new Form_Select(
	'pfb_dns_listen_vip4',
	gettext('IPv4 VIP'),
	$pconfig['pfb_dns_listen_vip4'],
	$options_dns_listen_vip4
))->setWidth(4)->setHelp(gettext('IPv4 Virtual IP (optional)'));
$group->add(new Form_Select(
	'pfb_dns_listen_vip6',
	gettext('IPv6 VIP'),
	$pconfig['pfb_dns_listen_vip6'],
	$options_dns_listen_vip6
))->setWidth(4)->setHelp(gettext('IPv6 Virtual IP (optional)'));
$group->setHelp(gettext('On a selected VIP, port 443 may already be taken. On an automatically created VIP, port 443 is free.'));
$section->add($group);
$section->addInput(new Form_Select(
	'pfb_dns_listen_interface',
	gettext('Automatic VIP interface'),
	$pconfig['pfb_dns_listen_interface'],
	$options_dns_listen_interface
))->setHelp(gettext('Used only for a family set to Create VIP automatically. Default: <strong>Localhost</strong>.'));
$section->addInput(new Form_Checkbox(
	'pfb_dns_listen_vip_only',
	gettext('VIP-only mode'),
	'Enable',
	pfb_cfg_toggle_read($pconfig['pfb_dns_listen_vip_only'] ?? NULL) === PfbToggle::On,
	'on'
))->setAttribute('aria-label', gettext('VIP-only mode'))
  ->setHelp(gettext('Serve <strong>pfB-DNS</strong> only on the selected <strong>Resolver VIPs</strong>.')
		. '<div class="infoblock"><ul>'
		. '<li>' . gettext('Requires <strong>pfB-DNS</strong>, <strong>Resolver addresses</strong> and at least one available VIP.') . '</li>'
		. '<li>' . gettext('Removes ordinary interface listeners; internal loopback remains available.') . '</li>'
		. '<li>' . gettext('<strong>DNS Name</strong> resolves to the selected VIP address pair.') . '</li>'
		. '<li>' . gettext('Missing VIPs do not restore ordinary interface listeners.') . '</li>'
		. '</ul><p>' . gettext('<span class="text-danger"><strong>Warning:</strong></span> Reconfigure client DNS settings and DHCP/RA advertisements before enabling. Existing leases and custom DNS options are not migrated.') . '</p>'
		. '<p>' . gettext('Manually configured DNS port forwards may temporarily redirect queries from old firewall DNS addresses to the <strong>Resolver VIPs</strong>. For a permanent transition, update client DNS settings and DHCP/RA advertisements, then remove the temporary rules.') . '</p>'
		. '<p>' . gettext('This setting does not restrict standalone <strong>DNS Resolver</strong> listeners.') . '</p>'
		. '<p>' . gettext('Default: <strong>Disabled</strong>') . '</p></div>');
$form->add($section);
print ($form);
include('foot.inc');
?>
