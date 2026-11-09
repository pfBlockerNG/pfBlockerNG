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

if (($_GET['ajax'] ?? '') === 'ddr') {
	header('Cache-Control: no-store');
	if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
		header('Allow: GET');
		http_response_code(405);
		exit;
	}
	session_write_close();
	// No listener is the metadata panel. A non-string (an array) is refused before any probe.
	$listener = $_GET['listener'] ?? NULL;
	if ($listener !== NULL && !is_string($listener)) {
		http_response_code(400);
		exit;
	}
	header('Content-Type: application/json');
	echo json_encode(['html' => pfb_dns_ddr_status_panel(pfb_dns_ddr_status($listener))]);
	exit;
}

// issue #3538: the first load takes pfB-DNS's listener settings from the Resolver once, so a box that is already moved has
// them without a save. A lock that stays taken skips the write: the form still shows the pending seed values.
if (pfb_dns_proxy_seed_values() !== []) {
	$pfb_seed_lock = pfb_dns_config_lock();
	if ($pfb_seed_lock !== NULL) {
		try {
			if (pfb_dns_proxy_seed()) {
				write_config('[pfBlockerNG] pfB-DNS took its listener settings from the DNS Resolver');
			}
		} finally {
			unlock($pfb_seed_lock);
		}
	}
}

$pconfig = array();
$pconfig['pfb_dns'] = PfbConfig::read('dns/pfb_dns');
// issues #3513, #3538: pfB-DNS's listener and certificate settings. A setting not seeded yet shows the value the seed will write;
// an interface list is split into the tokens the proxy reads from it (issue #3557: spaces too, as a hand edit may leave)
$pconfig['pfb_dns_interface']		= pfb_dns_proxy_tokens((string) pfb_dns_proxy_setting('pfb_dns_interface'));
$pconfig['pfb_dns_sslcertref']		= pfb_dns_proxy_setting('pfb_dns_sslcertref');
$pconfig['pfb_dns_name']		= PfbConfig::read('dns/pfb_dns_name');	// issue #3694: DDR's target and the name pfB-DNS answers for; never seeded
$pconfig['pfb_dns_dot']			= pfb_dns_proxy_setting('pfb_dns_dot');
$pconfig['pfb_dns_dot_port']		= pfb_dns_proxy_setting('pfb_dns_dot_port');
$pconfig['pfb_dns_dot_port6']		= PfbConfig::read('dns_shared/pfb_dns_dot_port6');
$pconfig['pfb_dns_dot_interface']	= pfb_dns_proxy_tokens((string) pfb_dns_proxy_setting('pfb_dns_dot_interface'));
$pconfig['pfb_dns_doh']			= PfbConfig::read('dns_shared/pfb_dns_doh');
$pconfig['pfb_dns_doh_port']		= PfbConfig::read('dns_shared/pfb_dns_doh_port');
$pconfig['pfb_dns_doh_port6']		= PfbConfig::read('dns_shared/pfb_dns_doh_port6');
$pconfig['pfb_dns_doh_interface']	= pfb_dns_proxy_tokens((string) pfb_dns_proxy_setting('pfb_dns_doh_interface'));
$pconfig['pfb_dns_doh_trusted']		= PfbConfig::read('dns_shared/pfb_dns_doh_trusted');
$pconfig['pfb_dns_doq']			= PfbConfig::read('dns_shared/pfb_dns_doq');
$pconfig['pfb_dns_doq_port']		= PfbConfig::read('dns_shared/pfb_dns_doq_port');
$pconfig['pfb_dns_doq_port6']		= PfbConfig::read('dns_shared/pfb_dns_doq_port6');
$pconfig['pfb_dns_doq_interface']	= pfb_dns_proxy_tokens((string) pfb_dns_proxy_setting('pfb_dns_doq_interface'));
// issue #3583: DDR (RFC 9462) answers
$pconfig['pfb_dns_ddr']			= PfbConfig::read('dns_shared/pfb_dns_ddr');
$pconfig['pfb_dns_ddr_doh_443_interfaces'] = pfb_dns_proxy_tokens((string) PfbConfig::read('dns/pfb_dns_ddr_doh_443_interfaces'));	// issue #3694: where DDR advertises DoH on port 443
// Resolver interface choices and unavailable stored tokens, excluding package-owned VIPs.
$options_dns_interface = pfb_dns_proxy_interface_options();
// The certificates the Resolver offers: the same call, so the same list and descriptions
$options_dns_cert = cert_build_list('cert', 'IPsec');

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

if ($_POST) {
	if (isset($_POST['save_pfb_dns'])) {
		// issue #1723: sanitize at ingestion -- first step, before any evaluation.
		foreach (array('pfb_dns_dot_port', 'pfb_dns_dot_port6', 'pfb_dns_doh_port', 'pfb_dns_doh_port6', 'pfb_dns_doq_port', 'pfb_dns_doq_port6', 'pfb_dns_doh_trusted') as $pfb_text_field) {
			$_POST[$pfb_text_field] = pfb_sanitize_text((string) ($_POST[$pfb_text_field] ?? ''));
		}
		// issue #3694: a name that is not text (an array post) stays as posted, for the validator to refuse; casting it would warn
		if (is_string($_POST['pfb_dns_name'] ?? '')) {
			$_POST['pfb_dns_name'] = pfb_sanitize_text((string) ($_POST['pfb_dns_name'] ?? ''));
		}

		$pfb_dns = pfb_filter($_POST['pfb_dns'] ?? '', PFB_FILTER_ON_OFF, 'pfb_dns') ?: '';

		$input_errors = array_merge($input_errors, pfb_validate_dns_proxy_listeners_post(
			$_POST,
			array_map('strval', array_keys($options_dns_interface)),
			array_map('strval', array_keys($options_dns_cert))
		));

		// issue #3515: the apply moves and restores the Resolver (config.xml keys and the snapshot kept in this section)
		// under this lock, from a fresh read. Hold it from a fresh read through write_config(), so this save cannot write
		// back a copy that predates a move or a restore.
		$pfb_config_lock = NULL;
		if (!$input_errors) {
			$pfb_config_lock = pfb_dns_config_lock();
			if ($pfb_config_lock === NULL) {
				$input_errors[] = 'pfB-DNS: another save of the pfSense configuration is in progress, so these settings were not saved. Save again in a moment.';
			}
		}

		if (!$input_errors) {
			foreach (pfb_dns_proxy_listeners_stored($_POST) as $pfb_dns_key => $pfb_dns_value) {
				PfbConfig::write(pfb_dns_config_key($pfb_dns_key), $pfb_dns_value);
			}
			PfbConfig::write('dns/pfb_dns', $pfb_dns);
			try {
				$pfb_written = write_config('[pfBlockerNG] save pfB-DNS settings');
			} finally {
				unlock($pfb_config_lock);
			}
			// pfSense's write_config() answers FALSE when it refuses the write and -1 when config.xml was not written: nothing was
			// saved, so the save is an input error and the form comes back as submitted
			if ($pfb_written !== FALSE && $pfb_written !== -1) {
				pfb_mark_pending_changes();	// applies on the next Update, not on save
				header('Location: /pfblockerng/pfblockerng_dns_general.php');
				exit;
			}
			$input_errors[] = 'pfB-DNS: the configuration could not be written, so these settings were not saved. Save again in a moment.';
		}

		$pconfig['pfb_dns'] = $_POST['pfb_dns'] ?? '';	// Restore the submitted state on input errors
		foreach (array('pfb_dns_dot', 'pfb_dns_dot_port', 'pfb_dns_dot_port6', 'pfb_dns_doh', 'pfb_dns_doh_port', 'pfb_dns_doh_port6', 'pfb_dns_doh_trusted', 'pfb_dns_doq', 'pfb_dns_doq_port', 'pfb_dns_doq_port6', 'pfb_dns_ddr', 'pfb_dns_sslcertref', 'pfb_dns_name') as $pfb_dns_field) {
			$pconfig[$pfb_dns_field] = $_POST[$pfb_dns_field] ?? '';
		}
		foreach (array('pfb_dns_interface', 'pfb_dns_dot_interface', 'pfb_dns_doh_interface', 'pfb_dns_doq_interface', 'pfb_dns_ddr_doh_443_interfaces') as $pfb_dns_field) {
			$pconfig[$pfb_dns_field] = array_filter((array) ($_POST[$pfb_dns_field] ?? array()), 'is_string');
		}
		if (!is_string($pconfig['pfb_dns_name'])) {
			$pconfig['pfb_dns_name'] = '';	// the validator refused a non-text name: the form cannot show it
		}
	}
}

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
$tab_array[] = array(gettext('DNSBL'), FALSE, '/pfblockerng/pfblockerng_dnsbl.php');
$tab_array[] = array(gettext('DNSBL Groups'), FALSE, '/pfblockerng/pfblockerng_category.php?type=dnsbl');
$tab_array[] = array(gettext('DNSBL Category'), FALSE, '/pfblockerng/pfblockerng_blacklist.php');
$tab_array[] = array(gettext('DNSBL SafeSearch'), FALSE, '/pfblockerng/pfblockerng_safesearch.php');
display_top_tabs($tab_array, TRUE);
pfb_print_pending_changes_box();
foreach (pfb_dns_proxy_ddr_warnings() as $pfb_ddr_warning) {
	print_info_box($pfb_ddr_warning, 'warning', FALSE);
}

foreach (pfb_dns_listen_foreign_warnings() as $pfb_foreign_warning) {
	print_info_box($pfb_foreign_warning, 'warning', FALSE);
}

$btn = new Form_Button('save_pfb_dns', 'Save pfB-DNS settings', NULL, 'fa-solid fa-save');
$btn->addClass('btn-primary');
$form = new Form($btn);

$section = new Form_Section('pfB-DNS Settings');
$section->addInput(new Form_Checkbox(
	'pfb_dns',
	gettext('pfB-DNS'),
	'Enable',
	pfb_cfg_toggle_read($pconfig['pfb_dns']) === PfbToggle::On,
	'on'
))->setHelp('<p><strong>Experimental.</strong> <strong>pfB-DNS</strong> answers client DNS. '
		. 'With DNSBL enabled, it answers blocked names locally and passes other queries to the DNS Resolver with the client address. '
		. '<strong>DNSBL</strong> runs only through <strong>pfB-DNS</strong>: turning <strong>pfB-DNS</strong> off stops <strong>DNSBL</strong>; the <strong>DNSBL</strong> setting is kept.</p>'
		. '<div class="infoblock">'
		. '<p><strong>Resolver changes</strong></p>'
		. '<ul>'
		. '<li><strong>Network Interfaces</strong> becomes <strong>Localhost</strong>.</li>'
		. '<li><strong>SSL/TLS Service</strong> is turned off; configure encrypted listeners with <strong>DoT</strong>, <strong>DoH</strong> and <strong>DoQ</strong> below.</li>'
		. '<li>The Resolver uses loopback ports <code>5353</code> and <code>5354</code>. Its <strong>Listen Port</strong> must use neither port.</li>'
		. '</ul>'
		. '<p>A <strong>Custom options</strong> line containing <code>interface:</code>, <code>port:</code> or <code>include:</code>, or an unmatched proxy marker, prevents activation. '
		. 'A notice identifies the conflict. Adding such a conflict later restores the Resolver with the conflicting line kept; <strong>pfB-DNS</strong> stays on, its status shows the activation failed and the next <strong>Update</strong> retries. '
		. 'Turning the option off is never refused.</p>'
		. '<p>Turning <strong>pfB-DNS</strong> off, disabling pfBlockerNG or removing the package restores the saved Resolver settings. '
		. 'Later edits to the saved <strong>Network Interfaces</strong>, <strong>SSL/TLS Service</strong> and <strong>Custom options</strong> fields are replaced.</p>'
		. '<p>Disabling the DNS Resolver stops <strong>pfB-DNS</strong> and restores the saved fields; this option stays on and <strong>pfB-DNS</strong> starts again once the Resolver is enabled. '
		. 'The proxy starts with the Resolver, including during boot, and handles the firewall\'s own DNS lookups.</p>'
		. '<p><span class="text-danger"><strong>Warning: High availability</strong></span></p>'
		. '<ol>'
		. '<li>Save the same setting on both nodes: where <strong>Sync Scope</strong> carries the enable, the primary\'s setting replaces the secondary\'s at the primary\'s next sync.</li>'
		. '<li>With DNS Resolver sync enabled, apply it on the secondary before the primary, whether enabling or disabling: apply it with <strong>Run Now</strong> on <strong>Update</strong> and confirm it took effect, because saving only marks the change pending. Otherwise the secondary receives the moved Resolver without a saved copy and refuses it on every apply, or restored Resolver settings conflict with its running proxy.</li>'
		. '</ol>'
		. '<p>Alternatively, turn DNS Resolver sync off before changing <strong>pfB-DNS</strong>.</p>'
		. '<p>Unset DNS, DoT, DoH and DoQ interfaces, the DoT setting and port, and the certificate are taken from the DNS Resolver once, the first time this page loads or <strong>pfB-DNS</strong> is turned on; '
		. 'later Resolver changes do not change them. Explicit DoT choices received through <strong>Sync</strong> are kept.</p>'
		. '<p><strong>Sync:</strong></p><ul>'
		. '<li>The <strong>pfB-DNS</strong> enable switch, <strong>Resolver addresses</strong> and <strong>VIP-only mode</strong> follow <strong>Sync Scope</strong>. The receiver applies a received enable at its next update.</li>'
		. '<li>Saved Resolver settings, <strong>DNS Name</strong>, <strong>SSL/TLS Certificate</strong> and transport interface selections stay local.</li>'
		. '</ul><p>See <strong>Sync</strong> for the settings included in each scope.</p>'
		. '<p>Default: <strong>Disabled</strong></p>'
		. '</div>');

$section->addInput(new Form_Select(
	'pfb_dns_interface',
	gettext('DNS Interface(s)'),
	$pconfig['pfb_dns_interface'] ?? [],
	$options_dns_interface,
	TRUE
))->setAttribute('style', 'width: auto')
  ->setAttribute('size', count($options_dns_interface) ?: '1')
  ->setAttribute('aria-label', gettext('DNS Interface(s)'))
  ->setHelp('Selected interfaces and unmanaged VIPs use the DNS Resolver\'s <strong>Listen Port</strong>. '
		. 'Package-owned Resolver VIPs automatically serve plain DNS on port <strong>53</strong>. '
		. '<strong>Localhost</strong>: loopback. <strong>All</strong>: every eligible firewall address except link-local. At least one entry is required.');

if ($options_dns_cert) {
	$section->addInput(new Form_Select(
		'pfb_dns_sslcertref',
		gettext('SSL/TLS Certificate'),
		$pconfig['pfb_dns_sslcertref'] ?? '',
		$options_dns_cert
	))->setHelp('The server certificate DoT, DoH and DoQ serve. The CA chain is determined automatically.');
} else {
	$section->addInput(new Form_StaticText(
		gettext('SSL/TLS Certificate'),
		sprintf(
			gettext('No Certificates have been defined. A certificate is required before SSL/TLS can be enabled. %1$s Create or Import %2$s a Certificate.'),
			'<a href="system_certmanager.php">',
			'</a>'
		)
	));
}

$section->addInput(new Form_Input(
	'pfb_dns_name',
	gettext('DNS Name'),
	'text',
	$pconfig['pfb_dns_name'],
	[ 'placeholder' => 'fw.example.lan' ]
))->setAttribute('aria-label', gettext('DNS Name'))
  ->setHelp('The name <strong>DDR</strong> gives clients as the target of the encrypted transports, and the name pfB-DNS answers <code>A</code> and <code>AAAA</code> queries for, '
		. 'with the address pair of the interface or VIP the query arrived on. DoT, DoH and DoQ require this name, covered by the <strong>SSL/TLS Certificate</strong> as a DNS name (SAN). '
		. 'In VIP-only mode, this name always resolves to the selected Resolver VIPs, including queries on internal loopback. '
		. 'Example ( fw.example.lan ). A name is also required for <strong>DDR</strong>. Empty is allowed for plain DNS only or when disabling pfB-DNS.');
$form->add($section);

$section = new Form_Section('DNS over TLS (DoT)');
$section->addInput(new Form_Checkbox(
	'pfb_dns_dot',
	gettext('DoT'),
	'Enable',
	pfb_cfg_toggle_read($pconfig['pfb_dns_dot'] ?? NULL) === PfbToggle::On,
	'on'
))->setHelp('<i class="fa fa-exclamation-triangle"></i> <strong>Experimental.</strong> '
		. 'Encrypt client DNS traffic using TLS over TCP.'
		. '<div class="infoblock"><ul>'
		. '<li>Enable <strong>pfB-DNS</strong>.</li>'
		. '<li>Set <strong>DNS Name</strong> and select an <strong>SSL/TLS Certificate</strong> covering that name.</li>'
		. '<li><strong>DNSBL</strong> filtering applies when enabled; DNSBL is not required.</li>'
		. '</ul><p>Default: <strong>Disabled</strong></p></div>');

$section->addInput(new Form_Input(
	'pfb_dns_dot_port',
	gettext('IPv4 DoT Port'),
	'number',
	$pconfig['pfb_dns_dot_port'],
	[ 'min' => 1, 'max' => 65535, 'placeholder' => 'Enter DoT Listening Port' ]
))->setHelp('Interfaces and unmanaged VIPs: a single PORT in the range 1 - 65535 (TCP), e.g. 853. Package-owned Resolver VIPs automatically use <strong>853</strong>, not this port.');

$section->addInput(new Form_Input(
	'pfb_dns_dot_port6',
	gettext('IPv6 DoT Port'),
	'number',
	$pconfig['pfb_dns_dot_port6'],
	[ 'min' => 1, 'max' => 65535 ]
))->setHelp(gettext('Empty: use the IPv4 port.'));

$section->addInput(new Form_Select(
	'pfb_dns_dot_interface',
	gettext('DoT Interface(s)'),
	$pconfig['pfb_dns_dot_interface'] ?? [],
	$options_dns_interface,
	TRUE
))->setAttribute('style', 'width: auto')
  ->setAttribute('size', count($options_dns_interface) ?: '1')
  ->setAttribute('aria-label', gettext('DoT Interface(s)'))
  ->setHelp('Interface(s) and unmanaged VIPs DoT listens on at the configured ports. Package-owned Resolver VIPs listen automatically on <strong>853</strong> when DoT is enabled. At least one entry is required.');
$form->add($section);

$section = new Form_Section('DNS over HTTPS (DoH)');
$section->addInput(new Form_Checkbox(
	'pfb_dns_doh',
	gettext('DoH'),
	'Enable',
	pfb_cfg_toggle_read($pconfig['pfb_dns_doh'] ?? NULL) === PfbToggle::On,
	'on'
))->setHelp('<i class="fa fa-exclamation-triangle"></i> <strong>Experimental.</strong> '
		. 'Serve encrypted client DNS over HTTPS at <code>/dns-query</code>.'
		. '<div class="infoblock"><ul>'
		. '<li>Enable <strong>pfB-DNS</strong>.</li>'
		. '<li>Set <strong>DNS Name</strong> and select an <strong>SSL/TLS Certificate</strong> covering that name.</li>'
		. '<li><strong>DNSBL</strong> filtering applies when enabled; DNSBL is not required.</li>'
		. '<li>Configure <strong>DoH Trusted Front Ends</strong> only when a trusted reverse proxy supplies client addresses.</li>'
		. '</ul><p>Default: <strong>Disabled</strong></p></div>');

$section->addInput(new Form_Input(
	'pfb_dns_doh_port',
	gettext('IPv4 DoH Port'),
	'number',
	$pconfig['pfb_dns_doh_port'],
	[ 'min' => 1, 'max' => 65535, 'placeholder' => 'Enter DoH Listening Port' ]
))->setHelp('Interfaces and unmanaged VIPs: a single PORT in the range 1 - 65535 (TCP), e.g. 4443. Package-owned Resolver VIPs automatically use <strong>443</strong>, not this port.');

$section->addInput(new Form_Input(
	'pfb_dns_doh_port6',
	gettext('IPv6 DoH Port'),
	'number',
	$pconfig['pfb_dns_doh_port6'],
	[ 'min' => 1, 'max' => 65535 ]
))->setHelp(gettext('Empty: use the IPv4 port.'));

$section->addInput(new Form_Select(
	'pfb_dns_doh_interface',
	gettext('DoH Interface(s)'),
	$pconfig['pfb_dns_doh_interface'] ?? [],
	$options_dns_interface,
	TRUE
))->setAttribute('style', 'width: auto')
  ->setAttribute('size', count($options_dns_interface) ?: '1')
  ->setAttribute('aria-label', gettext('DoH Interface(s)'))
  ->setHelp('Interface(s) and unmanaged VIPs DoH listens on at the configured ports. Package-owned Resolver VIPs listen automatically on <strong>443</strong> when DoH is enabled. At least one entry is required.');

$section->addInput(new Form_Input(
	'pfb_dns_doh_trusted',
	gettext('DoH Trusted Front Ends'),
	'text',
	$pconfig['pfb_dns_doh_trusted'] ?? '',
	['placeholder' => 'IP addresses or CIDR prefixes (optional)']
))->setHelp('Optional. IP addresses or CIDR prefixes, separated by spaces or commas, of a front end trusted to send the client address: '
		. 'the PROXY protocol v2 header (HAProxy <code>send-proxy-v2</code>) and X-Forwarded-For (HAProxy <code>option forwardfor</code>). '
		. 'Empty: no front end is trusted, DoH sees each connection\'s own address.');
$form->add($section);

$section = new Form_Section('DNS over QUIC (DoQ)');
$section->addInput(new Form_Checkbox(
	'pfb_dns_doq',
	gettext('DoQ'),
	'Enable',
	pfb_cfg_toggle_read($pconfig['pfb_dns_doq'] ?? NULL) === PfbToggle::On,
	'on'
))->setHelp('<i class="fa fa-exclamation-triangle"></i> <strong>Experimental.</strong> '
		. 'Encrypt client DNS traffic using QUIC over UDP.'
		. '<div class="infoblock"><ul>'
		. '<li>Enable <strong>pfB-DNS</strong>.</li>'
		. '<li>Set <strong>DNS Name</strong> and select an <strong>SSL/TLS Certificate</strong> covering that name.</li>'
		. '<li><strong>DNSBL</strong> filtering applies when enabled; DNSBL is not required.</li>'
		. '</ul><p>Default: <strong>Disabled</strong></p></div>');

$section->addInput(new Form_Input(
	'pfb_dns_doq_port',
	gettext('IPv4 DoQ Port'),
	'number',
	$pconfig['pfb_dns_doq_port'],
	[ 'min' => 1, 'max' => 65535, 'placeholder' => 'Enter DoQ Listening Port' ]
))->setHelp('Interfaces and unmanaged VIPs: a single PORT in the range 1 - 65535 (UDP), e.g. 853. Package-owned Resolver VIPs automatically use <strong>853</strong>, not this port.');

$section->addInput(new Form_Input(
	'pfb_dns_doq_port6',
	gettext('IPv6 DoQ Port'),
	'number',
	$pconfig['pfb_dns_doq_port6'],
	[ 'min' => 1, 'max' => 65535 ]
))->setHelp(gettext('Empty: use the IPv4 port.'));

$section->addInput(new Form_Select(
	'pfb_dns_doq_interface',
	gettext('DoQ Interface(s)'),
	$pconfig['pfb_dns_doq_interface'] ?? [],
	$options_dns_interface,
	TRUE
))->setAttribute('style', 'width: auto')
  ->setAttribute('size', count($options_dns_interface) ?: '1')
  ->setAttribute('aria-label', gettext('DoQ Interface(s)'))
  ->setHelp('Interface(s) and unmanaged VIPs DoQ listens on at the configured ports. Package-owned Resolver VIPs listen automatically on <strong>853</strong> when DoQ is enabled. At least one entry is required.');
$form->add($section);

$section = new Form_Section('Discovery of Designated Resolvers (DDR)');
$section->addInput(new Form_Checkbox(
	'pfb_dns_ddr',
	gettext('DDR'),
	'Enable',
	pfb_cfg_toggle_read($pconfig['pfb_dns_ddr'] ?? NULL) === PfbToggle::On,
	'on'
))->setAttribute('aria-label', gettext('DDR'))
  ->setHelp('<i class="fa fa-exclamation-triangle"></i> <strong>Experimental.</strong> '
		. 'Let compatible clients discover this firewall\'s encrypted DNS services.'
		. '<div class="infoblock"><ul>'
		. '<li>Enable <strong>pfB-DNS</strong> and set <strong>DNS Name</strong>.</li>'
		. '<li>Enable the <strong>DoT</strong>, <strong>DoH</strong> or <strong>DoQ</strong> services clients should discover.</li>'
		. '<li>Only running encrypted listeners on the queried DNS address are advertised.</li>'
		. '<li>Clients verifying <strong>DDR</strong> require an endpoint certificate covering the queried IP address.</li>'
		. '</ul><p>When disabled, the <strong>DNS Resolver</strong> answers these discovery queries.</p>'
		. '<p>Default: <strong>Disabled</strong></p></div>');

// issue #3694: where DDR advertises DoH on port 443, chosen among the DoH interfaces of the form (and the Resolver VIPs the operator chose)
$options_ddr_doh_443 = pfb_dns_proxy_ddr_doh_443_options($pconfig['pfb_dns_doh_interface'] ?? array());
$section->addInput(new Form_Select(
	'pfb_dns_ddr_doh_443_interfaces',
	gettext('Advertise DoH on port 443'),
	$pconfig['pfb_dns_ddr_doh_443_interfaces'] ?? [],
	$options_ddr_doh_443,
	TRUE
))->setAttribute('style', 'width: auto')
  ->setAttribute('size', count($options_ddr_doh_443) ?: '1')
  ->setAttribute('aria-label', gettext('Advertise DoH on port 443'))
  ->setHelp('Tell <strong>DDR</strong> clients to use <strong>DoH</strong> on port <code>443</code> for the selected interfaces or administrator-managed VIPs.'
		. '<div class="infoblock"><ul>'
		. '<li>Requires <strong>DDR</strong> and <strong>DoH</strong>.</li>'
		. '<li>A reverse proxy must already serve DoH on port <code>443</code>.</li>'
		. '<li>Does not change <strong>IPv4 DoH Port</strong> or <strong>IPv6 DoH Port</strong>.</li>'
		. '<li>Automatically created <strong>Resolver VIPs</strong> serve DoH directly on port <code>443</code> and need no selection here.</li>'
		. '</ul><p>Some clients do not accept a non-standard DoH port advertised through <strong>DDR</strong>.</p>'
		. '<p>Default: <strong>None</strong></p></div>');
$form->add($section);

print ($form);

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
$status = pfb_dns_status();
if ($status['transports'] !== NULL) {
	$status['ddr'] = pfb_dns_ddr_status();
}
print pfb_dns_status_panel($status);

include('foot.inc');
?>
<script>
events.push(function() {
	const panelBody = document.getElementById('pfb-dns-status-ddr_panel-body');
	if (!panelBody) {
		return;
	}
	const note = document.getElementById('pfb-dns-ddr-refresh-status');
	const rows = Array.from(panelBody.querySelectorAll('tr[data-address]'));
	let session = 0;
	let timer = null;
	let controller = null;

	function setNote(visible) {
		if (note) {
			note.textContent = 'Some checks could not be refreshed. Previous results are retained.';
			note.hidden = !visible;
		}
	}

	// One selected listener per request. Only its State cell and data-state change, and only for a response that proves it.
	async function check(row, current) {
		const address = row.getAttribute('data-address');
		const own = new AbortController();
		const timeout = setTimeout(function() { own.abort(); }, 15000);
		controller = own;
		try {
			const response = await fetch('pfblockerng_dns_general.php?ajax=ddr&listener=' + encodeURIComponent(address), {
				cache: 'no-store',
				credentials: 'same-origin',
				signal: own.signal
			});
			if (!response.ok || response.redirected ||
			    !(response.headers.get('Content-Type') || '').includes('application/json')) {
				throw new Error('Invalid DDR response');
			}
			const result = await response.json();
			if (!result || typeof result.html !== 'string') {
				throw new Error('Invalid DDR panel');
			}
			const parsed = new DOMParser().parseFromString(result.html, 'text/html');
			const panels = parsed.querySelectorAll('#pfb-dns-status-ddr > #pfb-dns-status-ddr_panel-body');
			if (panels.length !== 1) {
				throw new Error('Missing DDR panel');
			}
			const returned = panels[0].querySelectorAll('tr[data-address]');
			const matches = Array.from(returned).filter(function(candidate) {
				return candidate.getAttribute('data-address') === address && candidate.cells.length === 3;
			});
			const state = returned.length === 1 && matches.length === 1 ? matches[0].getAttribute('data-state') : null;
			if (!state) {
				throw new Error('Missing DDR row');
			}
			if (current === session) {
				row.setAttribute('data-state', state);
				row.cells[2].replaceChildren(...matches[0].cells[2].childNodes);
			}
		} finally {
			clearTimeout(timeout);
			if (controller === own) {
				controller = null;
			}
		}
	}

	async function sweep(current) {
		panelBody.setAttribute('aria-busy', 'true');
		let complete = true;
		for (const row of rows) {
			try {
				await check(row, current);
			} catch (error) {
				if (current === session) {
					complete = false;
					setNote(true);
				}
			}
			if (current !== session) {
				return;
			}
		}
		panelBody.removeAttribute('aria-busy');
		if (complete) {
			setNote(false);
		}
	}

	// The next sweep starts 30 seconds after this one finishes, so sweeps never overlap.
	function cycle(current) {
		sweep(current).then(function() {
			if (current === session) {
				timer = setTimeout(function() { cycle(current); }, 30000);
			}
		});
	}

	function start() {
		session += 1;
		cycle(session);
	}

	start();
	window.addEventListener('pagehide', function() {
		session += 1;
		clearTimeout(timer);
		timer = null;
		if (controller) {
			controller.abort();
		}
		panelBody.removeAttribute('aria-busy');
	});
	window.addEventListener('pageshow', function(event) {
		if (event.persisted) {
			start();
		}
	});
});
</script>
