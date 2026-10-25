<?php
/*
 * pfblockerng_dns.php
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
// issue #3515: the one DNS Reply Logging preference (dnsbl/pfb_py_reply) both DNS modes read: the DNSBL module's own log, and
// the proxy's --reply-log while DNSBL is off. Its control is here because this page is reachable in either mode.
$pconfig['pfb_py_reply'] = PfbConfig::read('dnsbl/pfb_py_reply');
// issues #3513, #3538: pfB-DNS's listener and certificate settings. A setting not seeded yet shows the value the seed will write;
// an interface list is split into the tokens the proxy reads from it (issue #3557: spaces too, as a hand edit may leave)
$pconfig['pfb_dns_interface']		= pfb_dns_proxy_tokens((string) pfb_dns_proxy_setting('pfb_dns_interface'));
$pconfig['pfb_dns_sslcertref']		= pfb_dns_proxy_setting('pfb_dns_sslcertref');
$pconfig['pfb_dns_dot']			= pfb_dns_proxy_setting('pfb_dns_dot');
$pconfig['pfb_dns_dot_port']		= pfb_dns_proxy_setting('pfb_dns_dot_port');
$pconfig['pfb_dns_dot_interface']	= pfb_dns_proxy_tokens((string) pfb_dns_proxy_setting('pfb_dns_dot_interface'));
$pconfig['pfb_dns_doh']			= PfbConfig::read('dns/pfb_dns_doh');
$pconfig['pfb_dns_doh_port']		= PfbConfig::read('dns/pfb_dns_doh_port');
$pconfig['pfb_dns_doh_interface']	= pfb_dns_proxy_tokens((string) pfb_dns_proxy_setting('pfb_dns_doh_interface'));
$pconfig['pfb_dns_doh_trusted']		= PfbConfig::read('dns/pfb_dns_doh_trusted');
$pconfig['pfb_dns_doq']			= PfbConfig::read('dns/pfb_dns_doq');
$pconfig['pfb_dns_doq_port']		= PfbConfig::read('dns/pfb_dns_doq_port');
$pconfig['pfb_dns_doq_interface']	= pfb_dns_proxy_tokens((string) pfb_dns_proxy_setting('pfb_dns_doq_interface'));
// issue #3583: DDR (RFC 9462) answers, and the option that leaves the port out of the DoH record they carry
$pconfig['pfb_dns_ddr']			= PfbConfig::read('dns/pfb_dns_ddr');
$pconfig['pfb_dns_ddr_doh_443']		= PfbConfig::read('dns/pfb_dns_ddr_doh_443');
// The Resolver's Network Interfaces (virtual IPs included) plus every stored token no longer offered (issue #3557)
$options_dns_interface = pfb_dns_proxy_interface_options();
// The certificates the Resolver offers: the same call, so the same list and descriptions
$options_dns_cert = cert_build_list('cert', 'IPsec');

$input_errors = array();

if ($_POST) {
	if (isset($_POST['save'])) {
		// issue #1723: sanitize at ingestion -- first step, before any evaluation.
		foreach (array('pfb_dns_dot_port', 'pfb_dns_doh_port', 'pfb_dns_doq_port', 'pfb_dns_doh_trusted') as $pfb_text_field) {
			$_POST[$pfb_text_field] = pfb_sanitize_text((string) ($_POST[$pfb_text_field] ?? ''));
		}

		$pfb_dns = pfb_filter($_POST['pfb_dns'] ?? '', PFB_FILTER_ON_OFF, 'pfb_dns') ?: '';
		$pfb_py_reply = pfb_filter($_POST['pfb_py_reply'] ?? '', PFB_FILTER_ON_OFF, 'dnsbl') ?: '';	// checkbox-absent is the owner-ruled empty Off token (issue #1907)

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
				PfbConfig::write('dns/' . $pfb_dns_key, $pfb_dns_value);
			}
			PfbConfig::write('dnsbl/pfb_py_reply', $pfb_py_reply);
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
				header('Location: /pfblockerng/pfblockerng_dns.php');
				exit;
			}
			$input_errors[] = 'pfB-DNS: the configuration could not be written, so these settings were not saved. Save again in a moment.';
		}

		$pconfig['pfb_dns'] = $_POST['pfb_dns'] ?? '';	// Restore the submitted state on input errors
		$pconfig['pfb_py_reply'] = $_POST['pfb_py_reply'] ?? '';
		foreach (array('pfb_dns_dot', 'pfb_dns_dot_port', 'pfb_dns_doh', 'pfb_dns_doh_port', 'pfb_dns_doh_trusted', 'pfb_dns_doq', 'pfb_dns_doq_port', 'pfb_dns_ddr', 'pfb_dns_ddr_doh_443', 'pfb_dns_sslcertref') as $pfb_dns_field) {
			$pconfig[$pfb_dns_field] = $_POST[$pfb_dns_field] ?? '';
		}
		if (pfb_dns_proxy_ddr_doh_443_locked()) {
			$pconfig['pfb_dns_ddr_doh_443'] = PfbConfig::read('dns/pfb_dns_ddr_doh_443');	// a disabled control posts nothing: the form shows the stored value, as the save keeps it
		}
		foreach (array('pfb_dns_interface', 'pfb_dns_dot_interface', 'pfb_dns_doh_interface', 'pfb_dns_doq_interface') as $pfb_dns_field) {
			$pconfig[$pfb_dns_field] = array_filter((array) ($_POST[$pfb_dns_field] ?? array()), 'is_string');
		}
	}
}

$pgtitle = array(gettext('Firewall'), gettext('pfBlockerNG'), gettext('DNS'), gettext('pfB-DNS'));
$pglinks = array('', '/pfblockerng/pfblockerng_general.php', '/pfblockerng/pfblockerng_dns.php', '@self');
$shortcut_section = 'pfblockerng';
include_once('head.inc');

if ($input_errors) {
	print_input_errors($input_errors);
}

// Define default Alerts Tab href link (Top row)
$get_req = pfb_alerts_default_page();

$tab_array	= array();
$tab_array[]	= array(gettext('General'),	FALSE,	'/pfblockerng/pfblockerng_general.php');
$tab_array[]	= array(gettext('IP'),		FALSE,	'/pfblockerng/pfblockerng_ip.php');
$tab_array[]	= array(gettext('DNS'),	TRUE,	'/pfblockerng/pfblockerng_dns.php');
$tab_array[]	= array(gettext('Update'),	FALSE,	'/pfblockerng/pfblockerng_update.php');
$tab_array[]	= array(gettext('Reports'),	FALSE,	"/pfblockerng/pfblockerng_alerts.php{$get_req}");
$tab_array[]	= array(gettext('Feeds'),	FALSE,	'/pfblockerng/pfblockerng_feeds.php');
$tab_array[]	= array(gettext('Logs'),	FALSE,	'/pfblockerng/pfblockerng_log.php');
$tab_array[]	= array(gettext('Sync'),	FALSE,	'/pfblockerng/pfblockerng_sync.php');
pfb_software_add_tab($tab_array);
$tab_array[]	= array(gettext('Wizard'),	FALSE,	'/wizard.php?xml=pfblockerng_wizard.xml');
display_top_tabs($tab_array, TRUE);
$tab_array	= array();
$tab_array[]	= array(gettext('pfB-DNS'),	TRUE,	'/pfblockerng/pfblockerng_dns.php');
$tab_array[]	= array(gettext('DNSBL'),	FALSE,	'/pfblockerng/pfblockerng_dnsbl.php');
$tab_array[]	= array(gettext('DNSBL Groups'),	FALSE,	'/pfblockerng/pfblockerng_category.php?type=dnsbl');
$tab_array[]	= array(gettext('DNSBL Category'),	FALSE,	'/pfblockerng/pfblockerng_blacklist.php');
$tab_array[]	= array(gettext('DNSBL SafeSearch'),	FALSE,	'/pfblockerng/pfblockerng_safesearch.php');
display_top_tabs($tab_array, TRUE);
pfb_print_pending_changes_box();
foreach (pfb_dns_proxy_ddr_warnings() as $pfb_ddr_warning) {
	print_info_box($pfb_ddr_warning, 'warning', FALSE);
}

$form = new Form('Save pfB-DNS settings');

$section = new Form_Section('pfB-DNS Settings');
$section->addInput(new Form_Checkbox(
	'pfb_dns',
	gettext('pfB-DNS'),
	'Enable',
	pfb_cfg_toggle_read($pconfig['pfb_dns']) === PfbToggle::On,
	'on'
))->setHelp('<i class="fa fa-exclamation-triangle"></i> <strong>Experimental.</strong> '
		. 'Runs pfBlockerNG\'s DNS proxy on the DNS Resolver\'s network interfaces and Listen Port, with or without DNSBL. '
		. 'The proxy forwards every query to the DNS Resolver with the client\'s address (PROXY protocol v2), so the Resolver sees and logs the real client. '
		. 'With DNSBL enabled the proxy also answers DNSBL blocks itself and the Resolver no longer loads the DNSBL Python module; '
		. 'with DNSBL disabled the proxy makes no DNSBL decision and loads no DNSBL module (the Resolver only runs a small inert script, which lets pfSense start the proxy during boot).'
		. '<div class="infoblock">'
		. 'Enabling it changes these DNS Resolver settings: Network Interfaces becomes Localhost (the Listen Port is not changed, and must be neither 5353 nor 5354: the proxy and the Resolver use those loopback ports), '
		. 'SSL/TLS Service is turned off (pfB-DNS serves DNS over TLS from its own DoT settings below), '
		. 'and a <code>server:</code> clause marked <code># pfBlockerNG DNS proxy</code> is added at the end of Custom options: '
		. 'the Resolver moves to 127.0.0.1 and ::1 port 5354 and also listens on port 5353 for the proxy, and the IPv6 networks of its interfaces stay allowed. '
		. 'Do not set <code>port:</code> or listen on those two ports in Custom options. '
		. 'A Custom options line with <code>interface:</code>, <code>port:</code> or <code>include:</code> (or a marker line without its partner) stops the move: nothing is changed and a notice names the line. '
		. 'Such a line added after the move turns pfB-DNS off and restores the Resolver, keeping your line, and a notice names it. '
		. 'Includes are refused because the file they name cannot be checked; turning this option off is never refused.<br />'
		. 'The previous values are saved and restored when this option is turned off, when pfBlockerNG is disabled, or when the package is removed; '
		. 'edits made to Network Interfaces, SSL/TLS Service or Custom options in between are replaced by the saved ones then.<br />'
		. 'Disabling the DNS Resolver while this option is on stops the proxy, restores the saved values (the Resolver stays disabled) and turns this option off, with a notice.<br />'
		. 'The firewall\'s own DNS lookups go through the proxy. The proxy starts together with the DNS Resolver, also at boot, so they are served while the system starts.<br />'
		. '<strong>High availability:</strong> the DNS Resolver sync copies these settings to the secondary node. '
		. 'With the sync on, do not enable this option on the primary before the secondary: the secondary then gets the moved Resolver with no saved snapshot and refuses it on every apply. '
		. 'Do not turn it off on the primary while the secondary still has it on: the restored Resolver settings reach the secondary, whose Unbound then collides with its running proxy on the client port. '
		. 'Enable it on the secondary first, or turn the DNS Resolver sync off.<br />'
		. 'The interface, DoT and certificate settings below are taken from the DNS Resolver once, the first time this page loads or pfB-DNS is turned on; later Resolver changes do not alter them.<br />'
		. 'The change is applied on the next Update.<br />'
		. 'Default: <strong>Disabled</strong>'
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
  ->setHelp('Interfaces pfB-DNS answers plain DNS on, at the DNS Resolver\'s Listen Port. Loopback (127.0.0.1 and ::1) is always served: the firewall\'s own lookups go through pfB-DNS. '
		. 'Localhost: loopback only. All: every address of the firewall. At least one entry is required.');

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
$form->add($section);

$section = new Form_Section('DNS over TLS (DoT)');
$section->addInput(new Form_Checkbox(
	'pfb_dns_dot',
	gettext('DoT'),
	'Enable',
	pfb_cfg_toggle_read($pconfig['pfb_dns_dot'] ?? NULL) === PfbToggle::On,
	'on'
))->setHelp('<i class="fa fa-exclamation-triangle"></i> <strong>Experimental.</strong> '
		. 'Serves DNS over TLS (RFC 7858) from pfB-DNS, with or without DNSBL. Requires the SSL/TLS Certificate selected above.'
		. '<div class="infoblock">The change is applied on the next Update. Default: <strong>Disabled</strong></div>');

$section->addInput(new Form_Input(
	'pfb_dns_dot_port',
	gettext('DoT Port'),
	'number',
	$pconfig['pfb_dns_dot_port'],
	[ 'min' => 1, 'max' => 65535, 'placeholder' => 'Enter DoT Listening Port' ]
))->setHelp('Example ( 853 ) &mdash; a single PORT in the range 1 - 65535 (TCP).');

$section->addInput(new Form_Select(
	'pfb_dns_dot_interface',
	gettext('DoT Interface(s)'),
	$pconfig['pfb_dns_dot_interface'] ?? [],
	$options_dns_interface,
	TRUE
))->setAttribute('style', 'width: auto')
  ->setAttribute('size', count($options_dns_interface) ?: '1')
  ->setAttribute('aria-label', gettext('DoT Interface(s)'))
  ->setHelp('Interface(s) DoT listens on, besides loopback (127.0.0.1 and ::1), which is always served. At least one entry is required.');
$form->add($section);

$section = new Form_Section('DNS over HTTPS (DoH)');
$section->addInput(new Form_Checkbox(
	'pfb_dns_doh',
	gettext('DoH'),
	'Enable',
	pfb_cfg_toggle_read($pconfig['pfb_dns_doh'] ?? NULL) === PfbToggle::On,
	'on'
))->setHelp('<i class="fa fa-exclamation-triangle"></i> <strong>Experimental.</strong> '
		. 'Serves DNS over HTTPS (RFC 8484, <code>/dns-query</code>) from pfB-DNS, with or without DNSBL. It needs the pfB-DNS binary (<code>pfb-dns</code>). '
		. 'Requires the SSL/TLS Certificate selected above.'
		. '<div class="infoblock">The change is applied on the next Update. Default: <strong>Disabled</strong></div>');

$section->addInput(new Form_Input(
	'pfb_dns_doh_port',
	gettext('DoH Port'),
	'number',
	$pconfig['pfb_dns_doh_port'],
	[ 'min' => 1, 'max' => 65535, 'placeholder' => 'Enter DoH Listening Port' ]
))->setHelp('Example ( 4443 ) &mdash; a single PORT in the range 1 - 65535 (TCP).');

$section->addInput(new Form_Select(
	'pfb_dns_doh_interface',
	gettext('DoH Interface(s)'),
	$pconfig['pfb_dns_doh_interface'] ?? [],
	$options_dns_interface,
	TRUE
))->setAttribute('style', 'width: auto')
  ->setAttribute('size', count($options_dns_interface) ?: '1')
  ->setAttribute('aria-label', gettext('DoH Interface(s)'))
  ->setHelp('Interface(s) DoH listens on, besides loopback (127.0.0.1 and ::1), which is always served for a local front end. At least one entry is required.');

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
		. 'Serves DNS over QUIC (RFC 9250) from pfB-DNS, with or without DNSBL. It needs the pfB-DNS binary (<code>pfb-dns</code>). DoQ is UDP. '
		. 'Requires the SSL/TLS Certificate selected above.'
		. '<div class="infoblock">The change is applied on the next Update. Default: <strong>Disabled</strong></div>');

$section->addInput(new Form_Input(
	'pfb_dns_doq_port',
	gettext('DoQ Port'),
	'number',
	$pconfig['pfb_dns_doq_port'],
	[ 'min' => 1, 'max' => 65535, 'placeholder' => 'Enter DoQ Listening Port' ]
))->setHelp('Example ( 853 ) &mdash; a single PORT in the range 1 - 65535 (UDP).');

$section->addInput(new Form_Select(
	'pfb_dns_doq_interface',
	gettext('DoQ Interface(s)'),
	$pconfig['pfb_dns_doq_interface'] ?? [],
	$options_dns_interface,
	TRUE
))->setAttribute('style', 'width: auto')
  ->setAttribute('size', count($options_dns_interface) ?: '1')
  ->setAttribute('aria-label', gettext('DoQ Interface(s)'))
  ->setHelp('Interface(s) DoQ listens on, besides loopback (127.0.0.1 and ::1). At least one entry is required.');
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
		. 'Answers Discovery of Designated Resolvers (RFC 9462) queries for <code>resolver.arpa</code> from pfB-DNS, so that clients that support DDR can find and switch to the encrypted transports enabled above (DoT, DoH, DoQ). '
		. 'Clients verify the certificate against the address they queried, as an IP address SAN. '
		. 'Disabled: the DNS Resolver answers these names, as before.'
		. '<div class="infoblock">The change is applied on the next Update. Default: <strong>Disabled</strong></div>');

// DoH already listens on 443, so there is no port to leave out
$pfb_ddr_doh_443 = (new Form_Checkbox(
	'pfb_dns_ddr_doh_443',
	gettext('DoH on port 443'),
	'Advertise DoH on port 443',
	pfb_cfg_toggle_read($pconfig['pfb_dns_ddr_doh_443'] ?? NULL) === PfbToggle::On,
	'on'
))->setAttribute('aria-label', gettext('DoH on port 443'));
if (pfb_dns_proxy_ddr_doh_443_locked()) {
	$pfb_ddr_doh_443->setAttribute('disabled', 'disabled');
}
$section->addInput($pfb_ddr_doh_443)->setHelp('Some clients might not accept a port for the DoH server provided over DDR. '
		. 'This option removes the port, so clients reach DoH on port 443. '
		. 'If DoH is not already listening on port 443, it will no longer be reachable. '
		. 'It is intended for users who, for example, serve multiple sites over HTTPS through a reverse proxy, '
		. 'and who are responsible for configuring that reverse proxy correctly.'
		. '<div class="infoblock">The change is applied on the next Update. Default: <strong>Disabled</strong></div>');
$form->add($section);

$section = new Form_Section('DNS Reply Logging');
$section->addInput(new Form_Checkbox(
	'pfb_py_reply',
	gettext('DNS Reply Logging'),
	'Enable',
	pfb_dnsbl_toggle_enabled($pconfig['pfb_py_reply'] ?? NULL),
	'on'
))->setHelp('Log each DNS reply to the DNS Reply log (the client, the name asked, the reply type, TTL and answer, and the answer\'s country), '
		. 'which fills the DNS Reply tab of Reports.'
		. '<div class="infoblock">'
		. 'This one setting applies to both DNS modes. With DNSBL enabled, the DNSBL Python module logs the replies that were not blocked. '
		. 'With pfB-DNS enabled and DNSBL disabled, the pfB-DNS proxy logs every reply it forwards from the DNS Resolver, '
		. 'without loading any DNSBL feed or module. '
		. 'Disabled: no reply is logged, and nothing is written to the DNS Reply log.<br />'
		. 'The log lists the names each client looked up: keep this disabled where that must not be recorded.<br />'
		. 'The change is applied on the next Update.<br />'
		. 'Default: <strong>Enabled</strong>'
		. '</div>');
$form->add($section);

print ($form);
print pfb_dns_status_panel(pfb_dns_status());

include('foot.inc');
?>
