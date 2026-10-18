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

$pconfig = array();
$pconfig['pfb_dns'] = PfbConfig::read('dns/pfb_dns');
// issue #3515: the one DNS Reply Logging preference (dnsbl/pfb_py_reply) both DNS modes read: the DNSBL module's own log, and
// the proxy's --reply-log while DNSBL is off. Its control is here because this page is reachable in either mode.
$pconfig['pfb_py_reply'] = PfbConfig::read('dnsbl/pfb_py_reply');

$input_errors = array();

if ($_POST) {
	if (isset($_POST['save'])) {
		$pfb_dns = pfb_filter($_POST['pfb_dns'] ?? '', PFB_FILTER_ON_OFF, 'pfb_dns') ?: '';
		$pfb_py_reply = pfb_filter($_POST['pfb_py_reply'] ?? '', PFB_FILTER_ON_OFF, 'dnsbl') ?: '';	// checkbox-absent is the owner-ruled empty Off token (issue #1907)

		// issue #3515: the apply moves and restores the Resolver (config.xml keys and the snapshot kept in this section)
		// under this lock, from a fresh read. Hold it from a fresh read through write_config(), so this save cannot write
		// back a copy that predates a move or a restore.
		$pfb_config_lock = pfb_dns_config_lock();
		if ($pfb_config_lock === NULL) {
			$input_errors[] = 'pfB-DNS: another save of the pfSense configuration is in progress, so this setting was not saved. Save again in a moment.';
		}

		if (!$input_errors) {
			PfbConfig::write('dnsbl/pfb_py_reply', $pfb_py_reply);
			PfbConfig::write('dns/pfb_dns', $pfb_dns);
			write_config('[pfBlockerNG] save pfB-DNS settings');
			unlock($pfb_config_lock);
			pfb_mark_pending_changes();	// applies on the next Update, not on save
			header('Location: /pfblockerng/pfblockerng_dns.php');
			exit;
		}

		$pconfig['pfb_dns'] = $_POST['pfb_dns'] ?? '';	// Restore the submitted state on input errors
		$pconfig['pfb_py_reply'] = $_POST['pfb_py_reply'] ?? '';
	}
}

$pgtitle = array(gettext('Firewall'), gettext('pfBlockerNG'), gettext('pfB-DNS'));
$pglinks = array('', '/pfblockerng/pfblockerng_general.php', '@self');
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
$tab_array[]	= array(gettext('DNSBL'),	FALSE,	'/pfblockerng/pfblockerng_dnsbl.php');
$tab_array[]	= array(gettext('pfB-DNS'),	TRUE,	'/pfblockerng/pfblockerng_dns.php');
$tab_array[]	= array(gettext('Update'),	FALSE,	'/pfblockerng/pfblockerng_update.php');
$tab_array[]	= array(gettext('Reports'),	FALSE,	"/pfblockerng/pfblockerng_alerts.php{$get_req}");
$tab_array[]	= array(gettext('Feeds'),	FALSE,	'/pfblockerng/pfblockerng_feeds.php');
$tab_array[]	= array(gettext('Logs'),	FALSE,	'/pfblockerng/pfblockerng_log.php');
$tab_array[]	= array(gettext('Sync'),	FALSE,	'/pfblockerng/pfblockerng_sync.php');
pfb_software_add_tab($tab_array);
$tab_array[]	= array(gettext('Wizard'),	FALSE,	'/wizard.php?xml=pfblockerng_wizard.xml');
display_top_tabs($tab_array, TRUE);
pfb_print_pending_changes_box();

$form = new Form('Save pfB-DNS settings');

$section = new Form_Section('pfB-DNS Settings');
$section->addInput(new Form_Checkbox(
	'pfb_dns',
	gettext('pfB-DNS'),
	'Enable',
	pfb_cfg_toggle_read($pconfig['pfb_dns']) === PfbToggle::On,
	'on'
))->setHelp('<i class="fa fa-exclamation-triangle text-warning"></i> <span class="text-warning"><strong>Experimental.</strong></span> '
		. 'Runs pfBlockerNG\'s DNS proxy on the DNS Resolver\'s network interfaces and Listen Port, with or without DNSBL. '
		. 'The proxy forwards every query to the DNS Resolver with the client\'s address (PROXY protocol v2), so the Resolver sees and logs the real client. '
		. 'With DNSBL enabled the proxy also answers DNSBL blocks itself and the Resolver no longer loads the DNSBL Python module; '
		. 'with DNSBL disabled the proxy makes no DNSBL decision and loads no DNSBL module (the Resolver only runs a small inert script, which lets pfSense start the proxy during boot).'
		. '<div class="infoblock">'
		. 'Enabling it changes these DNS Resolver settings: Network Interfaces becomes Localhost (the Listen Port is not changed, and must be neither 5353 nor 5354: the proxy and the Resolver use those loopback ports), '
		. 'SSL/TLS Service is turned off (the proxy serves DNS over TLS with the Resolver\'s certificate instead), '
		. 'and a <code>server:</code> clause marked <code># pfBlockerNG DNS proxy</code> is added at the end of Custom options: '
		. 'the Resolver moves to 127.0.0.1 and ::1 port 5354 and also listens on port 5353 for the proxy, and the IPv6 networks of its interfaces stay allowed. '
		. 'Do not set <code>port:</code> or listen on those two ports in Custom options. '
		. 'A Custom options line with <code>interface:</code>, <code>port:</code> or <code>include:</code> (or a marker line without its partner) stops the move: nothing is changed and a notice names the line. '
		. 'Includes are refused because the file they name cannot be checked; turning this option off is never refused.<br />'
		. 'The previous values are saved and restored when this option is turned off, when pfBlockerNG is disabled, or when the package is removed; '
		. 'edits made to Custom options in between are replaced by the saved ones then.<br />'
		. 'The firewall\'s own DNS lookups go through the proxy. The proxy starts together with the DNS Resolver, also at boot, so they are served while the system starts.<br />'
		. '<strong>High availability:</strong> the DNS Resolver sync copies these settings to the secondary node. '
		. 'Enable this option on the secondary node first, before the primary syncs the changed DNS Resolver, or turn the DNS Resolver sync off.<br />'
		. 'The change is applied on the next Update.<br />'
		. 'Default: <strong>Disabled</strong>'
		. '</div>');
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

$status = pfb_dns_status();
$section = new Form_Section('pfB-DNS Status');
$section->addInput(new Form_StaticText('Service', htmlspecialchars($status['service'])));
$section->addInput(new Form_StaticText('Mode', htmlspecialchars($status['mode'])));
$section->addInput(new Form_StaticText('Listening on', htmlspecialchars($status['listen'])));
$section->addInput(new Form_StaticText('DNS over TLS', htmlspecialchars($status['dot'])));
$form->add($section);

print ($form);

include('foot.inc');
?>
