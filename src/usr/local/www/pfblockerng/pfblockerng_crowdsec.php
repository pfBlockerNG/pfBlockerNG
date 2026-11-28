<?php
/*
 * pfblockerng_crowdsec.php
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

// The CrowdSec tab's Settings subtab (docs/specs/crowdsec-integration.md, D2-D4). The bouncer key is never rendered back.

require_once('guiconfig.inc');
require_once('globals.inc');
require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');

global $pfb;
pfb_global();

$interfaces = get_configured_interface_with_descr();
$settings = pfb_crowdsec_settings();
$key_stored = $settings['api_key'] !== '';

$pconfig = array();
foreach ($settings as $field => $value) {
	$pconfig[$field] = $value instanceof PfbToggle ? $value->toStored() : $value;
}
unset($pconfig['api_key']);

$input_errors = array();
if ($_POST && isset($_POST['save'])) {
	$checked = pfb_crowdsec_validate($_POST, (string) $settings['api_key'], array_map('strval', array_keys($interfaces)));
	$input_errors = $checked['errors'];
	if (!$input_errors) {
		pfb_crowdsec_save($checked['values']);
		$pfb['save'] = TRUE;
		sync_package_pfblockerng();
		header('Location: ' . PFB_CROWDSEC_PAGE);
		exit;
	}
	// Show what was posted again, for correction; never the key
	$pconfig = array_diff_key($checked['values'], array('api_key' => ''));
	$pconfig['rules_interfaces'] = implode(',', array_filter((array) ($_POST['rules_interfaces'] ?? array()), 'is_string'));
}

$pgtitle = array(gettext('Firewall'), gettext('pfBlockerNG'), gettext('CrowdSec'), gettext('Settings'));
$pglinks = array('', '/pfblockerng/pfblockerng_general.php', PFB_CROWDSEC_PAGE, '@self');
$shortcut_section = 'pfblockerng';
include_once('head.inc');

if ($input_errors) {
	print_input_errors($input_errors);
}

pfb_crowdsec_display_tabs(PFB_CROWDSEC_PAGE);

$form = new Form('Save');

$section = new Form_Section('CrowdSec Bouncer');
$section->addInput(new Form_Checkbox(
	'enable',
	'CrowdSec',
	gettext('Enable'),
	$pconfig['enable'] === 'on',
	'on'
))->setHelp('Drop the addresses a remote CrowdSec Security Engine bans, on every selected interface, in both directions. '
	. 'The bouncer runs only while pfBlockerNG is enabled and this firewall has its own key.');

$section->addInput(new Form_Input(
	'lapi_url',
	gettext('Remote LAPI URL'),
	'text',
	$pconfig['lapi_url'],
	['placeholder' => 'http://192.0.2.10:8080']
))->setHelp('The engine\'s Local API, <code>http://</code> or <code>https://</code>.');

$section->addInput(new Form_Input(
	'api_key',
	gettext('Bouncer API key'),
	'password',
	'',
	['placeholder' => $key_stored ? gettext('A key is stored -- leave blank to keep it') : '', 'autocomplete' => 'new-password']
))->setHelp('On the engine, register this firewall with <code>cscli bouncers add &lt;name&gt;</code> and paste the key it prints. '
	. 'Each firewall needs its own key, which never leaves it. '
	. ($key_stored ? '<strong>A key is stored.</strong> Leave blank on Save to keep it.' : 'No key is stored.'));

$section->addInput(new Form_Select(
	'log_level',
	gettext('Log level'),
	$pconfig['log_level'],
	array_combine(PFB_CROWDSEC_LOG_LEVELS, PFB_CROWDSEC_LOG_LEVELS)
))->setHelp('The bouncer logs to the system log, tagged <code>pfb_crowdsec</code>, each line at its own syslog severity. pfSense keeps '
	. 'only lines at or above <strong>Status &gt; System Logs &gt; Settings</strong>\' log level (notice by default on CE 2.9 and Plus): '
	. 'to see info or debug lines, choose that level there too. pfSense\'s own logs reach the engine through '
	. '<strong>Status &gt; System Logs &gt; Settings &gt; Remote Logging</strong>, which pfBlockerNG does not configure.')
  ->setAttribute('style', 'width: auto');
$form->add($section);

$section = new Form_Section('Firewall Rules');
$section->addInput(new Form_Checkbox(
	'rules_all_interfaces',
	gettext('All interfaces'),
	gettext('Enable'),
	$pconfig['rules_all_interfaces'] === 'on',
	'on'
))->setHelp('Apply the rules on every interface. Uncheck to select the interfaces below.');

$section->addInput(new Form_Select(
	'rules_interfaces',
	gettext('Interface(s)'),
	pfb_csv_list($pconfig['rules_interfaces']),
	$interfaces,
	TRUE
))->setHelp('The interfaces the rules apply on when <strong>All interfaces</strong> is unchecked.')
  ->setAttribute('size', (string) max(1, min(10, count($interfaces))));

$section->addInput(new Form_Checkbox(
	'rules_log',
	gettext('Log blocked packets'),
	gettext('Enable'),
	$pconfig['rules_log'] === 'on',
	'on'
));

$section->addInput(new Form_Input(
	'rules_tag',
	gettext('Tag'),
	'text',
	$pconfig['rules_tag']
))->setHelp('Optional pf tag on the rules: up to 63 letters, digits, <code>_</code> or <code>-</code>.');

$section->addInput(new Form_Checkbox(
	'rule_v4',
	gettext('IPv4 rules'),
	gettext('Enable'),
	$pconfig['rule_v4'] === 'on',
	'on'
));

$section->addInput(new Form_Checkbox(
	'rule_v6',
	gettext('IPv6 rules'),
	gettext('Enable'),
	$pconfig['rule_v6'] === 'on',
	'on'
));
$form->add($section);

$section = new Form_Section('HAProxy SPOA Listener');
$section->addInput(new Form_Checkbox(
	'spoa_enable',
	gettext('HAProxy SPOA'),
	gettext('Enable'),
	($pconfig['spoa_enable'] ?? '') === 'on',
	'on'
))->setHelp('Expose a local HAProxy SPOP (SPOA) listener serving cached CrowdSec LAPI decisions with zero fail-closed 503 outages during remote LAPI restarts. '
	. 'Returns <code>txn.crowdsec.remediation</code>, <code>txn.crowdsec.origin</code>, and <code>txn.crowdsec.scenario</code>.');

$section->addInput(new Form_Input(
	'spoa_listen',
	gettext('SPOA Listen Address'),
	'text',
	$pconfig['spoa_listen'] ?? PFB_CROWDSEC_SPOA_DEFAULT_LISTEN,
	['placeholder' => PFB_CROWDSEC_SPOA_DEFAULT_LISTEN]
))->setHelp('Default: <strong>127.0.0.1:10091</strong> (works with pfSense HAProxy\'s default <code>/var/empty</code> chroot). '
	. 'Accepts <code>127.0.0.1:&lt;port&gt;</code>, <code>[::1]:&lt;port&gt;</code>, or <code>unix:/abs/path/to/spoa.sock</code>.');

$section->addInput(new Form_Input(
	'appsec_url',
	gettext('AppSec Engine URL (optional)'),
	'text',
	$pconfig['appsec_url'] ?? '',
	['placeholder' => 'http://192.0.2.10:7422']
))->setHelp('Optional CrowdSec Security Engine AppSec endpoint for L7 WAF inspection of requests not already blocked locally. Leave blank for pure local IP/range remediation.');

$section->addInput(new Form_Input(
	'appsec_timeout',
	gettext('AppSec Timeout'),
	'text',
	$pconfig['appsec_timeout'] ?? PFB_CROWDSEC_APPSEC_DEFAULT_TIMEOUT,
	['placeholder' => PFB_CROWDSEC_APPSEC_DEFAULT_TIMEOUT]
))->setHelp('Bounded HTTP timeout per AppSec check (50ms to 30s, default <strong>500ms</strong>).');

$section->addInput(new Form_Select(
	'appsec_failure_action',
	gettext('AppSec Failure Action'),
	$pconfig['appsec_failure_action'] ?? 'passthrough',
	['passthrough' => gettext('Passthrough (fail-open, recommended)'), 'deny' => gettext('Deny (fail-closed)')]
))->setHelp('Action when the remote AppSec endpoint times out or is unreachable. <strong>Passthrough</strong> avoids 503 outages during Security Engine restarts.')
  ->setAttribute('style', 'width: auto');

$coreListen = (string) PfbConfig::read('ip/spoa_listen');
$csListen = ($pconfig['spoa_listen'] ?? '') !== '' ? (string) $pconfig['spoa_listen'] : PFB_CROWDSEC_SPOA_DEFAULT_LISTEN;
$snippets = pfb_spoa_haproxy_snippets(
	$coreListen !== '' ? $coreListen : PFB_CORE_SPOA_DEFAULT_LISTEN,
	$csListen,
	($pconfig['appsec_url'] ?? '') !== '',
	($pconfig['appsec_timeout'] ?? '') !== '' ? (string) $pconfig['appsec_timeout'] : PFB_CROWDSEC_APPSEC_DEFAULT_TIMEOUT,
	($pconfig['appsec_failure_action'] ?? '') !== '' ? (string) $pconfig['appsec_failure_action'] : 'passthrough'
);
$section->addInput(new Form_StaticText(
	gettext('HAProxy SPOE Snippet'),
	'<p>Copy into HAProxy\'s SPOE engine config (<code>/var/etc/haproxy/spoe-pfb-crowdsec.conf</code>) and frontend/backend settings:</p>'
	. '<pre style="max-height:240px;overflow:auto;">'
	. htmlspecialchars($snippets['spoe_crowdsec'] . "\n\n" . $snippets['haproxy_backends'] . "\n\n" . $snippets['haproxy_frontend'], ENT_QUOTES, 'UTF-8')
	. '</pre>'
));
$form->add($section);

print($form);
include('foot.inc');
?>
