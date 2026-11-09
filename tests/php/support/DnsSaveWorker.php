<?php

declare(strict_types=1);

/**
 * Child process for DnsSettingsSaveRaceTest, DnsblSaveWithPfbDnsOffTest and DnsGeneralPfbDnsFoldTest: executes the real POST save of
 * DNS > General (issue #3771: the pfB-DNS form and the DNS General form share that one page) over the PHPUnit doubles, with another
 * request's writes interleaved at the instant the save re-reads config.xml. The page cannot be included whole (it renders and exits),
 * so its save code is extracted from the shipped pfblockerng_dns_general.php. argv: scenario name, result file, mode, button.
 *
 * Modes (argv[3]): `dns` (default) runs the pfB-DNS handler, from its config lock to the end of `if (isset($_POST['save_pfb_dns']))`,
 * extracted by its tokens; `general` runs the DNS General handler `if ($_POST && isset($_POST['save']))` alone; `region` runs the page's
 * whole POST region (from `$input_errors = array();` to `$pgtitle =`: both handlers and their gates, validation included) with ONLY the
 * submit button of argv[4] (`save_pfb_dns` or `save`) and that form's own valid fields posted, as a browser sends them.
 *
 * Scenarios: `interleave` (an apply's Resolver move lands on disk after this request started), `lock_taken` (another
 * process holds the config lock), `read_fails` (the fresh read fails), `write_throws` (config.xml cannot be written),
 * `write_refused` (write_config answers FALSE), `write_failed` (file write fails: -1), `advert_write_fails` (DNS General selects a
 * listener VIP whose advertisement write_config answers FALSE while every other write succeeds), `dnsbl_on` (issue #3770: DNSBL is
 * stored On, which a save of pfB-DNS Off leaves as it is); any other name saves with nothing interleaved.
 * The result file holds what config.xml would contain afterwards ("disk") and before the save ("before"), the lock/read/write order,
 * the page's input errors, whether the config lock is still held, the reply-logging preference the form would show ("reply"), the
 * write_config() descriptions ("writes"), how often Unbound was regenerated ("unboundCalls") and whether
 * the save marked pending changes ("pendingMarked") or returned to render instead of exiting via redirect ("returned").
 */

$workerArgv = $argv;
$scenario = (string) $workerArgv[1];
$resultFile = (string) $workerArgv[2];
$repo = dirname(__DIR__, 3);
$mode = (string) ($workerArgv[3] ?? 'dns');
$region = $mode === 'region';
// The submit button the browser posts: the DNS General form's own, or the pfB-DNS form's.
$submit = $mode === 'general' ? 'save' : ($region ? (string) ($workerArgv[4] ?? '') : 'save_pfb_dns');
if (!in_array($submit, ['save', 'save_pfb_dns'], TRUE)) {
	throw new RuntimeException("worker: unknown submit button '{$submit}'");
}
$page = $repo . '/src/usr/local/www/pfblockerng/pfblockerng_dns_general.php';
$disk = $before = NULL;
$input_errors = [];
$pconfig = [];
$returned = FALSE;
$handedPost = [];

register_shutdown_function(static function () use ($resultFile, &$disk, &$before, &$input_errors, &$pconfig, &$returned, &$handedPost): void {
	file_put_contents($resultFile, json_encode([
		'disk'          => $disk,
		'before'        => $before,
		'events'        => $GLOBALS['pfb_test_lock_events'] ?? [],
		'lockHeld'      => !empty($GLOBALS['pfb_test_lock_held']),
		'inputErrors'   => $input_errors,
		'reply'         => $pconfig['pfb_py_reply'] ?? NULL,
		'pendingMarked' => is_file($GLOBALS['pfb']['pending_marker'] ?? ''),
		'returned'      => $returned,
		'writes'        => $GLOBALS['pfb_test_write_config_calls'] ?? [],
		'unboundCalls'  => count($GLOBALS['pfb_test_unbound_configure_calls'] ?? []),
		'posted'        => $handedPost,
	], JSON_THROW_ON_ERROR));
});

require_once $repo . '/tests/php/bootstrap.php';
require_once $repo . '/tests/php/SyncPrereqSeedTrait.php';

final class DnsSaveWorkerSeeder
{
	use SyncPrereqSeedTrait;

	public function seed(): void
	{
		$this->seedSyncPrereqs();
	}
}

/** The pfB-DNS save handler: from the config lock's first statement to the end of `if (isset($_POST['save_pfb_dns']))`. */
function dns_save_worker_block(string $source): string
{
	$anchor = '$pfb_config_lock = NULL;';
	$from = strpos($source, $anchor);
	if ($from === FALSE) {
		throw new RuntimeException('worker: DNS General has no pfB-DNS save handler (no config lock anchor)');
	}
	$tokens = token_get_all('<?php ' . substr($source, $from));
	$code = '';
	$depth = 0;
	foreach ($tokens as $token) {
		$text = is_array($token) ? $token[1] : $token;
		if ($text === '{' || (is_array($token) && in_array($token[0], [T_CURLY_OPEN, T_DOLLAR_OPEN_CURLY_BRACES], TRUE))) {
			$depth++;
		} elseif ($text === '}') {
			if (--$depth < 0) {
				return substr($code, strlen('<?php '));
			}
		}
		$code .= $text;
	}
	throw new RuntimeException('worker: the pfB-DNS save handler has no end');
}

/** The source between two markers (start inclusive, end exclusive), or a worker error naming the one that is missing. */
function dns_save_worker_region(string $source, string $start, string $end): string
{
	$from = strpos($source, $start);
	$to = strpos($source, $end);
	if ($from === FALSE || $to === FALSE || $to < $from) {
		throw new RuntimeException("worker: DNS General has no region {$start} .. {$end}");
	}
	return substr($source, $from, $to - $from);
}

$source = (string) file_get_contents($page);
$block = match ($mode) {
	'general' => dns_save_worker_region($source, 'if ($_POST &&', '$pgtitle ='),
	'region' => dns_save_worker_region($source, '$input_errors = array();', '$pgtitle ='),
	default => dns_save_worker_block($source),
};
$dnsbl = 'installedpackages/pfblockerngdnsblsettings/config/0';
$dns = 'installedpackages/pfblockerngdns/config/0';
$GLOBALS['config'] = [];
(new DnsSaveWorkerSeeder())->seed();
config_set_path("{$dns}/pfb_dns", 'on');	// pfB-DNS is on as the last apply left it
config_set_path("{$dnsbl}/pfb_py_reply", 'on');
config_set_path('unbound/active_interface', 'lan');
config_set_path('unbound/custom_options', base64_encode('do-ip6: no'));
// What the other requests wrote after this one started: an apply's Resolver move (snapshot, moved interface).
$other = $GLOBALS['config'];
$other['unbound']['active_interface'] = 'lo0';
$other['installedpackages']['pfblockerngdns']['config'][0]['pfb_dns_saved'] = base64_encode((string) json_encode([
	'active_interface' => ['present' => TRUE, 'value' => 'lan'],
	'enablessl'        => ['present' => FALSE, 'value' => ''],
	'custom_options'   => ['present' => TRUE, 'value' => base64_encode('do-ip6: no')],
]));
global $pfb;
pfb_global();
$tmp = $GLOBALS['pfb_test_tmp'];
$pfb['pending_marker'] = "{$tmp}/pending";
// The page renders the stored preference before the save: a failed save re-displays what the form posted, not this.
$pconfig['pfb_py_reply'] = PfbConfig::read('dnsbl/pfb_py_reply');
// The posted form: the clicked form's button, and for DNS General its own fields (each form posts only its own).
$_POST = [$submit => 'Save'];
$pfb_dns = '';
if ($submit === 'save') {
	$_POST += ['pfb_dns_listen_vip4' => 'none', 'pfb_dns_listen_vip6' => 'none', 'pfb_dns_listen_interface' => 'lo0'];
	$options_dns_listen_vip4 = $options_dns_listen_vip6 = ['none' => '', 'auto' => 'Create VIP automatically'];
	$options_dns_listen_interface = ['lo0' => 'Localhost'];
}
if ($region && $submit === 'save_pfb_dns') {
	// A complete valid pfB-DNS form with pfB-DNS turned On, DoT, DoH and DDR on and DoQ off; its option lists are the page's, as the page loads them.
	$options_dns_interface = ['lo0' => 'Localhost'];
	$options_dns_cert = ['cert1' => 'Certificate'];
	$_POST += [
		'pfb_dns' => 'on', 'pfb_dns_interface' => ['lo0'], 'pfb_dns_sslcertref' => 'cert1', 'pfb_dns_name' => 'fw.example.lan',
		'pfb_dns_dot' => 'on', 'pfb_dns_dot_port' => '853', 'pfb_dns_dot_port6' => '', 'pfb_dns_dot_interface' => ['lo0'],
		'pfb_dns_doh' => 'on', 'pfb_dns_doh_port' => '4443', 'pfb_dns_doh_port6' => '', 'pfb_dns_doh_interface' => ['lo0'], 'pfb_dns_doh_trusted' => '',
		'pfb_dns_doq_port' => '8853', 'pfb_dns_doq_port6' => '', 'pfb_dns_doq_interface' => ['lo0'],
		'pfb_dns_ddr' => 'on',
	];
}
if (!$region) {
	// The cut-out handler reads these fields of its form: each is posted empty, as a browser posts an unticked box
	preg_match_all("~\\\$_POST\\['([a-z0-9_]+)'\\]~", $block, $posted);
	foreach (array_unique($posted[1]) as $key) {
		$_POST[$key] = $_POST[$key] ?? '';
	}
}
if ($scenario === 'dnsbl_on') {
	config_set_path("{$dnsbl}/pfb_dnsbl", 'on');
}
if ($region && $submit === 'save_pfb_dns') {
	config_set_path("{$dns}/pfb_dns", '');	// pfB-DNS is Off in config.xml: the form turns it On
}
$disk = $before = $GLOBALS['config'];
if ($scenario === 'interleave') {
	$disk = $other;
	$GLOBALS['pfb_test_config_read_hook'] = static function () use ($other): void {
		$GLOBALS['pfb_test_lock_events'][] = ['read'];
		$GLOBALS['config'] = $other;
	};
} elseif ($scenario === 'lock_taken') {
	$GLOBALS['pfb_test_try_lock_fail'] = TRUE;
	$disk = $other;
} elseif ($scenario === 'read_fails') {
	$GLOBALS['pfb_test_config_read_fails'] = TRUE;
	$disk = $other;
} elseif ($scenario === 'write_refused') {
	$GLOBALS['pfb_test_write_config_result'] = FALSE;
} elseif ($scenario === 'write_failed') {
	$GLOBALS['pfb_test_write_config_result'] = -1;
} elseif ($scenario === 'advert_write_fails') {
	$_POST['pfb_dns_listen_vip'] = 'on';
	$_POST['pfb_dns_listen_vip6'] = '_vipx';
	$options_dns_listen_vip6['_vipx'] = 'fd12::53';
	config_set_path("{$dns}/pfb_dns", '');	// the Resolver's own interfaces are what the listener advertisement edits
	config_set_path('virtualip/vip', [['mode' => 'ipalias', 'interface' => 'lan', 'type' => 'single', 'subnet' => 'fd12::53', 'subnet_bits' => '128', 'descr' => 'operator', 'uniqid' => 'x']]);
	$disk = $GLOBALS['config'];
}
$GLOBALS['pfb_test_write_config_hook'] = static function (string $description) use (&$disk, $scenario): void {
	$GLOBALS['pfb_test_lock_events'][] = ['write'];
	if ($scenario === 'advert_write_fails') {
		$refused = str_contains($description, 'DNS listener advertisements');
		$GLOBALS['pfb_test_write_config_result'] = !$refused;
		if ($refused) {
			return;
		}
	}
	if ($scenario === 'write_throws') {
		throw new RuntimeException("config.xml could not be written: {$description}");
	}
	if (!in_array($scenario, ['write_refused', 'write_failed'], TRUE)) {
		$disk = $GLOBALS['config'];
	}
};
$input_errors = [];
$handedPost = $_POST;
ini_set('open_basedir', "{$tmp}:" . dirname($resultFile) . ":{$repo}:/usr/share/php:/dev/null:/dev/urandom");
eval($block);
$returned = TRUE;
