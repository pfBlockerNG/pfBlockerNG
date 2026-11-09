<?php

declare(strict_types=1);

/**
 * Child process for DnsSettingsSaveRaceTest: executes the pfB-DNS page's real POST save (the code from its config lock to
 * the end of `if (isset($_POST['save']))`, extracted from the shipped pfblockerng_dns.php by its tokens) over the PHPUnit
 * doubles, with another request's writes interleaved at the instant the save re-reads config.xml. The page cannot be
 * included whole: its validation reads files under /usr/local/www on the appliance. argv: scenario name, result file.
 *
 * Scenarios: `interleave` (an apply's Resolver move lands on disk after this request started), `lock_taken` (another
 * process holds the config lock), `read_fails` (the fresh read fails), `write_throws` (config.xml cannot be written),
 * `write_refused` (write_config answers FALSE), `write_failed` (file write fails: -1), `advert_write_fails` (DNS General selects a
 * listener VIP whose advertisement write_config answers FALSE while every other write succeeds).
 * Issue #3770 (DNSBL runs only through pfB-DNS), the pfB-DNS page's form posts pfB-DNS Off while: `dnsbl_on` (DNSBL is
 * stored On), `dnsbl_turned_on_meanwhile` (this request loaded DNSBL Off, another save turned it On before the fresh
 * read); `dnsbl_off` stores DNSBL Off, and `dnsbl_on_pfb_dns_on` stores DNSBL On and posts pfB-DNS On.
 * The result file holds what config.xml would contain afterwards ("disk"), the lock/read/write order, the page's input
 * errors, whether the config lock is still held, the reply-logging preference the form would show ("reply"), the write_config()
 * descriptions ("writes"), how often Unbound was regenerated ("unboundCalls") and whether
 * the save marked pending changes ("pendingMarked") or returned to render instead of exiting via redirect ("returned"),
 * the config before the save ("before") and the pfB-DNS checkbox the form would show ("pfbDnsShown").
 */

$workerArgv = $argv;
$scenario = (string) $workerArgv[1];
$resultFile = (string) $workerArgv[2];
$repo = dirname(__DIR__, 3);
$general = ($workerArgv[3] ?? '') === 'general';
$page = $repo . '/src/usr/local/www/pfblockerng/' . ($general ? 'pfblockerng_dns_general.php' : 'pfblockerng_dns.php');
$disk = NULL;
$before = NULL;
$input_errors = [];
$pconfig = [];
$returned = FALSE;

register_shutdown_function(static function () use ($resultFile, &$disk, &$before, &$input_errors, &$pconfig, &$returned): void {
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
		'pfbDnsShown'   => $pconfig['pfb_dns'] ?? NULL,
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

/** The page's POST save: from the config lock's first statement to the end of `if (isset($_POST['save']))`. */
function dns_save_worker_block(string $source): string
{
	$anchor = '$pfb_config_lock = NULL;';
	$from = strpos($source, $anchor);
	if ($from === FALSE) {
		throw new RuntimeException('worker: the pfB-DNS page no longer has its config lock anchor');
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
	throw new RuntimeException('worker: the pfB-DNS page save block has no end');
}

$source = (string) file_get_contents($page);
$block = $general
	? substr($source, strpos($source, 'if ($_POST &&'), strpos($source, '$pgtitle =') - strpos($source, 'if ($_POST &&'))
	: dns_save_worker_block($source);
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
// Both pages submit their own checkbox Off; the other page's preference must survive.
$_POST = ['save' => 'Save'];
$pfb_dns = '';
if ($general) {
	$_POST += ['pfb_dns_listen_vip4' => 'none', 'pfb_dns_listen_vip6' => 'none', 'pfb_dns_listen_interface' => 'lo0'];
	$options_dns_listen_vip4 = $options_dns_listen_vip6 = ['none' => '', 'auto' => 'Create VIP automatically'];
	$options_dns_listen_interface = ['lo0' => 'Localhost'];
}
preg_match_all("~\\\$_POST\\['([a-z0-9_]+)'\\]~", $block, $posted);
foreach (array_unique($posted[1]) as $key) {
	$_POST[$key] = $_POST[$key] ?? '';
}
if (in_array($scenario, ['dnsbl_on', 'dnsbl_on_pfb_dns_on'], TRUE)) {
	config_set_path("{$dnsbl}/pfb_dnsbl", 'on');
} elseif ($scenario === 'dnsbl_off') {
	config_set_path("{$dnsbl}/pfb_dnsbl", '');
}
if ($scenario === 'dnsbl_on_pfb_dns_on') {
	$pfb_dns = $_POST['pfb_dns'] = 'on';
}
$disk = $GLOBALS['config'];
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
} elseif ($scenario === 'dnsbl_turned_on_meanwhile') {
	$other['installedpackages']['pfblockerngdnsblsettings']['config'][0]['pfb_dnsbl'] = 'on';
	$disk = $other;
	$GLOBALS['pfb_test_config_read_hook'] = static function () use ($other): void {
		$GLOBALS['config'] = $other;
	};
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
$before = $disk;
$input_errors = [];
ini_set('open_basedir', "{$tmp}:" . dirname($resultFile) . ":{$repo}:/usr/share/php:/dev/null:/dev/urandom");
eval($block);
$returned = TRUE;
