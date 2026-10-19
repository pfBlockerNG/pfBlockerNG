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
 * `write_refused` (write_config answers FALSE), `write_failed` (file write fails: -1).
 * The result file holds what config.xml would contain afterwards ("disk"), the lock/read/write order, the page's input
 * errors, whether the config lock is still held, the reply-logging preference the form would show ("reply") and whether
 * the save marked pending changes ("pendingMarked") or returned to render instead of exiting via redirect ("returned").
 */

$workerArgv = $argv;
$scenario = (string) $workerArgv[1];
$resultFile = (string) $workerArgv[2];
$repo = dirname(__DIR__, 3);
$page = $repo . '/src/usr/local/www/pfblockerng/pfblockerng_dns.php';
$disk = NULL;
$input_errors = [];
$pconfig = [];
$returned = FALSE;

register_shutdown_function(static function () use ($resultFile, &$disk, &$input_errors, &$pconfig, &$returned): void {
	file_put_contents($resultFile, json_encode([
		'disk'          => $disk,
		'events'        => $GLOBALS['pfb_test_lock_events'] ?? [],
		'lockHeld'      => !empty($GLOBALS['pfb_test_lock_held']),
		'inputErrors'   => $input_errors,
		'reply'         => $pconfig['pfb_py_reply'] ?? NULL,
		'pendingMarked' => is_file($GLOBALS['pfb']['pending_marker'] ?? ''),
		'returned'      => $returned,
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

$block = dns_save_worker_block((string) file_get_contents($page));
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
// The posted form: an absent toggle and an absent checkbox are the Off tokens, so the save turns pfB-DNS off and the
// logging preference off. The page's first statements derive the two values the save writes.
$_POST = ['save' => 'Save'];
$pfb_dns = pfb_filter($_POST['pfb_dns'] ?? '', PFB_FILTER_ON_OFF, 'pfb_dns') ?: '';
$pfb_py_reply = pfb_filter($_POST['pfb_py_reply'] ?? '', PFB_FILTER_ON_OFF, 'dnsbl') ?: '';
preg_match_all("~\\\$_POST\\['([a-z0-9_]+)'\\]~", $block, $posted);
foreach (array_unique($posted[1]) as $key) {
	$_POST[$key] = $_POST[$key] ?? '';
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
}
$GLOBALS['pfb_test_write_config_hook'] = static function (string $description) use (&$disk, $scenario): void {
	$GLOBALS['pfb_test_lock_events'][] = ['write'];
	if ($scenario === 'write_throws') {
		throw new RuntimeException("config.xml could not be written: {$description}");
	}
	if (!in_array($scenario, ['write_refused', 'write_failed'], TRUE)) {
		$disk = $GLOBALS['config'];
	}
};
$input_errors = [];
ini_set('open_basedir', "{$tmp}:" . dirname($resultFile) . ":{$repo}:/usr/share/php:/dev/null:/dev/urandom");
eval($block);
$returned = TRUE;
