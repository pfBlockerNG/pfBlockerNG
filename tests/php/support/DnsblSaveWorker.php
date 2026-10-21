<?php

declare(strict_types=1);

/**
 * Child process for DnsblSettingsSaveRaceTest: executes the DNSBL page's real POST save (the code that follows the
 * page's validation, extracted from the shipped pfblockerng_dnsbl.php by its tokens) over the PHPUnit doubles, with
 * another request's writes interleaved at the instant the save re-reads config.xml. The page cannot be included whole:
 * its validation reads files under /usr/local/www on the appliance. argv: scenario name, result file.
 *
 * Scenarios: `interleave` (a pfB-DNS save of Off and a Resolver move land on disk after this request started),
 * `lock_taken` (another process holds the config lock), `read_fails` (the fresh read fails), `write_throws` (exception),
 * `write_refused` (write_config answers FALSE), `write_failed` (file write fails: -1).
 * The result holds disk config, lock events, input errors, pending marker presence, whether control returned to render
 * instead of exiting through the redirect, and the submitted port rendered after a failure.
 */

$workerArgv = $argv;
$scenario = (string) $workerArgv[1];
$resultFile = (string) $workerArgv[2];
$repo = dirname(__DIR__, 3);
$page = $repo . '/src/usr/local/www/pfblockerng/pfblockerng_dnsbl.php';
$disk = NULL;
$input_errors = [];
$returned = FALSE;
$pconfig = [];

register_shutdown_function(static function () use ($resultFile, &$disk, &$input_errors, &$returned, &$pconfig): void {
	file_put_contents($resultFile, json_encode([
		'disk'        => $disk,
		'events'      => $GLOBALS['pfb_test_lock_events'] ?? [],
		'lockHeld'    => !empty($GLOBALS['pfb_test_lock_held']),
		'inputErrors' => $input_errors,
		'pendingMarked' => is_file($GLOBALS['pfb']['pending_marker'] ?? ''),
		'returned'      => $returned,
		'postedPort'    => $pconfig['pfb_dnsport'] ?? NULL,
	], JSON_THROW_ON_ERROR));
});

require_once $repo . '/tests/php/bootstrap.php';
require_once $repo . '/tests/php/SyncPrereqSeedTrait.php';

final class DnsblSaveWorkerSeeder
{
	use SyncPrereqSeedTrait;

	public function seed(): void
	{
		$this->seedSyncPrereqs();
	}
}

/** The page's POST save: from the validation's last statement to the end of `if (isset($_POST['save']))`. */
function dnsbl_save_worker_block(string $source): string
{
	$anchor = '$input_errors = array_merge($input_errors, $dot_block_errors);';
	$from = strpos($source, $anchor);
	if ($from === FALSE) {
		throw new RuntimeException('worker: the DNSBL page no longer has its validation anchor');
	}
	$tokens = token_get_all('<?php ' . substr($source, $from + strlen($anchor)));
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
	throw new RuntimeException('worker: the DNSBL page save block has no end');
}

$block = dnsbl_save_worker_block((string) file_get_contents($page));

$dnsbl = 'installedpackages/pfblockerngdnsblsettings/config/0';
$dns = 'installedpackages/pfblockerngdns/config/0';
$GLOBALS['config'] = [];
(new DnsblSaveWorkerSeeder())->seed();
config_set_path("{$dnsbl}/pfb_py_reply", 'on');
config_set_path("{$dnsbl}/pfb_dnsport", '8081');
config_set_path("{$dnsbl}/dnsbl_webpage", 'dnsbl_default.php');
config_set_path('unbound/active_interface', 'lan');
config_set_path('unbound/custom_options', base64_encode('do-ip6: no'));
config_set_path("{$dnsbl}/global_log_mode", 'default');	// a migrated policy: the upgrade facade writes nothing

// What the other requests wrote after this one started: the pfB-DNS page's Off, and an apply's Resolver move.
$other = $GLOBALS['config'];
$other['installedpackages']['pfblockerngdnsblsettings']['config'][0]['pfb_py_reply'] = '';
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
$pfb['dconfig'] = PfbConfig::readSection($dnsbl);	// the page's first statement: this request's copy, pfb_py_reply still on

// The page's validation, as it leaves them for the save.
$dnsbl_webpage_file = 'dnsbl_alt.php';
$dnsbl_webpage = TRUE;
$pfb['dconfig']['dnsbl_webpage'] = $dnsbl_webpage_file;
config_set_path("{$dnsbl}/dnsbl_webpage", $dnsbl_webpage_file);
$pfb_auto = FALSE;
$pfb_top1m_token_post = '';
$redir_ifaces_raw = [];
$redir_alias_raw = '';
$dot_block_ifaces_raw = [];
$dot_block_alias_raw = '';
$dot_block_action_raw = 'reject';
$local_tld = 'local';
$default_tlds = ['arpa', 'local', 'com', 'net', 'org', 'edu', 'ca', 'co', 'io'];
$_POST = ['save' => 'Save'];
preg_match_all("~\\\$_POST\\['([a-z0-9_]+)'\\]~", $block, $posted);
foreach (array_unique($posted[1]) as $key) {
	$_POST[$key] = '';
}
$_POST['pfb_dnsbl'] = 'on';
$_POST['pfb_dnsport'] = '8082';	// the unrelated field this save changes
$_POST['pfb_dnsport_ssl'] = '8443';
$_POST['pfb_idn'] = 'off';
$_POST['pfb_py_cache_max'] = '10000';
$_POST['top1m_count'] = '1000';
$pfb_posted_policy = pfb_dnsbl_policy_from_post($_POST);	// the page's validation computes it once; the save reuses it

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
