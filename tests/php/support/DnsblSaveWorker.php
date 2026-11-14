<?php

declare(strict_types=1);

/**
 * Child process for DnsblSettingsSaveRaceTest: executes the DNSBL page's real POST save (the code that follows the
 * page's validation, extracted from the shipped pfblockerng_dnsbl.php by its tokens) over the PHPUnit doubles, with
 * another request's writes interleaved at the instant the save re-reads config.xml. The page cannot be included whole:
 * its validation reads files under /usr/local/www on the appliance. argv: scenario name, result file, case (JSON, optional): `post`
 * maps a field to the value posted over the worker's defaults, `core.socket` is the Core API socket the page's validation and notice
 * talk to (default: none listens, so Core is down).
 *
 * Scenarios: `interleave` (a pfB-DNS save of Off and a Resolver move land on disk after this request started),
 * `lock_taken` (another process holds the config lock), `read_fails` (the fresh read fails), `write_throws` (exception),
 * `write_refused` (write_config answers FALSE), `write_failed` (file write fails: -1), `pfb_dns_off` (issue #3770: pfB-DNS is
 * stored Off, which the save leaves as it is); any other name saves with nothing interleaved.
 * The result holds disk config, the config before the save, lock events, input errors, pending marker presence, whether control
 * returned to render instead of exiting through the redirect, the submitted port rendered after a failure, the write_config()
 * descriptions ("writes") and the record of a failed notice to Core the save left ("settingsFailed": the reason, or NULL).
 * "effects" holds the save's file side effects before and after it ran, in the sandbox: the TOP1M baseline files present
 * ("baseline"), the TOP1M rebuild marker ("updateMarker") and the blocked-page file DNSBL serves ("activePage": its content, or NULL
 * when there is none). The case's `webpageChanged` (default true) is whether the posted block page differs from the one stored when
 * the request loaded the form; `otherWebpage` is the block page the `interleave` scenario's other save stored meanwhile (default:
 * unchanged); `activePage` is the content seeded as the served block page (default "ACTIVE ORIGINAL", NULL for none). "effects.atUnlock" lists
 * the same state at each release of the DNS config lock. The case's `seed.migrated` (default true) is whether the stored DNSBL
 * policy is already migrated: when false the page's upgrade facade writes config.xml itself, mid-save.
 * The page's fresh read of config.xml under the lock gives back what is on disk: the block page chosen in the validation is in
 * memory only until the save writes it.
 */

$workerArgv = $argv;
$scenario = (string) $workerArgv[1];
$resultFile = (string) $workerArgv[2];
$repo = dirname(__DIR__, 3);
$case = json_decode((string) ($workerArgv[3] ?? '{}'), TRUE, 512, JSON_THROW_ON_ERROR);
$page = $repo . '/src/usr/local/www/pfblockerng/pfblockerng_dnsbl.php';
$disk = NULL;
$before = NULL;
$input_errors = [];
$returned = FALSE;
$pconfig = [];

$effectsBefore = NULL;
$effectsAtUnlock = [];

/** @return array{baseline: list<string>, updateMarker: bool, activePage: ?string} the save's file side effects, as they stand */
function dnsbl_save_worker_effects(): array
{
	global $pfb;
	$sidecars = ['.orig', '.xxhash128', '.md5', '.source', '.orig.etag', '.orig.lastmod'];
	$active = @file_get_contents("{$pfb['dnsbl_www']}/dnsbl_active.php");
	return [
		'baseline'     => array_values(array_filter($sidecars, static fn (string $suffix): bool => file_exists("{$pfb['dbdir']}/top-1m.csv.zip{$suffix}"))),
		'updateMarker' => file_exists("{$pfb['dbdir']}/top-1m.update"),
		'activePage'   => $active === FALSE ? NULL : $active,
	];
}

register_shutdown_function(static function () use ($resultFile, &$disk, &$before, &$input_errors, &$returned, &$pconfig, &$effectsBefore, &$effectsAtUnlock): void {
	file_put_contents($resultFile, json_encode([
		'disk'        => $disk,
		'before'      => $before,
		'events'      => $GLOBALS['pfb_test_lock_events'] ?? [],
		'lockHeld'    => !empty($GLOBALS['pfb_test_lock_held']),
		'inputErrors' => $input_errors,
		'pendingMarked' => is_file($GLOBALS['pfb']['pending_marker'] ?? ''),
		'returned'      => $returned,
		'postedPort'    => $pconfig['pfb_dnsport'] ?? NULL,
		'writes'        => $GLOBALS['pfb_test_write_config_calls'] ?? [],
		'settingsFailed' => ($failed = @file_get_contents($GLOBALS['pfb']['core_settings_failed'] ?? '')) === FALSE ? NULL : $failed,
		'effects'       => ['before' => $effectsBefore, 'after' => dnsbl_save_worker_effects(), 'atUnlock' => $effectsAtUnlock],
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
// The block page stored when this request loaded the form: the posted alternative unless the case says it changed
config_set_path("{$dnsbl}/dnsbl_webpage", ($case['webpageChanged'] ?? TRUE) ? 'dnsbl_default.php' : 'dnsbl_alt.php');
config_set_path('unbound/active_interface', 'lan');
config_set_path('unbound/custom_options', base64_encode('do-ip6: no'));
if ($case['seed']['migrated'] ?? TRUE) {
	config_set_path("{$dnsbl}/global_log_mode", 'default');	// a migrated policy: the upgrade facade writes nothing
}

// What the other requests wrote after this one started: the pfB-DNS form's Off (DNS > General), and an apply's Resolver move.
$other = $GLOBALS['config'];
$other['installedpackages']['pfblockerngdnsblsettings']['config'][0]['pfb_py_reply'] = '';
$other['unbound']['active_interface'] = 'lo0';
$other['installedpackages']['pfblockerngdns']['config'][0]['pfb_dns_saved'] = base64_encode((string) json_encode([
	'active_interface' => ['present' => TRUE, 'value' => 'lan'],
	'enablessl'        => ['present' => FALSE, 'value' => ''],
	'custom_options'   => ['present' => TRUE, 'value' => base64_encode('do-ip6: no')],
]));
if (isset($case['otherWebpage'])) {
	// issue #3998: another save chose (and served) this block page after this request loaded the form
	$other['installedpackages']['pfblockerngdnsblsettings']['config'][0]['dnsbl_webpage'] = $case['otherWebpage'];
}

global $pfb;
pfb_global();
$tmp = $GLOBALS['pfb_test_tmp'];
$pfb['pending_marker'] = "{$tmp}/pending";
$pfb['dconfig'] = PfbConfig::readSection($dnsbl);	// the page's first statement: this request's copy, pfb_py_reply still on
// Core: the case's socket, else one nothing listens on (Core down); the failure record stays in the sandbox either way
$pfb['core_socket'] = $case['core']['socket'] ?? "{$tmp}/core.sock";
$pfb['core_settings_failed'] = "{$tmp}/core_settings_failed";
// The save's file side effects land in the sandbox: the TOP1M baseline (six files beside the download), the block pages DNSBL serves
$pfb['dbdir'] = "{$tmp}/db/pfblockerng";
$pfb['dnsbl_www'] = "{$tmp}/www";
foreach ([$pfb['dbdir'], $pfb['dnsbl_www']] as $workerDir) {
	is_dir($workerDir) || mkdir($workerDir, 0700, TRUE);
}
foreach (['.orig', '.xxhash128', '.md5', '.source', '.orig.etag', '.orig.lastmod'] as $workerSuffix) {
	file_put_contents("{$pfb['dbdir']}/top-1m.csv.zip{$workerSuffix}", 'baseline');
}
file_put_contents("{$pfb['dnsbl_www']}/dnsbl_alt.php", 'ALTERNATIVE PAGE');
$workerActive = array_key_exists('activePage', $case) ? $case['activePage'] : 'ACTIVE ORIGINAL';
if ($workerActive !== NULL) {
	file_put_contents("{$pfb['dnsbl_www']}/dnsbl_active.php", $workerActive);
}
$effectsBefore = dnsbl_save_worker_effects();

// The page's validation, as it leaves them for the save.
$dnsbl_webpage_file = 'dnsbl_alt.php';
$dnsbl_webpage = $dnsbl_webpage_file != $pfb['dconfig']['dnsbl_webpage'];	// the validation compares with this request's copy
$pfb['dconfig']['dnsbl_webpage'] = $dnsbl_webpage_file;
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
// The eight DNSBL policy fields, each different from the seeded section so a save that drops one shows on disk.
$_POST['global_log'] = 'nxdomain';
$_POST['global_log_mode'] = 'override';
$_POST['pfb_regex'] = 'on';
$_POST['pfb_regex_list'] = 'a.*';
$_POST['pfb_idn'] = 'confusable';
$_POST['tld_allow'] = 'on';
$_POST['tld_wildcard'] = 'on';
$_POST['tld_wildcard_blacklist'] = 'zip';
$_POST['pfb_py_cache_max'] = '10000';
$_POST['top1m_count'] = '1000';
foreach ($case['post'] ?? [] as $field => $value) {
	$_POST[$field] = $value;
}
$pfb_posted_policy = pfb_dnsbl_policy_from_post($_POST, $local_tld, $default_tlds);	// the page's validation computes it once; the save reuses it

if ($scenario === 'pfb_dns_off') {
	config_set_path("{$dns}/pfb_dns", '');
}
$disk = $before = $GLOBALS['config'];
config_set_path("{$dnsbl}/dnsbl_webpage", $dnsbl_webpage_file);	// the validation's write, in memory only: the fresh read under the lock drops it
$GLOBALS['pfb_test_config_read_hook'] = static function () use (&$disk): void {
	$GLOBALS['config'] = $disk;
};
$GLOBALS['pfb_test_unlock_hook'] = static function () use (&$effectsAtUnlock): void {
	$effectsAtUnlock[] = dnsbl_save_worker_effects();
};
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
