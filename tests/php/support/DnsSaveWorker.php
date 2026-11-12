<?php

declare(strict_types=1);

/**
 * Child process for DnsSettingsSaveRaceTest, DnsblSaveWithPfbDnsOffTest and DnsGeneralPfbDnsFoldTest: executes the real POST save of
 * DNS > General (issue #3856: ONE form, ONE "Save DNS settings" button carrying the pfB-DNS settings and the DNS General ones) over the
 * PHPUnit doubles, with another request's writes interleaved at the instant the save re-reads config.xml. The page cannot be included
 * whole (it renders and exits), so its save code is extracted from the shipped pfblockerng_dns_general.php: the whole POST region, from
 * `$input_errors = array();` to `$pgtitle =` (the handler, its gate and validation included). argv: scenario name, result file, case.
 *
 * What is stored and posted: config.xml holds pfB-DNS Off and DNS Reply Logging On, and the browser posts the complete valid page with
 * the button `save`: pfB-DNS On with DoT, DoH and DDR on and DoQ off, and the DNS General fields with DNS Reply Logging unticked. So
 * a plain save changes one setting of each part. The case (argv[3], JSON) shapes one save: `stored` maps a registry key to the value
 * config.xml holds before the save (`{"dns/pfb_dns": "on"}`), `post` maps a field to the value posted (a NULL removes the field, as
 * a browser omits an unticked box). The page's option lists are the ones a page load builds for this post.
 *
 * Scenarios: `interleave` (an apply's Resolver move lands on disk after this request started), `lock_taken` (another
 * process holds the config lock), `read_fails` (the fresh read fails), `write_throws` (config.xml cannot be written),
 * `write_refused` (write_config answers FALSE), `write_failed` (file write fails: -1), `advert_write_fails` (DNS General selects a
 * listener VIP whose advertisement write_config answers FALSE while every other write succeeds), `dnsbl_on` (issue #3770: DNSBL is
 * stored On, which a save of pfB-DNS Off leaves as it is); any other name saves with nothing interleaved.
 * The result file holds what config.xml would contain afterwards ("disk") and before the save ("before"), the lock/read/write order,
 * the page's input errors, whether the config lock is still held, the page's $pconfig after the save ("pconfig": what the form shows
 * again when the save fails), the reply-logging preference it would show ("reply"), the write_config() descriptions ("writes"),
 * how often Unbound was regenerated ("unboundCalls"), the posted form ("posted") and whether the save marked pending changes
 * ("pendingMarked") or returned to render instead of exiting via redirect ("returned").
 */

$workerArgv = $argv;
$scenario = (string) $workerArgv[1];
$resultFile = (string) $workerArgv[2];
$repo = dirname(__DIR__, 3);
$case = json_decode((string) ($workerArgv[3] ?? '{}'), TRUE, 512, JSON_THROW_ON_ERROR);
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
		'pconfig'       => $pconfig,
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

$block = dns_save_worker_region((string) file_get_contents($page), '$input_errors = array();', '$pgtitle =');
$dnsbl = 'installedpackages/pfblockerngdnsblsettings/config/0';
$dns = 'installedpackages/pfblockerngdns/config/0';
$GLOBALS['config'] = [];
(new DnsSaveWorkerSeeder())->seed();
config_set_path("{$dns}/pfb_dns", '');	// pfB-DNS is Off in config.xml: the form turns it On
config_set_path("{$dnsbl}/pfb_py_reply", 'on');
config_set_path('unbound/active_interface', 'lan');
config_set_path('unbound/custom_options', base64_encode('do-ip6: no'));
foreach ($case['stored'] ?? [] as $key => $value) {
	PfbConfig::write($key, $value);
}
if ($scenario === 'dnsbl_on') {
	config_set_path("{$dnsbl}/pfb_dnsbl", 'on');
}
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
// The page's option lists, as a page load builds them
$options_dns_interface = ['lo0' => 'Localhost'];
$options_dns_cert = ['cert1' => 'Certificate'];
$options_dns_listen_vip4 = $options_dns_listen_vip6 = ['none' => '', 'auto' => 'Create VIP automatically'];
$options_dns_listen_interface = ['lo0' => 'Localhost'];
$_POST = [
	'save' => 'Save DNS settings',
	// the pfB-DNS settings: pfB-DNS On, DoT, DoH and DDR on, DoQ off
	'pfb_dns' => 'on', 'pfb_dns_interface' => ['lo0'], 'pfb_dns_sslcertref' => 'cert1', 'pfb_dns_name' => 'fw.example.lan',
	'pfb_dns_dot' => 'on', 'pfb_dns_dot_port' => '853', 'pfb_dns_dot_port6' => '', 'pfb_dns_dot_interface' => ['lo0'],
	'pfb_dns_doh' => 'on', 'pfb_dns_doh_port' => '4443', 'pfb_dns_doh_port6' => '', 'pfb_dns_doh_interface' => ['lo0'], 'pfb_dns_doh_trusted' => '',
	'pfb_dns_doq_port' => '8853', 'pfb_dns_doq_port6' => '', 'pfb_dns_doq_interface' => ['lo0'],
	'pfb_dns_ddr' => 'on',
	// the DNS General settings: DNS Reply Logging unticked, no Resolver addresses
	'pfb_dns_listen_vip4' => 'none', 'pfb_dns_listen_vip6' => 'none', 'pfb_dns_listen_interface' => 'lo0',
];
foreach ($case['post'] ?? [] as $field => $value) {
	if ($value === NULL) {
		unset($_POST[$field]);
	} else {
		$_POST[$field] = $value;
	}
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
	unset($_POST['pfb_dns']);	// pfB-DNS stays Off: the Resolver's own interfaces are what the listener advertisement edits
	$_POST['pfb_dns_listen_vip'] = 'on';
	$_POST['pfb_dns_listen_vip6'] = '_vipx';
	$options_dns_listen_vip6['_vipx'] = 'fd12::53';
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
