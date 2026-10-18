<?php

declare(strict_types=1);

/**
 * Child process for DnsProxyUninstallAbortTest: runs pfblockerng.xml's custom_php_pre_deinstall_command the way
 * pfSense's eval_once() does (@eval of the XML text, so the package boundary is the shipped one) against the shipped
 * .inc over the PHPUnit doubles. The process is a private sandbox: after the bootstrap its file access is narrowed to its
 * own temporary directory, the result directory and the repository. argv: scenario JSON, result file.
 *
 * Scenario: `failure` (lock | read | survivor | none: why the Resolver cannot be restored, none = it can) and `keep`
 * (on | off: Keep Settings). The result file records what survived and whether the hook returned or exited.
 */

$workerArgv = $argv;
$scenario = json_decode((string) $workerArgv[1], TRUE, 8, JSON_THROW_ON_ERROR);
$resultFile = (string) $workerArgv[2];
$repo = dirname(__DIR__, 3);
$paths = [];
$returned = FALSE;

// Registered before the bootstrap's own, so it reads the sandbox before the bootstrap deletes it.
register_shutdown_function(static function () use ($resultFile, &$paths, &$returned): void {
	$canary = static fn (string $key): bool => isset($paths[$key]) && file_exists($paths[$key]);
	file_put_contents($resultFile, json_encode([
		'returned'  => $returned,
		'snapshot'  => pfb_dns_proxy_saved() !== NULL,
		'interface' => config_get_path('unbound/active_interface'),
		'sections'  => array_keys(config_get_path('installedpackages', [])),
		'pending'   => $canary('pending'),
		'dbCanary'  => $canary('db'),
		'logCanary' => $canary('log'),
		'rcScript'  => file_exists(PFB_DNS_PROXY_RCFILE),
		'lockHeld'  => !empty($GLOBALS['pfb_test_lock_held']),
		'notices'   => array_column($GLOBALS['pfb_test_file_notices'] ?? [], 'notice'),
	], JSON_THROW_ON_ERROR));
});

require_once $repo . '/tests/php/bootstrap.php';
require_once $repo . '/tests/php/SyncPrereqSeedTrait.php';

final class PackageRemovalWorkerSeeder
{
	use SyncPrereqSeedTrait;

	public function seed(): void
	{
		$this->seedSyncPrereqs();
	}
}

global $pfb, $g;
$tmp = $GLOBALS['pfb_test_tmp'];
$g['unbound_chroot_path'] = "{$tmp}/unbound";
mkdir($g['unbound_chroot_path'], 0777, TRUE);
$GLOBALS['config'] = [];
(new PackageRemovalWorkerSeeder())->seed();
// Keep Settings: the registered toggle's Off token is the empty string.
config_set_path('installedpackages/pfblockerng/config/0/pfb_keep', $scenario['keep'] === 'on' ? 'on' : '');

// The Resolver as the DNS proxy leaves it, with the copy of the user's settings it saved.
$GLOBALS['config']['unbound'] = [
	'port'             => '53',
	'active_interface' => 'lo0',
	'custom_options'   => base64_encode("do-ip6: no\nserver:\n# pfBlockerNG DNS proxy\nport: 5354\ninterface: 127.0.0.1@5353\n"
		. "interface: ::1@5353\nproxy-protocol-port: 5353\n# end pfBlockerNG DNS proxy"),
];
$saved = [];
foreach (['active_interface' => 'lan,opt1', 'enablessl' => '', 'custom_options' => base64_encode('do-ip6: no')] as $key => $value) {
	$saved[$key] = ['present' => TRUE, 'value' => $value];
}
config_set_path('installedpackages/pfblockerngdns/config/0/pfb_dns_saved', base64_encode((string) json_encode($saved)));

pfb_global();
$paths = ['pending' => "{$tmp}/pending", 'db' => "{$pfb['dbdir']}/canary.txt", 'log' => "{$pfb['logdir']}/canary.txt"];
$pfb['pending_marker'] = $paths['pending'];
pfb_mark_pending_changes();
foreach (['db', 'log'] as $dir) {
	@mkdir(dirname($paths[$dir]), 0777, TRUE);
	file_put_contents($paths[$dir], 'user data');
}
file_put_contents(PFB_DNS_PROXY_RCFILE, "#!/bin/sh\n");

switch ($scenario['failure']) {
	case 'lock':
		$GLOBALS['pfb_test_try_lock_fail'] = TRUE;
		break;
	case 'read':
		$GLOBALS['pfb_test_config_read_fails'] = TRUE;
		break;
	case 'survivor':
		$GLOBALS['pfb_test_valid_pids'] = [PFB_DNS_PROXY_PIDFILE => TRUE];
		break;
}

// The one include the hook requires that the shared doubles do not shim.
mkdir("{$tmp}/inc");
touch("{$tmp}/inc/config.inc");
set_include_path("{$tmp}/inc" . PATH_SEPARATOR . get_include_path());
ini_set('open_basedir', "{$tmp}:" . dirname($resultFile) . ":{$repo}:/usr/share/php:/dev/null:/dev/urandom");

$xml = simplexml_load_file($repo . '/src/usr/local/pkg/pfblockerng.xml');
@eval((string) $xml->custom_php_pre_deinstall_command);
$returned = TRUE;
