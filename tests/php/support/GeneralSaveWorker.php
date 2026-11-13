<?php

declare(strict_types=1);

/**
 * Child process for the tests of the General page's save past its verdict (CoreSettingsPageSavesTest): runs the page's real save --
 * from its metrics export gate through the schedule-cache branch (`elseif (!$pfb_core_errors)`) that ends in header() and exit -- over
 * the PHPUnit doubles, which a test cannot do in its own process. The page cannot be included whole (top-level rendering); the region is
 * cut from the shipped page. Two calls in it are swapped for recorders, since neither can be observed otherwise: sync_package_pfblockerng()
 * (the real one drives the live firewall) becomes pfb_test_sync(), and header() becomes pfb_test_header(), which records what the page
 * redirects to (the CLI keeps no headers). The swap fails loudly unless each is called exactly once.
 *
 * argv: scenario (unused: there is one save), result file, case (JSON, optional): `core.socket` is the Core API socket the page's
 * dry run talks to (default: none listens, so Core is down), `post` maps a field to the value posted.
 * The result holds the input errors, whether control returned to render instead of exiting through the redirect, whether the page
 * synced the package ("synced"), the redirect target ("redirect", NULL for none) and the write_config() descriptions ("writes").
 */

$workerArgv = $argv;
$resultFile = (string) $workerArgv[2];
$repo = dirname(__DIR__, 3);
$case = json_decode((string) ($workerArgv[3] ?? '{}'), TRUE, 512, JSON_THROW_ON_ERROR);
$input_errors = [];
$returned = FALSE;
$synced = FALSE;
$redirect = NULL;

register_shutdown_function(static function () use ($resultFile, &$input_errors, &$returned, &$synced, &$redirect): void {
	file_put_contents($resultFile, json_encode([
		'inputErrors' => $input_errors,
		'returned'    => $returned,
		'synced'      => $synced,
		'redirect'    => $redirect,
		'writes'      => $GLOBALS['pfb_test_write_config_calls'] ?? [],
	], JSON_THROW_ON_ERROR));
});

require_once $repo . '/tests/php/bootstrap.php';
require_once $repo . '/tests/php/PageStatementLoader.php';

function pfb_test_sync(): bool
{
	$GLOBALS['synced'] = TRUE;
	return TRUE;
}

function pfb_test_header(string $header): void
{
	$GLOBALS['redirect'] = $header;
}

$region = pfb_test_page_block_from(PFB_TEST_GENERAL_PAGE, PFB_TEST_GENERAL_SAVE_FROM);
$code = $region;
foreach (['header(' => 'pfb_test_header(', 'sync_package_pfblockerng(' => 'pfb_test_sync('] as $real => $recorder) {
	$code = str_replace($real, $recorder, $code, $replaced);
	if ($replaced !== 1) {
		throw new RuntimeException("worker: expected one {$real} call in the General save, found {$replaced}");
	}
}

$tmp = $GLOBALS['pfb_test_tmp'];
$GLOBALS['config'] = [];
global $pfb;
$pfb['core_socket'] = $case['core']['socket'] ?? "{$tmp}/core.sock";
$pfb['core_settings_failed'] = "{$tmp}/core_settings_failed";
$pfb['metrics_lock'] = "{$tmp}/metrics.lock";
$pfb['dnsbl_info'] = "{$tmp}/dnsbl_info.sqlite";
$pfb['dnsbl_resolver'] = "{$tmp}/dnsbl_resolver.sqlite";
$pfb['log'] = "{$tmp}/pfblockerng.log";
$pfb['errlog'] = "{$tmp}/error.log";
$pfb['runlog'] = '';

// The page's own variables for the save: `$pfb` is the page's local copy (the schedule ledger in the sandbox), so the code runs in a
// function scope and does not replace the global `$pfb` the library reads. Its `$input_errors` is the global one, by reference.
$vars = pfb_test_general_save_vars($region, $case['post'] ?? ['pfb_metrics_client_ip' => 'on']);
$vars['pfb']['schedule_state_dir'] = "{$tmp}/schedule";
$vars['pfb']['schedule_timezone'] = 'UTC';
unset($vars['input_errors']);

function pfb_test_general_worker_run(string $code, array $vars, array &$input_errors): void
{
	extract($vars);
	eval($code);
}

$GLOBALS['pfb_test_write_config_calls'] = [];
ini_set('open_basedir', "{$tmp}:" . sys_get_temp_dir() . ':' . dirname($resultFile) . ":{$repo}:/usr/share/php:/dev/null:/dev/urandom");
pfb_test_general_worker_run($code . "\n", $vars, $input_errors);
$returned = TRUE;
