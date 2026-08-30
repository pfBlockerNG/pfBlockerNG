<?php

declare(strict_types=1);

$workerArgv = $argv;
require_once dirname(__DIR__) . '/bootstrap.php';
require_once dirname(__DIR__) . '/SyncPrereqSeedTrait.php';
require_once dirname(__DIR__, 3) . '/src/usr/local/pkg/pfblockerng/pfblockerng_cron.inc';
require_once __DIR__ . '/FailingFlockStream.php';
$argv = $workerArgv;

final class FeedPassCliWorkerSeeder
{
	use SyncPrereqSeedTrait;

	public function seed(): void
	{
		$this->seedSyncPrereqs();
	}
}

/** Return one complete named function from shipped PHP source. */
function pfb_test_cli_worker_function(string $source, string $name): string
{
	$tokens = token_get_all($source);
	$count = count($tokens);
	for ($i = 0; $i < $count; $i++) {
		if (!is_array($tokens[$i]) || $tokens[$i][0] !== T_FUNCTION) {
			continue;
		}
		$functionName = NULL;
		for ($j = $i + 1; $j < $count; $j++) {
			if (is_array($tokens[$j]) && $tokens[$j][0] === T_STRING) {
				$functionName = $tokens[$j][1];
				break;
			}
			if ($tokens[$j] === '(') {
				break;
			}
		}
		if ($functionName !== $name) {
			continue;
		}
		$code = '';
		$depth = 0;
		$opened = FALSE;
		for ($j = $i; $j < $count; $j++) {
			$token = $tokens[$j];
			$text = is_array($token) ? $token[1] : $token;
			$code .= $text;
			if ($text === '{') {
				$depth++;
				$opened = TRUE;
			} elseif ($text === '}') {
				$depth--;
				if ($opened && $depth === 0) {
					return $code;
				}
			}
		}
	}
	throw new RuntimeException("worker fixture: {$name}() not found in pfblockerng.php");
}

/** Return the shipped `$pfb_deferred_by = NULL; switch ($argv[1]) { ... }` dispatch. */
function pfb_test_cli_worker_dispatch(string $source): string
{
	$tokens = token_get_all($source);
	$count = count($tokens);
	for ($i = 0; $i < $count; $i++) {
		if (!is_array($tokens[$i]) || $tokens[$i][0] !== T_VARIABLE || $tokens[$i][1] !== '$pfb_deferred_by') {
			continue;
		}
		$code = '';
		$sawSwitch = FALSE;
		$depth = 0;
		for ($j = $i; $j < $count; $j++) {
			$token = $tokens[$j];
			$text = is_array($token) ? $token[1] : $token;
			$code .= $text;
			if (is_array($token) && $token[0] === T_SWITCH) {
				$sawSwitch = TRUE;
			}
			if (!$sawSwitch) {
				continue;
			}
			if ($text === '{') {
				$depth++;
			} elseif ($text === '}') {
				$depth--;
				if ($depth === 0) {
					return $code;
				}
			}
		}
	}
	throw new RuntimeException('worker fixture: deferral-aware CLI switch not found in pfblockerng.php');
}

$lockDir = getenv('PFB_TEST_LOCK_DIR');
$scenario = getenv('PFB_TEST_SCENARIO') ?: 'dispatch';
if (!is_string($lockDir) || $lockDir === '' || !is_dir($lockDir)) {
	fwrite(STDERR, "worker fixture: PFB_TEST_LOCK_DIR is not a directory\n");
	exit(97);
}

$GLOBALS['pfb'] = array_merge($GLOBALS['pfb'] ?? [], [
	'dbdir' => $lockDir,
	'schedule_state_dir' => $lockDir,
	'log' => "{$lockDir}/pfblockerng.log",
	'errlog' => "{$lockDir}/error.log",
	'runlog' => "{$lockDir}/run.log",
	'pending_marker' => "{$lockDir}/pfb_pending_changes",
]);
$GLOBALS['config'] = [];
(new FeedPassCliWorkerSeeder())->seed();

if ($scenario === 'success') {
	$GLOBALS['g']['pfblockerng_install'] = TRUE;
} elseif ($scenario === 'real-failure') {
	file_put_contents("{$lockDir}/pfb_schedule_state.json", 'not json at all');
} elseif ($scenario === 'dispatcher-open-error') {
	$GLOBALS['pfb']['schedule_state_dir'] = "{$lockDir}/missing/child";
} elseif ($scenario === 'dispatcher-flock-error' || $scenario === 'feed-flock-error') {
	if (!stream_wrapper_register('pfbfailingflock', PfbFailingFlockStream::class)) {
		fwrite(STDERR, "worker fixture: could not register failing flock stream\n");
		exit(93);
	}
	if ($scenario === 'dispatcher-flock-error') {
		$GLOBALS['pfb']['schedule_state_dir'] = 'pfbfailingflock://dispatcher';
	} else {
		$GLOBALS['g']['vardb_path'] = 'pfbfailingflock://feed';
		$GLOBALS['pfb']['dbdir'] = 'pfbfailingflock://feed';
	}
}

$entrypoint = dirname(__DIR__, 3) . '/src/usr/local/www/pfblockerng/pfblockerng.php';
$source = file_get_contents($entrypoint);
if (!is_string($source)) {
	fwrite(STDERR, "worker fixture: could not read pfblockerng.php\n");
	exit(96);
}

try {
	eval(pfb_test_cli_worker_function($source, 'pfb_cli_feed_pass_exit'));
	eval(pfb_test_cli_worker_dispatch($source));
} catch (Throwable $error) {
	fwrite(STDERR, 'worker fixture: ' . $error->getMessage() . "\n");
	exit(95);
}

fwrite(STDERR, "worker fixture: CLI dispatch returned without exiting\n");
exit(94);
