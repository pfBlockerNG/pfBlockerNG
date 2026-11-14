<?php

declare(strict_types=1);

/**
 * The `core_update` verb as Core runs it (issue #3941): the request on stdin, the progress on stdout, the result on fd 3, the
 * exit status the verb's. Every path is the test's own directory (PFB_TEST_DIR); the apply itself is a seam that succeeds. With
 * PFB_TEST_TERM_IN_PASS the feed pass is a seam that reports two terminal checks and then gets TERM (issue #4002).
 */
require_once dirname(__DIR__) . '/bootstrap.php';

$dir = getenv('PFB_TEST_DIR');
if (!is_string($dir) || $dir === '' || !is_dir($dir)) {
	fwrite(STDERR, "worker fixture: PFB_TEST_DIR is not a directory\n");
	exit(97);
}
$GLOBALS['pfb'] = array_merge($GLOBALS['pfb'] ?? [], [
	'dbdir' => $dir, 'schedule_state_dir' => $dir, 'core_state' => $dir, 'ccdir' => "{$dir}/cc",
	'pending_marker' => "{$dir}/pfb_pending_changes", 'log' => "{$dir}/pfb.log", 'errlog' => "{$dir}/error.log",
	'runlog' => "{$dir}/run.log", 'enable' => PfbToggle::On,
]);
unset($GLOBALS['pfb']['run_stdout_override']);
$GLOBALS['config'] = [];

$seams = ['sync' => static fn (): bool => TRUE];
if (getenv('PFB_TEST_TERM_IN_PASS') !== FALSE) {
	$seams['cron'] = static function (): bool {
		pfb_schedule_outcome_record('ipv4:feed_v4', PfbScheduleTerminalResult::Success);
		pfb_schedule_outcome_record('ipv4:other_v4', PfbScheduleTerminalResult::RetryCapReached);
		echo "the pass reported its feeds\n";
		posix_kill(getmypid(), 15);	// SIGTERM: the pcntl constants are not in every PHP build
		sleep(30);	// not reached: TERM's default action ends the process
		return TRUE;
	};
}
exit(pfb_core_update_serve((string) stream_get_contents(STDIN), 'php://fd/3', $seams));
