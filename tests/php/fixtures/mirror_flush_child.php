<?php

/*
 * Child process for PfbMirrorFlushTest.
 *
 * Models the pkg Software page condition: the resync runs under an ACTIVE PHP
 * output buffer (ob_start). Each mirror print() lands in that buffer; only an
 * explicit ob_flush()+flush() (pfb_flush_output(), the code under test) pushes it
 * to the real stdout, which the parent redirects to a FILE. The child then
 * HARD-KILLS itself with SIGKILL, so PHP's shutdown -- which would otherwise flush
 * the ob buffer -- never runs. The printed bytes are on disk afterwards ONLY if
 * the production code drained the buffer itself; without that they die in the ob
 * buffer with the process and the file stays empty.
 *
 * argv: <mode: hook|logger> <logfile> <offset> <marker>
 *   hook   -> pfb_mirror_hook_output($logfile, $offset) prints the log delta
 *   logger -> pfb_logger("<marker>\n", 1) prints via the #690 lifecycle mirror
 */

// Capture argv BEFORE bootstrap.php clears $argv (it blanks it to keep the
// pfblockerng.inc daemon dispatch dormant).
$args = $argv;
require __DIR__ . '/../bootstrap.php';

global $pfb;
$mode    = $args[1] ?? '';
$logfile = $args[2] ?? '';
$offset  = (int) ($args[3] ?? 0);
$marker  = $args[4] ?? '';

// A pkg lifecycle callback is what turns on both mirrors.
$pfb['hook_lifecycle'] = 'install';

// The pkg Software page runs the resync under output buffering -- reproduce that,
// so a print() reaches the fd only if the code under test drains the ob buffer.
ob_start();

if ($mode === 'logger') {
	pfb_logger("{$marker}\n", 1);
} else {
	pfb_mirror_hook_output($logfile, $offset);
}

// Terminate WITHOUT PHP's shutdown sequence (which flushes the ob buffer). SIGKILL
// leaves any still-buffered output unwritten — the whole point of the probe.
posix_kill(posix_getpid(), SIGKILL);
