<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/*
 * During a pkg install/upgrade pfSense's Software page (pkg_mgr_install.php) runs
 * the pfBlockerNG resync under an ACTIVE PHP output buffer. The two lifecycle
 * mirrors -- pfb_logger()'s #690 progress mirror and pfb_mirror_hook_output()'s
 * #693 hook-body mirror -- print() into that buffer, which is flushed only in
 * chunks / at request end, so a long upgrade shows the progress + hook output cut
 * off "mid way" (and drops the tail if the poll stops first). pfb_flush_output()
 * drains the ob buffer + SAPI after each mirror print so every line streams now.
 *
 * The existing PfbHookOutputMirrorTest captures via ob_start()+ob_get_clean(),
 * which reads the buffer directly and so sees the print whether or not it was
 * drained -- it cannot prove this fix. This pins the DRAIN directly: run the mirror
 * under ob_start() in a child whose real stdout is a redirected FILE, then SIGKILL
 * the child before the shutdown that would flush the buffer. The bytes are on disk
 * only if the code drained the buffer itself -- red without pfb_flush_output()
 * (output dies in the ob buffer with the process), green with it.
 */
#[CoversFunction('pfb_mirror_hook_output')]
#[CoversFunction('pfb_logger')]
#[CoversFunction('pfb_flush_output')]
final class PfbMirrorFlushTest extends TestCase
{
	private const BODY   = "Firing up HAProxy ACL update hook\nReloading HAProxy\n";
	private const MARKER = 'pfb-upgrade-progress-marker';

	private array $tmp = [];

	protected function setUp(): void
	{
		// SIGKILL-before-shutdown is how we deny the process its exit-time fflush;
		// without ext-posix there is no portable way to observe the pre-exit flush.
		if (!function_exists('posix_kill') || !defined('SIGKILL')) {
			$this->markTestSkipped('ext-posix (posix_kill/SIGKILL) required to observe the pre-exit flush');
		}
	}

	protected function tearDown(): void
	{
		foreach ($this->tmp as $f) {
			@unlink($f);
		}
		$this->tmp = [];
	}

	private function tempfile(string $prefix): string
	{
		$f = (string) tempnam(sys_get_temp_dir(), $prefix);
		$this->tmp[] = $f;
		return $f;
	}

	/*
	 * Run the fixture child with its stdout redirected to a file, wait for it to die
	 * (SIGKILL), and return exactly what landed on disk.
	 */
	private function runChild(string $mode, string $logfile, int $offset, string $marker): string
	{
		$child   = __DIR__ . '/fixtures/mirror_flush_child.php';
		$outfile = $this->tempfile('pfb_mirror_out_');
		$cmd = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($child) . ' '
			. escapeshellarg($mode) . ' ' . escapeshellarg($logfile) . ' '
			. escapeshellarg((string) $offset) . ' ' . escapeshellarg($marker)
			. ' > ' . escapeshellarg($outfile) . ' 2>/dev/null';
		exec($cmd);
		return (string) @file_get_contents($outfile);
	}

	public function testHookBodyReachesRedirectedStdoutBeforeProcessExit(): void
	{
		// Given a hook that appended BODY after the framing-marker offset,
		$logfile = $this->tempfile('pfb_mirror_log_');
		file_put_contents($logfile, "[ pfB Hook ] post haproxy\n");
		clearstatcache(TRUE, $logfile);
		$offset = (int) filesize($logfile);
		file_put_contents($logfile, self::BODY, FILE_APPEND);

		// When the mirror runs under an active output buffer and the child is SIGKILLed before
		// the shutdown that would flush it,
		$out = $this->runChild('hook', $logfile, $offset, '');

		// Then the whole body is already on disk -- pfb_mirror_hook_output() drained the buffer
		// itself. Pre-fix it would die in the ob buffer with the process and $out would be empty.
		$this->assertSame(self::BODY, $out);
	}

	public function testLoggerLifecycleMirrorReachesRedirectedStdoutBeforeProcessExit(): void
	{
		// Given a lifecycle callback, a case-1 pfb_logger() line is mirrored to stdout (#690).
		// When it runs under an active output buffer and the child is SIGKILLed before exit,
		$out = $this->runChild('logger', '', 0, self::MARKER);

		// Then the mirrored line is already on disk -- pfb_logger() drained the buffer itself.
		// Pre-fix it would sit in the ob buffer and be lost, leaving $out without the marker.
		$this->assertStringContainsString(self::MARKER, $out);
	}
}
