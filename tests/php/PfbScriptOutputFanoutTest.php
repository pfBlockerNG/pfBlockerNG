<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

#[CoversFunction('pfb_run_hooks')]
#[CoversFunction('pfb_script_output_exec')]
#[CoversFunction('pfb_script_output_sanitize_chunk')]
#[CoversFunction('pfb_stdout_close_line')]
final class PfbScriptOutputFanoutTest extends TestCase
{
	private const VIEWER_LIMIT = 1_000_000;
	private const VIEWER_NOTICE = "\n[ pfBlockerNG ] Script output limit (1,000,000 characters) reached; remaining output is in the main log.\n";

	private string $tmp;
	/** @var array<string, mixed> */
	private array $originalPfb;
	private bool $hadPfb;
	/** @var list<string> */
	private array $descendantPidFiles = [];

	protected function setUp(): void
	{
		$this->tmp = sys_get_temp_dir() . '/pfb_script_fanout_' . getmypid() . '_' . bin2hex(random_bytes(4));
		$this->assertTrue(mkdir($this->tmp, 0700, TRUE));
		$this->hadPfb = array_key_exists('pfb', $GLOBALS);
		$this->originalPfb = $GLOBALS['pfb'] ?? [];
		$this->setLogPaths($this->tmp, TRUE);
	}

	protected function tearDown(): void
	{
		foreach ($this->descendantPidFiles as $pidfile) {
			$this->killPidFile($pidfile);
		}
		if ($this->hadPfb) {
			$GLOBALS['pfb'] = $this->originalPfb;
		} else {
			unset($GLOBALS['pfb']);
		}
		$this->removeTree($this->tmp);
	}

	private function setLogPaths(string $dir, bool $viewerActive): void
	{
		global $pfb;
		$pfb['log'] = "{$dir}/main.log";
		$pfb['errlog'] = "{$dir}/error.log";
		$pfb['runlog'] = "{$dir}/viewer.log";
		$pfb['tmp'] = $dir;
		$pfb['runlog_active'] = $viewerActive;
		unset($pfb['core_update'], $pfb['hook_lifecycle']);
		file_put_contents($pfb['log'], '');
		file_put_contents($pfb['errlog'], '');
		file_put_contents($pfb['runlog'], '');
	}

	private function makeListOutputScript(): string
	{
		return $this->makePhpScript('list-output.php', <<<'PHP'
foreach (array_slice($argv, 1) as $index => $path) {
	$input = fopen($path, 'rb');
	$target = ($index === 1) ? STDERR : STDOUT;
	while (!feof($input)) {
		$chunk = fread($input, 8192);
		if ($chunk === FALSE) {
			exit(91);
		}
		$offset = 0;
		while ($offset < strlen($chunk)) {
			$written = fwrite($target, substr($chunk, $offset));
			if ($written === FALSE || $written === 0) {
				exit(92);
			}
			$offset += $written;
		}
		usleep(500);
	}
	fclose($input);
}
PHP);
	}

	private function makePhpScript(string $name, string $source): string
	{
		$path = "{$this->tmp}/{$name}";
		$this->assertNotFalse(file_put_contents($path, "#!/usr/bin/env php\n<?php\n{$source}\n"));
		$this->assertSame(0700, chmod($path, 0700) ? fileperms($path) & 0777 : FALSE);
		return $path;
	}

	/** @return list<string> */
	private function makeParts(int $total, int $seed): array
	{
		$firstLength = intdiv($total, 3);
		$middleLength = intdiv($total, 3);
		$middleTail = 'ERR';
		$lastTail = 'tail' . chr(65 + $seed);
		$lastLength = $total - $firstLength - $middleLength;
		return [
			str_repeat(chr(65 + $seed), $firstLength),
			str_repeat(chr(97 + $seed), $middleLength - strlen($middleTail)) . $middleTail,
			str_repeat(chr(48 + $seed), $lastLength - strlen($lastTail)) . $lastTail,
		];
	}

	/** @param list<string> $parts
	 *  @return list<string>
	 */
	private function writeParts(string $prefix, array $parts): array
	{
		$paths = [];
		foreach ($parts as $index => $part) {
			$path = "{$this->tmp}/{$prefix}.{$index}.bin";
			$this->assertSame(strlen($part), file_put_contents($path, $part));
			$paths[] = $path;
		}
		return $paths;
	}

	/** @param list<string> $args */
	private function runListScript(string $script, array $args = []): int
	{
		$prefix = escapeshellarg((string) $GLOBALS['pfb_test_timeout']) . ' -s TERM -k 1 15 ';
		$tail = implode(' ', array_map('escapeshellarg', $args));
		// issue #3977: the list-script wrapper left with the PHP Update pass; run its command through the surviving sink seam.
		return pfb_script_output_exec($prefix . escapeshellarg($script) . " {$tail}");
	}

	public function testListOutputIsSanitizedAndCharacterLimitedPerInvocationWhileProgressAndLaterRunsRemainVisible(): void
	{
		$script = $this->makeListOutputScript();
		$captureFilesBefore = $this->captureFiles();
		$payloads = [];
		$viewerPrefix = '';
		foreach ([self::VIEWER_LIMIT - 1, self::VIEWER_LIMIT, self::VIEWER_LIMIT + 1, self::VIEWER_LIMIT + 1] as $index => $size) {
			$parts = $this->makeParts($size, $index + 1);
			$paths = $this->writeParts("case{$index}", $parts);
			$payload = implode('', $parts);
			$this->assertSame($size, strlen($payload));
			$this->assertSame(0, $this->runListScript($script, $paths));
			$payloads[] = $payload;
			if ($index < 2) {
				$viewerPrefix .= $payload;
			} elseif ($index === 2) {
				$viewerPrefix .= substr($payload, 0, self::VIEWER_LIMIT) . self::VIEWER_NOTICE;
			}
			if ($index === 2) {
				pfb_logger("ORDINARY_PROGRESS after overflow\n", 1);
			}
		}

		$main = (string) file_get_contents($GLOBALS['pfb']['log']);
		$viewer = (string) file_get_contents($GLOBALS['pfb']['runlog']);
		$this->assertSame($viewerPrefix, substr($viewer, 0, strlen($viewerPrefix)));
		$this->assertSame(2, substr_count($viewer, self::VIEWER_NOTICE), 'each over-limit invocation gets one notice');
		$this->assertStringNotContainsString(substr($payloads[2], -7), $viewer, 'characters after the exact allowance stay out of the viewer');
		foreach ($payloads as $payload) {
			$this->assertSame(1, substr_count($main, $payload), 'the complete sanitized invocation is persisted once');
		}
		$this->assertSame(0, substr_count($main, self::VIEWER_NOTICE), 'the viewer notice is not duplicated into the main log');
		$progress = strpos($viewer, 'ORDINARY_PROGRESS after overflow');
		$this->assertNotFalse($progress);
		$this->assertGreaterThan(strlen($viewerPrefix), $progress, 'normal progress remains visible after the first script notice');
		$later = strpos($viewer, substr($payloads[3], 0, 64), $progress);
		$this->assertNotFalse($later, 'a later invocation receives a fresh allowance');
		$this->assertSame(substr($payloads[3], 0, self::VIEWER_LIMIT), substr($viewer, $later, self::VIEWER_LIMIT));
		$this->assertSame(self::VIEWER_NOTICE, substr($viewer, $later + self::VIEWER_LIMIT, strlen(self::VIEWER_NOTICE)));
		$this->assertSame($captureFilesBefore, $this->captureFiles(), 'private captures are removed after final drain');
	}

	public function testMixedUnicodeCountsCodepointsAtTheExactViewerBoundary(): void
	{
		$pattern = "\u{00E9}\u{20AC}\u{1F4A9}e\u{0301}";
		$this->assertSame(5, mb_strlen($pattern, 'UTF-8'));
		$repetitions = intdiv(self::VIEWER_LIMIT, 5);
		$expected = str_repeat($pattern, $repetitions);
		$script = $this->makePhpScript('unicode-limit.php', '$payload = str_repeat('
			. var_export($pattern, TRUE) . ', ' . $repetitions . '); fwrite(STDOUT, $payload);');

		$this->assertSame(self::VIEWER_LIMIT, mb_strlen($expected, 'UTF-8'));

		$this->assertSame(0, pfb_script_output_exec(escapeshellarg($script)));
		$this->assertSame($expected, file_get_contents($GLOBALS['pfb']['log']));
		$this->assertSame($expected, file_get_contents($GLOBALS['pfb']['runlog']));
		$this->assertStringNotContainsString(self::VIEWER_NOTICE, (string) file_get_contents($GLOBALS['pfb']['runlog']));
	}

	public function testSanitizesUtf8ControlsMalformedBytesAndChunkBoundariesIdenticallyForBothSinks(): void
	{
		$first = str_repeat('P', 8190) . "\xf0\x9f";
		$tail = "\x92\xa9\u{00E9}\u{20AC}e\u{0301}\n\t\r\n\x00\x1b\x7f\u{0085}\u{200e}\xe2\x28\xa1\xe2\x82";
		$expected = str_repeat('P', 8190) . "\u{1F4A9}\u{00E9}\u{20AC}e\u{0301}\n\t"
			. "\\x0D\n\\x00\\x1B\\x7F\\u{85}\\u{200E}\\xE2(\\xA1\\xE2\\x82";
		$source = 'fwrite(STDOUT, base64_decode(' . var_export(base64_encode($first), TRUE) . ')); fflush(STDOUT); usleep(500000);'
			. 'fwrite(STDERR, base64_decode(' . var_export(base64_encode($tail), TRUE) . '));';
		$script = $this->makePhpScript('sanitize-output.php', $source);

		$this->assertSame(0, pfb_script_output_exec(escapeshellarg($script)));
		$this->assertSame($expected, file_get_contents($GLOBALS['pfb']['log']));
		$this->assertSame($expected, file_get_contents($GLOBALS['pfb']['runlog']));
	}

	public function testEscapeTokenIsAtomicAtViewerCharacterBoundary(): void
	{
		$prefix = str_repeat('Q', self::VIEWER_LIMIT - 2);
		$raw = $prefix . "\x1bZ";
		$script = $this->makePhpScript('escape-limit.php',
			'fwrite(STDOUT, base64_decode(' . var_export(base64_encode($raw), TRUE) . '));');

		$this->assertSame(0, pfb_script_output_exec(escapeshellarg($script)));
		$this->assertSame($prefix . "\\x1BZ", file_get_contents($GLOBALS['pfb']['log']));
		$this->assertSame($prefix . self::VIEWER_NOTICE, file_get_contents($GLOBALS['pfb']['runlog']));
	}

	public function testGeneratedEscapeTokensAreAtomicWhenViewerHasInsufficientSpaceAndAtExactFit(): void
	{
		$cases = [
			['label' => 'unicode-short', 'prefix' => 'A', 'raw' => "\u{200E}", 'escaped' => "\\u{200E}", 'remaining' => 4, 'overflow' => TRUE],
			['label' => 'byte-short', 'prefix' => 'B', 'raw' => "\xff", 'escaped' => "\\xFF", 'remaining' => 2, 'overflow' => TRUE],
			['label' => 'unicode-exact', 'prefix' => 'C', 'raw' => "\u{200E}", 'escaped' => "\\u{200E}", 'remaining' => 8, 'overflow' => FALSE],
			['label' => 'byte-exact', 'prefix' => 'D', 'raw' => "\xff", 'escaped' => "\\xFF", 'remaining' => 4, 'overflow' => FALSE],
		];
		$search_from = 0;
		$notice_count = 0;
		foreach ($cases as $case) {
			$prefix = str_repeat($case['prefix'], self::VIEWER_LIMIT - $case['remaining']);
			$expected = $prefix . $case['escaped'];
			$source = 'fwrite(STDOUT, base64_decode(' . var_export(base64_encode($prefix . $case['raw']), TRUE) . '));';
			$script = $this->makePhpScript("escape-{$case['label']}.php", $source);

			$this->assertSame(0, pfb_script_output_exec(escapeshellarg($script)));
			$main = (string) file_get_contents($GLOBALS['pfb']['log']);
			$this->assertSame(1, substr_count($main, $expected), "main log must retain the complete {$case['label']} token");

			$viewer = (string) file_get_contents($GLOBALS['pfb']['runlog']);
			$viewer_start = strpos($viewer, $prefix, $search_from);
			$this->assertNotFalse($viewer_start, "{$case['label']} prefix must reach the viewer");
			$viewer_text = $case['overflow'] ? $prefix . self::VIEWER_NOTICE : $expected;
			$this->assertSame($viewer_text, substr($viewer, $viewer_start, strlen($viewer_text)),
				"viewer must emit {$case['label']} atomically");
			$search_from = $viewer_start + strlen($viewer_text);
			if ($case['overflow']) {
				$notice_count++;
				$progress = "TOKEN_BOUNDARY_PROGRESS {$case['label']}\n";
				pfb_logger($progress, 1);
				$viewer = (string) file_get_contents($GLOBALS['pfb']['runlog']);
				$progress_at = strpos($viewer, $progress, $search_from);
				$this->assertNotFalse($progress_at, "later progress must remain visible after {$case['label']} overflow");
				$search_from = $progress_at + strlen($progress);
			}
			$this->assertSame($notice_count, substr_count($viewer, self::VIEWER_NOTICE));
		}

		$this->assertSame(0, substr_count((string) file_get_contents($GLOBALS['pfb']['log']), self::VIEWER_NOTICE));
	}

	public function testUnicodeSanitizationIsStableAcrossSmallChunkPartitions(): void
	{
		$units = ["\u{00E9}", "\u{20AC}", "\u{1F4A9}"];
		foreach (range(1, 8) as $chunkSize) {
			foreach ($units as $unit) {
				foreach ([$chunkSize - 3, $chunkSize - 2, $chunkSize - 1] as $offset) {
					$prefix = str_repeat('A', max(0, $offset));
					$raw = $prefix . $unit . "Z\xe2\x28\xa1\u{1F4A9}\xe2\x82";
					$expected = $prefix . $unit . "Z\\xE2(\\xA1\u{1F4A9}\\xE2\\x82";
					$this->assertSame($expected, $this->sanitizeInChunks($raw, $chunkSize),
						"UTF-8 split failed: chunk={$chunkSize} offset={$offset} unit=" . bin2hex($unit));
				}
			}
		}
	}


	public function testOutputWithoutDistinctViewerRemainsUnlimitedAndIsLoggedOnce(): void
	{
		$this->setLogPaths($this->tmp, FALSE);
		$parts = $this->makeParts(self::VIEWER_LIMIT + 129, 8);
		$paths = $this->writeParts('no-viewer', $parts);
		$payload = implode('', $parts);

		$this->assertSame(0, $this->runListScript($this->makeListOutputScript(), $paths));

		$this->assertSame($payload, file_get_contents($GLOBALS['pfb']['log']));
		$this->assertSame('', file_get_contents($GLOBALS['pfb']['runlog']));
		$this->assertStringNotContainsString(self::VIEWER_NOTICE, (string) file_get_contents($GLOBALS['pfb']['log']));
	}

	public function testLifecycleCaptureClosesUnterminatedStdoutBeforeFraming(): void
	{
		$raw = "lifecycle-visible-without-newline";
		$source = 'fwrite(STDOUT, base64_decode(' . var_export(base64_encode($raw), TRUE) . '));';
		$script = $this->makePhpScript('lifecycle-line.php', $source);
		$captureFilesBefore = $this->captureFiles();

		ob_start();
		$status = pfb_script_output_exec(escapeshellarg($script), TRUE);
		pfb_stdout_close_line();
		print "done.\n";
		$stdout = (string) ob_get_clean();

		$this->assertSame(0, $status);
		$this->assertSame($raw . "\ndone.\n", $stdout);
		$this->assertSame(1, substr_count((string) file_get_contents($GLOBALS['pfb']['log']), $raw));
		$this->assertSame(1, substr_count((string) file_get_contents($GLOBALS['pfb']['runlog']), $raw));
		$this->assertSame($captureFilesBefore, $this->captureFiles());
	}

	public function testMainLogRotationDoesNotChangeViewerBytesOrLoseCapturedOutput(): void
	{
		$first = "rotation-first\n" . str_repeat('F', 16_384);
		$second = "rotation-second" . str_repeat('S', 16_384);
		$script = $this->makePhpScript('rotate-main.php', '$first = ' . var_export($first, TRUE) . ";\n"
			. '$second = ' . var_export($second, TRUE) . ";\n"
			. 'fwrite(STDOUT, $first); fflush(STDOUT); usleep(500000);' . "\n"
			. 'if (!rename($argv[1], $argv[1] . ".rotated")) { exit(93); }' . "\n"
			. 'file_put_contents($argv[1], ""); fwrite(STDERR, $second);');
		$expected = $first . $second;

		$this->assertSame(0, $this->runListScript($script, [$GLOBALS['pfb']['log']]));

		$this->assertSame($expected, file_get_contents($GLOBALS['pfb']['log'] . '.rotated') . file_get_contents($GLOBALS['pfb']['log']));
		$this->assertSame($expected, file_get_contents($GLOBALS['pfb']['runlog']));
	}

	public function testRealSinkWriteFailuresDoNotChangeChildStatusOrBlockHealthySink(): void
	{
		if (!file_exists('/dev/full') || !is_writable('/dev/full')) {
			$this->markTestSkipped('/dev/full is unavailable for a real write-failure proof');
		}
		$payload = 'SINK_FAILURE_STDOUT|SINK_FAILURE_STDERR';
		$script = $this->makePhpScript('sink-failure.php', 'fwrite(STDOUT, ' . var_export(substr($payload, 0, 20), TRUE) . ');'
			. 'fwrite(STDERR, ' . var_export(substr($payload, 20), TRUE) . '); exit(7);');

		$GLOBALS['pfb']['log'] = '/dev/full';
		$this->assertSame(7, $this->runListScript($script));
		$this->assertSame($payload, substr((string) file_get_contents($GLOBALS['pfb']['runlog']), 0, strlen($payload)));
		$error = (string) file_get_contents($GLOBALS['pfb']['errlog']);
		$this->assertSame(1, substr_count($error, 'Failed to write script output to main log'));

		$this->setLogPaths($this->tmp, TRUE);
		$GLOBALS['pfb']['runlog'] = '/dev/full';
		$this->assertSame(7, $this->runListScript($script));
		$main = (string) file_get_contents($GLOBALS['pfb']['log']);
		$this->assertSame(1, substr_count($main, $payload));
		$error = (string) file_get_contents($GLOBALS['pfb']['errlog']);
		$this->assertSame(1, substr_count($error, 'Failed to write script output to viewer'));
	}

	public function testGlobalHooksFanOutPreAndPostOutputAndKeepDetachedChildrenAndLifecycleStdout(): void
	{
		$normal = "{$this->tmp}/hook-normal";
		$this->assertTrue(mkdir($normal, 0700));
		$this->assertTrue(mkdir("{$normal}/hooks", 0700));
		$this->makeHookOutputScript($normal, 'pre');
		$this->makeHookOutputScript($normal, 'post');
		$this->writeHookScript("{$normal}/hooks", 'hook_pre_fail.sh',
			escapeshellarg(PHP_BINARY) . ' -r ' . escapeshellarg('exit(7);'));
		$this->writeHookScript("{$normal}/hooks", 'hook_post_timeout.sh',
			escapeshellarg(PHP_BINARY) . ' -r ' . escapeshellarg('sleep(5);'));
		$worker = $this->runHookWorker($normal, 'normal');
		$this->descendantPidFiles = ["{$normal}/pre.pid", "{$normal}/post.pid"];
		foreach ($this->descendantPidFiles as $pidfile) {
			$this->killPidFile($pidfile);
		}

		$this->assertSame(0, $worker['status']);
		$this->assertLessThan(5.0, $worker['elapsed'], 'an inherited regular-file descriptor cannot delay direct-runner completion');
		$main = (string) file_get_contents("{$normal}/main.log");
		$viewer = (string) file_get_contents("{$normal}/viewer.log");
		$preBytes = $this->hookOutputBytes('pre');
		$postBytes = $this->hookOutputBytes('post');
		$this->assertSame(1, substr_count($main, $preBytes));
		$this->assertSame(1, substr_count($main, $postBytes));
		$this->assertSame(2, substr_count($viewer, self::VIEWER_NOTICE));
		$this->assertHookViewerPrefix($viewer, $preBytes);
		$this->assertHookViewerPrefix($viewer, $postBytes);
		$progress = strpos($viewer, 'NORMAL_PROGRESS after overflow');
		$preNotice = strpos($viewer, self::VIEWER_NOTICE);
		$postStart = strpos($viewer, 'FDREG-post');
		$this->assertNotFalse($progress);
		$this->assertLessThan($progress, $preNotice, 'ordinary progress follows the first script notice');
		$this->assertLessThan($postStart, $progress, 'post-hook output remains visible after normal progress');
		$this->assertStringContainsString('exited non-zero [ 7 ]', $main);
		$this->assertStringContainsString('TIMED OUT after 1s', $main);

		$lifecycle = "{$this->tmp}/hook-lifecycle";
		$this->assertTrue(mkdir($lifecycle, 0700));
		$this->assertTrue(mkdir("{$lifecycle}/hooks", 0700));
		$lifecycleBytes = 'LIFECYCLE_VISIBLE_without-newline';
		$lifecyclePhp = 'fwrite(STDOUT, base64_decode(' . var_export(base64_encode($lifecycleBytes), TRUE) . '));';
		$this->writeHookScript("{$lifecycle}/hooks", 'hook_pre_lifecycle.sh',
			escapeshellarg(PHP_BINARY) . ' -r ' . escapeshellarg($lifecyclePhp));
		$lifecycleRun = $this->runHookWorker($lifecycle, 'lifecycle');
		$this->assertSame(0, $lifecycleRun['status']);
		$this->assertSame(1, substr_count($lifecycleRun['stdout'], $lifecycleBytes));
		$hookStart = strpos($lifecycleRun['stdout'], $lifecycleBytes);
		$done = strpos($lifecycleRun['stdout'], "done.\n");
		$this->assertNotFalse($hookStart);
		$this->assertNotFalse($done);
		$this->assertGreaterThan($hookStart, $done, 'package framing resumes after the hook output');
		$this->assertSame(1, substr_count((string) file_get_contents("{$lifecycle}/main.log"), $lifecycleBytes));
		$this->assertSame('', file_get_contents("{$lifecycle}/viewer.log"));
		$this->assertStringNotContainsString(self::VIEWER_NOTICE, (string) file_get_contents("{$lifecycle}/main.log"));
	}

	private function makeHookOutputScript(string $dir, string $label): string
	{
		$prefix = "FDREG-{$label}\n";
		$errorPrefix = "ERR-{$label}\n";
		$tail = "TAIL-{$label}";
		$php = '$out = fstat(STDOUT); $err = fstat(STDERR); '
			. '$regular = (($out["mode"] & 0170000) === 0100000) && (($err["mode"] & 0170000) === 0100000) && (($out["mode"] & 0777) === 0600) && (($err["mode"] & 0777) === 0600); '
			. 'fwrite(STDOUT, $regular ? ' . var_export($prefix, TRUE) . ' : ' . var_export("FDNOTREG-{$label}\n", TRUE) . '); '
			. '$write = static function ($stream, string $char, int $length): void { '
			. 'for ($offset = 0; $offset < $length; $offset += 8192) { '
			. 'fwrite($stream, str_repeat($char, min(8192, $length - $offset))); usleep(500); } }; '
			. '$write(STDOUT, "A", 600000); fwrite(STDERR, ' . var_export($errorPrefix, TRUE) . '); '
			. '$write(STDERR, "B", 500000); fwrite(STDOUT, base64_decode(' . var_export(base64_encode($tail), TRUE) . '));';
		$pidfile = "{$dir}/{$label}.pid";
		$body = escapeshellarg(PHP_BINARY) . ' -r ' . escapeshellarg($php) . "\n"
			. '(sleep 30) &' . "\nprintf '%s' \"\$!\" > " . escapeshellarg($pidfile) . "\n";
		$this->writeHookScript("{$dir}/hooks", "hook_{$label}_capture.sh", $body);
		return $pidfile;
	}

	private function hookOutputBytes(string $label): string
	{
		return "FDREG-{$label}\n" . str_repeat('A', 600000) . "ERR-{$label}\n" . str_repeat('B', 500000) . "TAIL-{$label}";
	}

	private function assertHookViewerPrefix(string $viewer, string $output): void
	{
		$start = strpos($viewer, substr($output, 0, 32));
		$this->assertNotFalse($start);
		$this->assertSame(substr($output, 0, self::VIEWER_LIMIT), substr($viewer, $start, self::VIEWER_LIMIT));
		$this->assertSame(self::VIEWER_NOTICE, substr($viewer, $start + self::VIEWER_LIMIT, strlen(self::VIEWER_NOTICE)));
	}

	private function writeHookScript(string $dir, string $name, string $body): string
	{
		$path = "{$dir}/{$name}";
		$this->assertNotFalse(file_put_contents($path, "#!/bin/sh\n{$body}\n"));
		$this->assertTrue(chmod($path, 0700));
		return $path;
	}

	/** @return array{status:int, stdout:string, elapsed:float} */
	private function runHookWorker(string $dir, string $mode): array
	{
		$repo = dirname(__DIR__, 2);
		$worker = "{$dir}/worker.php";
		$source = <<<'PHP'
$root = $argv[1];
$mode = $argv[2];
$repo = $argv[3];
define('PFB_HOOK_SCRIPT_DIR', "{$root}/hooks");
require "{$repo}/tests/php/bootstrap.php";
$pfb =& $GLOBALS['pfb'];
$pfb['log'] = "{$root}/main.log";
$pfb['errlog'] = "{$root}/error.log";
$pfb['runlog'] = "{$root}/viewer.log";
$pfb['tmp'] = $root;
file_put_contents($pfb['log'], '');
file_put_contents($pfb['errlog'], '');
file_put_contents($pfb['runlog'], '');
unset($pfb['core_update']);
if ($mode === 'normal') {
	$pfb['runlog_active'] = TRUE;
	$rows = [
		['script' => 'hook_pre_capture.sh', 'when' => 'pre', 'enabled' => 'on', 'timeout' => '5', 'description' => 'pre capture'],
		['script' => 'hook_pre_fail.sh', 'when' => 'pre', 'enabled' => 'on', 'timeout' => '5', 'description' => 'pre fail'],
		['script' => 'hook_post_capture.sh', 'when' => 'post', 'enabled' => 'on', 'timeout' => '5', 'description' => 'post capture'],
		['script' => 'hook_post_timeout.sh', 'when' => 'post', 'enabled' => 'on', 'timeout' => '1', 'description' => 'post timeout'],
	];
} else {
	unset($pfb['runlog_active']);
	$pfb['hook_lifecycle'] = 'install';
	$rows = [['script' => 'hook_pre_lifecycle.sh', 'when' => 'pre', 'enabled' => 'on', 'timeout' => '5', 'description' => 'lifecycle']];
}
$GLOBALS['config']['installedpackages']['pfblockerng']['config'][0] = ['hooks' => ['row' => $rows]];
if ($mode === 'normal') {
	pfb_run_hooks('pre');
	pfb_logger("NORMAL_PROGRESS after overflow\n", 1);
	pfb_run_hooks('post');
} else {
	pfb_run_hooks('pre');
	pfb_stdout_close_line();
	print "done.\n";
}
PHP;
		$phpSource = "<?php\n" . str_replace(['{$root}', '{$repo}'], ['$root', '$repo'], $source);
		$this->assertNotFalse(file_put_contents($worker, $phpSource));
		$stdout = "{$dir}/worker.stdout";
		$timeout = escapeshellarg((string) $GLOBALS['pfb_test_timeout']) . ' --foreground -k 2 12 ';
		$command = $timeout . escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($worker) . ' '
			. escapeshellarg($dir) . ' ' . escapeshellarg($mode) . ' ' . escapeshellarg($repo)
			. ' > ' . escapeshellarg($stdout) . ' 2>&1';
		$start = microtime(TRUE);
		$captureFilesBefore = $this->captureFiles();
		exec($command, $discard, $status);
		$elapsed = microtime(TRUE) - $start;
		$this->assertSame($captureFilesBefore, $this->captureFiles(), 'worker captures are removed after final drain');
		foreach (glob("{$dir}/*.pid") ?: [] as $pidfile) {
			$this->descendantPidFiles[] = $pidfile;
			$this->killPidFile($pidfile);
		}
		return ['status' => $status, 'stdout' => (string) file_get_contents($stdout), 'elapsed' => $elapsed];
	}

	private function sanitizeInChunks(string $raw, int $chunkSize): string
	{
		$carry = '';
		$out = '';
		$emit = static function (string $text, int $characters, bool $atomic) use (&$out): void {
			$out .= $text;
		};
		for ($offset = 0, $length = strlen($raw); $offset < $length; $offset += $chunkSize) {
			pfb_script_output_sanitize_chunk(substr($raw, $offset, $chunkSize), $carry, FALSE, $emit);
		}
		pfb_script_output_sanitize_chunk('', $carry, TRUE, $emit);
		return $out;
	}

	private function killPidFile(string $pidfile): void
	{
		if (!is_file($pidfile)) {
			return;
		}
		$pid = (int) trim((string) file_get_contents($pidfile));
		if ($pid > 1) {
			if (function_exists('posix_kill')) {
				@posix_kill($pid, SIGTERM);
			} else {
				exec('kill ' . escapeshellarg((string) $pid) . ' 2>/dev/null');
			}
		}
	}

	private function captureFiles(): array
	{
		return glob(rtrim(sys_get_temp_dir(), '/') . '/pfb-script-output-*') ?: [];
	}

	private function removeTree(string $path): void
	{
		if (!is_dir($path)) {
			@unlink($path);
			return;
		}
		foreach (glob("{$path}/*") ?: [] as $child) {
			$this->removeTree($child);
		}
		@rmdir($path);
	}
}
