<?php

declare(strict_types=1);

require_once __DIR__ . '/support/ProcessRunner.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3941: Core starts every Update and runs the Outpost's `core_update` verb (pfb_core_update.sh, --update-cmd) with the
 * request on stdin. Since the cutover (#3977) the Core Updater loop runs each Update and the verb serves only the Outpost apply
 * of a version 2 request (OutpostApplyTest pins it). A request of any other version, the PHP Update program's version 1 among
 * them, is refused before anything runs: no result is written, the refusal is in the progress log, and the exit is 2.
 */
#[CoversFunction('pfb_core_update_serve')]
final class CoreUpdateServeTest extends TestCase
{
	private string $dir = '';
	private array $originalPfb = [];

	protected function setUp(): void
	{
		$this->originalPfb = $GLOBALS['pfb'];
		$this->dir = sys_get_temp_dir() . '/pfb_core_update_' . getmypid() . '_' . bin2hex(random_bytes(6));
		mkdir($this->dir, 0755, TRUE);
		$GLOBALS['pfb']['dbdir'] = $this->dir;
		$GLOBALS['pfb']['pending_marker'] = "{$this->dir}/pfb_pending_changes";
		$GLOBALS['pfb']['log'] = "{$this->dir}/pfb.log";
		$GLOBALS['pfb']['run_stdout_override'] = FALSE;
	}

	protected function tearDown(): void
	{
		$GLOBALS['pfb'] = $this->originalPfb;
		rmdir_recursive($this->dir);
	}

	/** @return array<string, array{0: string}> */
	public static function requestsOfAnotherVersion(): array
	{
		$v1 = '"trigger":"apply","scope":"both","force":"none"';
		return [
			'a version 1 apply'      => ["{\"version\":1,{$v1}}"],
			'a version 1 manual'     => ['{"version":1,"trigger":"manual","scope":"both","force":"download"}'],
			'a version 1 scheduled'  => ['{"version":1,"trigger":"scheduled","feeds":["ipv4:feed_v4"],"extras":["extra:dcc"]}'],
			'the string "2"'         => ["{\"version\":\"2\",{$v1}}"],
			'the number 2.0'         => ["{\"version\":2.0,{$v1}}"],
			'the integer 3'          => ["{\"version\":3,{$v1}}"],
			'no version'             => ["{{$v1}}"],
			'not JSON'               => ['{"version":'],
		];
	}

	#[DataProvider('requestsOfAnotherVersion')]
	public function testARequestOfAnotherVersionIsRefusedRunsNothingAndExitsTwo(string $request): void
	{
		// Given a pending change a run would clear, and seams that fail the test when they run
		pfb_mark_pending_changes();
		$fail = static fn (): bool => self::fail('something ran');
		$resultPath = "{$this->dir}/result.json";

		ob_start();
		try {
			$exit = pfb_core_update_serve($request, $resultPath, ['extra' => $fail, 'cron' => $fail, 'sync' => $fail, 'fetch' => $fail]);
		} finally {
			$out = (string) ob_get_clean();
		}

		$this->assertSame(2, $exit, $out);
		$this->assertFileDoesNotExist($resultPath, 'a refused request writes no result');
		$this->assertTrue(pfb_pending_changes(), 'the pending change is untouched');
		$this->assertStringContainsString('Core Update request refused: the request is not of version 2', $out);
	}

	public function testTheVersion1UpdateProgramIsGone(): void
	{
		$extra = php_strip_whitespace(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_extra.inc');
		foreach (['function pfb_core_update_run(', 'function pfb_core_update_scheduled(', 'function pfb_core_update_apply(',
			'function pfb_core_update_request('] as $gone) {
			$this->assertStringNotContainsString($gone, $extra);
		}
	}

	// ----- the verb and its wrapper -----

	private const WRAPPER = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfb_core_update.sh';

	public function testTheWrapperExecsTheVerbWithPhpErrorsOffStdoutAndNothingElse(): void
	{
		$lines = file(self::WRAPPER, FILE_IGNORE_NEW_LINES);

		$this->assertIsArray($lines, 'the wrapper exists');
		$this->assertCount(3, $lines);
		$this->assertSame('#!/bin/sh', $lines[0]);
		$this->assertStringStartsWith('# ', $lines[1]);
		$this->assertSame('exec /usr/local/bin/php -d display_errors=stderr -f /usr/local/pkg/pfblockerng/pfblockerng.inc core_update', $lines[2]);
		$this->assertTrue(is_executable(self::WRAPPER), 'the nightly port installs *.sh with their mode; Core execs it');
		$syntax = pfb_test_run_process(['/bin/sh', '-n', self::WRAPPER]);
		$this->assertSame(0, $syntax['exit'], $syntax['stderr']);
	}

	public function testTheVerbRefusesARequestThatIsNoRequestWithExitTwoAndNoResult(): void
	{
		$in = "{$this->dir}/stdin";
		file_put_contents($in, '{"version":1,"trigger":"daily"}');
		$result = "{$this->dir}/verb-result";
		touch($result);
		$command = [PHP_BINARY, __DIR__ . '/bin/cli_dispatch_entry.php', 'core_update'];
		$process = proc_open($command, [0 => ['file', $in, 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w'], 3 => ['file', $result, 'w']], $pipes);
		$this->assertIsResource($process);
		stream_set_blocking($pipes[1], FALSE);
		stream_set_blocking($pipes[2], FALSE);

		$run = pfb_test_finish_process([$process, $pipes, implode(' ', $command)], 60.0);

		$this->assertSame(2, $run['exit'], $run['stdout'] . $run['stderr']);
		$this->assertStringContainsString('refused', $run['stdout'], 'the refusal is in the progress log');
		$this->assertSame('', (string) file_get_contents($result), 'nothing reported on fd 3');
	}
}
