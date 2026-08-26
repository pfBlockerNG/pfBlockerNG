<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_ip_parse_fail_warn() -- issue #993. Per-feed IP parse-error summary: one
 * WARNING line naming the feed + the final count, emitted only when $parse_fail>0
 * (the fix that replaced one spammed log line PER failed line). logtype 2 writes
 * both the main pfBlockerNG log ($pfb['log']) and the Error log ($pfb['errlog']);
 * both are pointed at temp files so the guard is asserted on the primary log.
 */
#[CoversFunction('pfb_ip_parse_fail_warn')]
final class PfbIpParseFailWarnTest extends TestCase
{
	/** @var string[] temp files to remove in tearDown */
	private array $tmpfiles = [];

	private mixed $prevLog = false;
	private mixed $prevErrLog = false;

	protected function setUp(): void
	{
		$this->prevLog = array_key_exists('log', $GLOBALS['pfb'] ?? []) ? $GLOBALS['pfb']['log'] : false;
		$this->prevErrLog = array_key_exists('errlog', $GLOBALS['pfb'] ?? []) ? $GLOBALS['pfb']['errlog'] : false;
	}

	protected function tearDown(): void
	{
		if ($this->prevLog === false) {
			unset($GLOBALS['pfb']['log']);
		} else {
			$GLOBALS['pfb']['log'] = $this->prevLog;
		}
		if ($this->prevErrLog === false) {
			unset($GLOBALS['pfb']['errlog']);
		} else {
			$GLOBALS['pfb']['errlog'] = $this->prevErrLog;
		}
		foreach ($this->tmpfiles as $f) {
			if (is_file($f)) {
				$this->assertTrue(unlink($f), "failed to remove temp file {$f}");
			}
		}
		$this->tmpfiles = [];
	}

	private function mktemp(string $prefix): string
	{
		$path = tempnam(sys_get_temp_dir(), $prefix);
		$this->assertNotFalse($path, "tempnam({$prefix}) failed");
		$this->tmpfiles[] = $path;
		$this->assertNotFalse(file_put_contents($path, ''), "could not truncate {$path}");
		return $path;
	}

	private function readFile(string $path): string
	{
		$raw = file_get_contents($path);
		$this->assertNotFalse($raw, "could not read {$path}");
		return (string) $raw;
	}

	public function testNoWarningWrittenWhenParseFailIsZero(): void
	{
		$mainlog = $this->mktemp('pfb_main_log_');
		$errlog  = $this->mktemp('pfb_err_log_');
		$GLOBALS['pfb']['log']    = $mainlog;
		$GLOBALS['pfb']['errlog'] = $errlog;

		pfb_ip_parse_fail_warn(0, 'TestFeed_v4');

		$this->assertSame('', $this->readFile($mainlog));
		$this->assertSame('', $this->readFile($errlog));
	}

	public function testWarningWrittenOnceWithFeedAndCountWhenParseFailPositive(): void
	{
		$mainlog = $this->mktemp('pfb_main_log_');
		$errlog  = $this->mktemp('pfb_err_log_');
		$GLOBALS['pfb']['log']    = $mainlog;
		$GLOBALS['pfb']['errlog'] = $errlog;

		pfb_ip_parse_fail_warn(5, 'TestFeed_v4');

		$logged = $this->readFile($mainlog);
		$this->assertStringContainsString('[!] Parse Errors [ TestFeed_v4 ]: 5', $logged);
		$this->assertSame(1, substr_count($logged, 'Parse Errors ['));
	}
}
