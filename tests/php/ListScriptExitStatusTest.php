<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class ListScriptExitStatusTest extends TestCase
{
	private const APPLY = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc';

	private string $tmp;
	/** @var array<string, mixed> */
	private array $originalPfb;
	private bool $hadPfb;

	public static function setUpBeforeClass(): void
	{
		require_once self::APPLY;
	}

	protected function setUp(): void
	{
		$this->tmp = sys_get_temp_dir() . '/pfb_script_exit_' . getmypid() . '_' . bin2hex(random_bytes(4));
		$this->assertTrue(mkdir($this->tmp, 0700, TRUE));
		$this->hadPfb = array_key_exists('pfb', $GLOBALS);
		$this->originalPfb = $GLOBALS['pfb'] ?? [];
		$GLOBALS['pfb'] = array_merge($GLOBALS['pfb'] ?? [], [
			'log'    => "{$this->tmp}/pfblockerng.log",
			'errlog' => "{$this->tmp}/error.log",
		]);
	}

	protected function tearDown(): void
	{
		if ($this->hadPfb) {
			$GLOBALS['pfb'] = $this->originalPfb;
		} else {
			unset($GLOBALS['pfb']);
		}
		foreach (glob("{$this->tmp}/*") ?: [] as $file) {
			@unlink($file);
		}
		@rmdir($this->tmp);
	}

	public function testDnsblSuccessfulPreScriptConsumesBeforeCleanup(): void
	{
		$staged = "{$this->tmp}/feed.pre";
		file_put_contents($staged, 'dnsbl-data');
		$events = [];

		$result = pfb_dnsbl_script_consume_staged($staged, $staged, function (string $path) use (&$events): string {
			$events[] = 'consume:' . file_get_contents($path);
			return 'parsed';
		});

		$this->assertSame('parsed', $result);
		$this->assertSame(['consume:dnsbl-data'], $events);
		$this->assertFileDoesNotExist($staged);
	}

	public function testDnsblKnownPrePathIsRemovedWithoutAnActiveStagedCopy(): void
	{
		$norm  = "{$this->tmp}/feed.norm";
		$known = "{$this->tmp}/feed.pre";
		file_put_contents($known, 'stale-dnsbl-data');

		$result = pfb_dnsbl_script_consume_staged(
			$norm,
			NULL,
			static fn(string $path): string => $path,
			$known
		);

		$this->assertSame($norm, $result);
		$this->assertFileDoesNotExist($known,
			'a processed DNSBL row must remove a stale known .pre path even without a pre-script stage');
	}
}
