<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Alias totals use the apply-pass count seam: unreadable input contributes zero,
 * while empty and unterminated files retain their real line counts.
 */
final class AliasCntGrepCountGuardTest extends TestCase
{
	private const APPLY = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc';
	private string $dir;

	public static function setUpBeforeClass(): void
	{
		require_once self::APPLY;
	}

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_alias_count_' . getmypid() . '_' . bin2hex(random_bytes(4));
		$this->assertTrue(mkdir($this->dir, 0700, TRUE));
	}

	protected function tearDown(): void
	{
		foreach (glob("{$this->dir}/*") ?: [] as $path) {
			is_dir($path) ? @rmdir($path) : @unlink($path);
		}
		@rmdir($this->dir);
	}

	/** @return array<string, array{string}> */
	public static function aliasSeams(): array
	{
		return [
			'verbatim reuse'    => ['pfb_dnsbl_alias_count_verbatim'],
			'pre-script failure' => ['pfb_dnsbl_alias_count_script_failure'],
			'rebuilt feed'      => ['pfb_dnsbl_alias_count_rebuild'],
		];
	}

	#[\PHPUnit\Framework\Attributes\DataProvider('aliasSeams')]
	public function testEveryAliasRouteUsesSafeFileLineCount(string $seam): void
	{
		$path = "{$this->dir}/feed.txt";
		$this->assertNotFalse(file_put_contents($path, "one\ntwo\n"));

		$this->assertSame(12, $seam($path, 10));
	}

	#[\PHPUnit\Framework\Attributes\DataProvider('aliasSeams')]
	public function testEveryAliasRouteCountsAnUnterminatedLastLine(string $seam): void
	{
		$path = "{$this->dir}/unterminated.txt";
		$this->assertNotFalse(file_put_contents($path, "one\ntwo"));
		$this->assertSame(12, $seam($path, 10));
	}

	#[\PHPUnit\Framework\Attributes\DataProvider('aliasSeams')]
	public function testEveryAliasRouteTurnsReadFailureIntoZero(string $seam): void
	{
		$path = "{$this->dir}/unreadable";
		$this->assertTrue(mkdir($path, 0700));

		$this->assertSame(10, $seam($path, 10));
	}

	/**
	 * Keep outer dispatch pinned alongside the executable line-count cases above.
	 * DnsblVipApplyLifecycleTest covers actual script/source failure retention;
	 * those mutually exclusive paths share the same last-good count helper.
	 */
	public function testSyncPassDispatchesEveryDistinctAliasCountRoute(): void
	{
		$source = php_strip_whitespace(self::APPLY);
		$start = strpos($source, 'function sync_package_pfblockerng(');
		$this->assertNotFalse($start);
		$end = strrpos($source, 'pfb_feed_pass_release();');
		$this->assertNotFalse($end);
		$sync = substr($source, $start, $end + strlen('pfb_feed_pass_release();') - $start);
		foreach (self::aliasSeams() as [$seam]) {
			$expected = $seam === 'pfb_dnsbl_alias_count_script_failure' ? 2 : 1;
			$this->assertSame($expected, substr_count($sync, "{$seam}("), "unexpected dispatch count for {$seam}");
		}
		$this->assertSame(1, substr_count($sync, 'pfb_dnsbl_alias_count_script_failure("'),
			'script failure must count its retained staging exactly once');
		$this->assertSame(1, substr_count($sync, 'pfb_dnsbl_alias_count_script_failure($txt,'),
			'source failure must count its retained staging exactly once');
	}
}
