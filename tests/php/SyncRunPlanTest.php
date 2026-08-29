<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversFunction('pfb_sync_run_plan')]
final class SyncRunPlanTest extends TestCase
{
	public static function planProvider(): iterable
	{
		$off = [
			'reuse' => '', 'reuse_dnsbl' => '', 'updatednsbl' => FALSE,
			'save' => FALSE, 'clear_masterfiles' => FALSE,
		];
		$on = [
			'reuse' => 'on', 'reuse_dnsbl' => '', 'updatednsbl' => FALSE,
			'save' => FALSE, 'clear_masterfiles' => FALSE,
		];

		yield 'no updates outranks force' => [
			['scope' => 'both', 'force' => TRUE], TRUE, FALSE, '',
			array_replace($off, ['save' => TRUE]),
		];
		yield 'force both domains' => [
			['scope' => 'both', 'force' => TRUE], FALSE, FALSE, '',
			[
				'reuse' => 'on', 'reuse_dnsbl' => 'on', 'updatednsbl' => TRUE,
				'save' => FALSE, 'clear_masterfiles' => TRUE,
			],
		];
		yield 'force IP only' => [
			['scope' => 'ip', 'force' => TRUE], FALSE, FALSE, '',
			array_replace($off, ['reuse' => 'on', 'clear_masterfiles' => TRUE]),
		];
		yield 'force DNSBL only' => [
			['scope' => 'dnsbl', 'force' => TRUE], FALSE, FALSE, 'on',
			array_replace($off, ['reuse_dnsbl' => 'on', 'updatednsbl' => TRUE]),
		];
		yield 'legacy update cron tick reuses DNSBL' => [
			['scope' => 'both', 'force' => FALSE], FALSE, TRUE, 'on',
			array_replace($on, ['reuse_dnsbl' => 'on', 'clear_masterfiles' => TRUE]),
		];
		yield 'manual array update keeps configured reuse local to IP' => [
			['scope' => 'both', 'force' => FALSE], FALSE, FALSE, 'on', $on,
		];
		yield 'cron tick with reuse disabled' => [
			['scope' => 'both', 'force' => FALSE], FALSE, TRUE, '', $off,
		];
		yield 'IP scope without force' => [
			['scope' => 'ip', 'force' => FALSE], FALSE, FALSE, 'on', $on,
		];
		yield 'invalid scope is inert' => [
			['scope' => 'invalid', 'force' => TRUE], FALSE, FALSE, 'on', $on,
		];
		yield 'empty request is inert' => [
			[], FALSE, FALSE, '', $off,
		];
	}

	#[DataProvider('planProvider')]
	public function testPlanMatchesCurrentDecision(
		array $request,
		bool $no_updates,
		bool $cron_tick,
		string $configured_reuse,
		array $expected
	): void {
		$this->assertSame(
			$expected,
			pfb_sync_run_plan($request, $no_updates, $cron_tick, $configured_reuse)
		);
	}

	public function testRepeatedPlanningHasNoGlobalOrFilesystemEffects(): void
	{
		$previous_pfb = $GLOBALS['pfb'];
		$dir = sys_get_temp_dir() . '/pfb_sync_plan_' . getmypid() . '_' . uniqid();
		mkdir($dir, 0777, TRUE);
		file_put_contents("{$dir}/masterfile", 'master');
		file_put_contents("{$dir}/mastercat", 'category');
		$GLOBALS['pfb'] = ['dbdir' => $dir, 'sentinel' => 'unchanged'];

		try {
			$request = ['scope' => 'both', 'force' => TRUE];
			$first = pfb_sync_run_plan($request, FALSE, FALSE, '');
			$this->assertSame($first, pfb_sync_run_plan($request, FALSE, FALSE, ''));
			$this->assertSame(['dbdir' => $dir, 'sentinel' => 'unchanged'], $GLOBALS['pfb']);
			$this->assertSame('master', file_get_contents("{$dir}/masterfile"));
			$this->assertSame('category', file_get_contents("{$dir}/mastercat"));
		} finally {
			$GLOBALS['pfb'] = $previous_pfb;
			@unlink("{$dir}/masterfile");
			@unlink("{$dir}/mastercat");
			@rmdir($dir);
		}
	}
}
