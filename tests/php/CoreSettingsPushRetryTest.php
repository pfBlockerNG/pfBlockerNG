<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3913: a push that failed is retried by the next tick even when config.xml has not changed since the last recorded
 * push. The rc start's forced push is the case: Core came back without the values (a lost store) while the record still
 * names config.xml's current revision/time and values, so a record-only check would skip Core until the next config change.
 */
#[CoversFunction('pfb_core_settings_push')]
final class CoreSettingsPushRetryTest extends TestCase
{
	private array $priorConfig;
	private array $priorPfb;
	private string $dir;
	/** @var list<string> */
	private array $methods = [];

	protected function setUp(): void
	{
		$this->priorConfig = $GLOBALS['config'] ?? [];
		$this->priorPfb = $GLOBALS['pfb'];
		$this->dir = sys_get_temp_dir() . '/pfb_core_retry_' . bin2hex(random_bytes(8));
		$this->assertTrue(mkdir($this->dir, 0700));
		$GLOBALS['config'] = [];
		$GLOBALS['pfb']['core_push_failed'] = "{$this->dir}/core_push_failed";
		$GLOBALS['pfb']['core_pushed'] = "{$this->dir}/core_pushed";
		$GLOBALS['pfb']['log'] = "{$this->dir}/pfblockerng.log";
		$GLOBALS['pfb']['errlog'] = "{$this->dir}/error.log";
		$GLOBALS['pfb']['runlog'] = '';
	}

	protected function tearDown(): void
	{
		$GLOBALS['config'] = $this->priorConfig;
		$GLOBALS['pfb'] = $this->priorPfb;
		rmdir_recursive($this->dir);
	}

	/** A Core that answers GetSettings with $get and records every method it is asked. */
	private function core(array $get, array $save): callable
	{
		$this->methods = [];
		return function (string $method, array $params = []) use ($get, $save): array {
			$this->methods[] = $method;
			return $method === 'GetSettings' ? $get : $save;
		};
	}

	public function testAFailedForcedPushIsRetriedByTheNextTickWithNoConfigChange(): void
	{
		// Given: the last push succeeded at this revision time with these values
		config_set_path('revision/time', '1700000000');
		$want = ['dns' => pfb_core_dns_settings()];
		file_put_contents("{$this->dir}/core_pushed", json_encode(['time' => '1700000000', 'hash' => hash('sha256', (string) json_encode($want))]));
		$uninitialized = ['status' => 200, 'body' => ['initialized' => FALSE, 'revision' => 0, 'projections' => []], 'error' => NULL];

		// When: Core's start pushes (forced) and Core fails it
		$failed = pfb_core_settings_push($this->core($uninitialized, ['status' => 500, 'body' => ['error' => ['code' => 'internal', 'message' => 'disk full']], 'error' => NULL]), TRUE);
		$this->assertSame(['GetSettings', 'InitializeSettings'], $this->methods, 'the forced push asked Core');
		$this->assertNotNull($failed, 'the forced push failed');
		$this->assertFileExists("{$this->dir}/core_push_failed", 'the failure is kept for status');

		// Then: the next tick, config.xml unchanged, asks Core again and the push lands
		$retried = pfb_core_settings_push($this->core($uninitialized, ['status' => 200, 'body' => ['revision' => 1, 'projections' => []], 'error' => NULL]));
		$this->assertSame(['GetSettings', 'InitializeSettings'], $this->methods, 'the tick retries the failed push instead of trusting the record');
		$this->assertNull($retried);
		$this->assertFileDoesNotExist("{$this->dir}/core_push_failed", 'the failure is cleared once Core holds the values');
	}
}
