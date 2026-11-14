<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/** Issue #3977: PHP callers build only Core's versioned StartUpdate request. */
final class FeedCoreStartRequestTest extends TestCase
{
	/** @var list<array{string, array, ?string, int}> */
	private array $calls = [];

	/** @return array{status: int, body: array, error: null} */
	private function core(): callable
	{
		return function (string $method, array $params, ?string $socket, int $timeout): array {
			$this->calls[] = [$method, $params, $socket, $timeout];
			return ['status' => 200, 'body' => [], 'error' => NULL];
		};
	}

	public function testApplyHasNoManualScopeOrForceFields(): void
	{
		pfb_core_update_start('apply', $this->core());
		$this->assertSame('StartUpdate', $this->calls[0][0]);
		$this->assertSame(['requestId', 'trigger'], array_keys($this->calls[0][1]));
		$this->assertSame('apply', $this->calls[0][1]['trigger']);
		$this->assertMatchesRegularExpression('/^[a-f0-9]{32}$/', $this->calls[0][1]['requestId']);
		$this->assertNull($this->calls[0][2]);
		$this->assertSame(PFB_CORE_PAGE_TIMEOUT, $this->calls[0][3]);
	}

	public function testManualRequestPreservesScopeAndForce(): void
	{
		pfb_core_update_start('manual', $this->core(), 'ip', 'download');
		$this->assertSame(['manual', 'ip', 'download'], [
			$this->calls[0][1]['trigger'],
			$this->calls[0][1]['scope'],
			$this->calls[0][1]['force'],
		]);
	}
}
