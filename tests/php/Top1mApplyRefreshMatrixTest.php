<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

#[CoversFunction('pfb_dnsbl_reload_needed')]
final class Top1mApplyRefreshMatrixTest extends TestCase
{
	public function testPublishFailureSuppressesReloadAndPostHookChangeSignal(): void
	{
		$this->assertFalse(pfb_dnsbl_reload_needed(TRUE, TRUE, TRUE, TRUE, TRUE, TRUE));
		$this->assertFalse(pfb_dnsbl_reload_needed(FALSE, FALSE, FALSE, FALSE, FALSE, FALSE));
		foreach (range(0, 4) as $enabledIndex) {
			$flags = array_fill(0, 5, FALSE);
			$flags[$enabledIndex] = TRUE;
			$this->assertTrue(pfb_dnsbl_reload_needed(FALSE, ...$flags));
		}
	}
}
