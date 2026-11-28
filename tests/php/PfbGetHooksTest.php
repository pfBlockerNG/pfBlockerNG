<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-12: pfb_hook_timeout(), the timeout resolution of a stored hook row (set vs unset vs invalid). The settings
 * adapter projects each row's timeout through it. The PHP row reader pfb_get_hooks() and the runner it served were
 * retired with the Go cutover (issue #3977).
 */
#[CoversFunction('pfb_hook_timeout')]
final class PfbGetHooksTest extends TestCase
{
	public function testTimeoutHonoursValidOverride(): void
	{
		$this->assertSame(30, pfb_hook_timeout(['timeout' => '30']));
		$this->assertSame(5, pfb_hook_timeout(['timeout' => 5]));
	}

	public function testTimeoutFallsBackToDefaultWhenUnsetOrInvalid(): void
	{
		$this->assertSame(PFB_HOOK_TIMEOUT_DEFAULT, pfb_hook_timeout([]));		// unset
		$this->assertSame(PFB_HOOK_TIMEOUT_DEFAULT, pfb_hook_timeout(['timeout' => 0]));	// zero
		$this->assertSame(PFB_HOOK_TIMEOUT_DEFAULT, pfb_hook_timeout(['timeout' => '-9']));	// negative
		$this->assertSame(PFB_HOOK_TIMEOUT_DEFAULT, pfb_hook_timeout(['timeout' => 'abc']));	// non-numeric
	}
}
