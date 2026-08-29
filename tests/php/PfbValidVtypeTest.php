<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * pfb_valid_vtype() — the alias-type suffix allowlist. Only '_v4' and '_v6' may be
 * interpolated into an alias name or filesystem path; every other value is rejected
 * before it reaches a path/alias build. Exact-match only (no substring/prefix slack).
 */
#[CoversFunction('pfb_valid_vtype')]
final class PfbValidVtypeTest extends TestCase
{
	public static function vtypeProvider(): array
	{
		return [
			// Allowed — the only two legitimate suffixes.
			'_v4 accepted'            => ['_v4', true],
			'_v6 accepted'            => ['_v6', true],
			// Rejected — everything else.
			'empty rejected'          => ['', false],
			'bare v4 rejected'        => ['v4', false],
			'trailing junk rejected'  => ['_v4x', false],
			'leading junk rejected'   => ['x_v4', false],
			'path traversal rejected' => ['_v4/../etc', false],
			'separator rejected'      => ['_v4/passwd', false],
			'uppercase rejected'      => ['_V4', false],
		];
	}

	#[DataProvider('vtypeProvider')]
	public function testVtypeAllowlist(string $vtype, bool $expected): void
	{
		$this->assertSame($expected, pfb_valid_vtype($vtype));
	}
}
