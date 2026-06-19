<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_alias_entry_count() — read the grep -cv count from element [0] of the
 * exec() output array and return it as an int, returning 0 for absent, empty,
 * or non-numeric output.
 *
 * The dashboard widget runs `grep -cv '^1.1.1.1$' <alias-file>` (excluding
 * the placeholder entry pfBlockerNG writes for an otherwise-empty alias) and
 * passes the resulting array to this helper. grep -cv emits a single line —
 * the count — into element [0]; element [1] does not exist. The pre-fix widget
 * read $match[1] (always undefined → reset to 0), so every alias showed 0
 * until the authoritative pfctl branch overwrote it. This test suite pins the
 * correct [0] behaviour so that regression is detectable off-box.
 */
#[CoversFunction('pfb_alias_entry_count')]
final class WidgetAliasCountTest extends TestCase
{
	// Populated alias: grep -cv found 16 788 non-placeholder lines.
	// The old code read element [1] (absent → 0); the fix reads element [0].
	public function testPopulatedAliasReturnsCountFromElementZero(): void
	{
		$this->assertSame(16788, pfb_alias_entry_count(['16788']));
	}

	// Empty/placeholder-only alias: the sole entry is '1.1.1.1', which grep -cv
	// excludes, so the count is 0 — returned as int 0, not the string '0'.
	public function testPlaceholderOnlyAliasReturnsZero(): void
	{
		$this->assertSame(0, pfb_alias_entry_count(['0']));
	}

	// grep produced no output at all (file absent, exec failed).
	// Empty array → element [0] absent → 0.
	public function testMissingOutputReturnsZero(): void
	{
		$this->assertSame(0, pfb_alias_entry_count([]));
	}

	// grep output is an empty string — non-numeric → 0.
	public function testEmptyStringOutputReturnsZero(): void
	{
		$this->assertSame(0, pfb_alias_entry_count(['']));
	}

	// grep output is unexpected non-numeric text — non-numeric → 0.
	public function testNonNumericOutputReturnsZero(): void
	{
		$this->assertSame(0, pfb_alias_entry_count(['abc']));
	}
}
