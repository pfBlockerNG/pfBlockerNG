<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_strtolower() — lower-case + trim a line UNLESS it contains a '#', in which
 * case only trim (comment text is preserved verbatim). Used by the array-map in
 * pfbng_text_area_decode()'s comment-split path.
 */
#[CoversFunction('pfb_strtolower')]
final class PfbStrtolowerTest extends TestCase
{
	public function testLowercasesAndTrimsPlainLine(): void
	{
		$this->assertSame('example.com', pfb_strtolower('  EXAMPLE.COM  '));
	}

	public function testPreservesCaseWhenHashPresent(): void
	{
		$this->assertSame('Foo.COM # Note', pfb_strtolower('  Foo.COM # Note  '));
	}
}
