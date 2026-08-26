<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_dnsbl_strip_bom() -- issue #938.
 *
 * A UTF-8 BOM (EF BB BF) on a feed's first line defeats the generic DNSBL parser's
 * str_starts_with($line, '#') comment check, so a BOM-led '# Title: ...' header line is
 * treated as data and error-logged instead of skipped as a comment. This helper strips
 * exactly ONE leading BOM (encoding metadata, not content) and leaves everything else --
 * including a non-leading BOM -- untouched.
 */
#[CoversFunction('pfb_dnsbl_strip_bom')]
final class PfbDnsblStripBomTest extends TestCase
{
	public function testBomLedCommentLineBecomesRecognisable(): void
	{
		// Given a BOM-prefixed '# Title: ...' header line, stripping the BOM restores
		// the '#'-prefix the comment check needs.
		$this->assertSame('# Title: x', pfb_dnsbl_strip_bom("\xEF\xBB\xBF# Title: x"));
	}

	public function testBomLedDataLineIsStripped(): void
	{
		$this->assertSame('example.com', pfb_dnsbl_strip_bom("\xEF\xBB\xBFexample.com"));
	}

	public function testBareBomBecomesEmptyString(): void
	{
		$this->assertSame('', pfb_dnsbl_strip_bom("\xEF\xBB\xBF"));
	}

	public function testNoBomLeavesLineUnchanged(): void
	{
		$this->assertSame('example.com', pfb_dnsbl_strip_bom('example.com'));
	}

	public function testDoubleBomStripsExactlyOne(): void
	{
		// Pins the exactly-once contract: a malformed doubled BOM keeps its second
		// copy rather than the helper looping to strip every leading BOM.
		$this->assertSame("\xEF\xBB\xBFexample.com", pfb_dnsbl_strip_bom("\xEF\xBB\xBF\xEF\xBB\xBFexample.com"));
	}

	public function testMidLineBomIsNeverStripped(): void
	{
		// A BOM that is not at position 0 is content, not encoding metadata -- leave
		// the line unchanged.
		$line = "exam\xEF\xBB\xBFple.com";
		$this->assertSame($line, pfb_dnsbl_strip_bom($line));
	}

	public function testBomLedAnchorLineBecomesAnchorDetectable(): void
	{
		// Issue #946: pins the property the parse-loop hoist depends on -- once the
		// BOM is stripped, the line starts with '||' again, so the ADR-21 anchor
		// short-circuit (str_starts_with($line, '||')) can recognise it. Before the
		// hoist, this check ran AFTER the anchor short-circuit, so a BOM-led anchor
		// line took the generic parse path instead.
		$result = pfb_dnsbl_strip_bom("\xEF\xBB\xBF||example.com^");
		$this->assertSame('||example.com^', $result);
		$this->assertTrue(str_starts_with($result, '||'));
	}

	public function testBomLedCommentLineBecomesCommentDetectable(): void
	{
		// Issue #946: same property for the '!' comment skip (now the ADR-62
		// universal control-line skip) -- before the hoist, a BOM-led '! comment'
		// first line fell through as data and was error-logged instead of skipped.
		$result = pfb_dnsbl_strip_bom("\xEF\xBB\xBF! Some comment");
		$this->assertSame('! Some comment', $result);
		$this->assertTrue(str_starts_with($result, '!'));
	}
}
