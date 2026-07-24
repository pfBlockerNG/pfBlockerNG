<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Tests for pfb_dnsbl_regex_entry_error() (issue #1656).
 *
 * The DNSBL custom-list 'regex' save-time validator mirrors the resolver's
 * load-time user-regex guards (pfb_unbound.py): a pattern with a structurally
 * catastrophic backtracking shape (_regex_is_catastrophic_shape — nested
 * quantifier, alternation overlap, adjacent quantified groups, stacked bounded
 * repeats, or an over-budget quantifier/alternation count) or one that fails
 * to compile is silently DROPPED at resolver load, so the form must reject it
 * on save instead of persisting a dead entry.
 *
 * The sample patterns below were verdict-checked against the REAL Python
 * implementation (_regex_is_catastrophic_shape / re.compile) in-session, so
 * these tests pin PHP<->Python parity for the ported checks, not just the PHP
 * port's self-consistency.
 */
#[CoversFunction('pfb_dnsbl_regex_entry_error')]
final class DnsblRegexEntryErrorTest extends TestCase
{
	// -----------------------------------------------------------------------
	// Catastrophic shapes — every structural class the resolver drops must be
	// rejected with the shape error (one case per ported Python check).
	// -----------------------------------------------------------------------

	/** @return array<string, array{string}> */
	public static function catastrophicShapeProvider(): array
	{
		return [
			'nested quantifier (a+)+'           => ['(a+)+$'],
			'nested quantifier (\w+\.)+'        => ['(\w+\.)+bad'],
			'alternation overlap (a|ab)*'       => ['(a|ab)*'],
			'adjacent quantified groups'        => ['(a+)(a+)+'],
			'stacked bounded repeats'           => ['a{1000}{1000}'],
		];
	}

	#[DataProvider('catastrophicShapeProvider')]
	public function testCatastrophicShapeIsRejected(string $pattern): void
	{
		// Given a pattern the resolver's _regex_is_catastrophic_shape drops at load
		// When it is validated at save time
		$error = pfb_dnsbl_regex_entry_error($pattern);

		// Then the save-time validator rejects it with the shape error
		$this->assertSame(
			'Regex has a catastrophic-backtracking shape (the DNSBL resolver would drop it)',
			$error,
			"{$pattern} must be rejected as a catastrophic shape"
		);
	}

	// -----------------------------------------------------------------------
	// Budget backstop — combined unescaped +/* and | count over 12 is dropped
	// by the resolver; exactly 12 is within budget. Both sides of the branch.
	// -----------------------------------------------------------------------

	public function testThirteenAlternationsExceedBudgetAndAreRejected(): void
	{
		// Given 13 unescaped alternations (budget 13 > _REGEX_BUDGET_MAX 12)
		$pattern = 'a|b|c|d|e|f|g|h|i|j|k|l|m|n';

		$error = pfb_dnsbl_regex_entry_error($pattern);

		$this->assertSame(
			'Regex has too many quantifiers/alternations (the DNSBL resolver would drop it)',
			$error,
			'13 alternations must exceed the resolver budget'
		);
	}

	public function testTwelveAlternationsAreWithinBudgetAndAccepted(): void
	{
		// Given exactly 12 unescaped alternations (budget 12, not > 12)
		$pattern = 'a|b|c|d|e|f|g|h|i|j|k|l|m';

		$this->assertSame('', pfb_dnsbl_regex_entry_error($pattern), '12 alternations are within the resolver budget');
	}

	public function testEscapedQuantifiersDoNotCountTowardTheBudget(): void
	{
		// Given many ESCAPED + / * / | (literals, not quantifiers/alternations)
		$pattern = 'a\+b\*c\|d\+e\*f\|g\+h\*i\|j\+k\*l\|m\+n';

		$this->assertSame('', pfb_dnsbl_regex_entry_error($pattern), 'escaped +, * and | are literals, not budget');
	}

	// -----------------------------------------------------------------------
	// Compile probe — a pattern re.compile rejects is dropped by the resolver
	// and must be rejected at save.
	// -----------------------------------------------------------------------

	/** @return array<string, array{string}> */
	public static function malformedProvider(): array
	{
		return [
			'unterminated group'    => ['(unclosed'],
			'unterminated class'    => ['[a-'],
		];
	}

	#[DataProvider('malformedProvider')]
	public function testMalformedPatternIsRejected(string $pattern): void
	{
		$this->assertSame(
			'Regex does not compile (the DNSBL resolver would drop it)',
			pfb_dnsbl_regex_entry_error($pattern),
			"{$pattern} must be rejected as non-compiling"
		);
	}

	public function testUppercaseNamedGroupIsRejectedBecauseResolverLowercases(): void
	{
		// Given '(?P<x>a)' — valid as typed, but pfbng_text_area_decode lowercases
		// every entry before the [REGEX] ini, so the resolver compiles '(?p<x>a)'
		// (unknown extension ?p -> re.error -> dropped). The save-time validator
		// must judge the lowercased pattern the resolver actually receives.
		$this->assertSame(
			'Regex does not compile (the DNSBL resolver would drop it)',
			pfb_dnsbl_regex_entry_error('(?P<x>a)'),
			'(?P<x>a) reaches the resolver lowercased as (?p<x>a), a compile error'
		);
	}

	// -----------------------------------------------------------------------
	// Benign patterns — realistic DNSBL regex entries stay accepted (the guard
	// must not reject what the resolver loads fine).
	// -----------------------------------------------------------------------

	/** @return array<string, array{string}> */
	public static function benignProvider(): array
	{
		return [
			'simple anchor'                  => ['^ads\.'],
			'realistic domain pattern'       => ['^(.+\.)?ads?[0-9]*\.example\.(com|net|org)$'],
			'contains a slash (delimiter)'   => ['foo/bar'],
			'bounded repeat, single'         => ['[a-z]{2,10}\.example\.com'],
		];
	}

	#[DataProvider('benignProvider')]
	public function testBenignPatternIsAccepted(string $pattern): void
	{
		$this->assertSame('', pfb_dnsbl_regex_entry_error($pattern), "{$pattern} must be accepted");
	}
}
