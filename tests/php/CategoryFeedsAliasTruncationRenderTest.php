<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** Off-box render coverage for alias values not seedable by the Tier-A fixture (#2039). */
final class CategoryFeedsAliasTruncationRenderTest extends TestCase
{
	private static function source(string $file): string
	{
		$src = file_get_contents(dirname(__DIR__, 2) . "/src/usr/local/www/pfblockerng/{$file}");
		if ($src === false) {
			throw new RuntimeException("failed to read {$file}");
		}
		return $src;
	}

	private static function slice(string $src, string $startMarker, string $endMarker): string
	{
		$start = strpos($src, $startMarker);
		$end   = strpos($src, $endMarker, $start === false ? 0 : $start);
		if ($start === false || $end === false || $end <= $start) {
			throw new RuntimeException('could not locate alias render block');
		}
		return substr($src, $start, $end - $start);
	}

	private static function renderCategoryAlias(string $alias): string
	{
		$code = self::slice(
			self::source('pfblockerng_category.php'),
			"\t\t\t\t\t\t\$aliasname_raw = \$row['aliasname'];",
			"\n\t\t\t\t\t?>"
		);
		$row = array('aliasname' => $alias);

		ob_start();
		eval($code);
		return (string) ob_get_clean();
	}

	private static function renderFeedsAlias(string $alias): string
	{
		$code = self::slice(
			self::source('pfblockerng_feeds.php'),
			"\t\t\t\t\t\t\t\t\$title = '';",
			"\n\t\t\t\t\t?>"
		);
		$row         = array('aliasname' => $alias, 'rowid' => 17);
		$p_aliasname = '';
		$feedtype    = 'ipv4';

		ob_start();
		eval($code);
		return (string) ob_get_clean();
	}

	/** @return array<string, array{string, string}> */
	public static function hostileAliasProvider(): array
	{
		return array(
			'entity boundary' => array(str_repeat('a', 13) . '&' . str_repeat('b', 8), str_repeat('a', 13) . '&amp;b...'),
			'multibyte boundary' => array(str_repeat('a', 14) . 'é' . str_repeat('b', 8), str_repeat('a', 14) . 'é...'),
		);
	}

	/**
	 * Values UNDER each gate by raw characters but over it by escaped bytes.
	 *
	 * The existing provider's aliases are 22-23 raw characters, past every gate, so both
	 * cases only ever exercised cut correctness -- they pass unchanged against the
	 * pre-fix code. These pin the gate boundary itself (issue #2078).
	 */
	public function testCategoryGateMeasuresRawCharactersNotEscapedBytes(): void
	{
		// 18 CJK characters: 18 raw, 54 bytes once escaped. Under the 20 gate.
		$alias = str_repeat("\u{4E2D}", 18);
		$html  = self::renderCategoryAlias($alias);

		$this->assertStringNotContainsString(
			'...',
			$html,
			'Category alias truncated an 18-character value against a 20-character gate -- '
			. 'the gate is measuring escaped bytes (' . strlen(htmlspecialchars($alias)) . ' of them)'
		);
	}

	public function testFeedsGateDoesNotEllipsiseWhenNothingIsRemoved(): void
	{
		// Exactly the cut length: mb_substr(0, 15) returns the whole string, so an
		// ellipsis here names a truncation that did not happen.
		$alias = str_repeat('a', 15);
		$html  = self::renderFeedsAlias($alias);

		$this->assertStringNotContainsString(
			'...',
			$html,
			'Feeds alias rendered an ellipsis although mb_substr() removed no character'
		);
	}

	#[DataProvider('hostileAliasProvider')]
	public function testCategoryAliasTruncatesRawCharactersBeforeEscaping(string $alias, string $prefix): void
	{
		$html = self::renderCategoryAlias($alias);

		$this->assertStringContainsString($prefix, $html, 'Category alias display split an entity or UTF-8 character');
		$this->assertStringContainsString('title="' . htmlspecialchars($alias) . '"', $html, 'Category title lost the full alias');
		$this->assertTrue(mb_check_encoding($html, 'UTF-8'), 'Category alias render must remain valid UTF-8');
	}

	#[DataProvider('hostileAliasProvider')]
	public function testFeedsAliasTruncatesRawCharactersBeforeEscaping(string $alias, string $prefix): void
	{
		$html = self::renderFeedsAlias($alias);

		$this->assertStringContainsString($prefix, $html, 'Feeds alias display split an entity or UTF-8 character');
		$this->assertStringContainsString('title="' . htmlspecialchars($alias) . '"', $html, 'Feeds title lost the full alias');
		$this->assertTrue(mb_check_encoding($html, 'UTF-8'), 'Feeds alias render must remain valid UTF-8');
	}
}
