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
