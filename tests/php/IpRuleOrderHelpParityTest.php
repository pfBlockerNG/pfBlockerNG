<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * The Firewall 'Auto' Rule Order help must state the real order_0 default (issue #2895).
 */
final class IpRuleOrderHelpParityTest extends TestCase
{
	private const PAGE = __DIR__ . '/../../src/usr/local/www/pfblockerng/pfblockerng_ip.php';

	private static function source(): string
	{
		$source = file_get_contents(self::PAGE);
		self::assertIsString($source, 'the IP page must be readable');
		return $source;
	}

	/** Concatenate the single-quoted PHP string literals of a source slice. */
	private static function rendered(string $slice): string
	{
		$count = preg_match_all("/'((?:[^'\\\\]|\\\\.)*)'/", $slice, $strings);
		self::assertGreaterThanOrEqual(1, $count, 'could not read any PHP string literal');
		$parts = array_map(
			static fn (string $s): string => str_replace(['\\\'', '\\\\'], ["'", '\\'], $s),
			$strings[1]
		);
		return implode('', $parts);
	}

	private static function help(): string
	{
		$source = self::source();
		self::assertSame(1, preg_match("/new Form_Select\(\s*'pass_order'.*?->setHelp\((.*?)\)\s*->setAttribute/s", $source, $control),
			'could not locate the Firewall Auto Rule Order control and its help');
		return self::rendered($control[1]);
	}

	/** @return array<string, string> option value => rendered label */
	private static function optionLabels(): array
	{
		$source = self::source();
		self::assertSame(1, preg_match('/\$options_pass_order\s*=\s*\[(.*?)\];/s', $source, $block),
			'could not locate the Firewall Auto Rule Order options');
		preg_match_all("/'(order_\d+)'\s*=>\s*'([^']+)'/", $block[1], $options, PREG_SET_ORDER);
		return array_column($options, 2, 1);
	}

	/** The help's stated default is the verbatim order_0 option label. */
	public function testStatedDefaultMatchesOrderZeroLabelExactly(): void
	{
		$labels = self::optionLabels();
		$this->assertArrayHasKey('order_0', $labels, 'order_0 must remain an offered option');
		self::assertSame(1, preg_match('/Default Order:<strong>(.*?)<\/strong>/', self::help(), $stated),
			'the help must state the default order');
		$this->assertSame(
			$labels['order_0'],
			$stated[1],
			'the help default must match the order_0 option label verbatim'
		);
	}
}
