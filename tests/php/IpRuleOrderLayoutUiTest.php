<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/** Firewall Auto Rule Order keeps its choices while fitting narrow viewports (issue #2898). */
final class IpRuleOrderLayoutUiTest extends TestCase
{
	private const PAGE = __DIR__ . '/../../src/usr/local/www/pfblockerng/pfblockerng_ip.php';

	private static function source(): string
	{
		$source = file_get_contents(self::PAGE);
		self::assertIsString($source, 'the IP page must be readable');
		return $source;
	}

	public function testRuleOrderKeepsFiveDistinctValuesAndOrderZeroDefault(): void
	{
		$source = self::source();
		$this->assertMatchesRegularExpression(
			'/\$pconfig\[\'pass_order\'\]\s*=.*\?:\s*\'order_0\';/',
			$source,
			'Firewall Auto Rule Order must keep order_0 as its fallback default'
		);
		$this->assertSame(1, preg_match('/\\$options_pass_order\\s*=\\s*\\[(.*?)\\];/s', $source, $block),
			'could not locate the Firewall Auto Rule Order options');
		preg_match_all("/'(order_\\d+)'\\s*=>\\s*'([^']+)'/", $block[1], $options, PREG_SET_ORDER);

		$values = array_column($options, 1);
		$labels = array_column($options, 2);
		$this->assertSame(['order_0', 'order_1', 'order_2', 'order_3', 'order_4'], $values);
		$this->assertCount(5, array_unique($labels), 'all five rule orderings must remain distinguishable');
	}

	public function testRuleOrderKeepsIntrinsicDesktopWidthButCapsAtItsContainer(): void
	{
		$source = self::source();
		$this->assertSame(1, preg_match("/new Form_Select\\(\\s*'pass_order'.*?;\\n/s", $source, $control),
			'could not locate the Firewall Auto Rule Order control');
		$this->assertStringContainsString(
			"->setAttribute('style', 'width: auto; max-width: 100%')",
			$control[0],
			'width:auto must preserve native desktop sizing while max-width caps narrow rendering'
		);
	}
}
