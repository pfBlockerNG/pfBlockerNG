<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * The DNSBL group Action dropdown offers the 'unbound' stored value under the label
 * Block. The stored key stays 'unbound' so existing configs keep resolving; only the
 * user-facing label changed. Each page builds its own option array, so each is
 * evaluated from its comment-free source.
 */
final class DnsblGroupActionLabelTest extends TestCase
{
	private static function optionsFromPage(string $relative, string $pattern): array
	{
		$source = php_strip_whitespace(dirname(__DIR__, 2) . '/' . $relative);
		if (preg_match($pattern, $source, $match) !== 1) {
			self::fail("DNSBL group Action option array not found in {$relative}");
		}
		$options = [];
		eval($match[0] . ' $options = $list_array ?? $options_action;');
		return $options;
	}

	public static function pages(): array
	{
		return [
			'category list' => [
				'src/usr/local/www/pfblockerng/pfblockerng_category.php',
				"/\\\$list_array\\s*=\\s*array\\([^;]*'unbound'[^;]*\\);/",
			],
			'category edit' => [
				'src/usr/local/www/pfblockerng/pfblockerng_category_edit.php',
				"/\\\$options_action\\s*=\\s*\\[[^;]*'unbound'[^;]*\\];/",
			],
		];
	}

	#[DataProvider('pages')]
	public function testDnsblGroupActionOffersUnboundStoredValueAsBlock(string $relative, string $pattern): void
	{
		$options = self::optionsFromPage($relative, $pattern);

		$this->assertSame('Block', $options['unbound'] ?? NULL, 'the stored unbound value must be labelled Block');
		$this->assertSame('Disabled', $options['Disabled'] ?? NULL, 'Disabled must stay on the dropdown');
		$this->assertNotContains('Unbound', $options, 'no option may still be labelled Unbound');
	}
}
