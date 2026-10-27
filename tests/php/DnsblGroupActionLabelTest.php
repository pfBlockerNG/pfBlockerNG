<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * The DNSBL group Action dropdown offers the 'unbound' stored value under the label
 * Enable: the group setting only switches the group on, while each feed row's own
 * Action (Deny/Permit) decides whether its domains block or allow. The stored key
 * stays 'unbound' so existing configs keep resolving; only the user-facing label
 * changed. Each page builds its own option array, so each is evaluated from its
 * comment-free source.
 */
final class DnsblGroupActionLabelTest extends TestCase
{
	private const CATEGORY_EDIT = 'src/usr/local/www/pfblockerng/pfblockerng_category_edit.php';

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
				self::CATEGORY_EDIT,
				"/\\\$options_action\\s*=\\s*\\[[^;]*'unbound'[^;]*\\];/",
			],
		];
	}

	#[DataProvider('pages')]
	public function testDnsblGroupActionOffersUnboundStoredValueAsEnable(string $relative, string $pattern): void
	{
		$options = self::optionsFromPage($relative, $pattern);

		$this->assertSame('Enable', $options['unbound'] ?? NULL, 'the stored unbound value must be labelled Enable');
		$this->assertSame('Disabled', $options['Disabled'] ?? NULL, 'Disabled must stay on the dropdown');
		$this->assertNotContains('Unbound', $options, 'no option may still be labelled Unbound');
	}

	public function testGroupActionHelpNamesEnableAndThePerFeedAction(): void
	{
		$source = php_strip_whitespace(dirname(__DIR__, 2) . '/' . self::CATEGORY_EDIT);
		if (preg_match("/\\\$action_txt = (\"[^\"\\n]*Each feed's <strong>Action<\\/strong>[^\"\\n]*\");/", $source, $match) !== 1) {
			self::fail('DNSBL group action help text not found in category edit page');
		}
		$help = '';
		eval('$help = ' . $match[1] . ';');

		$this->assertStringContainsString('Select <strong>Enable</strong>', $help, 'help must name the Enable option');
		$this->assertStringContainsString('<strong>Deny</strong>', $help, 'help must name the per-feed Deny action');
		$this->assertStringContainsString('<strong>Permit</strong>', $help, 'help must name the per-feed Permit action');
		$this->assertStringNotContainsString('Select <strong>Block</strong>', $help, 'help must not name the retired Block label');
	}
}
