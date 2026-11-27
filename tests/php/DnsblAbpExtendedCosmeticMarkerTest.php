<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #4272: AdGuard's extended cosmetic markers ('#$?#', '#@$?#', '#@%#', '#@?#', '#@$#') are
 * cosmetic rules, so the capture guard takes them to the ABP path, where parse_abp() skips them.
 * Without them, the AdGuard Turkish filter's 'eksisozluk.com#$?#…' reached the plain path, and
 * Lenient cut 'eksisozluk.com' out of it as a block of the whole site.
 * The Python twin, _dnsbl_is_abp_rule_line(), is pinned to the same rows by
 * tests/test_issue4272_extended_cosmetic_markers.py.
 */
final class DnsblAbpExtendedCosmeticMarkerTest extends TestCase
{
	/** @return array<string, array{string}> */
	public static function cosmeticProvider(): array
	{
		return [
			'extended CSS'            => ['eksisozluk.com#$?#.ads'],
			'extended CSS, generic'   => ['#$?#div:has(> a[href*="ads"])'],
			'extended CSS exception'  => ['site.com#@$?#.ads'],
			'extended exception'      => ['site.com#@?#div:has(.ad)'],
			'CSS injection exception' => ['site.com#@$#body { color: red }'],
			'scriptlet exception'     => ["site.com#@%#//scriptlet('abort-on-property-read', 'ads')"],
			'domain list'             => ['a.com,b.com#$?#.ads'],
		];
	}

	#[DataProvider('cosmeticProvider')]
	public function testAnAdGuardExtendedCosmeticRuleIsCaptured(string $line): void
	{
		$this->assertTrue(pfb_dnsbl_is_abp_rule_line($line), "[{$line}]");
	}

	/** Controls: a comment line and a plain path line stay off the ABP path. */
	public function testACommentOrAPlainLineIsNotCaptured(): void
	{
		$this->assertFalse(pfb_dnsbl_is_abp_rule_line('#$?# comment'));
		$this->assertFalse(pfb_dnsbl_is_abp_rule_line('example.com/path#$?#x'));
	}
}
