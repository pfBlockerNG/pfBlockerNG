<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #4284: AdGuard's subdomain-only mask '.host^' is an Adblock rule, so the capture guard
 * takes it to the ABP path in any feed. There parse_abp() reads it as a block of the subdomains of
 * 'host' alone (a zone entry marked "apex": false). Before, an Adblock feed dropped it and Lenient
 * cut a plain feed's '.host^' to a block of the whole site.
 * The Python twin, _dnsbl_is_abp_rule_line(), is pinned to the same rows by
 * tests/test_issue4284_zone_apex.py.
 */
final class DnsblAbpSubdomainMaskTest extends TestCase
{
	/** @return array<string, array{string}> */
	public static function maskProvider(): array
	{
		return [
			'subdomain-only mask'  => ['.webhop.net^'],
			'with important'       => ['.webhop.net^$important'],
			'mixed case'           => ['.Ads.Example.com^'],
		];
	}

	#[DataProvider('maskProvider')]
	public function testASubdomainOnlyMaskIsCaptured(string $line): void
	{
		$this->assertTrue(pfb_dnsbl_is_abp_rule_line($line), "[{$line}]");
	}

	/** @return array<string, array{string}> */
	public static function notMaskProvider(): array
	{
		return [
			'path rule'           => ['.imgur.com/lumbar.gif'],
			'no separator'        => ['.webhop.net'],
			'wildcard after mask' => ['.top^*-960x80-*.gif'],
			'wildcard label'      => ['.*.webhop.net^'],
			'pipe inside'         => ['.web|hop.net^'],
			'space after dot'     => ['. webhop.net^'],
		];
	}

	#[DataProvider('notMaskProvider')]
	public function testAPathWildcardOrUnterminatedDotLineIsNotCaptured(string $line): void
	{
		$this->assertFalse(pfb_dnsbl_is_abp_rule_line($line), "[{$line}]");
	}
}
