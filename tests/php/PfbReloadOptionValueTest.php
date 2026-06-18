<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * pfb_reload_option_value() — normalises $_POST['pfb_reload_option'] to one
 * of the only three legitimate values ('All', 'IP', 'DNSBL'), defaulting to
 * 'All' for any absent, non-string, or unexpected input. Exact-match only.
 */
#[CoversFunction('pfb_reload_option_value')]
final class PfbReloadOptionValueTest extends TestCase
{
	public static function reloadOptionProvider(): array
	{
		return [
			// Allowed — each of the three legitimate values passes through unchanged.
			"'All' passes through"  => ['All',   'All'],
			"'IP' passes through"   => ['IP',    'IP'],
			"'DNSBL' passes through" => ['DNSBL', 'DNSBL'],
			// Rejected — every non-allowlisted input class normalises to 'All'.
			'empty string normalises to All'       => ['',                         'All'],
			'lowercase all normalises to All'      => ['all',                      'All'],
			'unknown token normalises to All'      => ['Bogus',                    'All'],
			'XSS payload normalises to All'        => ['<script>alert(1)</script>', 'All'],
			'value with whitespace normalises to All' => [' All ',                 'All'],
		];
	}

	#[DataProvider('reloadOptionProvider')]
	public function testReloadOptionAllowlist(mixed $input, string $expected): void
	{
		$this->assertSame($expected, pfb_reload_option_value($input));
	}
}
