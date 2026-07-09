<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * pfb_ip_is_opposite_family() -- issue #993. A syntactically valid address of the
 * list's OTHER family (colon-bearing IPv6 in a '_v4' list, or dotted IPv4 in a
 * '_v6' list) is not a parse failure -- mixed-family feeds are common. Inputs are
 * letter-free (production only reaches this predicate for lines that already
 * passed the caller's no-letters regex guard).
 *
 * Scenario: both families x {collected, opposite, garbage}.
 */
#[CoversFunction('pfb_ip_is_opposite_family')]
final class PfbIpOppositeFamilyTest extends TestCase
{
	public static function cases(): array
	{
		return [
			'_v4 list, collected v4 address'  => ['_v4', '1.2.3.4', false],
			'_v4 list, opposite v6 address'   => ['_v4', '2000::1', true],
			'_v4 list, garbage'               => ['_v4', '999.999.999.999', false],
			'_v6 list, collected v6 address'  => ['_v6', '2000::1', false],
			'_v6 list, opposite v4 address'   => ['_v6', '1.2.3.4', true],
			'_v6 list, garbage'               => ['_v6', '1.2.3', false],
		];
	}

	#[DataProvider('cases')]
	public function testOppositeFamilyClassification(string $vtype, string $line, bool $expected): void
	{
		$this->assertSame($expected, pfb_ip_is_opposite_family($line, $vtype));
	}
}
