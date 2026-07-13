<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Tests for pfb_header_reserved_error() (issue #1234).
 *
 * A Deny-type list whose source Header is literally 'dedup' makes
 * pfb_recompute_finish() (pfblockerng.sh) write the per-alias artifact to the
 * same path as the reserved ccwhite-dedup file (matchdedup_v4.txt), so the
 * dedup swap silently overwrites or deletes it. This is save-time-only
 * (config import/HA-sync bypasses it via the \W-stripping normaliser) --
 * pfb_header_reserved_error() itself is pure and only judges what it is given.
 */
#[CoversFunction('pfb_header_reserved_error')]
final class HeaderReservedErrorTest extends TestCase
{
	public static function reservedRowsProvider(): array
	{
		return [
			'Deny_Inbound rejects dedup'  => ['dedup', 'Deny_Inbound', TRUE],
			'Deny_Outbound rejects dedup' => ['dedup', 'Deny_Outbound', TRUE],
			'Deny_Both rejects dedup'     => ['dedup', 'Deny_Both', TRUE],
			'Alias_Deny rejects dedup'    => ['dedup', 'Alias_Deny', TRUE],
		];
	}

	#[DataProvider('reservedRowsProvider')]
	public function testDenyActionWithDedupHeaderIsReserved(string $header, string $action, bool $expectReserved): void
	{
		$error = pfb_header_reserved_error($header, $action);
		if ($expectReserved) {
			$this->assertNotSame('', $error, "action={$action} header={$header} must be reserved");
		} else {
			$this->assertSame('', $error);
		}
	}

	public static function allowedActionsProvider(): array
	{
		return [
			'Disabled'        => ['Disabled'],
			'Permit_Inbound'  => ['Permit_Inbound'],
			'Permit_Outbound' => ['Permit_Outbound'],
			'Permit_Both'     => ['Permit_Both'],
			'Match_Inbound'   => ['Match_Inbound'],
			'Match_Outbound'  => ['Match_Outbound'],
			'Match_Both'      => ['Match_Both'],
			'Alias_Permit'    => ['Alias_Permit'],
			'Alias_Match'     => ['Alias_Match'],
			'Alias_Native'    => ['Alias_Native'],
			'unbound (DNSBL)' => ['unbound'],
		];
	}

	#[DataProvider('allowedActionsProvider')]
	public function testNonDenyActionWithDedupHeaderIsAllowed(string $action): void
	{
		$this->assertSame(
			'',
			pfb_header_reserved_error('dedup', $action),
			"action={$action} must not reserve the 'dedup' header"
		);
	}

	public static function caseAndNearMissProvider(): array
	{
		return [
			'Dedup (mixed case)'    => ['Dedup'],
			'DEDUP (upper case)'    => ['DEDUP'],
			'DeDuP (mixed case)'    => ['DeDuP'],
			'dedupfoo (suffix)'     => ['dedupfoo'],
			'foodedup (prefix)'     => ['foodedup'],
			'xdedup (prefix)'       => ['xdedup'],
			'matchdedup (distinct)' => ['matchdedup'],
		];
	}

	#[DataProvider('caseAndNearMissProvider')]
	public function testCaseVariantAndNearMissHeaderIsNotReservedEvenUnderDeny(string $header): void
	{
		// FreeBSD UFS/ZFS are case-sensitive: 'matchDedup_v4.txt' != 'matchdedup_v4.txt'.
		// A lowercase-compare would reject a legitimate header for no reason.
		$this->assertSame('', pfb_header_reserved_error($header, 'Deny_Both'));
	}
}
