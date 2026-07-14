<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Tests for pfb_header_reserved_error() (issue #1270).
 *
 * pfBlockerNG synthesizes several lists whose header/filename the package
 * itself picks -- DNSBLIP and the 9 GeoIP continent aliases -- into the SAME
 * folder+namespace a user Deny/Permit/Match/Native list Header can collide
 * with (pfb_determine_list_detail() routes by <header><vtype>.txt,
 * last-writer-wins). Pure, brand-new function (no pre-existing behaviour to
 * pin -- CLAUDE.md Test coverage #1 exception 2).
 */
#[CoversFunction('pfb_header_reserved_error')]
final class HeaderReservedErrorTest extends TestCase
{
	protected function setUp(): void
	{
		// Self-encapsulated: fail loudly rather than silently mis-grade on a
		// corrupted bootstrap -- $pfb['continents'] is 9 name=>alias pairs
		// (pfblockerng.inc:165-174).
		$continents = $GLOBALS['pfb']['continents'] ?? null;
		if (!is_array($continents) || count($continents) !== 9) {
			throw new RuntimeException('$pfb[continents] must have exactly 9 entries; got: ' . var_export($continents, true));
		}
	}

	/** Transcribed from $pfb['continents']' values (pfblockerng.inc:165-174) -- all 9, none dropped. */
	public static function reservedHeadersProvider(): array
	{
		return [
			'DNSBLIP'                    => ['DNSBLIP'],
			'pfB_Top (Top Spammers)'     => ['pfB_Top'],
			'pfB_Africa'                 => ['pfB_Africa'],
			'pfB_Antarctica'             => ['pfB_Antarctica'],
			'pfB_Asia'                   => ['pfB_Asia'],
			'pfB_Europe'                 => ['pfB_Europe'],
			'pfB_NAmerica'               => ['pfB_NAmerica'],
			'pfB_Oceania'                => ['pfB_Oceania'],
			'pfB_SAmerica'               => ['pfB_SAmerica'],
			'pfB_PS (Proxy and Satellite)' => ['pfB_PS'],
		];
	}

	#[DataProvider('reservedHeadersProvider')]
	public function testReservedHeaderIsRejected(string $header): void
	{
		$this->assertNotSame('', pfb_header_reserved_error($header), "header={$header} must be reserved");
	}

	/** issue #1270: $pfb['continent_list'] omits pfB_PS -- proves the function
	 * reads $pfb['continents'] (9 entries), never continent_list (8, no PS). */
	public function testContinentListOmitsPfBPsButFunctionStillRejectsIt(): void
	{
		$this->assertArrayNotHasKey(
			'pfB_PS',
			$GLOBALS['pfb']['continent_list'] ?? [],
			'fixture check: continent_list must omit pfB_PS for this test to be meaningful'
		);
		$this->assertNotSame('', pfb_header_reserved_error('pfB_PS'));
	}

	public static function notReservedProvider(): array
	{
		return [
			'empty string'                                              => [''],
			'ordinary header'                                           => ['MyBlocklist'],
			'ordinary header 2'                                         => ['ThreatFeed'],
			"'dedup' -- resolved by #1250, out of #1270 scope"          => ['dedup'],
			"'matchdedup' -- unrelated name"                            => ['matchdedup'],
			'DNSBLIPX (suffix, not an exact match)'                     => ['DNSBLIPX'],
			'XDNSBLIP (prefix, not an exact match)'                     => ['XDNSBLIP'],
			'dnsblip (lowercase -- FreeBSD UFS/ZFS is case-sensitive)'  => ['dnsblip'],
			"pfBAfrica (no underscore, distinct from 'pfB_Africa')"     => ['pfBAfrica'],
		];
	}

	#[DataProvider('notReservedProvider')]
	public function testNonReservedHeaderIsAllowed(string $header): void
	{
		$this->assertSame('', pfb_header_reserved_error($header));
	}

	/**
	 * issue #1270: pfblockerng.inc's SEPARATE "Download and Collect IPv4/IPv6
	 * lists" loop reads config independently of the normalize loop and skips a
	 * row via `!isset($list['dnsblip']) && pfb_header_reserved_error(...) !== ''`
	 * -- pins that exact guard expression for a real user row, the exempt
	 * synthesized DNSBLIP row, and an ordinary row.
	 */
	public function testDownloadLoopGuardSkipsReservedNonSyntheticRow(): void
	{
		$userList = ['aliasname' => 'MyEvilList', 'row' => [['header' => 'DNSBLIP']]];
		$header = $userList['row'][0]['header'] ?? '';
		$this->assertTrue(!isset($userList['dnsblip']) && pfb_header_reserved_error($header) !== '');
	}

	public function testDownloadLoopGuardExemptsSynthesizedDnsblipRow(): void
	{
		$synthesizedList = ['aliasname' => 'DNSBLIP', 'dnsblip' => '', 'row' => [['header' => 'DNSBLIP']]];
		$header = $synthesizedList['row'][0]['header'] ?? '';
		$this->assertFalse(!isset($synthesizedList['dnsblip']) && pfb_header_reserved_error($header) !== '');
	}

	public function testDownloadLoopGuardAllowsOrdinaryHeader(): void
	{
		$userList = ['aliasname' => 'MyBlocklist', 'row' => [['header' => 'MyBlocklist']]];
		$header = $userList['row'][0]['header'] ?? '';
		$this->assertFalse(!isset($userList['dnsblip']) && pfb_header_reserved_error($header) !== '');
	}
}
