<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Pure parser for `pfctl -vvsTables` (issue #2645).
 *
 * Widget used to pipe that dump through grep -A4, which drops the In/Out
 * packet lines, then re-exec pfctl -Tshow | wc per alias for the same
 * Addresses count. This parser takes the FULL dump.
 *
 * Live fixture captured 2026-08-23 on pfb-testing clone 80823863
 * (pfSense CE 2.8.1, pfBlockerNG 3.3.3).
 */
#[CoversFunction('pfb_pfctl_tables_parse')]
final class PfctlTablesParseTest extends TestCase
{
	private const LIVE = __DIR__ . '/fixtures/pfctl-vvsTables-pfsense-281.txt';

	/** @return list<string> */
	private function liveLines(): array
	{
		$raw = file_get_contents(self::LIVE);
		$this->assertNotFalse($raw, 'missing live pfctl -vvsTables fixture');
		return explode("\n", rtrim($raw, "\n"));
	}

	public function testEmptyInput_ReturnsEmptyArray(): void
	{
		$this->assertSame([], pfb_pfctl_tables_parse([]));
	}

	public function testLiveFixture_ParsesPfBAddresses(): void
	{
		$parsed = pfb_pfctl_tables_parse($this->liveLines());
		$this->assertArrayHasKey('pfB_PRI1_v4', $parsed);
		$this->assertSame(
			16733,
			$parsed['pfB_PRI1_v4']['addresses'],
			"expected: 16733 Addresses on pfB_PRI1_v4;\nactual: " . ($parsed['pfB_PRI1_v4']['addresses'] ?? 'missing')
		);
	}

	public function testLiveFixture_ParsesTableLevelPackets(): void
	{
		$parsed = pfb_pfctl_tables_parse($this->liveLines());
		$this->assertSame(0, $parsed['pfB_PRI1_v4']['in_block_packets']);
		$this->assertSame(
			11513,
			$parsed['LAN__NETWORK']['in_pass_packets'],
			"expected: 11513 In/Pass packets on LAN__NETWORK;\nactual: " . ($parsed['LAN__NETWORK']['in_pass_packets'] ?? 'missing')
		);
		$this->assertSame(68, $parsed['bogons']['in_block_packets']);
		$this->assertSame(25144, $parsed['bogons']['in_block_bytes']);
	}

	public function testLiveFixture_KeepsFlagsAndCleared(): void
	{
		$parsed = pfb_pfctl_tables_parse($this->liveLines());
		$this->assertSame('-pa-r--', $parsed['pfB_PRI1_v4']['flags']);
		$this->assertSame('Sun Aug 23 00:51:40 2026', $parsed['pfB_PRI1_v4']['cleared']);
		$this->assertSame(1569, $parsed['pfB_PRI1_v4']['evaluations_nomatch']);
		$this->assertSame(0, $parsed['pfB_PRI1_v4']['evaluations_match']);
		$this->assertSame(1, $parsed['pfB_PRI1_v4']['references_rules']);
	}

	public function testTruncatedA4Dump_OmitsPacketLinesAsZero(): void
	{
		// What the widget's grep -A4 captured: name + Addresses/Cleared/References/Evaluations.
		$lines = [
			"-pa-r--\tpfB_PRI1_v4",
			"\tAddresses:   16733",
			"\tCleared:     Sun Aug 23 00:51:40 2026",
			"\tReferences:  [ Anchors: 0                  Rules: 1                  ]",
			"\tEvaluations: [ NoMatch: 1569               Match: 0                  ]",
		];
		$parsed = pfb_pfctl_tables_parse($lines);
		$this->assertSame(16733, $parsed['pfB_PRI1_v4']['addresses']);
		$this->assertSame(
			0,
			$parsed['pfB_PRI1_v4']['in_block_packets'],
			'truncated -A4 dump has no In/Block line; packets must default to 0, not unset'
		);
	}

	public function testSyntheticBlockCounters_ParsePacketsAndBytes(): void
	{
		$lines = [
			"-pa-r--\tpfB_Test_v4",
			"\tAddresses:   3",
			"\tCleared:     Sun Aug 23 00:51:40 2026",
			"\tReferences:  [ Anchors: 0                  Rules: 1                  ]",
			"\tEvaluations: [ NoMatch: 10                 Match: 2                  ]",
			"\tIn/Block:    [ Packets: 7                  Bytes: 100                ]",
			"\tIn/Pass:     [ Packets: 0                  Bytes: 0                  ]",
			"\tIn/XPass:    [ Packets: 0                  Bytes: 0                  ]",
			"\tOut/Block:   [ Packets: 1                  Bytes: 50                 ]",
			"\tOut/Pass:    [ Packets: 0                  Bytes: 0                  ]",
			"\tOut/XPass:   [ Packets: 0                  Bytes: 0                  ]",
		];
		$parsed = pfb_pfctl_tables_parse($lines);
		$this->assertSame(3, $parsed['pfB_Test_v4']['addresses']);
		$this->assertSame(7, $parsed['pfB_Test_v4']['in_block_packets']);
		$this->assertSame(100, $parsed['pfB_Test_v4']['in_block_bytes']);
		$this->assertSame(1, $parsed['pfB_Test_v4']['out_block_packets']);
		$this->assertSame(50, $parsed['pfB_Test_v4']['out_block_bytes']);
		$this->assertSame(10, $parsed['pfB_Test_v4']['evaluations_nomatch']);
		$this->assertSame(2, $parsed['pfB_Test_v4']['evaluations_match']);
	}
}
