<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

/**
 * Issue #1784 — the comma-joined IP alert `$details` line, evaled verbatim out
 * of pfblockerng.inc (Issue1792SweepSiteLoader's line-scoped extractor).
 *
 * Admin-authored descr/hostname values (NAT rules, host aliases, DHCP static
 * maps) reach `$hostname`/`$resolved_host` UNfiltered and were bare-joined
 * into the CSV `$details` line — a comma in a description shifted every
 * subsequent field for that row in the Alerts/Reports rendering and the
 * ipcache table. Every reader of these logs is already quote-aware
 * (`fgetcsv(..., ',', '"', '')`, the issue #1369 contract pfb_asn_csv_fields()
 * writes under), so the fix is the same CSV quoting at the join — one guard
 * instead of five producer filters.
 */
#[CoversNothing]
final class AlertDetailsCsvFieldTest extends TestCase
{
	public static function setUpBeforeClass(): void
	{
		require_once __DIR__ . '/Issue1792SweepSiteLoader.php';
	}

	/** Build the real $details line with the given host fields seeded. */
	private function buildDetails(string $resolved_host, string $hostname): string
	{
		$out = pfb_test_1792_eval_site(
			'src/usr/local/pkg/pfblockerng/pfblockerng.inc',
			"\$details\t= \"{\$dir},{\$geoip}",
			[
				'dir'           => 'Inbound',
				'geoip'         => 'US',
				'pfb_alias'     => 'pfB_Test',
				'pfb_query'     => ['TestFeed', '192.0.2.9'],
				'resolved_host' => $resolved_host,
				'hostname'      => $hostname,
				'asn'           => 'asn: AS64500 | domain: example.net | name: Example AS',
			]
		);
		return $out['details'];
	}

	/** Parse exactly like every log reader does (issue #1369 contract). */
	private static function fields(string $line): array
	{
		return str_getcsv($line, ',', '"', '');
	}

	public function testCommaBearingHostnameDoesNotShiftFields(): void
	{
		$fields = self::fields($this->buildDetails('host.example.lan', 'Bob, den PC'));

		$this->assertSame('host.example.lan', $fields[5], 'resolved-host field must stay in column 5');
		$this->assertSame('Bob, den PC', $fields[6],
			'a comma-bearing client hostname/descr must survive as ONE field, never shift the row (issue #1784)');
		$this->assertSame('AS64500', $fields[7], 'the ASN column must still follow the hostname field');
	}

	public function testCommaBearingResolvedHostDoesNotShiftFields(): void
	{
		$fields = self::fields($this->buildDetails('weird, rdns', 'client-pc'));

		$this->assertSame('weird, rdns', $fields[5]);
		$this->assertSame('client-pc', $fields[6]);
		$this->assertSame('AS64500', $fields[7]);
	}

	public function testPlainHostFieldsStayByteIdentical(): void
	{
		// The quoting guard must be invisible for well-formed values -- the
		// existing on-disk format is pinned byte-identical.
		$details = $this->buildDetails('host.example.lan', 'client-pc');
		$this->assertStringStartsWith(
			'Inbound,US,pfB_Test,192.0.2.9,TestFeed,host.example.lan,client-pc,',
			$details,
			'clean values must serialize unquoted -- no format change for existing rows'
		);
	}
}
