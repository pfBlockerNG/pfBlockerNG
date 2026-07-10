<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #1083 Phase 3 -- the NDJSON interchange FLIP, PHP-side writer/reader behaviour.
 *
 * Every DNSBL interchange writer/reader now speaks schema-v1 NDJSON
 * (pfb_dnsbl_ndjson_emit_domain_row()/emit_abp_row()/parse_row()), never the retired
 * positional CSV. Pins: pfb_unbound_python_sources() extracts a domain/abp raw payload
 * from NDJSON staging and silently skips an undecodable line; tld_analysis() over an
 * NDJSON pfb_dnsbl.raw produces the expected NDJSON data/zone rows, including the
 * synthetic TLD-blacklist row; pfb_dnsbl_parse_compute() returns attribution read from
 * NDJSON py_data/py_zone AND refuses an abp-embedded-needle spoof (hostile row).
 */
#[CoversFunction('pfb_unbound_python_sources')]
#[CoversFunction('tld_analysis')]
#[CoversFunction('pfb_dnsbl_parse_compute')]
final class DnsblNdjsonFlipTest extends TestCase
{
	private string $tmp;
	private bool $hadPfb = false;
	private array $originalPfb = [];
	private bool $hadTlds = false;
	private mixed $originalTlds = null;

	protected function setUp(): void
	{
		$this->hadPfb = array_key_exists('pfb', $GLOBALS);
		$this->originalPfb = $GLOBALS['pfb'] ?? [];
		$this->hadTlds = array_key_exists('tlds', $GLOBALS);
		$this->originalTlds = $GLOBALS['tlds'] ?? null;
		$GLOBALS['tlds'] = array();

		$this->tmp = sys_get_temp_dir() . '/pfb_ndjson_flip_' . uniqid('', true);
		mkdir("{$this->tmp}/dnsbl", 0777, true);
		mkdir("{$this->tmp}/db", 0777, true);
		mkdir("{$this->tmp}/dnsalias", 0777, true);

		pfb_dnsbl_prefetch_store(NULL);
	}

	protected function tearDown(): void
	{
		if ($this->hadPfb) {
			$GLOBALS['pfb'] = $this->originalPfb;
		} else {
			unset($GLOBALS['pfb']);
		}
		if ($this->hadTlds) {
			$GLOBALS['tlds'] = $this->originalTlds;
		} else {
			unset($GLOBALS['tlds']);
		}
		pfb_dnsbl_prefetch_store(NULL);
		rmdir_recursive($this->tmp);
	}

	// --- pfb_unbound_python_sources(): NDJSON staging -> per-feed .raw ------------

	public function testPythonSourcesExtractsDomainAndAbpFromNdjsonAndSkipsNullLine(): void
	{
		$GLOBALS['pfb'] = array_merge($GLOBALS['pfb'] ?? [], [
			'log'                => "{$this->tmp}/pfblockerng.log",
			'errlog'             => "{$this->tmp}/error.log",
			'unbound_py_rawdir'  => "{$this->tmp}/pfb_py_raw",
			'dnsdir'             => "{$this->tmp}/dnsbl",
			'unbound_py_sources' => "{$this->tmp}/pfb_py_sources.json",
			'dbdir'              => "{$this->tmp}/db",
			'dnsbl_top1m'        => 'off',
			'dnsbl_tld_data'     => "{$this->tmp}/does_not_exist",
			'dnsbl_unlock'       => "{$this->tmp}/dnsbl_unlock",
			'dnsblconfig'        => ['tldblacklist' => '', 'tldexclusion' => '', 'suppression' => ''],
		]);

		file_put_contents(
			"{$this->tmp}/dnsbl/feed1.txt",
			pfb_dnsbl_ndjson_emit_domain_row('blocked.example', '1', 'FeedA', 'GroupA')
			. pfb_dnsbl_ndjson_emit_abp_row('||ads.example^')
			. "this is not valid ndjson\n"
		);

		pfb_unbound_python_sources([
			['header' => 'feed1', 'group' => 'g', 'log' => '1', 'format' => 'plain', 'provenance' => 'feed'],
		]);

		$raw = file_get_contents("{$this->tmp}/pfb_py_raw/feed1.raw");
		$this->assertSame(
			"blocked.example\n||ads.example^\n",
			$raw,
			'expected the domain to be extracted, the abp raw passed through verbatim, and the NULL line silently skipped; got: '
				. var_export($raw, TRUE)
		);
	}

	// --- tld_analysis(): NDJSON pfb_dnsbl.raw -> NDJSON data/zone -----------------

	public function testTldAnalysisOverNdjsonProducesExpectedDataZoneRowsIncludingSyntheticTldRow(): void
	{
		$tldMaster = "{$this->tmp}/tld_master.txt";
		file_put_contents($tldMaster, "example\ndeep.example\n");

		$GLOBALS['pfb'] = array_merge($GLOBALS['pfb'] ?? [], [
			'log'              => "{$this->tmp}/pfblockerng.log",
			'errlog'           => "{$this->tmp}/error.log",
			'dnsdir'           => "{$this->tmp}/dnsbl",
			'dnsbl_file'       => "{$this->tmp}/pfb_dnsbl",
			'dnsbl_tmpdir'     => "{$this->tmp}/DNSBL_TMP",
			'dnsbl_tmp'        => "{$this->tmp}/dnsbl_tmp",
			'dnsbl_tld_txt'    => "{$this->tmp}/dnsbl/DNSBL_TLD.txt",
			'dnsbl_tld_data'   => $tldMaster,
			'unbound_py_data'  => "{$this->tmp}/pfb_py_data.txt",
			'unbound_py_zone'  => "{$this->tmp}/pfb_py_zone.txt",
			'domain_max_cnt'   => 1000000,
			'dnsbl_info'       => "{$this->tmp}/dnsbl_info.sqlite",
			'sqlite_timeout'   => 2000,
			'alias_dnsbl_all'  => [],
			'dnsbl_info_stats' => [],
			// pre-existing 'DNSBL_TLD' key (pre-seeded null, not missing) avoids an
			// unrelated undefined-array-key warning in tld_analysis()'s blacklist branch.
			'tld_update'       => ['DNSBL_TLD' => null],
			'dnsalias'         => "{$this->tmp}/dnsalias",
			'dnsblconfig'      => [
				'tldblacklist' => base64_encode('blacklisted-tld'),
				'tldexclusion' => '',
			],
		]);

		file_put_contents(
			"{$this->tmp}/pfb_dnsbl.raw",
			pfb_dnsbl_ndjson_emit_domain_row('sub.deep.example', '1', 'FeedZone', 'GroupZone')
			. pfb_dnsbl_ndjson_emit_domain_row('nosuffixmatch.example.invalidtld', '1', 'FeedData', 'GroupData')
		);

		tld_analysis();

		$zone = (string) file_get_contents("{$this->tmp}/pfb_py_zone.txt");
		$data = (string) file_get_contents("{$this->tmp}/pfb_py_data.txt");

		$this->assertSame(
			pfb_dnsbl_ndjson_emit_domain_row('blacklisted-tld', '1', 'DNSBL_TLD', 'DNSBL_TLD')
			. pfb_dnsbl_ndjson_emit_domain_row('sub.deep.example', '1', 'FeedZone', 'GroupZone'),
			$zone,
			'expected the synthetic TLD-blacklist row (W4) followed by the known-suffix zone match (W5); got: '
				. var_export($zone, TRUE)
		);
		$this->assertSame(
			pfb_dnsbl_ndjson_emit_domain_row('nosuffixmatch.example.invalidtld', '1', 'FeedData', 'GroupData'),
			$data,
			'expected the no-suffix-match domain as the transparent data row (W6); got: ' . var_export($data, TRUE)
		);
	}

	// --- pfb_dnsbl_parse_compute(): attribution from NDJSON + hostile-row refusal -

	private function seedDataZone(string $dataContent, string $zoneContent): void
	{
		$dataFile = "{$this->tmp}/py_data.txt";
		$zoneFile = "{$this->tmp}/py_zone.txt";
		file_put_contents($dataFile, $dataContent);
		file_put_contents($zoneFile, $zoneContent);

		$GLOBALS['pfb'] = [
			'grep'            => '/usr/bin/grep',
			'extdns'          => '127.0.0.1',
			'unbound_py_data' => $dataFile,
			'unbound_py_zone' => $zoneFile,
			'dnsbl_cache'     => "{$this->tmp}/dnsblcache.sqlite",
			'errlog'          => "{$this->tmp}/error.log",
			'sqlite_timeout'  => 2000,
		];
	}

	public function testPfbDnsblParseReturnsAttributionFromNdjsonPyData(): void
	{
		$domain = 'blocked.example.com';
		$this->seedDataZone(pfb_dnsbl_ndjson_emit_domain_row($domain, '1', 'FeedA', 'GroupA'), '');

		$result = pfb_dnsbl_parse_compute('test', $domain, '', '');

		$this->assertSame(
			['pfb_mode' => 'DNSBL', 'pfb_group' => 'GroupA', 'pfb_final' => $domain, 'pfb_feed' => 'FeedA'],
			$result,
			'expected attribution read straight from the NDJSON py_data row; got: ' . var_export($result, TRUE)
		);
	}

	/**
	 * Hostile row (zone-mode, R6): the zone fixture carries a non-JSON garbage line
	 * embedding the literal NDJSON needle text for a suffix that has NO real entry.
	 * `grep -F` substring-matches it (byte-level, format-blind), but
	 * pfb_dnsbl_ndjson_domain_row_verified() refuses it (not valid JSON) -- the lookup
	 * must resolve to a genuine miss, never a spoofed TLD match.
	 */
	public function testPfbDnsblParseRefusesNeedleTextInsideGarbageLine(): void
	{
		$queryDomain = 'sub.uuid-zone-spoof-target.example.com';
		$suffix = 'uuid-zone-spoof-target.example.com';
		$hostileLine = 'not json at all "domain":"' . $suffix . '" trailing garbage' . "\n";
		$this->seedDataZone('', $hostileLine);

		$result = pfb_dnsbl_parse_compute('test', $queryDomain, '', '');

		$this->assertSame(
			['pfb_mode' => 'Unknown', 'pfb_group' => 'Unknown', 'pfb_final' => 'Unknown', 'pfb_feed' => 'Unknown'],
			$result,
			'expected the grep hit inside a non-JSON garbage line to be refused, never treated as a TLD match; got: '
				. var_export($result, TRUE)
		);
	}

	/**
	 * Each refusal arm of pfb_dnsbl_ndjson_domain_row_verified(), exercised directly:
	 * the abp-kind and wrong-domain arms are unreachable through the production files
	 * (JSON escaping forbids a literal needle inside a string value), so the pure
	 * helper is the only honest surface for their branch coverage.
	 */
	public function testDomainRowVerifiedAcceptsOnlyTheExactDomainKindRow(): void
	{
		$domain = 'uuid-verify-arm.example.com';
		$genuine = pfb_dnsbl_ndjson_emit_domain_row($domain, '1', 'FeedV', 'GroupV');

		$accepted = pfb_dnsbl_ndjson_domain_row_verified($genuine, $domain);
		$this->assertNotNull($accepted, 'genuine row must verify');
		$this->assertSame($domain, $accepted['domain']);

		$arms = [
			'non-JSON garbage embedding the needle text'
				=> 'garbage "domain":"' . $domain . '" tail' . "\n",
			'abp-kind row (kind arm)'
				=> pfb_dnsbl_ndjson_emit_abp_row('||' . $domain . '^'),
			'domain-kind row for a DIFFERENT domain (equality arm)'
				=> pfb_dnsbl_ndjson_emit_domain_row('other-' . $domain, '1', 'FeedV', 'GroupV'),
		];
		foreach ($arms as $label => $line) {
			$this->assertNull(
				pfb_dnsbl_ndjson_domain_row_verified($line, $domain),
				"refusal arm not taken for: {$label}"
			);
		}
	}
}
