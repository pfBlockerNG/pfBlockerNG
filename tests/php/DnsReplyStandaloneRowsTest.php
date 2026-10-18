<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #3515 -- pfB-DNS with DNSBL off writes dns_reply.log itself (pfb_dns_proxy.py --no-module --reply-log), through the
 * shipped pfb_unbound.py's own row writer. Reports and Stats must read those rows like the module's: the rows are the
 * ones tests/dns_proxy/test_reply_log.py pins in both modes (tests/fixtures/dns_reply_standalone_rows.json), so a row the
 * proxy writes and the viewers fail to read would fail here, and a writer that drifts from the fixture would fail there.
 *
 * Two readers: the Reports tab (convert_dns_reply_log(), on a row parsed with fgetcsv's own arguments) and the filterlog
 * daemon's pass into unified.log (pfb_unified_format_dnsreply(), on the row split the way the daemon splits it).
 */
#[CoversFunction('convert_dns_reply_log')]
#[CoversFunction('pfb_unified_format_dnsreply')]
final class DnsReplyStandaloneRowsTest extends TestCase
{
	private const FIXTURE = __DIR__ . '/../fixtures/dns_reply_standalone_rows.json';

	/** @var array<string, mixed> */
	private array $savedGlobals = [];

	public static function setUpBeforeClass(): void
	{
		require_once __DIR__ . '/AlertsPageLoader.php';
		pfb_test_load_alerts_page_functions();
	}

	protected function setUp(): void
	{
		foreach ([
			'pfb', 'local_hosts', 'filterfieldsarray', 'clists', 'counter',
			'pfbentries', 'skipcount', 'dnsfilterlimit', 'dnsfilterlimitentries',
		] as $g) {
			$this->savedGlobals[$g] = $GLOBALS[$g] ?? null;
		}

		$GLOBALS['pfb'] = ['filterlogentries' => FALSE];
		$GLOBALS['local_hosts'] = [self::fixture()['client'] => ''];
		$GLOBALS['filterfieldsarray'] = [];
		$GLOBALS['clists'] = [
			'dnsbl'          => ['options' => []],
			'dnsblwhitelist' => ['data' => []],
			'tld_wildcard_exclusion' => ['data' => []],
		];
		$GLOBALS['counter'] = ['DNS' => 0, 'Unified' => 0];
		$GLOBALS['pfbentries'] = 1000;
		$GLOBALS['skipcount'] = 0;
		$GLOBALS['dnsfilterlimit'] = FALSE;
		$GLOBALS['dnsfilterlimitentries'] = 100;
	}

	protected function tearDown(): void
	{
		foreach ($this->savedGlobals as $g => $v) {
			if ($v === null) {
				unset($GLOBALS[$g]);
			} else {
				$GLOBALS[$g] = $v;
			}
		}
	}

	/** @return array{stamp: string, client: string, rows: array<string, list<string>>} */
	private static function fixture(): array
	{
		return json_decode((string) file_get_contents(self::FIXTURE), TRUE, 512, JSON_THROW_ON_ERROR);
	}

	/** @return array<string, array{string, string}> one entry per row of every case: [case, the row as written] */
	public static function rows(): array
	{
		$rows = [];
		foreach (self::fixture()['rows'] as $case => $lines) {
			foreach ($lines as $i => $line) {
				$rows["{$case} #{$i}"] = [$case, $line];
			}
		}
		return $rows;
	}

	#[DataProvider('rows')]
	public function testTheReportsTabParsesTheRowIntoItsTenColumnsAndPrintsItsClientAndNameEncoded(string $case, string $line): void
	{
		// Given a row exactly as the proxy writes it, read the way every reader reads the log
		$fields = str_getcsv($line, ',', '"', '');
		$this->assertCount(10, $fields, "{$case}: the reader sees ten columns, whatever the queried name held");

		// When the Reports tab renders it
		ob_start();
		$limited = convert_dns_reply_log('Reports', $fields);
		$html = (string) ob_get_clean();

		// Then one row is printed with the client, the domain and the resolved value, and nothing the name carried is markup
		$this->assertFalse($limited, "{$case}: the row was printed");
		$this->assertSame(1, substr_count($html, '<tr>'), "{$case}: one table row");
		$this->assertStringContainsString("<td>{$fields[1]}</td>", $html, "{$case}: timestamp");
		$this->assertStringContainsString(pfb_hsc($fields[7]), $html, "{$case}: the client");
		$this->assertStringContainsString('<td title="">' . pfb_hsc($fields[6]) . '</td>', $html, "{$case}: the domain, encoded");
		$this->assertStringContainsString('<td title="">' . pfb_hsc($fields[8]) . '</td>', $html, "{$case}: the resolved value");
		$this->assertStringNotContainsString('<d>', $html, "{$case}: a name's markup stays text");
	}

	#[DataProvider('rows')]
	public function testTheDaemonsUnifiedLogRowIsTheRowItself(string $case, string $line): void
	{
		// Given the daemon's own split of a DNS-reply row (explode, not fgetcsv: a quoted name leaves the ten-column branch)
		$rf = explode(',', $line);
		if (count($rf) !== 10) {
			$this->assertGreaterThan(10, count($rf), "{$case}: a name with a comma is the only way to leave ten columns");
			return;  // the daemon appends such a row verbatim, the same in both modes
		}

		// When it is rendered for unified.log
		$unified = pfb_unified_format_dnsreply([
			'l_type' => $rf[0], 'datetime' => $rf[1], 'm_type' => $rf[2], 'o_type' => $rf[3], 'q_type' => $rf[4],
			'ttl' => $rf[5], 'q_name' => $rf[6], 'q_ip' => $rf[7], 'r_addr' => $rf[8], 'iso_code' => $rf[9],
		]);

		// Then nothing is lost or reordered
		$this->assertSame($line, $unified, "{$case}: unified.log keeps the row byte for byte");
	}

	public function testEveryCaseOfTheFixtureHasARowTheViewersCanReadAndTheNameThatSplitsItIsTheOnlyOneThatDoes(): void
	{
		// Given the fixture's cases, one of them a hostile name with a comma in it
		$splits = [];
		foreach (self::fixture()['rows'] as $case => $lines) {
			$this->assertNotSame([], $lines, "{$case}: a case that logs nothing would pin nothing");
			foreach ($lines as $line) {
				if (count(explode(',', $line)) !== 10) {
					$splits[] = $case;
				}
			}
		}

		// Then only that one is quoted for fgetcsv and left to the daemon's verbatim branch
		$this->assertSame(['hostile-name'], $splits);
	}
}
