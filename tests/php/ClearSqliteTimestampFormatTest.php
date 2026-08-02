<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-60 §1.8: pfBlockerNG_clearsqlite()'s 'clearip'/'cleardnsbl' branches stamped
 * lastipclear/lastdnsblclear with date('M j H:i:s', time()) -- no year -- and the
 * dashboard widget (widget.php ~:797-:798) displays that value RAW, with no
 * reformatter at all (unlike dnsbl_stats_update()'s value, which pfb_iso_timestamp()
 * at least guesses a year for). Both branches now write date('Y-m-d H:i:s', time()),
 * so the operator sees the real write year, not an ambiguous "Dec 31 23:00:00" that
 * could be any past year.
 */
#[CoversFunction('pfBlockerNG_clearsqlite')]
final class ClearSqliteTimestampFormatTest extends TestCase
{
	/** @var string[] temp files to remove in tearDown */
	private array $tmpfiles = [];

	/** @var array<string,mixed> saved $GLOBALS['pfb'] keys (sentinel FALSE = was unset) */
	private array $saved = [];

	protected function setUp(): void
	{
		foreach (['dnsbl_resolver', 'dnsbl_info', 'sqlite_timeout', 'errlog'] as $k) {
			$this->saved[$k] = array_key_exists($k, $GLOBALS['pfb'] ?? []) ? $GLOBALS['pfb'][$k] : false;
		}
	}

	protected function tearDown(): void
	{
		foreach ($this->saved as $k => $prev) {
			if ($prev === false) {
				unset($GLOBALS['pfb'][$k]);
			} else {
				$GLOBALS['pfb'][$k] = $prev;
			}
		}
		foreach ($this->tmpfiles as $f) {
			if (is_file($f)) {
				$this->assertTrue(unlink($f), "failed to remove temp file {$f}");
			}
		}
		$this->tmpfiles = [];
	}

	private function tempFile(string $prefix): string
	{
		$f = tempnam(sys_get_temp_dir(), $prefix);
		$this->assertNotFalse($f, "could not create temp file ({$prefix})");
		$this->tmpfiles[] = $f;
		return $f;
	}

	/**
	 * Seeds a real SQLite 'lastclear' row=0 (the row pfBlockerNG_clearsqlite()'s
	 * UPDATE targets) at a fresh temp DB, and redirects $pfb['dnsbl_resolver']
	 * (table 6's database, ALSO table 3's -- 'cleardnsbl' touches both) AND
	 * $pfb['dnsbl_info'] (table 1) away from their real /var/unbound/*.sqlite
	 * production paths -- mirrors LogTimestampBaselineTest's sandbox pattern.
	 */
	private function seedLastClearSandbox(): string
	{
		$db_file = $this->tempFile('pfb_lastclear_');
		$GLOBALS['pfb']['dnsbl_resolver'] = $db_file;
		$GLOBALS['pfb']['dnsbl_info'] = $this->tempFile('pfb_lastclear_dnsblinfo_');
		$GLOBALS['pfb']['sqlite_timeout'] = 2000;
		$GLOBALS['pfb']['errlog'] = $this->tempFile('pfb_lastclear_errlog_');

		$db = new SQLite3($db_file);
		$db->exec('CREATE TABLE IF NOT EXISTS lastclear ( row INTEGER, lastipclear TEXT, lastdnsblclear TEXT )');
		$db->exec("INSERT INTO lastclear (row, lastipclear, lastdnsblclear) VALUES (0, 'Unknown', 'Unknown')");
		$db->close();

		return $db_file;
	}

	private function readLastClearRow(string $db_file): array
	{
		$db = new SQLite3($db_file);
		$row = $db->querySingle('SELECT lastipclear, lastdnsblclear FROM lastclear WHERE row = 0', TRUE);
		$db->close();
		return $row;
	}

	/**
	 * Red -> green proof (write side): the REAL function, called for real (real
	 * clock), must store a YEAR-bearing ISO 'lastipclear' timestamp now.
	 */
	public function testClearIpModeWritesYearBearingIsoTimestamp(): void
	{
		$db_file = $this->seedLastClearSandbox();

		pfBlockerNG_clearsqlite('clearip');

		$row = $this->readLastClearRow($db_file);
		$this->assertMatchesRegularExpression(
			'/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/',
			$row['lastipclear'],
			"pfBlockerNG_clearsqlite('clearip') must store a year-bearing ISO 'lastipclear'; got: {$row['lastipclear']}"
		);
	}

	/**
	 * Same proof for the 'cleardnsbl' branch -- the second, separate call site.
	 */
	public function testClearDnsblModeWritesYearBearingIsoTimestamp(): void
	{
		$db_file = $this->seedLastClearSandbox();

		// 'cleardnsbl' also touches table 3 (resolver) + calls flush_stats via exec() when
		// unbound is "running" -- neither exists in this sandbox, so avoid the extra I/O by
		// keeping is_process_running('unbound') false (the real function on a dev/CI box).
		pfBlockerNG_clearsqlite('cleardnsbl');

		$row = $this->readLastClearRow($db_file);
		$this->assertMatchesRegularExpression(
			'/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/',
			$row['lastdnsblclear'],
			"pfBlockerNG_clearsqlite('cleardnsbl') must store a year-bearing ISO 'lastdnsblclear'; got: {$row['lastdnsblclear']}"
		);
	}

	/**
	 * Characterization: the widget displays this field RAW (widget.php ~:797-:798,
	 * `htmlspecialchars("{$res['lastipclear']}")`, no reformatter). Reproducing that
	 * exact display line against the OLD no-year format shows the operator an
	 * ambiguous string with NO year at all -- they cannot tell which past year it is.
	 */
	public function testOldNoYearFormatDisplayedRawCarriesNoYear(): void
	{
		$oldStoredValue = date('M j H:i:s', mktime(23, 0, 0, 12, 31, 2024));
		$displayed = htmlspecialchars("{$oldStoredValue}");

		$this->assertDoesNotMatchRegularExpression(
			'/\d{4}/',
			$displayed,
			"BUG: the OLD raw-displayed value must carry no year at all -- got: {$displayed}"
		);
	}

	/**
	 * Green pairing: the widget's SAME raw display line, fed the NEW year-bearing
	 * value, shows the real write year -- and remains a sensible, readable string
	 * (htmlspecialchars() is a no-op on plain digits/dashes/colons/spaces).
	 */
	public function testNewYearBearingFormatDisplayedRawShowsTheYear(): void
	{
		$newStoredValue = date('Y-m-d H:i:s', mktime(23, 0, 0, 12, 31, 2024));
		$displayed = htmlspecialchars("{$newStoredValue}");

		$this->assertSame('2024-12-31 23:00:00', $displayed, 'the ISO value must display unchanged (no HTML-escapable characters)');
	}

}
