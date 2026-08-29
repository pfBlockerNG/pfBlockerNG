<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * pfb_unbound_clear_work_files() -- issue #1083 review: the writer/unlink sites for
 * the legacy DNSBL_TLD.txt diagnostic were retired, but a pre-#1083 box's stray file
 * would otherwise sit forever. This sweep runs on every DNSBL update pass
 * (pfb_update_unbound()), so adding it here is the natural opportunistic cleanup site.
 */
#[CoversFunction('pfb_unbound_clear_work_files')]
final class PfbUnboundClearWorkFilesTest extends TestCase
{
	private string $workdir = '';

	/** @var array<string,mixed> saved $pfb keys (sentinel FALSE = was unset) */
	private array $saved = [];

	protected function setUp(): void
	{
		$workdir = tempnam(sys_get_temp_dir(), 'pfbclearwork');
		$this->assertNotFalse($workdir);
		$this->assertTrue(unlink($workdir) && mkdir($workdir, 0700));
		$this->workdir = $workdir;

		foreach (['dnsbl_cache', 'dnsbldir', 'dnsbl_file', 'unbound_py_data', 'unbound_py_zone', 'dnsdir'] as $k) {
			$this->saved[$k] = array_key_exists($k, $GLOBALS['pfb'] ?? []) ? $GLOBALS['pfb'][$k] : false;
		}
		mkdir("{$workdir}/dnsbldir", 0700);
		mkdir("{$workdir}/dnsdir", 0700);
		$GLOBALS['pfb']['dnsbl_cache']     = "{$workdir}/pfb_py_cache.sqlite";
		$GLOBALS['pfb']['dnsbldir']        = "{$workdir}/dnsbldir";
		$GLOBALS['pfb']['dnsbl_file']      = "{$workdir}/dnsbl_file";
		$GLOBALS['pfb']['unbound_py_data'] = "{$workdir}/pfb_py_data.txt";
		$GLOBALS['pfb']['unbound_py_zone'] = "{$workdir}/pfb_py_zone.txt";
		$GLOBALS['pfb']['dnsdir']          = "{$workdir}/dnsdir";
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
		rmdir_recursive($this->workdir);
	}

	public function testLegacyDnsblTldTxtIsSweptAlongsideTheOtherWorkFiles(): void
	{
		$legacy = "{$this->workdir}/dnsdir/DNSBL_TLD.txt";
		file_put_contents($legacy, "stale pre-#1083 diagnostic content\n");
		$this->assertFileExists($legacy, 'precondition: the stray legacy file exists');

		pfb_unbound_clear_work_files();

		$this->assertFileDoesNotExist($legacy, 'a stray pre-upgrade DNSBL_TLD.txt must be swept opportunistically');
	}

	public function testAbsentLegacyDnsblTldTxtIsANoOp(): void
	{
		$legacy = "{$this->workdir}/dnsdir/DNSBL_TLD.txt";
		$this->assertFileDoesNotExist($legacy);

		pfb_unbound_clear_work_files();

		$this->assertFileDoesNotExist($legacy);
	}

	/** @return iterable<string,array{0:list<string>}> */
	public static function legacyReportsCacheFamilyProvider(): iterable
	{
		yield 'base only' => [['']];
		yield 'WAL only' => [['-wal']];
		yield 'SHM only' => [['-shm']];
		yield 'complete family' => [['', '-wal', '-shm']];
		yield 'no family members' => [[]];
	}

	/** ADR-65 follow-up: remove the retired reports DB and its exact SQLite sidecars. */
	#[DataProvider('legacyReportsCacheFamilyProvider')]
	public function testLegacyReportsCacheFamilyIsSweptWithoutPrefixWildcards(array $presentSuffixes): void
	{
		$base = $GLOBALS['pfb']['dnsbl_cache'];
		$unrelated = "{$base}.backup";
		file_put_contents($unrelated, "keep\n");

		foreach ($presentSuffixes as $suffix) {
			file_put_contents("{$base}{$suffix}", "stale\n");
		}

		pfb_unbound_clear_work_files();

		foreach (['', '-wal', '-shm'] as $suffix) {
			$this->assertFileDoesNotExist("{$base}{$suffix}");
		}
		$this->assertFileExists($unrelated, 'similarly prefixed unrelated files must survive');
	}

	/** ADR-65: sweep a stray pre-upgrade pfb_py_data.txt (writer retired). */
	public function testStrayUnboundPyDataIsSweptAlongsideTheOtherWorkFiles(): void
	{
		$legacy = $GLOBALS['pfb']['unbound_py_data'];
		file_put_contents($legacy, "stale retired interchange content\n");
		$this->assertFileExists($legacy, 'precondition: the stray retired file exists');

		pfb_unbound_clear_work_files();

		$this->assertFileDoesNotExist($legacy, 'a stray pre-ADR-65 pfb_py_data.txt must be swept opportunistically');
	}

	/** ADR-65: sweep a stray pre-upgrade pfb_py_zone.txt (writer retired). */
	public function testStrayUnboundPyZoneIsSweptAlongsideTheOtherWorkFiles(): void
	{
		$legacy = $GLOBALS['pfb']['unbound_py_zone'];
		file_put_contents($legacy, "stale retired interchange content\n");
		$this->assertFileExists($legacy, 'precondition: the stray retired file exists');

		pfb_unbound_clear_work_files();

		$this->assertFileDoesNotExist($legacy, 'a stray pre-ADR-65 pfb_py_zone.txt must be swept opportunistically');
	}
}
