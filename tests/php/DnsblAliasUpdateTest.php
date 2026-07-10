<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * dnsbl_alias_update() unchecked-fopen guards (issue #1073).
 *
 * The master-alias copy loop opened its destination without checking the
 * return and closed the per-list source handle outside its own open-check.
 * On PHP 8, fwrite(FALSE)/fclose(FALSE) throw TypeError ('@' only silences
 * warnings), so an unwritable destination directory or a vanished source
 * file aborted the whole DNSBL update instead of degrading to a skipped
 * copy. Both opens are now guarded; the stats bookkeeping after the copy
 * must run either way.
 *
 * The unwritable destination is modeled as a NON-EXISTENT directory (fopen
 * fails for any uid, unlike a chmod fixture, which root bypasses).
 */
#[CoversFunction('dnsbl_alias_update')]
final class DnsblAliasUpdateTest extends TestCase
{
	private string $workdir = '';

	/** @var array<string,mixed> saved $pfb keys (sentinel FALSE = was unset) */
	private array $saved = [];

	protected function setUp(): void
	{
		$workdir = tempnam(sys_get_temp_dir(), 'pfbdnsbl');
		$this->assertNotFalse($workdir);
		$this->assertTrue(unlink($workdir) && mkdir($workdir, 0700));
		$this->workdir = $workdir;

		foreach (['dnsalias', 'dnsbl_info_stats'] as $k) {
			$this->saved[$k] = array_key_exists($k, $GLOBALS['pfb'] ?? []) ? $GLOBALS['pfb'][$k] : false;
		}
		$GLOBALS['pfb']['dnsbl_info_stats'] = [];
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
		if ($this->workdir !== '' && is_dir($this->workdir)) {
			foreach ((array) glob("{$this->workdir}/*") as $f) {
				@unlink((string) $f);
			}
			rmdir($this->workdir);
		}
	}

	private function statsEntryFor(string $alias): ?array
	{
		foreach ($GLOBALS['pfb']['dnsbl_info_stats'] as $entry) {
			if (($entry['groupname'] ?? '') === $alias) {
				return $entry;
			}
		}
		return null;
	}

	public function testUpdateConcatenatesSourcesAndRecordsStats(): void
	{
		// Given: a writable alias dir and two source lists.
		$GLOBALS['pfb']['dnsalias'] = $this->workdir;
		file_put_contents("{$this->workdir}/one.txt", "1.example.com\n");
		file_put_contents("{$this->workdir}/two.txt", "2.example.com\n");

		dnsbl_alias_update('update', 'TestGroup', $this->workdir, ['one', 'two'], 2);

		$this->assertSame(
			"1.example.com\n2.example.com\n",
			file_get_contents("{$this->workdir}/TestGroup"),
			'both source lists must land in the master alias file, in order'
		);
		$entry = $this->statsEntryFor('TestGroup');
		$this->assertNotNull($entry, 'a stats entry must be recorded');
		$this->assertSame('2', (string) $entry['entries']);
	}

	public function testUnwritableDestinationDegradesInsteadOfThrowing(): void
	{
		// Given: the alias dir does not exist, so the destination fopen fails.
		$GLOBALS['pfb']['dnsalias'] = "{$this->workdir}/does-not-exist";
		file_put_contents("{$this->workdir}/one.txt", "1.example.com\n");

		// When/Then: before the guard this threw TypeError from fwrite(FALSE)
		// (PHP 8; '@' does not suppress it) and aborted the DNSBL update.
		dnsbl_alias_update('update', 'TestGroup', $this->workdir, ['one'], 1);

		$this->assertFileDoesNotExist("{$this->workdir}/does-not-exist/TestGroup");
		$this->assertNotNull(
			$this->statsEntryFor('TestGroup'),
			'the stats bookkeeping after the copy must still run on a failed open'
		);
	}

	public function testVanishedSourceListIsSkippedNotFatal(): void
	{
		// Given: one existing and one missing source list (concurrent teardown).
		$GLOBALS['pfb']['dnsalias'] = $this->workdir;
		file_put_contents("{$this->workdir}/one.txt", "1.example.com\n");

		// When/Then: before the fix the fclose(FALSE) outside the open-check
		// threw TypeError for the missing list.
		dnsbl_alias_update('update', 'TestGroup', $this->workdir, ['one', 'gone'], 1);

		$this->assertSame(
			"1.example.com\n",
			file_get_contents("{$this->workdir}/TestGroup"),
			'the existing list must still be copied when a sibling vanished'
		);
		$this->assertNotNull($this->statsEntryFor('TestGroup'));
	}
}
