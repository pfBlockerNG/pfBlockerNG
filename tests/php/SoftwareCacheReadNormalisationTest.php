<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Consumers of the software-update cache read its values with a ``(string)`` cast — the cron
 * orchestrator's latest/last_notified, the Software page's displayed fields, the install
 * matcher — or, for a timestamp, through a validating accessor (``pfb_software_failed_at()``,
 * issue #2674). A non-scalar value in the file therefore emits "Array to string conversion"
 * at EACH casting call site, once per call (issue #2367).
 *
 * Guarding each site would leave the next one to be written unguarded, so the value is
 * dropped where the file becomes data: a key the reader cannot hand to a caster is a key no
 * caller can use.
 */
#[CoversFunction('pfb_software_read_cache')]
final class SoftwareCacheReadNormalisationTest extends TestCase
{
	private string $dbdir = '';
	private bool $hadDbdir = FALSE;
	private mixed $savedDbdir = NULL;

	protected function setUp(): void
	{
		$this->dbdir = sys_get_temp_dir() . '/pfb_sw_cache_' . uniqid('', TRUE);
		mkdir($this->dbdir, 0o755, TRUE);
		$this->hadDbdir   = isset($GLOBALS['pfb']) && array_key_exists('dbdir', $GLOBALS['pfb']);
		$this->savedDbdir = $GLOBALS['pfb']['dbdir'] ?? NULL;
		$GLOBALS['pfb']['dbdir'] = $this->dbdir;
	}

	protected function tearDown(): void
	{
		if ($this->hadDbdir) {
			$GLOBALS['pfb']['dbdir'] = $this->savedDbdir;
		} else {
			unset($GLOBALS['pfb']['dbdir']);
		}
		foreach ((array) glob($this->dbdir . '/*') as $file) {
			@unlink((string) $file);
		}
		@rmdir($this->dbdir);
	}

	/** @param array<string,mixed> $payload */
	private function writeCache(array $payload): void
	{
		file_put_contents(
			$this->dbdir . '/software_update.json',
			(string) json_encode($payload)
		);
	}

	/**
	 * The scalar keys the writer stores survive a read unchanged — the normalisation must
	 * not cost the cache its contents.
	 */
	public function testScalarValuesSurvive(): void
	{
		$this->writeCache([
			'pkgname'       => 'pfSense-pkg-pfBlockerNG',
			'repo'          => 'pfblockerng-stable',
			'channel'       => 'Stable',
			'installed'     => '4.0.0',
			'latest'        => '4.0.1',
			'last_notified' => '',
			'last_checked'  => 1755200000,
		]);

		$cache = pfb_software_read_cache();

		$this->assertSame('pfSense-pkg-pfBlockerNG', $cache['pkgname']);
		$this->assertSame('4.0.1', $cache['latest']);
		$this->assertSame(1755200000, $cache['last_checked']);
	}

	/**
	 * A non-scalar value is dropped, so a caller casting it never sees it. Asserted through
	 * the cast the string-valued consumers perform, with warnings captured rather than
	 * converted — the point is what the code EMITS, not merely what it returns. The one
	 * consumer that does not cast (``pfb_software_failed_at()``, which validates instead)
	 * refuses the same values, pinned in SoftwareFailedCheckStateTest.
	 */
	public function testNonScalarValuesAreDroppedSoConsumerCastsAreSilent(): void
	{
		$this->writeCache([
			'pkgname'       => 'pfSense-pkg-pfBlockerNG',
			'latest'        => ['4.0.1'],
			'last_notified' => ['nested' => ['deep']],
			'last_checked'  => 1755200000,
		]);

		$seen = [];
		set_error_handler(static function (int $errno, string $msg) use (&$seen): bool {
			$seen[] = $msg;
			return TRUE;
		});

		try {
			$cache  = pfb_software_read_cache();
			// Exactly what the orchestrator and the page do with these two keys.
			$latest = (string) ($cache['latest'] ?? '');
			$last   = (string) ($cache['last_notified'] ?? '');
		} finally {
			restore_error_handler();
		}

		$this->assertSame([], $seen, 'reading and casting the cache must be silent: ' . implode(' | ', $seen));
		$this->assertArrayNotHasKey('latest', $cache, 'an array latest cannot be a version string');
		$this->assertArrayNotHasKey('last_notified', $cache, 'an array last_notified cannot be a version string');
		$this->assertSame('', $latest);
		$this->assertSame('', $last);
		// The scalars around it are untouched, so one bad key does not blank the cache.
		$this->assertSame('pfSense-pkg-pfBlockerNG', $cache['pkgname']);
		$this->assertSame(1755200000, $cache['last_checked']);
	}

	/** A file that is absent, empty, or not a JSON object still reads as an empty cache. */
	public function testUnusableFilesStillReadAsEmpty(): void
	{
		$this->assertSame([], pfb_software_read_cache(), 'an absent cache file reads empty');

		file_put_contents($this->dbdir . '/software_update.json', '');
		$this->assertSame([], pfb_software_read_cache(), 'an empty cache file reads empty');

		file_put_contents($this->dbdir . '/software_update.json', '{"latest": ');
		$this->assertSame([], pfb_software_read_cache(), 'a truncated cache file reads empty');

		file_put_contents($this->dbdir . '/software_update.json', '"just a string"');
		$this->assertSame([], pfb_software_read_cache(), 'a non-object cache file reads empty');
	}
}
