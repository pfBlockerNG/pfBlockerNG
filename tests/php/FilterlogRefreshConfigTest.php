<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;

/**
 * pfb_filterlog_refresh_config() — the long-running filterlog daemon must reload
 * $config whenever config.xml's CONTENT changed since it last loaded it, so a live
 * log_syslog toggle takes effect on the next block event (ADR-38 Amendment 1).
 *
 * Issue #3384: mtime is second-granular. A toggle written in the same wall-clock
 * second the daemon last observed config.xml keeps the mtime unchanged, so an
 * mtime-only check kept exporting DNSBL events after syslog was switched OFF.
 *
 * Each test runs in its own process: the daemon's observation state is
 * per-process, exactly as on the appliance.
 */
#[CoversFunction('pfb_filterlog_refresh_config')]
final class FilterlogRefreshConfigTest extends TestCase
{
	private string $configXml;

	/**
	 * A config.xml mtime the observing check cannot have outlived: the rewrite
	 * lands in the second the daemon is still in. Pinned ahead of the clock so the
	 * scenario never depends on where a second boundary falls during the test.
	 */
	private int $openSecond;

	protected function setUp(): void
	{
		$path = tempnam(sys_get_temp_dir(), 'pfb_refresh_cfg_');
		$this->assertIsString($path, 'test setup: temp file creation failed');
		$this->configXml = $path;
		$this->openSecond = time() + 3600;
		$GLOBALS['pfb_test_config_read_calls'] = [];
	}

	protected function tearDown(): void
	{
		if (is_file($this->configXml)) {
			unlink($this->configXml);
		}
	}

	private function writeConfig(string $logSyslog, int $mtime): void
	{
		$xml = "<pfsense><installedpackages><pfblockerng><config>"
			. "<log_syslog>{$logSyslog}</log_syslog>"
			. "</config></pfblockerng></installedpackages></pfsense>\n";
		$this->assertNotFalse(file_put_contents($this->configXml, $xml), 'test setup: config write failed');
		$this->assertTrue(touch($this->configXml, $mtime), 'test setup: mtime pin failed');
	}

	/** @return list<array{0: bool, 1: bool}> */
	private function reloads(): array
	{
		return $GLOBALS['pfb_test_config_read_calls'];
	}

	/**
	 * Scenario: syslog switched OFF in the same second the daemon saw it switched ON.
	 *   Given the daemon observed config.xml with log_syslog=on
	 *   And   a later config.xml change was picked up by an mtime change
	 *   When  log_syslog is written OFF within that same second (mtime unchanged)
	 *   Then  the next block event reloads $config
	 */
	#[RunInSeparateProcess]
	public function testSameSecondToggleIsReloaded(): void
	{
		// Given: daemon-start baseline — recording it is not a reload.
		$this->writeConfig('', $this->openSecond - 1);
		pfb_filterlog_refresh_config($this->configXml);
		$this->assertSame([], $this->reloads(), 'baseline capture must not reload $config');

		// Before: an mtime-changing write (syslog ON) is reloaded.
		$this->writeConfig('on', $this->openSecond);
		pfb_filterlog_refresh_config($this->configXml);
		$this->assertCount(1, $this->reloads(), 'an mtime-changing config.xml write must reload $config');

		// When: syslog OFF lands in the same second — mtime identical, content differs.
		$this->writeConfig('', $this->openSecond);
		pfb_filterlog_refresh_config($this->configXml);

		// Then.
		$this->assertCount(
			2,
			$this->reloads(),
			'a same-second config.xml rewrite (unchanged mtime, changed content) must reload $config: '
			. 'reloads=' . json_encode($this->reloads())
		);
	}

	/**
	 * Scenario: nothing changed.
	 *   Given the daemon loaded config.xml after a change in the still-open second
	 *   When  further block events arrive with config.xml untouched
	 *   Then  no further reload happens
	 */
	#[RunInSeparateProcess]
	public function testUntouchedConfigIsNotReloaded(): void
	{
		$this->writeConfig('', $this->openSecond - 1);
		pfb_filterlog_refresh_config($this->configXml);
		$this->writeConfig('on', $this->openSecond);
		pfb_filterlog_refresh_config($this->configXml);
		$this->assertCount(1, $this->reloads(), 'before: the ON write must have been reloaded once');

		pfb_filterlog_refresh_config($this->configXml);
		pfb_filterlog_refresh_config($this->configXml);

		$this->assertCount(1, $this->reloads(), 'untouched config.xml must not be reloaded again');
	}

	/**
	 * Scenario: the reload reads config.xml itself.
	 *   Given a config.xml change the daemon has not loaded yet
	 *   When  the next block event reloads $config
	 *   Then  pfSense's config.cache is bypassed — CE 2.8's write_config renames
	 *         config.xml into place before it refreshes that cache, so a reload in
	 *         between would load the old toggle and never retry
	 */
	#[RunInSeparateProcess]
	public function testReloadBypassesConfigCache(): void
	{
		$this->writeConfig('', $this->openSecond - 1);
		pfb_filterlog_refresh_config($this->configXml);
		$this->writeConfig('on', $this->openSecond);
		pfb_filterlog_refresh_config($this->configXml);

		$this->assertSame(
			[[FALSE, FALSE]],
			$this->reloads(),
			'reload must call config_read_file(use_backup: FALSE, use_cache: FALSE)'
		);
	}
}
