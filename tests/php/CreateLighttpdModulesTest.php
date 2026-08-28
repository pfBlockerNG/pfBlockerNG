<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_create_lighttpd() — pins the server.modules set emitted for the DNSBL
 * lighttpd configuration.
 *
 * Three facts this test enforces:
 *   (1) mod_auth is ABSENT from the configuration — it was loaded in all four
 *       variants but never referenced by any auth.* directive; removing it is
 *       the fix for issue #266.
 *   (2) mod_access is ALWAYS loaded, regardless of the py_nolog setting — it is
 *       what makes the unconditional `url.access-deny = ( "~", ".inc" )` directive
 *       effective. With mod_access unloaded, lighttpd treats url.access-deny as an
 *       unknown directive and silently ignores it, so the ".inc"/"~" denial is not
 *       enforced (issue #279). It is appended on its own `server.modules += (...)`
 *       line so it is independent of the logging branch.
 *   (3) The py_nolog flag drives a real branch — but only for mod_accesslog (the
 *       access-log module): 'off' omits it, 'on' adds it. The flip is asserted
 *       before/after so the test fails on a regression, not just on coverage; the
 *       same flip confirms mod_access stays present on BOTH sides (it is not
 *       py_nolog-gated).
 *
 * On the CI runner (no lighttpd binary, no /usr/local/lib/lighttpd/mod_openssl.so)
 * the function deterministically exercises the non-openssl branches. Those are the
 * two branches asserted here; the openssl variants are structurally identical — the
 * module-list logic is the same conditional, so the non-openssl gate is sufficient.
 */
#[CoversFunction('pfb_create_lighttpd')]
final class CreateLighttpdModulesTest extends TestCase
{
	private array $originalPfb = [];
	private bool $hadPfb       = false;

	protected function setUp(): void
	{
		$this->hadPfb     = array_key_exists('pfb', $GLOBALS);
		$this->originalPfb = $GLOBALS['pfb'] ?? [];

		// Minimal keys pfb_create_lighttpd() reads from $pfb.
		$GLOBALS['pfb'] = array_merge($GLOBALS['pfb'] ?? [], [
			'dnsbl_iface'    => 'lo0',
			'dnsbl_vip4'     => '10.10.10.1',
			'dnsbl_port'     => '8081',
			'dnsbl_port_ssl' => '8443',
			'dnsbl_vip6'     => '',
			'dnsbl_py_nolog' => PfbToggle::Off,
		]);
	}

	protected function tearDown(): void
	{
		if ($this->hadPfb) {
			$GLOBALS['pfb'] = $this->originalPfb;
		} else {
			unset($GLOBALS['pfb']);
		}
	}

	/**
	 * Extract the first server.modules list line from a generated lighttpd conf
	 * string (the branch-selected `server.modules = ( ... )` list). Returns the
	 * raw line (trimmed) so assertions are on the exact emitted text.
	 *
	 * mod_access lives on a separate unconditional `server.modules += ( ... )`
	 * line, so assertions about it run against the whole conf, not this line.
	 */
	private function modulesLine(string $conf): string
	{
		foreach (explode("\n", $conf) as $line) {
			if (strpos($line, 'server.modules') !== false) {
				return trim($line);
			}
		}
		return '';
	}

	// -------------------------------------------------------------------------
	// py_nolog OFF — access-log module absent; mod_access still loaded (backs
	// url.access-deny); mod_auth absent (regression guard).
	// -------------------------------------------------------------------------

	public function testNologOffLoadsModAccessOmitsAccessLogAndModAuth(): void
	{
		// Given: py_nolog is off (the shipped default).
		$GLOBALS['pfb']['dnsbl_py_nolog'] = PfbToggle::Off;

		// When: conf is generated.
		$conf    = pfb_create_lighttpd();
		$modules = $this->modulesLine($conf);

		// Then: core modules are present in the branch-selected list.
		$this->assertStringContainsString('"mod_fastcgi"', $modules,
			'mod_fastcgi must be present when py_nolog=off');
		$this->assertStringContainsString('"mod_rewrite"', $modules,
			'mod_rewrite must be present when py_nolog=off');

		// The access-log module must NOT appear (logging is disabled).
		$this->assertStringNotContainsString('"mod_accesslog"', $modules,
			'mod_accesslog must be absent when py_nolog=off');

		// mod_access MUST be loaded even with logging off — it backs the
		// unconditional url.access-deny directive (issue #279).
		$this->assertStringContainsString('url.access-deny', $conf,
			'url.access-deny is emitted unconditionally');
		$this->assertStringContainsString('"mod_access"', $conf,
			'mod_access must be loaded when py_nolog=off so url.access-deny is enforced (#279)');

		// Regression guard — mod_auth must be absent (dead config removed in #266).
		$this->assertStringNotContainsString('"mod_auth"', $conf,
			'mod_auth must not appear in the config (issue #266: no auth.* directive uses it)');
	}

	// -------------------------------------------------------------------------
	// py_nolog ON — before/after: the flip drives mod_accesslog only, while
	// mod_access stays loaded on both sides (proves it is not py_nolog-gated).
	// -------------------------------------------------------------------------

	public function testNologFlipDrivesAccessLogWhileModAccessStaysLoaded(): void
	{
		// Given: start with py_nolog off (before-state asserted explicitly).
		$GLOBALS['pfb']['dnsbl_py_nolog'] = PfbToggle::Off;
		$confBefore    = pfb_create_lighttpd();
		$modulesBefore = $this->modulesLine($confBefore);

		// Before: access-log module absent; mod_access already present.
		$this->assertStringNotContainsString('"mod_accesslog"', $modulesBefore,
			'before: mod_accesslog absent with py_nolog=off');
		$this->assertStringContainsString('"mod_access"', $confBefore,
			'before: mod_access present even with py_nolog=off (#279)');

		// When: py_nolog is flipped to on.
		$GLOBALS['pfb']['dnsbl_py_nolog'] = PfbToggle::On;
		$confAfter    = pfb_create_lighttpd();
		$modulesAfter = $this->modulesLine($confAfter);

		// Then: the access-log module now appears (the flip caused the change).
		$this->assertStringContainsString('"mod_accesslog"', $modulesAfter,
			'after: mod_accesslog must be present when py_nolog=on');

		// mod_access is unaffected by the flip — still present.
		$this->assertStringContainsString('"mod_access"', $confAfter,
			'after: mod_access still present when py_nolog=on (#279)');

		// Core modules still present.
		$this->assertStringContainsString('"mod_fastcgi"', $modulesAfter,
			'mod_fastcgi must be present when py_nolog=on');
		$this->assertStringContainsString('"mod_rewrite"', $modulesAfter,
			'mod_rewrite must be present when py_nolog=on');

		// Regression guard — mod_auth absent in the on-branch too.
		$this->assertStringNotContainsString('"mod_auth"', $confAfter,
			'mod_auth must not appear in the config with py_nolog=on (issue #266)');
	}
}
