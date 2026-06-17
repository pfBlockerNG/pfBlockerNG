<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_create_lighttpd() — pins the server.modules list emitted for the DNSBL
 * lighttpd configuration.
 *
 * Two facts this test enforces:
 *   (1) mod_auth is ABSENT from every server.modules line — it was loaded in all
 *       four variants but never referenced by any auth.* directive; removing it is
 *       the fix for issue #266.
 *   (2) The py_nolog flag drives a real branch: 'off' produces no access-log modules
 *       (mod_access / mod_accesslog absent); 'on' adds them (mod_access +
 *       mod_accesslog present). Both sides are asserted before/after the flip so the
 *       test fails on a regression, not just on coverage.
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
			'dnsbl_py_nolog' => 'off',
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
	 * Extract the server.modules line from a generated lighttpd conf string.
	 * Returns the raw line (trimmed) so assertions are on the exact emitted text.
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
	// py_nolog OFF — logging modules absent; mod_auth absent (regression guard).
	// -------------------------------------------------------------------------

	public function testNologOffOmitsAccessLogModulesAndModAuth(): void
	{
		// Given: py_nolog is off (the before-state).
		$GLOBALS['pfb']['dnsbl_py_nolog'] = 'off';

		// When: conf is generated.
		$conf    = pfb_create_lighttpd();
		$modules = $this->modulesLine($conf);

		// Then: core modules are present.
		$this->assertStringContainsString('"mod_fastcgi"', $modules,
			'mod_fastcgi must be present when py_nolog=off');
		$this->assertStringContainsString('"mod_rewrite"', $modules,
			'mod_rewrite must be present when py_nolog=off');

		// Access-log modules must NOT appear (logging is disabled).
		$this->assertStringNotContainsString('"mod_access"', $modules,
			'mod_access must be absent when py_nolog=off');
		$this->assertStringNotContainsString('"mod_accesslog"', $modules,
			'mod_accesslog must be absent when py_nolog=off');

		// Regression guard — mod_auth must be absent (dead config removed in #266).
		$this->assertStringNotContainsString('"mod_auth"', $modules,
			'mod_auth must not appear in server.modules (issue #266: no auth.* directive uses it)');
	}

	// -------------------------------------------------------------------------
	// py_nolog ON — before/after: proves the flag is a live branch, not dead code.
	// -------------------------------------------------------------------------

	public function testNologOnAddsAccessLogModulesAndStillOmitsModAuth(): void
	{
		// Given: start with py_nolog off (before-state asserted explicitly).
		$GLOBALS['pfb']['dnsbl_py_nolog'] = 'off';
		$confBefore    = pfb_create_lighttpd();
		$modulesBefore = $this->modulesLine($confBefore);

		// Before: access-log modules absent (same as the dedicated off-test above,
		// but re-asserted here so the flip has an observable before-state).
		$this->assertStringNotContainsString('"mod_access"', $modulesBefore,
			'before: mod_access absent with py_nolog=off');
		$this->assertStringNotContainsString('"mod_accesslog"', $modulesBefore,
			'before: mod_accesslog absent with py_nolog=off');

		// When: py_nolog is flipped to on.
		$GLOBALS['pfb']['dnsbl_py_nolog'] = 'on';
		$confAfter    = pfb_create_lighttpd();
		$modulesAfter = $this->modulesLine($confAfter);

		// Then: access-log modules now appear (the flip caused the change).
		$this->assertStringContainsString('"mod_access"', $modulesAfter,
			'after: mod_access must be present when py_nolog=on');
		$this->assertStringContainsString('"mod_accesslog"', $modulesAfter,
			'after: mod_accesslog must be present when py_nolog=on');

		// Core modules still present.
		$this->assertStringContainsString('"mod_fastcgi"', $modulesAfter,
			'mod_fastcgi must be present when py_nolog=on');
		$this->assertStringContainsString('"mod_rewrite"', $modulesAfter,
			'mod_rewrite must be present when py_nolog=on');

		// Regression guard — mod_auth absent in the on-branch too.
		$this->assertStringNotContainsString('"mod_auth"', $modulesAfter,
			'mod_auth must not appear in server.modules with py_nolog=on (issue #266)');
	}
}
