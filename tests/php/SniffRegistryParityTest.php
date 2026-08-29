<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Issue #1902 — mechanical sync guard between the ADR-29 enforcement sniff and
 * the config-gateway registry.
 *
 * RequireConfigGatewaySniff::$registeredPaths (tests/phpcs/.../Config/
 * RequireConfigGatewaySniff.php) is a hand-maintained literal list of full
 * config paths; pfb_cfg_registry() (pfblockerng_extra.inc) is the source of
 * truth it mirrors. Before this test the sync was enforced only by a comment:
 * a key registered in the gateway but missing from the sniff silently lost its
 * mechanical enforcement (raw config_*_path on that key passed phpcs).
 *
 * This test derives the expected path set from pfb_cfg_registry() itself —
 * "<section>/<key>" per entry — and asserts set-equality against the sniff
 * property, naming any missing/extra path in the failure message.
 *
 * The sniff class implements PHP_CodeSniffer\Sniffs\Sniff. phpcs ships no
 * composer autoload metadata, so that interface is not autoloadable here;
 * the guarded no-op stub below is what lets the class load without the
 * phpcs runtime (only the property is inspected — behaviour is pinned by
 * RequireConfigGatewaySniffTest).
 */
final class SniffRegistryParityTest extends TestCase
{
	public function testRegisteredPathsMatchCfgRegistry(): void
	{
		if (!interface_exists(\PHP_CodeSniffer\Sniffs\Sniff::class)) {
			eval('namespace PHP_CodeSniffer\Sniffs; interface Sniff {}');
		}
		require_once dirname(__DIR__)
			. '/phpcs/PfBlockerNG/Sniffs/Config/RequireConfigGatewaySniff.php';

		$actual = (array) (new \PfBlockerNG\Sniffs\Config\RequireConfigGatewaySniff())->registeredPaths;

		$expected = [];
		foreach (array_keys(pfb_cfg_registry()) as $path_key) {
			// issue #1931: $path_key is '<alias>/<bare-key>'; resolve the alias to the
			// real section path via PFB_SECTIONS.
			[$alias, $bare] = explode('/', $path_key, 2);
			$expected[] = PFB_SECTIONS[$alias] . '/' . $bare;
		}

		$missing = array_values(array_diff($expected, $actual));
		$extra   = array_values(array_diff($actual, $expected));

		$this->assertSame([], $missing,
			'pfb_cfg_registry() paths missing from the sniff $registeredPaths (add them there): '
			. implode(', ', $missing));
		$this->assertSame([], $extra,
			'sniff $registeredPaths entries absent from pfb_cfg_registry() (stale — remove or register): '
			. implode(', ', $extra));

		// Exactness (catches duplicates on either side, which the set diffs miss).
		sort($expected);
		sort($actual);
		$this->assertSame($expected, $actual);
	}
}
