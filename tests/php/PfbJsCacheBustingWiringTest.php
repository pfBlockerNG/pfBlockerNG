<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Every page that ships `pfBlockerNG.js` must reference it with an mtime cache-buster,
 * the same way the pfSense chrome and this package's CodeMirror assets already do.
 *
 * A bare `src="pfBlockerNG.js"` lets a browser keep its pre-upgrade copy of the script:
 * the response carries no Expires/Cache-Control, so heuristic freshness applies. The
 * stale copy then throws against post-upgrade markup, and pfSense's unguarded `events`
 * drain skips every page callback queued behind it (issue #1845).
 *
 * These pages carry top-level render execution and cannot be require()d off-appliance,
 * so reading the shipped source IS reading the render for this markup. The rendered
 * form is pinned on a live appliance by tests/smoke/ui/test_render_smoke.py.
 */
final class PfbJsCacheBustingWiringTest extends TestCase
{
	/** The shipped script, as the pages address it and as it lands on the appliance. */
	private const SCRIPT_SRC  = 'pfBlockerNG.js';
	private const SCRIPT_PATH = '/usr/local/www/pfblockerng/pfBlockerNG.js';

	/**
	 * @return array<string, array{string}>
	 */
	public static function pageProvider(): array
	{
		$pages = array(
			'pfblockerng_category_edit.php',
			'pfblockerng_category.php',
			'pfblockerng_ip.php',
			'pfblockerng_dnsbl.php',
		);
		$cases = array();
		foreach ($pages as $page) {
			$cases[$page] = array($page);
		}
		return $cases;
	}

	private static function read(string $page): string
	{
		$path = dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/' . $page;
		$src  = file_get_contents($path);
		if ($src === false) {
			throw new RuntimeException("failed to read {$page}");
		}
		return $src;
	}

	#[DataProvider('pageProvider')]
	public function testPfbJsIsIncludedWithAnMtimeCacheBuster(string $page): void
	{
		$src = self::read($page);

		// Non-vacuity first: the page really does ship the script. A page that stopped
		// including it would otherwise pass the cache-buster assertion by having nothing
		// to match.
		$this->assertStringContainsString(
			self::SCRIPT_SRC,
			$src,
			"{$page} does not include " . self::SCRIPT_SRC . ' at all'
		);

		$this->assertMatchesRegularExpression(
			'#<script src="' . preg_quote(self::SCRIPT_SRC, '#') . '\?v=<\?=pfb_file_mtime\('
			. "'" . preg_quote(self::SCRIPT_PATH, '#') . "'"
			. '\)\?>"#',
			$src,
			"{$page} includes " . self::SCRIPT_SRC . ' without the pfb_file_mtime() cache-buster,'
			. ' so a browser can keep running the pre-upgrade script'
		);
	}

	#[DataProvider('pageProvider')]
	public function testPfbJsIsNeverIncludedWithoutTheCacheBuster(string $page): void
	{
		$src = self::read($page);

		// Counting closes the gap a "one good include exists" assertion leaves open: a
		// second, un-busted include elsewhere in the same page would still serve the
		// stale script.
		$total  = preg_match_all('#src="' . preg_quote(self::SCRIPT_SRC, '#') . '#', $src);
		$busted = preg_match_all(
			'#src="' . preg_quote(self::SCRIPT_SRC, '#') . '\?v=<\?=pfb_file_mtime\(#',
			$src
		);

		$this->assertSame(
			$total,
			$busted,
			"{$page} has {$total} " . self::SCRIPT_SRC . " include(s) but only {$busted} carry the cache-buster"
		);
	}
}
