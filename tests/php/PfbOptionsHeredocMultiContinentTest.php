<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/PfbNoPhpWarningTrait.php';

/**
 * pfblockerng.php's pfblockerng_get_countries() (issue #1493 defect 2,
 * corrected -- verifier finding on commit 1b9ab1fa): unlike $ftotal4/
 * $ftotal6, $options4/$options6 ARE unset every continent iteration by the
 * unconditional `unset(${'options4'}, ${'options6'}, $php_data);` at the
 * end of the per-continent tail (~2216). The #1497 function-top init
 * (`$options4 = $options6 = '';`) runs ONCE per function call, so any
 * continent AFTER the first whose per-type data is empty (fopen failure or
 * an empty $coptions* -- 8 of $geoip_files's 9 continents in the bare
 * `gc`-before-any-GeoIP-download scenario #1493 exists to fix) reaches the
 * generated-page heredoc with $options4/$options6 undefined again.
 * PHPStan cannot see the dynamic ${'options4'}/${'options6'} unset (the
 * same blindness that hid the original defect), so its clean report after
 * 1b9ab1fa was an artifact of that blindness, not proof -- this test
 * drives the REAL multi-continent control flow instead.
 *
 * Extracts four verbatim anchors from pfblockerng.php: whatever sits at
 * the top of the continent loop (the per-continent $ftotal4/$ftotal6
 * reset -- extracted POSITIONALLY, not hand-copied, so this test proves
 * the issue #1507 fix lands in the right place), the per-type
 * coptions-guarded options-build block (+ its trailing $coptions* unset),
 * whatever guard sits between the type-loop's close and the heredoc start
 * (the `??=` pair, same positional-extraction contract), and the final
 * $options4/$options6 unset.
 * Drives two simulated continent iterations -- the file itself cannot be
 * require()d off-appliance (house precedent: CountryNetworksCountGuardTest.php,
 * GeoipContinentCatStderrGuardTest.php, PfbEtOptionsUndefinedTest.php).
 *
 * Feature: $options4/$options6 must reach the per-continent heredoc as a
 *          defined string on EVERY continent, not just the first
 *
 *   Scenario: continent 1 has IPv4 data, continent 2 has none -> continent
 *             2's heredoc-equivalent read must not warn, and must render
 *             as the empty string
 *
 * Feature: issue #1507 -- $ftotal4/$ftotal6 must render each continent's
 *          OWN count; $ftotal* is assigned only inside the coptions-guarded
 *          block, so without a per-continent reset a data-less continent
 *          renders the PREVIOUS continent's count beside an empty list
 *
 *   Scenario: continent 1 has one IPv4 entry (count 1), continent 2 has
 *             none -> continent 2's heredoc-equivalent count must render
 *             "0", not continent 1's stale "1"
 */
final class PfbOptionsHeredocMultiContinentTest extends TestCase
{
	use PfbNoPhpWarningTrait;

	public static function setUpBeforeClass(): void
	{
		if (function_exists('pfb_options_heredoc_oracle')) {
			return;
		}

		$path = dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng.php';
		$src = file_get_contents($path);
		if ($src === FALSE) {
			throw new RuntimeException('test bootstrap: failed to read pfblockerng.php');
		}

		if (!preg_match(
			'/foreach \(\$geoip_files as \$cont => \$file\) \{\n(.*?)\/\/ Process the following for IPv4 and IPv6/s',
			$src,
			$mLoopTop
		)) {
			throw new RuntimeException('oracle extraction failed: the continent-loop-top region (between the outer foreach open and the per-type loop comment) was not found in pfblockerng.php');
		}

		if (!preg_match(
			'/if \(!empty\(\$\{\'coptions\' \. \$type\}\)\) \{.*?unset\(\$\{\'coptions\' \. \$type\}\);/s',
			$src,
			$mBlock
		)) {
			throw new RuntimeException('oracle extraction failed: the per-type coptions-guarded options-build block was not found in pfblockerng.php');
		}

		if (!preg_match(
			'/unset\(\$\{\'coptions\' \. \$type\}\);\n\t\t\}\n\n(.*?)\$php_data = <<<EOF/s',
			$src,
			$mGuard
		)) {
			throw new RuntimeException('oracle extraction failed: the post-type-loop guard region (between the type-loop close and the heredoc start) was not found in pfblockerng.php');
		}

		if (!preg_match(
			'/unset\(\$\{\'options4\'\}, \$\{\'options6\'\}, \$php_data\);/',
			$src,
			$mUnset
		)) {
			throw new RuntimeException('oracle extraction failed: the final $options4/$options6 unset was not found in pfblockerng.php');
		}

		$loopTop    = $mLoopTop[1];
		$typeBlock  = $mBlock[0];
		$postGuard  = $mGuard[1];
		$finalUnset = $mUnset[0];

		eval(
			'function pfb_options_heredoc_oracle(): array {'
			. ' $coptions4 = $coptions6 = array();'
			. ' $options4 = $options6 = "";'
			. ' $ftotal4 = $ftotal6 = 0;'
			. ' $cont = "TestCont";'
			. ' $rendered = [];'
			. ' foreach ([TRUE, FALSE] as $continentHasV4Data) {'
			. '   ' . $loopTop
			. '   foreach (array("4", "6") as $type) {'
			. '     if ($type === "4" && $continentHasV4Data) {'
			. '       ${"coptions" . $type}[] = \'x|"US" => "Test US (1)"\';'
			. '     }'
			. '     ' . $typeBlock
			. '   }'
			. '   ' . $postGuard . ';'
			. '   $rendered[] = ["options" => "{$options4}{$options6}", "cnt4" => "{$ftotal4}", "cnt6" => "{$ftotal6}"];'
			. '   ' . $finalUnset
			. ' }'
			. ' return $rendered;'
			. ' }'
		);
	}

	public function testSecondContinentWithNoDataDoesNotWarnReadingOptions(): void
	{
		$rendered = $this->assertNoPhpWarning(static function (): array {
			return pfb_options_heredoc_oracle();
		});

		$this->assertNotSame('', $rendered[0]['options'], 'sanity: continent 1 (has IPv4 data) must render something non-empty');
		$this->assertSame(
			'',
			$rendered[1]['options'],
			'$options4/$options6 must render as the empty string on a data-less continent (unset by the previous continent\'s tail, never reassigned since its coptions4/6 are empty), not an undefined-variable NULL'
		);
	}

	public function testSecondContinentWithNoDataRendersZeroCounts(): void
	{
		$rendered = $this->assertNoPhpWarning(static function (): array {
			return pfb_options_heredoc_oracle();
		});

		$this->assertSame('1', $rendered[0]['cnt4'], 'before-state anchor: continent 1 (one IPv4 entry) must render count 1 -- the very value a stale carry would leak into continent 2');
		$this->assertSame('0', $rendered[0]['cnt6'], 'sanity: continent 1 has no IPv6 data, so its IPv6 count must render 0');
		$this->assertSame(
			'0',
			$rendered[1]['cnt4'],
			'issue #1507: $options_countries4_cnt must render 0 on a data-less continent, not the previous continent\'s stale $ftotal4'
		);
		$this->assertSame(
			'0',
			$rendered[1]['cnt6'],
			'issue #1507: $options_countries6_cnt must render 0 on a data-less continent, not a stale $ftotal6'
		);
	}
}
