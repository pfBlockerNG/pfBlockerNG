<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * The TLD Allow count renders because its data is in scope where the control is built.
 *
 * The DNSBL tab reorganisation moved the TLD Allow checkbox above the four $tld_list
 * arrays and dropped the "(N TLDs available)" figure, because $tld_total was no longer
 * in scope to render it there. The live-VM guard that catches the rendered value
 * (test_dnsbl_page_renders_tld_pickers) only runs in the UI fan-out; this pins the
 * ordering invariant behind it on every PHPUnit run.
 */
final class DnsblTldAllowCountTest extends TestCase
{
	private const PAGE = __DIR__ . '/../../src/usr/local/www/pfblockerng/pfblockerng_dnsbl.php';

	private const TYPES = ['gTLD', 'ccTLD', 'iTLD', 'bgTLD'];

	private const DATA_START = '$tld_list = array();';

	private const TOTAL = '$tld_total = array_sum(array_map(\'count\', $tld_list));';

	private const HELP = "setHelp('Enable the TLD Allow feature (' . number_format(\$tld_total) . ' TLDs available). '";

	private static function source(): string
	{
		$source = file_get_contents(self::PAGE);
		self::assertIsString($source, 'the DNSBL page must be readable');
		return $source;
	}

	/**
	 * Scenario: the control's help text renders a figure derived from the TLD arrays.
	 * Expected: those arrays are defined earlier in the file than the control that reads
	 * them, and the figure is derived rather than restated as a literal.
	 */
	public function testTldDataIsDefinedBeforeTheControlThatRendersTheCount(): void
	{
		$source = self::source();
		$data = strpos($source, self::DATA_START);
		$total = strpos($source, self::TOTAL);
		$help = strpos($source, self::HELP);

		$this->assertNotFalse($data, 'the TLD data block must exist: ' . self::DATA_START);
		$this->assertNotFalse($total, 'the derived total must exist: ' . self::TOTAL);
		$this->assertNotFalse($help,
			'the TLD Allow help must render number_format($tld_total), not a literal count');
		$this->assertLessThan($help, $total,
			"\$tld_total is assigned at offset {$total} but read at offset {$help}: the control is "
			. 'built before its own data, so the count cannot render there');
		$this->assertLessThan($total, $data, 'the arrays must precede the total derived from them');
		$this->assertStringNotContainsString('1,546 TLDs available', $source,
			'the retired hardcoded total must not come back');
	}

	/**
	 * Behaviour-preserving oracle for the move: the relocated block still defines the four
	 * lists the pickers render, and the total is still derived from them.
	 *
	 * Counted by tokenising, never by evaluating. Executing a slice of a page to measure it
	 * put arbitrary code one edit away from running in this suite, and no allowlist of
	 * tokens closes that -- `array_map` takes its callback as a string.
	 */
	public function testTldTotalIsTheSumOfTheFourListsAndPlausible(): void
	{
		$lists = $this->entryCounts('$tld_list');
		$info = $this->entryCounts('$tld_info');

		$this->assertSame(self::TYPES, array_keys($lists),
			'the four TLD lists must be present, in their rendered order');
		$this->assertSame(self::TYPES, array_keys($info),
			'every list must carry the description its picker renders beside the count');

		foreach ($lists as $type => $count) {
			$this->assertGreaterThan(0, $count, "the {$type} list must not be empty");
		}
		$total = array_sum($lists);
		$this->assertGreaterThanOrEqual(1000, $total,
			"a total of {$total} is implausibly low -- an array was blanked or narrowed: "
			. var_export($lists, TRUE));

		// The page derives the aggregate with exactly this expression, so it IS the sum of
		// these counts by construction; the ordering test pins that the expression is there.
		$this->assertStringContainsString(self::TOTAL, self::source(),
			'the total must stay derived from $tld_list, never restated');
	}

	/**
	 * Entries per sub-array of $name in the TLD data block, keyed by sub-array name.
	 *
	 * @return array<string, int>
	 */
	private function entryCounts(string $name): array
	{
		$tokens = token_get_all('<?php ' . $this->tldDataBlock());
		$counts = [];
		$current = NULL;
		$depth = 0;
		foreach ($tokens as $index => $token) {
			if (is_array($token) && $token[0] === T_VARIABLE && $token[1] === $name) {
				$key = NULL;
				for ($ahead = $index + 1; $ahead < $index + 6; $ahead++) {
					$next = $tokens[$ahead] ?? NULL;
					if (is_array($next) && $next[0] === T_CONSTANT_ENCAPSED_STRING) {
						$key = trim($next[1], "'\"");
						break;
					}
				}
				if ($key !== NULL) {
					$current = $key;
					$counts[$key] = 0;
					$depth = 0;
				}
			}
			if ($current === NULL) {
				continue;
			}
			if ($token === '(') {
				$depth++;
			} elseif ($token === ')') {
				if (--$depth <= 0) {
					$current = NULL;
				}
			} elseif (is_array($token) && $token[0] === T_DOUBLE_ARROW && $depth === 1) {
				$counts[$current]++;
			}
		}
		return $counts;
	}

	private function tldDataBlock(): string
	{
		$source = self::source();
		$start = strpos($source, self::DATA_START);
		$end = strpos($source, self::TOTAL);
		$this->assertNotFalse($start, 'the TLD data block must exist');
		$this->assertNotFalse($end, 'the derived total must exist');
		return substr($source, $start, ($end - $start) + strlen(self::TOTAL));
	}
}
