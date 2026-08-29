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

	/** The derivation, as a pattern: a reformat of that line is not a defect. */
	private const TOTAL = '/\$tld_total\s*=\s*array_sum\(\s*array_map\(\s*\'count\'\s*,\s*\$tld_list\s*\)\s*\)\s*;/';

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
		$total = $this->derivationOffset($source);
		$help = strpos($source, self::HELP);

		$this->assertNotFalse($data, 'the TLD data block must exist: ' . self::DATA_START);
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
	 * lists the pickers render, with unique keys, and the total is still derived from them.
	 *
	 * Counted by tokenising, never by evaluating. Executing a slice of a page to measure it
	 * put arbitrary code one edit away from running in this suite, and no allowlist of
	 * tokens closes that -- array_map takes its callback as a string.
	 */
	public function testTldTotalIsTheSumOfTheFourListsAndPlausible(): void
	{
		$lists = $this->entryKeys('$tld_list');
		$info = $this->entryKeys('$tld_info');

		$this->assertSame(self::TYPES, array_keys($lists),
			'the four TLD lists must be present, in their rendered order');
		$this->assertSame(self::TYPES, array_keys($info),
			'every list must carry the description its picker renders beside the count');

		$counts = [];
		foreach ($lists as $type => $keys) {
			$this->assertNotSame([], $keys, "the {$type} list must not be empty");
			$duplicates = array_keys(array_filter(array_count_values($keys),
				static fn (int $seen): bool => $seen > 1));
			$this->assertSame([], $duplicates,
				"the {$type} list must not repeat a TLD -- PHP keeps the last of a duplicate pair, so "
				. 'the rendered count would silently drop one: ' . implode(', ', $duplicates));
			$counts[$type] = count($keys);
		}

		$total = array_sum($counts);
		$this->assertGreaterThanOrEqual(1000, $total,
			"a total of {$total} is implausibly low -- an array was blanked or narrowed: "
			. var_export($counts, TRUE));

		// The page derives the aggregate with exactly this expression, so it IS the sum of
		// these counts by construction; the ordering test pins that the expression is there.
		$this->assertNotFalse($this->derivationOffset(self::source()),
			'the total must stay derived from $tld_list, never restated');
	}

	/** Byte offset of the $tld_total derivation, or FALSE when it is absent. */
	private function derivationOffset(string $source): int|false
	{
		return preg_match(self::TOTAL, $source, $match, PREG_OFFSET_CAPTURE) === 1
			? $match[0][1] : FALSE;
	}

	/**
	 * Entry keys per sub-array of $name in the TLD data block, keyed by sub-array name.
	 *
	 * Keys rather than a tally: a repeated key is one entry at runtime but two arrows in
	 * the source, so counting arrows would report a list larger than the page renders.
	 *
	 * @return array<string, list<string>>
	 */
	private function entryKeys(string $name): array
	{
		$tokens = token_get_all('<?php ' . $this->tldDataBlock());
		$keys = [];
		$current = NULL;
		$depth = 0;
		foreach ($tokens as $index => $token) {
			if (is_array($token) && $token[0] === T_VARIABLE && $token[1] === $name) {
				$subscript = NULL;
				for ($ahead = $index + 1; $ahead < $index + 6; $ahead++) {
					$next = $tokens[$ahead] ?? NULL;
					if (is_array($next) && $next[0] === T_CONSTANT_ENCAPSED_STRING) {
						$subscript = trim($next[1], "'\"");
						break;
					}
				}
				if ($subscript !== NULL) {
					$current = $subscript;
					$keys[$subscript] = [];
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
			} elseif ($depth === 1 && is_array($token) && $token[0] === T_CONSTANT_ENCAPSED_STRING
				&& $this->arrowFollows($tokens, $index)) {
				$keys[$current][] = trim($token[1], "'\"");
			}
		}
		return $keys;
	}

	/** @param array<int, array{0: int, 1: string}|string> $tokens */
	private function arrowFollows(array $tokens, int $index): bool
	{
		for ($ahead = $index + 1; $ahead < $index + 4; $ahead++) {
			$next = $tokens[$ahead] ?? NULL;
			if (is_array($next) && $next[0] === T_DOUBLE_ARROW) {
				return TRUE;
			}
			if (!is_array($next) || $next[0] !== T_WHITESPACE) {
				return FALSE;
			}
		}
		return FALSE;
	}

	private function tldDataBlock(): string
	{
		$source = self::source();
		$start = strpos($source, self::DATA_START);
		$end = $this->derivationOffset($source);
		$this->assertNotFalse($start, 'the TLD data block must exist');
		$this->assertNotFalse($end, 'the derived total must exist');
		return substr($source, $start, $end - $start);
	}
}
