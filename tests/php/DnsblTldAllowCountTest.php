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
	 * Behaviour-preserving oracle for the move: the relocated block still computes the
	 * same aggregate the four per-list "Total TLD Count: [N]" figures add up to.
	 */
	public function testTldTotalIsTheSumOfTheFourListsAndPlausible(): void
	{
		$data = $this->evaluateTldDataBlock();

		$this->assertSame(self::TYPES, array_keys($data['list']),
			'the four TLD lists must be present, in their rendered order');
		$this->assertSame(self::TYPES, array_keys($data['info']),
			'every list must carry the description its picker renders beside the count');

		$per_list = array_map('count', $data['list']);
		$this->assertSame(array_sum($per_list), $data['total'],
			'the aggregate must equal the sum of the four per-list counts, which the page renders '
			. 'separately: ' . var_export($per_list, TRUE));
		$this->assertGreaterThanOrEqual(1000, $data['total'],
			"a total of {$data['total']} is implausibly low -- an array was blanked or narrowed");
		foreach ($per_list as $type => $count) {
			$this->assertGreaterThan(0, $count, "the {$type} list must not be empty");
		}
	}

	/**
	 * The oracle below evaluates the block, so the block must stay inert data. Allowlist
	 * rather than blocklist: a backtick shell-exec produces neither a variable binding nor
	 * a name-followed-by-paren, so anything screening for known-bad constructs misses it.
	 */
	public function testTldDataBlockIsInertEnoughToEvaluate(): void
	{
		$this->assertTldDataBlockIsInert();
	}

	/** @return list<string> the disallowed tokens found, empty when the block is inert */
	private function foreignTokens(string $block): array
	{
		// Every token the four literal arrays plus the array_sum(array_map(...)) need.
		$types = ['T_OPEN_TAG', 'T_VARIABLE', 'T_WHITESPACE', 'T_ARRAY',
			'T_CONSTANT_ENCAPSED_STRING', 'T_DOUBLE_ARROW', 'T_STRING'];
		$chars = ['=', '(', ')', ';', '[', ']', ','];
		$names = ['$tld_list', '$tld_info', '$tld_total'];
		$callees = ['array', 'array_sum', 'array_map'];

		$foreign = [];
		foreach (token_get_all('<?php ' . $block) as $token) {
			if (!is_array($token)) {
				if (!in_array($token, $chars, TRUE)) {
					$foreign[] = $token;
				}
				continue;
			}
			$name = token_name($token[0]);
			if (!in_array($name, $types, TRUE)) {
				$foreign[] = $name . ' ' . trim($token[1]);
			} elseif ($name === 'T_VARIABLE' && !in_array($token[1], $names, TRUE)) {
				$foreign[] = $token[1];
			} elseif ($name === 'T_STRING' && !in_array($token[1], $callees, TRUE)) {
				$foreign[] = $token[1] . '()';
			}
		}
		return array_values(array_unique($foreign));
	}

	private function assertTldDataBlockIsInert(): void
	{
		$foreign = $this->foreignTokens($this->tldDataBlock());

		$this->assertSame([], $foreign,
			'the TLD data block is evaluated by this suite, so it must stay literal arrays plus '
			. 'the count it derives; it now carries: ' . implode(', ', $foreign));
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

	/** @return array{list: array<string, array<string, string>>, info: array<string, string>, total: int} */
	private function evaluateTldDataBlock(): array
	{
		$this->assertTldDataBlockIsInert();
		$data = eval($this->tldDataBlock()
			. ' return [\'list\' => $tld_list, \'info\' => $tld_info, \'total\' => $tld_total];');
		$this->assertIsArray($data, 'the TLD data block must evaluate to its three bindings alone');
		return $data;
	}
}
