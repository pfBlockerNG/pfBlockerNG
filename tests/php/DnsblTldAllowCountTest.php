<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * The TLD Allow count renders because its data is in scope where the control is built.
 *
 * The DNSBL tab reorganisation moved the TLD Allow checkbox above the four $tld_list
 * arrays, so number_format($tld_total) there read an undefined variable: the count
 * collapsed to 0 and every page load logged a warning. The live-VM guard that catches
 * the rendered value (test_dnsbl_page_renders_tld_pickers) only runs in the UI fan-out;
 * this pins the ordering invariant behind it on every PHPUnit run.
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
	 * them -- the single property whose loss produced "(0 TLDs available)".
	 */
	public function testTldDataIsDefinedBeforeTheControlThatRendersTheCount(): void
	{
		$source = self::source();
		$data = strpos($source, self::DATA_START);
		$total = strpos($source, self::TOTAL);
		$help = strpos($source, self::HELP);

		$this->assertNotFalse($data, 'the TLD data block must exist: ' . self::DATA_START);
		$this->assertNotFalse($total, 'the derived total must exist: ' . self::TOTAL);
		$this->assertNotFalse($help, 'the TLD Allow help must render the derived count');
		$this->assertLessThan($help, $total,
			"\$tld_total is assigned at offset {$total} but read at offset {$help}: the control is "
			. 'built before its own data, so the count renders as 0 and the load warns');
		$this->assertLessThan($total, $data, 'the arrays must precede the total derived from them');
	}

	/** The figure is derived from the arrays, never restated as a literal. */
	public function testTldAllowCountIsDerivedAndNotHardcoded(): void
	{
		$source = self::source();

		$this->assertStringContainsString(self::HELP, $source,
			'the help text must render number_format($tld_total), not a literal count');
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
	 * The block sits outside form construction, so it must not reach for form state --
	 * the property that made relocating it safe, and that a later edit could quietly lose.
	 */
	public function testTldDataBlockCarriesNoFormState(): void
	{
		$source = self::source();
		$start = strpos($source, self::DATA_START);
		$end = strpos($source, self::TOTAL);
		$this->assertNotFalse($start);
		$this->assertNotFalse($end);
		$block = substr($source, $start, $end - $start);

		foreach (['$pconfig', '$section', '$form', '$group'] as $symbol) {
			$this->assertStringNotContainsString($symbol, $block,
				"the TLD data block must stay pure data; it now references {$symbol}");
		}
	}

	/** @return array{list: array<string, array<string, string>>, info: array<string, string>, total: int} */
	private function evaluateTldDataBlock(): array
	{
		$source = self::source();
		$start = strpos($source, self::DATA_START);
		$end = strpos($source, self::TOTAL);
		$this->assertNotFalse($start, 'the TLD data block must exist');
		$this->assertNotFalse($end, 'the derived total must exist');
		$block = substr($source, $start, ($end - $start) + strlen(self::TOTAL));

		$path = tempnam(sys_get_temp_dir(), 'pfb_tld_');
		$this->assertNotFalse($path);
		try {
			file_put_contents($path,
				"<?php\n" . $block . "\nreturn ['list' => \$tld_list, 'info' => \$tld_info, 'total' => \$tld_total];\n");
			$data = (static fn (string $file): mixed => include $file)($path);
		} finally {
			@unlink($path);
		}
		$this->assertIsArray($data, 'the TLD data block must evaluate to its three bindings alone');
		return $data;
	}
}
