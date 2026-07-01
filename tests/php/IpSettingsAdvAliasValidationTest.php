<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Tests for the Advanced Inbound/Outbound alias handling on the IP settings page
 * (issue #676, sibling of #636).
 *
 * pfblockerng.php is a TEMPLATE: it generates the per-continent settings pages
 * (pfblockerng_<Continent>.php) via file_put_contents. On a POST save those pages
 * process the four Advanced alias fields (aliasports_in / aliasaddr_in /
 * aliasports_out / aliasaddr_out) in TWO steps that this suite exercises together,
 * both extracted verbatim from the shipped template source so the real page code
 * runs — not a copy:
 *
 *   1. Select-option normalization: each field whose submitted value is not a key
 *      in its dropdown options is reset to '' (its default). The options are built
 *      from the configuration — port aliases for the port fields, network aliases
 *      for the address fields — so this step silently drops any non-existent or
 *      wrong-type value BEFORE validation.
 *   2. Advanced alias validation: pfb_adv_alias_field_errors() (#636) checks each
 *      surviving value against the configuration via alias_get_type().
 *
 * The #676 bug is in step 2: it used is_alias(), which reads the in-memory
 * $aliastable cache — never populated on this page — so every alias that SURVIVED
 * normalization (i.e. every valid, existing, correct-type alias the user picked
 * from the dropdown) was then rejected with "Must use an existing Alias". The fix
 * resolves existence from alias_get_type() (config-based) instead, so surviving
 * aliases are accepted.
 *
 * Because normalization runs first, a non-existent or wrong-type value never
 * reaches validation as an error — it is reset to '' and saved empty. These tests
 * therefore assert the REAL page behaviour: a valid alias is accepted (the
 * regression, red->green against the old is_alias() check), while an invalid one
 * is silently normalized away. The generated per-continent pages need a MaxMind
 * GeoIP update to exist on disk, so this PHP-layer execution of the real blocks is
 * the CI-runnable evidence for the page.
 */
final class IpSettingsAdvAliasValidationTest extends TestCase
{
	/** The config-driven alias-options builder, extracted from the template. */
	private static string $optionsBlock;

	/** The select-option normalization + Advanced alias validation, extracted. */
	private static string $processBlock;

	public static function setUpBeforeClass(): void
	{
		$src = file_get_contents(
			dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng.php'
		);
		self::assertNotFalse($src, 'could not read pfblockerng.php');

		// Slice 1: build $options_aliasports_* / $options_aliasaddr_* from config.
		$ok = preg_match(
			'/\/\/ Collect all pfSense .Port. Aliases.*?(?=\$ports_list\s*=)/s',
			$src,
			$m
		);
		self::assertSame(1, $ok, 'could not locate the alias-options block in pfblockerng.php');
		self::$optionsBlock = $m[0];

		// Slice 2: the select-option normalization foreach(es) + the Advanced In/Out
		// validation — the full save-time processing of the four alias fields.
		$ok = preg_match(
			'/\/\/ Validate Select field options.*?' .
			'(?=\/\/ Validate Adv\. firewall rule \x27Protocol\x27 setting)/s',
			$src,
			$m
		);
		self::assertSame(1, $ok, 'could not locate the alias normalization/validation block in pfblockerng.php');
		self::$processBlock = $m[0];
	}

	protected function setUp(): void
	{
		$GLOBALS['config'] = [];
		// The aliases exist in the CONFIG but NOT in the is_alias() name list, so a
		// regression to is_alias() would reject every seeded alias that survives
		// normalization — the exact #676 failure.
		$GLOBALS['pfb_test_aliases'] = [];
	}

	protected function tearDown(): void
	{
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_aliases'] = [];
	}

	/**
	 * Seed firewall aliases into config — the source alias_get_type() and the
	 * dropdown-option builder both read.
	 *
	 * @param array<string, string> $typesByName  name => type ('port'/'network'/'host'/...)
	 */
	private function seedAliases(array $typesByName): void
	{
		$aliases = [];
		foreach ($typesByName as $name => $type) {
			$aliases[] = ['name' => $name, 'type' => $type];
		}
		$GLOBALS['config']['aliases']['alias'] = $aliases;
	}

	/**
	 * Run the REAL page save path for the four alias fields — options build, then
	 * normalization, then validation — against $post, and return both the
	 * normalized POST values and the collected $input_errors. $input_errors is left
	 * UNSET before the blocks run, exactly as on the page (proving the append idiom
	 * does not fatal on the happy path — an array_merge(null, ...) would).
	 *
	 * @param  array<string, string> $post
	 * @return array{errors: array<int, string>, post: array<string, mixed>}
	 */
	private function runSavePath(array $post): array
	{
		$_POST = $post;
		eval(self::$optionsBlock);
		unset($input_errors);
		eval(self::$processBlock);
		return ['errors' => $input_errors ?? [], 'post' => $_POST];
	}

	// -----------------------------------------------------------------------
	// The #676 regression: a valid, existing, correct-type alias — exactly what
	// the dropdown offers — survives normalization and is ACCEPTED (is_alias()
	// wrongly rejected it).
	// -----------------------------------------------------------------------

	public function testExistingPortAliasInPortFieldIsAccepted(): void
	{
		// Given a port alias that exists in the firewall configuration
		$this->seedAliases(['GoodPort' => 'port', 'GoodNet' => 'network']);

		// When it is submitted to a port field (as picked from the dropdown)
		$result = $this->runSavePath(['aliasports_in' => 'GoodPort']);

		// Then it survives normalization and is accepted — no error, value kept.
		// Under the old is_alias() check this existing alias was rejected (#676).
		$this->assertSame([], $result['errors']);
		$this->assertSame('GoodPort', $result['post']['aliasports_in']);
	}

	public function testExistingNetworkAliasInAddressFieldIsAccepted(): void
	{
		// Given a network alias that exists
		$this->seedAliases(['GoodPort' => 'port', 'GoodNet' => 'network']);

		// When submitted to the outbound address field
		$result = $this->runSavePath(['aliasaddr_out' => 'GoodNet']);

		// Then it is accepted and kept (the outbound address field renders as
		// "Custom Source"; the value is preserved regardless of the label).
		$this->assertSame([], $result['errors']);
		$this->assertSame('GoodNet', $result['post']['aliasaddr_out']);
	}

	// -----------------------------------------------------------------------
	// Real page behaviour: an invalid value never reaches validation as an error
	// — normalization silently resets it to '' first. (These pin the surrounding
	// normalization CodeRabbit flagged, so the accept cases above are not read in
	// isolation.)
	// -----------------------------------------------------------------------

	public function testWrongTypeAliasIsSilentlyNormalizedToEmpty(): void
	{
		// Given a NETWORK alias supplied to a PORT field (a wrong-type pick)
		$this->seedAliases(['GoodPort' => 'port', 'GoodNet' => 'network']);

		// When processed
		$result = $this->runSavePath(['aliasports_in' => 'GoodNet']);

		// Then normalization drops it to '' (not a port-dropdown option) and no
		// error is raised — the page saves it empty rather than surfacing a type
		// error. Asserting an error here would test behaviour the page cannot show.
		$this->assertSame('', $result['post']['aliasports_in']);
		$this->assertSame([], $result['errors']);
	}

	public function testNonExistentAliasIsSilentlyNormalizedToEmpty(): void
	{
		// Given: while it exists, the same name survives and is accepted (proves it
		// is normalization — not validation — that clears the non-existent case).
		$this->seedAliases(['GoodPort' => 'port', 'GoodNet' => 'network']);
		$survived = $this->runSavePath(['aliasports_in' => 'GoodPort']);
		$this->assertSame('GoodPort', $survived['post']['aliasports_in'],
			'pre-condition: an existing correct-type alias survives normalization');

		// When a name that is NOT a configured alias is supplied
		$result = $this->runSavePath(['aliasports_in' => 'NoSuchAlias']);

		// Then it is reset to '' and produces no error.
		$this->assertSame('', $result['post']['aliasports_in']);
		$this->assertSame([], $result['errors']);
	}

	public function testEmptyFieldsProduceNoErrors(): void
	{
		$this->seedAliases(['GoodPort' => 'port', 'GoodNet' => 'network']);

		$result = $this->runSavePath([
			'aliasports_in'  => '',
			'aliasaddr_in'   => '',
			'aliasports_out' => '',
			'aliasaddr_out'  => '',
		]);

		$this->assertSame([], $result['errors']);
	}
}
