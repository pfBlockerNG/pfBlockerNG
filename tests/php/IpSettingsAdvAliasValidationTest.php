<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Tests for the Advanced Inbound/Outbound alias validation on the IP settings
 * page (issue #676, sibling of #636).
 *
 * pfblockerng.php is a TEMPLATE: it generates the per-continent settings pages
 * (pfblockerng_<Continent>.php) via file_put_contents. The Advanced In/Out alias
 * validation lives inside that generated template. Historically it gated each of
 * the four fields (aliasports_in / aliasaddr_in / aliasports_out / aliasaddr_out)
 * with is_alias(), which reads the in-memory $aliastable cache — never populated
 * on this page — so every EXISTING alias was rejected with "Must use an existing
 * Alias" (#676, identical root cause to #636 on the category-edit page).
 *
 * The fix delegates the block to pfb_adv_alias_field_errors(), which resolves
 * existence AND type from alias_get_type() (config-based). This suite EXECUTES
 * the real validation block, extracted verbatim from the shipped template source,
 * against a seeded configuration — so it exercises the generated page's actual
 * code, not a copy. The generated per-continent pages cannot be driven in CI
 * (they only exist after a MaxMind GeoIP update needing a key + network), so this
 * PHP-layer execution is the CI-runnable evidence for the page.
 *
 * Red -> green: aliases are seeded into the configuration ONLY (never into the
 * is_alias() name list $GLOBALS['pfb_test_aliases']). Against the old
 * is_alias()-backed block, an existing alias reads as missing (the bug); the type
 * check did not exist there at all. After the fix the block accepts existing
 * aliases, corrects the aliasaddr_out label to "Source" (the rendered field is
 * "Custom Source"), and enforces per-field type.
 */
final class IpSettingsAdvAliasValidationTest extends TestCase
{
	/** The Advanced In/Out validation block extracted from the shipped template. */
	private static string $validationBlock;

	public static function setUpBeforeClass(): void
	{
		$src = file_get_contents(
			dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng.php'
		);
		self::assertNotFalse($src, 'could not read pfblockerng.php');

		// Extract the block between the two anchor comments of the generated
		// template — from the Advanced In/Out validation up to the next validation
		// section (Protocol). This is the exact code the generated pages run.
		$ok = preg_match(
			'/\/\/ Validate Adv\. In\/Outbound firewall rules settings.*?' .
			'(?=\/\/ Validate Adv\. firewall rule \x27Protocol\x27 setting)/s',
			$src,
			$m
		);
		self::assertSame(1, $ok, 'could not locate the Advanced In/Out validation block in pfblockerng.php');
		self::$validationBlock = $m[0];
	}

	protected function setUp(): void
	{
		$GLOBALS['config'] = [];
		// The alias exists in the CONFIG but NOT in the is_alias() name list, so a
		// regression to is_alias() would visibly reject every seeded alias below.
		$GLOBALS['pfb_test_aliases'] = [];
	}

	protected function tearDown(): void
	{
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_aliases'] = [];
	}

	/**
	 * Seed firewall aliases into config — the source alias_get_type() reads.
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
	 * Run the extracted validation block against a POST and return the collected
	 * $input_errors. $input_errors is left UNSET before the block runs, exactly as
	 * on the real page — proving the append idiom does not fatal on the happy path
	 * (an array_merge(null, ...) would).
	 *
	 * @param  array<string, string> $post
	 * @return array<int, string>
	 */
	private function runValidation(array $post): array
	{
		$_POST = $post;
		unset($input_errors);
		eval(self::$validationBlock);
		return $input_errors ?? [];
	}

	// -----------------------------------------------------------------------
	// Existence oracle — the #676 regression: an EXISTING alias is accepted.
	// -----------------------------------------------------------------------

	public function testExistingNetworkAliasInAddressFieldIsAccepted(): void
	{
		// Given a network alias that exists in the firewall configuration
		$this->seedAliases(['MyNet' => 'network']);

		// When it is supplied to the outbound address field
		$errors = $this->runValidation(['aliasaddr_out' => 'MyNet']);

		// Then the save is allowed — under the old is_alias() block this existing
		// alias was wrongly rejected as non-existent (#676).
		$this->assertSame([], $errors);
	}

	public function testExistingPortAliasInPortFieldIsAccepted(): void
	{
		// Given a port alias that exists
		$this->seedAliases(['MyPorts' => 'port']);

		// When supplied to a port field
		$errors = $this->runValidation(['aliasports_in' => 'MyPorts']);

		// Then it is accepted
		$this->assertSame([], $errors);
	}

	// -----------------------------------------------------------------------
	// Non-existent alias — rejected, and with the corrected outbound label.
	// -----------------------------------------------------------------------

	public function testNonExistentAliasIsRejectedAsMissing(): void
	{
		// Given: while it exists, the same name is accepted (proves it is the
		// existence check doing the rejecting below, not a format error).
		$this->seedAliases(['KnownNet' => 'network']);
		$this->assertSame([], $this->runValidation(['aliasaddr_out' => 'KnownNet']),
			'pre-condition: the alias is accepted while it exists');

		// When a name that is NOT a configured alias is supplied
		$errors = $this->runValidation(['aliasaddr_out' => 'NoSuchAlias']);

		// Then it is rejected as non-existent...
		$this->assertCount(1, $errors);
		$this->assertStringContainsString('Must use an existing Alias', $errors[0]);
		// ...labelled "Source Outbound" — the outbound address field renders as
		// "Custom Source" on this page, so the old "Destination Out" label was wrong.
		$this->assertStringContainsString('Source Outbound', $errors[0]);
	}

	// -----------------------------------------------------------------------
	// Type enforcement — new on this page (issue #676 decision): a wrong-type
	// alias that previously saved is now rejected.
	// -----------------------------------------------------------------------

	public function testWrongTypeAliasInAddressFieldIsRejected(): void
	{
		// Given a PORT alias (exists) supplied to an ADDRESS field
		$this->seedAliases(['MyPorts' => 'port']);

		// When validated
		$errors = $this->runValidation(['aliasaddr_out' => 'MyPorts']);

		// Then it is rejected on type — the old block had no type check and saved it.
		$this->assertCount(1, $errors);
		$this->assertStringContainsString('Must use a Network or Host-type alias', $errors[0]);
	}

	public function testWrongTypeAliasInPortFieldIsRejected(): void
	{
		// Given a NETWORK alias (exists) supplied to a PORT field
		$this->seedAliases(['MyNet' => 'network']);

		$errors = $this->runValidation(['aliasports_out' => 'MyNet']);

		$this->assertCount(1, $errors);
		$this->assertStringContainsString('Must use a Port-type alias', $errors[0]);
	}

	// -----------------------------------------------------------------------
	// Empty fields are skipped (no spurious errors).
	// -----------------------------------------------------------------------

	public function testEmptyFieldsProduceNoErrors(): void
	{
		$this->seedAliases(['MyNet' => 'network']);

		$errors = $this->runValidation([
			'aliasports_in'  => '',
			'aliasaddr_in'   => '',
			'aliasports_out' => '',
			'aliasaddr_out'  => '',
		]);

		$this->assertSame([], $errors);
	}
}
