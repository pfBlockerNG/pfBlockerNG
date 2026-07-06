<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Tests for pfb_adv_alias_field_errors() (issue #636).
 *
 * The category-edit page validates its four Advanced Inbound/Outbound alias
 * fields (aliasports_in / aliasports_out / aliasaddr_in / aliasaddr_out) by
 * looking each non-empty value up as a firewall alias and checking its type.
 *
 * Existence + type MUST come from alias_get_type() (config-based), NOT
 * is_alias(): is_alias() reads the in-memory $aliastable cache, which is empty
 * on the category-edit page (it is only populated during filter generation), so
 * is_alias() reports every existing alias as missing — rejecting a valid alias
 * with "Must use an existing Alias" (#636). These tests seed firewall aliases
 * into the configuration — the source the fixed check reads — and are the
 * red->green for the fix: against an is_alias()-backed implementation the
 * "existing alias is accepted" cases fail (the seeded aliases are never written
 * into $aliastable / $GLOBALS['pfb_test_aliases']).
 */
#[CoversFunction('pfb_adv_alias_field_errors')]
final class AdvAliasFieldErrorsTest extends TestCase
{
	protected function setUp(): void
	{
		$GLOBALS['config'] = [];
		// Belt-and-braces: ensure the is_alias() double's name list is empty, so a
		// regression to is_alias() would visibly reject the seeded aliases below.
		$GLOBALS['pfb_test_aliases'] = [];
	}

	protected function tearDown(): void
	{
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_aliases'] = [];
	}

	// -----------------------------------------------------------------------
	// Helpers
	// -----------------------------------------------------------------------

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

	// -----------------------------------------------------------------------
	// Existence oracle — an EXISTING alias of the right type is accepted (the
	// core #636 regression: is_alias() rejected all of these).
	// -----------------------------------------------------------------------

	public function testExistingPortAliasInPortFieldIsAccepted(): void
	{
		// Given a port alias that exists in the firewall configuration
		$this->seedAliases(['MyPorts' => 'port']);

		// When it is supplied to a port field
		$errors = pfb_adv_alias_field_errors(['aliasports_in' => 'MyPorts']);

		// Then the save is allowed (no errors) — under the old is_alias() check this
		// existing alias was wrongly rejected as non-existent (#636).
		$this->assertSame([], $errors);
	}

	public function testExistingUrlPortsAliasInPortFieldIsAccepted(): void
	{
		// A URL-Ports alias is port-bearing, so a port field accepts it — the broadened
		// autocomplete offers it, so the validator must not reject it. Pre-broadening the
		// port branch only accepted the literal 'port' type and rejected this.
		$this->seedAliases(['MyUrlPorts' => 'url_ports']);

		$errors = pfb_adv_alias_field_errors(['aliasports_out' => 'MyUrlPorts']);

		$this->assertSame([], $errors);
	}

	public function testExistingUrltablePortsAliasInPortFieldIsAccepted(): void
	{
		// A URL-Table (Ports) alias is likewise a valid port restriction.
		$this->seedAliases(['MyUrlTablePorts' => 'urltable_ports']);

		$errors = pfb_adv_alias_field_errors(['aliasports_in' => 'MyUrlTablePorts']);

		$this->assertSame([], $errors);
	}

	public function testExistingNetworkAliasInAddressFieldIsAccepted(): void
	{
		// Given a network alias that exists
		$this->seedAliases(['MyNet' => 'network']);

		// When supplied to an address field
		$errors = pfb_adv_alias_field_errors(['aliasaddr_out' => 'MyNet']);

		// Then it is accepted
		$this->assertSame([], $errors);
	}

	public function testExistingHostAliasInAddressFieldIsAccepted(): void
	{
		// Given a host alias (also valid for address fields)
		$this->seedAliases(['MyHosts' => 'host']);

		$errors = pfb_adv_alias_field_errors(['aliasaddr_in' => 'MyHosts']);

		$this->assertSame([], $errors);
	}

	public function testExistingUrlAliasInAddressFieldIsAccepted(): void
	{
		// A URL alias is address-bearing, so an address field accepts it — the
		// autocomplete offers it, so the validator must not reject it (dropdown/
		// validator parity). Pre-broadening this was rejected as wrong-type.
		$this->seedAliases(['MyUrl' => 'url']);

		$errors = pfb_adv_alias_field_errors(['aliasaddr_out' => 'MyUrl']);

		$this->assertSame([], $errors);
	}

	public function testExistingUrltableAliasInAddressFieldIsAccepted(): void
	{
		// A URL-Table alias is likewise a valid rule address source.
		$this->seedAliases(['MyUrlTable' => 'urltable']);

		$errors = pfb_adv_alias_field_errors(['aliasaddr_in' => 'MyUrlTable']);

		$this->assertSame([], $errors);
	}

	// -----------------------------------------------------------------------
	// Non-existent alias — rejected with "Must use an existing Alias".
	// -----------------------------------------------------------------------

	public function testNonExistentAliasIsRejectedAsMissing(): void
	{
		// Given: before -> the SAME name is accepted while it exists (proves it is the
		// existence check, not the format/type check, doing the rejecting).
		$this->seedAliases(['KnownPorts' => 'port']);
		$this->assertSame([], pfb_adv_alias_field_errors(['aliasports_in' => 'KnownPorts']),
			'pre-condition: the alias is accepted while it exists');

		// When a name that is NOT a configured alias is supplied (config still seeded)
		$errors = pfb_adv_alias_field_errors(['aliasports_in' => 'NoSuchAlias']);

		// Then it is rejected as non-existent
		$this->assertCount(1, $errors);
		$this->assertStringContainsString('Must use an existing Alias', $errors[0]);
		$this->assertStringContainsString('Port Inbound', $errors[0]);
	}

	// -----------------------------------------------------------------------
	// Wrong-type alias — exists, but the field rejects its type.
	// -----------------------------------------------------------------------

	public function testNetworkAliasInPortFieldIsRejectedAsWrongType(): void
	{
		// Given a network alias that EXISTS (so the existence check passes and the
		// type check is the one that fires — the #636 page never reached this branch).
		$this->seedAliases(['NetInPort' => 'network']);

		// When supplied to a port field
		$errors = pfb_adv_alias_field_errors(['aliasports_in' => 'NetInPort']);

		// Then it is rejected as the wrong type (NOT "Must use an existing Alias")
		$this->assertCount(1, $errors);
		$this->assertStringContainsString('Must use a Port-type alias', $errors[0]);
		$this->assertStringNotContainsString('existing Alias', $errors[0]);
	}

	public function testPortAliasInAddressFieldIsRejectedAsWrongType(): void
	{
		// Given a port alias that EXISTS, supplied to an address field
		$this->seedAliases(['PortInAddr' => 'port']);

		$errors = pfb_adv_alias_field_errors(['aliasaddr_out' => 'PortInAddr']);

		// Then rejected as the wrong type
		$this->assertCount(1, $errors);
		$this->assertStringContainsString('Must use a Host, Network, URL or URL-Table-type alias', $errors[0]);
	}

	// -----------------------------------------------------------------------
	// Empty fields are skipped (the feature is optional).
	// -----------------------------------------------------------------------

	public function testEmptyFieldsProduceNoError(): void
	{
		// Given no aliases configured and all four fields empty/absent
		$errors = pfb_adv_alias_field_errors([
			'aliasports_in'  => '',
			'aliasports_out' => '',
			'aliasaddr_in'   => '',
			// aliasaddr_out absent entirely
		]);

		// Then nothing is validated — empty means "no Advanced alias", not an error
		$this->assertSame([], $errors);
	}

	// -----------------------------------------------------------------------
	// Every field is validated independently — each direction reports its own
	// error (branch coverage across all four fields).
	// -----------------------------------------------------------------------

	public function testAllFourFieldsAreValidatedIndependently(): void
	{
		// Given one valid alias of each kind plus one wrong-type value per field
		$this->seedAliases([
			'GoodPorts' => 'port',
			'GoodNet'   => 'network',
		]);

		// When: ports_in valid, ports_out wrong-type, addr_in valid, addr_out missing
		$errors = pfb_adv_alias_field_errors([
			'aliasports_in'  => 'GoodPorts',   // ok
			'aliasports_out' => 'GoodNet',     // network in a port field -> wrong type
			'aliasaddr_in'   => 'GoodNet',     // ok
			'aliasaddr_out'  => 'Ghost',       // does not exist -> missing
		]);

		// Then exactly the two invalid fields report, each with its own direction label
		$this->assertCount(2, $errors);
		$this->assertStringContainsString('Port Outbound', $errors[0]);
		$this->assertStringContainsString('Must use a Port-type alias', $errors[0]);
		$this->assertStringContainsString('Source Outbound', $errors[1]);
		$this->assertStringContainsString('Must use an existing Alias', $errors[1]);
	}
}
