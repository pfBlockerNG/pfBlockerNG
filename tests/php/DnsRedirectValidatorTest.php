<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-36 Phase 3 — DNS-redirect POST validator unit tests.
 *
 * Function under test: pfb_validate_dns_redirect_post()
 *   Validates the three DNS-redirect fields submitted via the DNSBL settings
 *   POST form before any PfbConfig::write() call is made.
 *
 * Mandatory cases (PFBL-01 + CLAUDE.md test-coverage mandate):
 *
 *   Valid cases — empty $errors returned:
 *     a. Valid interface name present in the allow-list → accepted.
 *     b. Empty exception alias → accepted (optional field).
 *     c. Valid exception alias (alphanumeric + underscore) → accepted.
 *     d. Empty interface list → accepted (no interfaces selected = no-op enable).
 *
 *   Invalid cases — non-empty $errors returned, PfbConfig::write() NOT called:
 *     e. Interface name NOT in the allow-list → rejected.
 *     f. Invalid alias name (contains space) → rejected.
 *     g. Invalid alias name (shell-special character) → rejected.
 *     h. Multiple interfaces, one invalid → rejected (invalid one flagged).
 *
 * Coverage mandate: branch coverage — every condition tested in both directions.
 */
#[CoversFunction('pfb_validate_dns_redirect_post')]
final class DnsRedirectValidatorTest extends TestCase
{
	// -----------------------------------------------------------------------
	// Fixture: a representative valid interface allow-list.
	// -----------------------------------------------------------------------

	/** @var array<string> */
	private array $validIfaceList = ['lan', 'opt1', 'opt2', 'wireguard', 'openvpn'];

	// Reset the seeded firewall aliases before each test (test isolation): the validator
	// requires a non-empty exception alias to be a REAL firewall alias.
	protected function setUp(): void
	{
		$this->seedAliases([]);
	}

	protected function tearDown(): void
	{
		$this->seedAliases([]);
	}

	// Seed firewall aliases into config — the source pfb_exclude_alias_exists() reads (#664).
	// (The check is config-based, NOT is_alias(): is_alias() consults the $aliastable cache,
	// which is empty in a cron/service-restart sync, so a valid alias would read as missing.)
	private function seedAliases(array $names, string $type = 'host'): void
	{
		$GLOBALS['config']['aliases']['alias'] = array_map(
			static fn (string $name): array => ['name' => $name, 'type' => $type],
			$names
		);
	}

	// -----------------------------------------------------------------------
	// Helper: assert no PfbConfig::write() calls happened via the write tracker.
	// pfblockerng.inc loads PfbConfig; write calls land in pfb_test_write_config_calls.
	// We instead assert that the returned errors array is non-empty — that is the
	// binding contract: the caller only writes when $errors is empty.
	// -----------------------------------------------------------------------

	// -----------------------------------------------------------------------
	// VALID CASES
	// -----------------------------------------------------------------------

	public function testValidInterfaceInAllowListIsAccepted(): void
	{
		// Given a valid interface in the allow-list and an empty alias
		$errors = pfb_validate_dns_redirect_post(['lan'], $this->validIfaceList, '');

		// Then no errors are returned
		$this->assertSame([], $errors, 'a valid interface must produce no errors');
	}

	public function testEmptyInterfaceListIsAccepted(): void
	{
		// Given no interfaces selected (valid state — feature is enabled but no ifaces)
		$errors = pfb_validate_dns_redirect_post([], $this->validIfaceList, '');

		// Then no errors are returned
		$this->assertSame([], $errors, 'an empty interface list must produce no errors');
	}

	public function testEmptyExceptionAliasIsAccepted(): void
	{
		// Given a valid interface and an empty alias (optional field)
		$errorsBefore = pfb_validate_dns_redirect_post(['lan'], $this->validIfaceList, '');

		// Then the alias branch produces no error
		$this->assertSame([], $errorsBefore, 'empty alias must be accepted');
	}

	public function testValidExistingAliasNameIsAccepted(): void
	{
		// Given a valid alias name that EXISTS as a firewall alias
		$this->seedAliases(['DNS_Whitelist']);
		$errors = pfb_validate_dns_redirect_post(['opt1'], $this->validIfaceList, 'DNS_Whitelist');

		// Then no errors are returned
		$this->assertSame([], $errors, 'a valid, existing alias name must be accepted');
	}

	public function testValidFormatButNonexistentAliasIsRejected(): void
	{
		// Regression (the real-world bite): a name that is syntactically valid but is NOT a
		// real alias used to pass format-only validation, then the rule builder emitted an
		// unresolvable "from !" that fails the entire pf ruleset load. It must now be rejected.

		// Given: before → the same name accepted WHEN it exists (proves it's the existence
		// check, not the format check, doing the rejecting)
		$this->seedAliases(['BraitServers_IPv4']);
		$errorsExisting = pfb_validate_dns_redirect_post(['lan'], $this->validIfaceList, 'BraitServers_IPv4');
		$this->assertSame([], $errorsExisting, 'pre-condition: the alias is accepted while it exists');

		// When the alias does NOT exist (e.g. a typo: _v4 instead of _IPv4)
		$this->seedAliases(['BraitServers_IPv4']);
		$errors = pfb_validate_dns_redirect_post(['lan'], $this->validIfaceList, 'BraitServers_v4');

		// Then it is rejected with a "does not exist" error
		$this->assertNotEmpty($errors, 'a non-existent exception alias must be rejected');
		$this->assertStringContainsString('DNS Redirect', $errors[0]);
		$this->assertStringContainsString('does not exist', $errors[0]);
	}

	public function testPfbManagedAliasIsRejected(): void
	{
		// A pfBlockerNG-managed alias (pfB_*) must NOT be usable as an exception alias, even
		// though it exists in config. Before this guard a pfB_ alias would pass (it exists);
		// it must now be rejected with a clear "managed alias" error.

		// Given a pfB_-managed alias that EXISTS in config
		$this->seedAliases(['pfB_DNSBLIP']);

		// When it is used as the exception alias
		$errors = pfb_validate_dns_redirect_post(['lan'], $this->validIfaceList, 'pfB_DNSBLIP');

		// Then it is rejected as a managed alias (not silently accepted because it exists)
		$this->assertNotEmpty($errors, 'a pfB_-managed alias must be rejected');
		$this->assertStringContainsString('DNS Redirect', $errors[0]);
		$this->assertStringContainsString('pfBlockerNG-managed', $errors[0]);
	}

	public function testPortAliasIsRejected(): void
	{
		// Only address-bearing aliases can be a firewall-rule source. A PORT alias exists but
		// cannot be a source, so it must be rejected (not accepted, and not reported as missing).

		// Given: before → the SAME name is accepted as an ADDRESS (host) alias
		$this->seedAliases(['SvcAlias'], 'host');
		$errorsHost = pfb_validate_dns_redirect_post(['lan'], $this->validIfaceList, 'SvcAlias');
		$this->assertSame([], $errorsHost, 'pre-condition: an address (host) alias is accepted');

		// When the same name is a PORT alias instead
		$this->seedAliases(['SvcAlias'], 'port');
		$errors = pfb_validate_dns_redirect_post(['lan'], $this->validIfaceList, 'SvcAlias');

		// Then it is rejected as not usable in firewall rules (not "does not exist")
		$this->assertNotEmpty($errors, 'a port alias must be rejected');
		$this->assertStringContainsString('DNS Redirect', $errors[0]);
		$this->assertStringContainsString('port aliases are not allowed', $errors[0]);
	}

	public function testMultipleValidInterfacesAreAccepted(): void
	{
		// Given multiple valid interfaces
		$errors = pfb_validate_dns_redirect_post(
			['lan', 'opt1', 'wireguard'],
			$this->validIfaceList,
			''
		);

		// Then no errors are returned
		$this->assertSame([], $errors, 'multiple valid interfaces must produce no errors');
	}

	// -----------------------------------------------------------------------
	// INVALID CASES — rejected without a write
	// -----------------------------------------------------------------------

	public function testInterfaceNotInAllowListIsRejected(): void
	{
		// Given: before → valid interface accepted; after → inject invalid name
		$errorsBefore = pfb_validate_dns_redirect_post(['lan'], $this->validIfaceList, '');
		$this->assertSame([], $errorsBefore, 'pre-condition: lan is accepted');

		// When an interface not in the allow-list is submitted
		$errors = pfb_validate_dns_redirect_post(['evil; rm -rf /'], $this->validIfaceList, '');

		// Then an error is returned
		$this->assertNotEmpty($errors, 'an unknown interface must be rejected');
		$this->assertCount(1, $errors);
		// The error message must name the field
		$this->assertStringContainsString('DNS Redirect', $errors[0]);
	}

	public function testAliasNameWithSpaceIsRejected(): void
	{
		// Given: before → empty alias accepted
		$errorsBefore = pfb_validate_dns_redirect_post(['lan'], $this->validIfaceList, '');
		$this->assertSame([], $errorsBefore, 'pre-condition: empty alias is accepted');

		// When an alias name containing a space is submitted
		$errors = pfb_validate_dns_redirect_post(['lan'], $this->validIfaceList, 'bad alias name');

		// Then an error is returned
		$this->assertNotEmpty($errors, 'an alias name with spaces must be rejected');
		$this->assertStringContainsString('DNS Redirect', $errors[0]);
		$this->assertStringContainsString('alias', $errors[0]);
	}

	public function testAliasNameWithShellSpecialCharIsRejected(): void
	{
		// Given: before → valid, existing alias accepted
		$this->seedAliases(['Good_Alias']);
		$errorsBefore = pfb_validate_dns_redirect_post(['lan'], $this->validIfaceList, 'Good_Alias');
		$this->assertSame([], $errorsBefore, 'pre-condition: Good_Alias is accepted');

		// When an alias name with a shell-special character is submitted
		$errors = pfb_validate_dns_redirect_post(['lan'], $this->validIfaceList, 'alias;reboot');

		// Then an error is returned
		$this->assertNotEmpty($errors, 'an alias name with special chars must be rejected');
		$this->assertStringContainsString('DNS Redirect', $errors[0]);
	}

	public function testMixedValidAndInvalidInterfaceIsRejected(): void
	{
		// Given: before → all-valid list accepted
		$errorsBefore = pfb_validate_dns_redirect_post(
			['lan', 'opt1'],
			$this->validIfaceList,
			''
		);
		$this->assertSame([], $errorsBefore, 'pre-condition: lan+opt1 accepted');

		// When one interface is valid and one is not in the allow-list
		$errors = pfb_validate_dns_redirect_post(
			['lan', 'unknown_iface'],
			$this->validIfaceList,
			''
		);

		// Then an error is returned for the invalid interface
		$this->assertCount(1, $errors, 'exactly one error for the one invalid interface');
		$this->assertStringContainsString('DNS Redirect', $errors[0]);
	}

	public function testBothInterfaceAndAliasInvalidProducesTwoErrors(): void
	{
		// When both fields are invalid
		$errors = pfb_validate_dns_redirect_post(
			['not_a_real_iface'],
			$this->validIfaceList,
			'bad alias!'
		);

		// Then two errors are returned (one per invalid field)
		$this->assertCount(2, $errors, 'one error per invalid field');
	}
}
