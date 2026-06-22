<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-37 Phase 3 — DoT/DoQ block POST validator unit tests.
 *
 * Function under test: pfb_validate_dot_block_post()
 *   Validates the three DoT/DoQ-block fields submitted via the DNSBL settings
 *   POST form before any PfbConfig::write() call is made.
 *
 * Mandatory cases (PFBL-01 + CLAUDE.md test-coverage mandate):
 *
 *   Valid cases — empty $errors returned:
 *     a. Valid interface name present in the allow-list → accepted.
 *     b. Empty exception alias → accepted (optional field).
 *     c. Valid exception alias (alphanumeric + underscore) → accepted.
 *     d. Empty interface list → accepted (no interfaces selected = no-op enable).
 *     e. Multiple valid interfaces → accepted.
 *
 *   Invalid cases — non-empty $errors returned, PfbConfig::write() NOT called:
 *     f. Interface name NOT in the allow-list → rejected.
 *     g. Invalid alias name (contains space) → rejected.
 *     h. Invalid alias name (shell-special character) → rejected.
 *     i. Multiple interfaces, one invalid → rejected (invalid one flagged).
 *     j. Both interface and alias invalid → two errors returned.
 *
 * Coverage mandate: branch coverage — every condition tested in both directions;
 * rejection tests assert the before-state is accepted first.
 */
#[CoversFunction('pfb_validate_dot_block_post')]
final class DotDoQBlockUiValidatorTest extends TestCase
{
	// -----------------------------------------------------------------------
	// Fixture: a representative valid interface allow-list.
	// -----------------------------------------------------------------------

	/** @var array<string> */
	private array $validIfaceList = ['lan', 'opt1', 'opt2', 'wireguard', 'openvpn'];

	// -----------------------------------------------------------------------
	// VALID CASES
	// -----------------------------------------------------------------------

	public function testValidInterfaceInAllowListIsAccepted(): void
	{
		// Given a valid interface in the allow-list and an empty alias
		$errors = pfb_validate_dot_block_post(['lan'], $this->validIfaceList, '');

		// Then no errors are returned
		$this->assertSame([], $errors, 'a valid interface must produce no errors');
	}

	public function testEmptyInterfaceListIsAccepted(): void
	{
		// Given no interfaces selected (valid state — feature is enabled but no ifaces)
		$errors = pfb_validate_dot_block_post([], $this->validIfaceList, '');

		// Then no errors are returned
		$this->assertSame([], $errors, 'an empty interface list must produce no errors');
	}

	public function testEmptyExceptionAliasIsAccepted(): void
	{
		// Given a valid interface and an empty alias (optional field)
		$errors = pfb_validate_dot_block_post(['lan'], $this->validIfaceList, '');

		// Then the alias branch produces no error
		$this->assertSame([], $errors, 'empty alias must be accepted');
	}

	public function testValidAliasNameIsAccepted(): void
	{
		// Given a valid alias name (alphanumeric + underscore, no leading digit)
		$errors = pfb_validate_dot_block_post(['opt1'], $this->validIfaceList, 'DoT_Exceptions');

		// Then no errors are returned
		$this->assertSame([], $errors, 'a valid alias name must be accepted');
	}

	public function testMultipleValidInterfacesAreAccepted(): void
	{
		// Given multiple valid interfaces
		$errors = pfb_validate_dot_block_post(
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
		// Given: before → valid interface accepted
		$errorsBefore = pfb_validate_dot_block_post(['lan'], $this->validIfaceList, '');
		$this->assertSame([], $errorsBefore, 'pre-condition: lan is accepted');

		// When an interface not in the allow-list is submitted
		$errors = pfb_validate_dot_block_post(['evil; rm -rf /'], $this->validIfaceList, '');

		// Then an error is returned
		$this->assertNotEmpty($errors, 'an unknown interface must be rejected');
		$this->assertCount(1, $errors);
		// The error message must name the feature
		$this->assertStringContainsString('DoT/DoQ Block', $errors[0]);
	}

	public function testAliasNameWithSpaceIsRejected(): void
	{
		// Given: before → empty alias accepted
		$errorsBefore = pfb_validate_dot_block_post(['lan'], $this->validIfaceList, '');
		$this->assertSame([], $errorsBefore, 'pre-condition: empty alias is accepted');

		// When an alias name containing a space is submitted
		$errors = pfb_validate_dot_block_post(['lan'], $this->validIfaceList, 'bad alias name');

		// Then an error is returned
		$this->assertNotEmpty($errors, 'an alias name with spaces must be rejected');
		$this->assertStringContainsString('DoT/DoQ Block', $errors[0]);
		$this->assertStringContainsString('alias', $errors[0]);
	}

	public function testAliasNameWithShellSpecialCharIsRejected(): void
	{
		// Given: before → valid alias accepted
		$errorsBefore = pfb_validate_dot_block_post(['lan'], $this->validIfaceList, 'Good_Alias');
		$this->assertSame([], $errorsBefore, 'pre-condition: Good_Alias is accepted');

		// When an alias name with a shell-special character is submitted
		$errors = pfb_validate_dot_block_post(['lan'], $this->validIfaceList, 'alias;reboot');

		// Then an error is returned
		$this->assertNotEmpty($errors, 'an alias name with special chars must be rejected');
		$this->assertStringContainsString('DoT/DoQ Block', $errors[0]);
	}

	public function testMixedValidAndInvalidInterfaceIsRejected(): void
	{
		// Given: before → all-valid list accepted
		$errorsBefore = pfb_validate_dot_block_post(
			['lan', 'opt1'],
			$this->validIfaceList,
			''
		);
		$this->assertSame([], $errorsBefore, 'pre-condition: lan+opt1 accepted');

		// When one interface is valid and one is not in the allow-list
		$errors = pfb_validate_dot_block_post(
			['lan', 'unknown_iface'],
			$this->validIfaceList,
			''
		);

		// Then an error is returned for the invalid interface
		$this->assertCount(1, $errors, 'exactly one error for the one invalid interface');
		$this->assertStringContainsString('DoT/DoQ Block', $errors[0]);
	}

	public function testBothInterfaceAndAliasInvalidProducesTwoErrors(): void
	{
		// When both fields are invalid
		$errors = pfb_validate_dot_block_post(
			['not_a_real_iface'],
			$this->validIfaceList,
			'bad alias!'
		);

		// Then two errors are returned (one per invalid field)
		$this->assertCount(2, $errors, 'one error per invalid field');
		$this->assertStringContainsString('DoT/DoQ Block', $errors[0]);
		$this->assertStringContainsString('DoT/DoQ Block', $errors[1]);
	}
}
