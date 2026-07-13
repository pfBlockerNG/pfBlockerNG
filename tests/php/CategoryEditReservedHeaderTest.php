<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Category-edit save-time rejection of a reserved source Header (issue #1234).
 *
 * A Deny-type list whose Header is literally 'dedup' collides with the
 * reserved matchdedup_v4.txt recompute artifact (pfblockerng.sh
 * pfb_recompute_finish() writes both the per-alias file and the dedup swap to
 * the same path). This must be rejected at save.
 *
 * Like CategoryEditPostGuardTest, the page carries top-level execution and
 * cannot be require()d off-appliance, so the rowhelper state-loop region is
 * eval-extracted verbatim from the REAL source, anchored on text stable
 * across the pre-fix and post-fix code -- the same test proves red on the old
 * code and green on the new.
 */
final class CategoryEditReservedHeaderTest extends TestCase
{
	private array $savedPost = [];

	public static function setUpBeforeClass(): void
	{
		$src = file_get_contents(
			dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_category_edit.php'
		);
		if ($src === false) {
			throw new RuntimeException('test bootstrap: failed to read pfblockerng_category_edit.php');
		}

		if (!function_exists('pfb_category_oracle_reserved_header_state_loop')) {
			if (!preg_match(
				'/(\tforeach \(\$_POST as \$key => \$value\) \{\n.*?\n\t\})\n\n\n\t\/\/ Validate Adv\. firewall rule settings/s',
				$src,
				$m
			)) {
				throw new RuntimeException('test bootstrap: state validation loop not found');
			}
			eval(
				'function pfb_category_oracle_reserved_header_state_loop(string $type): array {'
				. ' global $pfb; $input_errors = array(); $line = 1;'
				. $m[1]
				. ' return $input_errors; }'
			);
		}
	}

	protected function setUp(): void
	{
		$this->savedPost = $_POST;
		$_POST = [];
	}

	protected function tearDown(): void
	{
		$_POST = $this->savedPost;
	}

	/**
	 * @param array<int, string> $errors
	 */
	private static function hasReservedError(array $errors): bool
	{
		foreach ($errors as $error) {
			if (str_contains($error, 'reserved')) {
				return TRUE;
			}
		}
		return FALSE;
	}

	private function makeRow(string $action, string $header, string $state = 'Enabled'): void
	{
		$_POST = [
			'action'   => $action,
			'state-0'  => $state,
			'header-0' => $header,
			'url-0'    => 'http://192.0.2.1/feed',	// RFC 5737 literal -- avoids DNS resolution
			'format-0' => 'auto',
		];
	}

	// --- Action axis (enumerated from category_edit.php's $options_action) ----

	public static function denyActionsProvider(): array
	{
		return [
			'Deny_Inbound' => ['Deny_Inbound'],
			'Deny_Outbound' => ['Deny_Outbound'],
			'Deny_Both' => ['Deny_Both'],
			'Alias_Deny' => ['Alias_Deny'],
		];
	}

	#[DataProvider('denyActionsProvider')]
	public function testDenyActionWithDedupHeaderIsRejected(string $action): void
	{
		$this->makeRow($action, 'dedup');
		$errors = pfb_category_oracle_reserved_header_state_loop('IPv4');
		$this->assertTrue(
			self::hasReservedError($errors),
			"action={$action} header=dedup must add a reserved-header input error; got: " . var_export($errors, TRUE)
		);
	}

	public static function nonDenyActionsProvider(): array
	{
		return [
			'Disabled'        => ['Disabled'],
			'Permit_Inbound'  => ['Permit_Inbound'],
			'Permit_Outbound' => ['Permit_Outbound'],
			'Permit_Both'     => ['Permit_Both'],
			'Match_Inbound'   => ['Match_Inbound'],
			'Match_Outbound'  => ['Match_Outbound'],
			'Match_Both'      => ['Match_Both'],
			'Alias_Permit'    => ['Alias_Permit'],
			'Alias_Match'     => ['Alias_Match'],
			'Alias_Native'    => ['Alias_Native'],
		];
	}

	#[DataProvider('nonDenyActionsProvider')]
	public function testNonDenyActionWithDedupHeaderIsAllowed(string $action): void
	{
		$this->makeRow($action, 'dedup');
		$errors = pfb_category_oracle_reserved_header_state_loop('IPv4');
		$this->assertFalse(
			self::hasReservedError($errors),
			"action={$action} header=dedup must NOT add a reserved-header input error; got: " . var_export($errors, TRUE)
		);
	}

	public function testDnsblActionWithDedupHeaderIsAllowed(): void
	{
		$this->makeRow('unbound', 'dedup');
		$errors = pfb_category_oracle_reserved_header_state_loop('DNSBL');
		$this->assertFalse(self::hasReservedError($errors));
	}

	public function testDisabledRowSkipsReservedCheckEvenWithDenyAction(): void
	{
		$this->makeRow('Deny_Both', 'dedup', 'Disabled');
		$errors = pfb_category_oracle_reserved_header_state_loop('IPv4');
		$this->assertSame([], $errors, 'a Disabled row must add no errors at all -- it is skipped entirely');
	}

	// --- Hostile-input rows (case sensitivity + near misses) -------------------

	public static function caseAndNearMissProvider(): array
	{
		return [
			'Dedup'      => ['Dedup'],
			'DEDUP'      => ['DEDUP'],
			'DeDuP'      => ['DeDuP'],
			'dedupfoo'   => ['dedupfoo'],
			'foodedup'   => ['foodedup'],
			'xdedup'     => ['xdedup'],
			'matchdedup' => ['matchdedup'],
		];
	}

	#[DataProvider('caseAndNearMissProvider')]
	public function testCaseVariantOrNearMissHeaderUnderDenyIsAllowed(string $header): void
	{
		$this->makeRow('Deny_Both', $header);
		$errors = pfb_category_oracle_reserved_header_state_loop('IPv4');
		$this->assertFalse(
			self::hasReservedError($errors),
			"header={$header} under Deny_Both must NOT be treated as reserved; got: " . var_export($errors, TRUE)
		);
	}

	// --- Existing rules must still fire, and must not be duplicated ------------

	public function testEmptyHeaderStillTriggersExistingEmptyRuleNotReservedRule(): void
	{
		$this->makeRow('Deny_Both', '');
		$errors = pfb_category_oracle_reserved_header_state_loop('IPv4');
		$this->assertNotEmpty(
			array_filter($errors, static fn (string $e): bool => str_contains($e, 'must be defined')),
			'the existing empty-header rule must still fire'
		);
		$this->assertFalse(self::hasReservedError($errors), 'an empty header must not also trip the reserved rule');
	}

	public static function nonWordHeaderProvider(): array
	{
		return [
			'de-dup'        => ['de-dup'],
			'de dup'        => ['de dup'],
			'dedup!'        => ['dedup!'],
			'leading space' => [' dedup'],
			'trailing space' => ['dedup '],
		];
	}

	#[DataProvider('nonWordHeaderProvider')]
	public function testNonWordHeaderStillTriggersExistingWRuleNotReservedRule(string $header): void
	{
		$this->makeRow('Deny_Both', $header);
		$errors = pfb_category_oracle_reserved_header_state_loop('IPv4');
		$this->assertNotEmpty(
			array_filter($errors, static fn (string $e): bool => str_contains($e, 'special or international')),
			"the existing \\W rule must still fire for header={$header}"
		);
		$this->assertFalse(
			self::hasReservedError($errors),
			"header={$header} must not additionally trip the reserved rule (it never reaches a clean 'dedup' compare)"
		);
	}
}
