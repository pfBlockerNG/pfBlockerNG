<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #3150 — the v4 shell `suppress` verb no-ops when pfbsuppression.txt is
 * absent or empty, but PHP still spawned it once per v4 alias (and once for
 * suppressheader) whenever the Suppression toggle was on. v6 already gated on
 * a nonempty customlist file; v4 did not.
 *
 * Feature: suppress-list presence gate
 *   Scenario: missing or empty customlist file is inactive (toggle alone must
 *     not buy a process spawn)
 *   Scenario: a nonempty customlist file is present
 *   Scenario: live v4 header/body execs and the v6 sibling all dispatch through
 *     this predicate — firewall orchestration has no safe off-box driver
 */
#[CoversFunction('pfb_ip_suppress_list_present')]
final class IpSuppressListPresentTest extends TestCase
{
	private string $dir;

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_supplist_' . getmypid() . '_' . uniqid();
		$this->assertTrue(mkdir($this->dir, 0777, TRUE));
	}

	protected function tearDown(): void
	{
		rmdir_recursive($this->dir);
		$this->assertDirectoryDoesNotExist($this->dir);
	}

	public function testMissingFileIsInactive(): void
	{
		$this->assertFalse(
			pfb_ip_suppress_list_present("{$this->dir}/pfbsuppression.txt"),
			'absent customlist must not unlock the suppress spawn'
		);
	}

	public function testEmptyFileIsInactive(): void
	{
		$path = "{$this->dir}/pfbsuppression.txt";
		$this->assertNotFalse(file_put_contents($path, ''));

		$this->assertFalse(
			pfb_ip_suppress_list_present($path),
			'empty customlist must not unlock the suppress spawn'
		);
	}

	public function testNonemptyFileIsPresent(): void
	{
		$path = "{$this->dir}/pfbsuppression.txt";
		$this->assertNotFalse(file_put_contents($path, "10.0.0.1/32\n"));

		$this->assertTrue(
			pfb_ip_suppress_list_present($path),
			'nonempty customlist must unlock the suppress spawn'
		);
	}

	public function testLiveV4SuppressExecsRequireTheNonemptyCustomlist(): void
	{
		$source = php_strip_whitespace(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc');
		$this->assertStringContainsString(
			'if ($pfbrunonce && $pfb[\'supp\'] === PfbToggle::On && $vtype == \'_v4\' && $pfb[\'supp_update\'] && pfb_ip_suppress_list_present($pfb[\'supptxt\'])) {',
			$source,
			'issue #3150: suppressheader spawn must not run when the customlist file is empty or absent'
		);
		$this->assertStringContainsString(
			'if ($suppression_body_active && $vtype == \'_v4\' && pfb_ip_suppress_list_present($pfb[\'supptxt\'])) {',
			$source,
			'issue #3150: per-alias suppress exec must not run when the customlist file is empty or absent'
		);
	}

	public function testLiveV6SuppressBodyUsesTheSameListPresencePredicate(): void
	{
		$source = php_strip_whitespace(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc');
		$this->assertStringContainsString(
			'if ($suppression_body_active && $vtype == \'_v6\' && pfb_ip_suppress_list_present($pfb[\'supptxt_v6\'])) {',
			$source,
			'issue #3150: v6 sibling must share the nonempty-list predicate'
		);
	}
}
