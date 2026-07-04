<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Pin pfb_whitelist_trash_icon() (issue #798): the shared "host in a Permit
 * Whitelist Alias -> trash-can icon" lookup extracted from convert_ip_log()'s
 * two duplicated blocks. Direct coverage matters because the empty-list
 * branch — the one whose NULL return replaces the old undefined $pfb_found
 * flag (PHP 8 E_WARNING) — is unreachable through the live Alerts page: the
 * customlist collection always seeds a default 'options' entry, so only a
 * unit test can prove it.
 *
 * The function under test is loaded off-appliance via the same eval-extract
 * technique as AlertsFeedMatchCellGroupingTest: the alerts page source is
 * read, require_once() lines stripped, and only the function block eval'd.
 */
#[CoversFunction('pfb_whitelist_trash_icon')]
final class WhitelistTrashIconTest extends TestCase
{
	public static function setUpBeforeClass(): void
	{
		if (function_exists('pfb_whitelist_trash_icon')) {
			return;
		}
		$src = file_get_contents(
			dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_alerts.php'
		);
		if ($src === false) {
			throw new RuntimeException('failed to read pfblockerng_alerts.php');
		}
		$src = preg_replace('/^\s*require_once\(.*\);\s*$/m', '', $src);
		$start = strpos($src, "\nfunction ");
		$end   = strpos($src, "\n\$pgtitle = ");
		if ($start === false || $end === false || $end <= $start) {
			throw new RuntimeException('could not locate the function block in pfblockerng_alerts.php');
		}
		eval("\n" . substr($src, $start + 1, $end - $start - 1));
	}

	/**
	 * The empty-list branch: NULL, with no PHP warning — this is the branch
	 * that replaces the old undefined-$pfb_found read, and it is unreachable
	 * via the live page (see the class docblock).
	 */
	public function testEmptyWhitelistArrayReturnsNull(): void
	{
		$this->assertNull(pfb_whitelist_trash_icon([], '10.0.0.1', 4, '10.0.0.1', '10.0.0.0/24'));
	}

	/**
	 * An options-only array (the collection's always-seeded default when no
	 * Permit alias is configured) has no 'data' rows — no match, no warning.
	 */
	public function testOptionsOnlyArrayReturnsNull(): void
	{
		$wlists = ['options' => ['Create new pfB_Whitelist_v4']];

		$this->assertNull(pfb_whitelist_trash_icon($wlists, '10.0.0.1', 4, '10.0.0.1', '10.0.0.0/24'));
	}

	public function testHostNotInAnyAliasReturnsNull(): void
	{
		$wlists = [
			'pfB_Whitelist_v4' => ['data' => ['192.0.2.1' => "192.0.2.1\r\n"]],
			'options' => ['pfB_Whitelist_v4'],
		];

		$this->assertNull(pfb_whitelist_trash_icon($wlists, '10.0.0.1', 4, '10.0.0.1', '10.0.0.0/24'));
	}

	/**
	 * A covered host yields the exact trash-can markup both retired blocks
	 * emitted: DNSBLWT|delete_ipwhitelist id carrying the ENCODED host + alias
	 * name, and the tooltip carrying the raw customlist line + evaluated IP.
	 */
	public function testCoveredHostRendersTrashIconWithAliasAndLine(): void
	{
		$wlists = [
			'pfB_Whitelist_v4' => ['data' => ['192.0.2.7' => "192.0.2.7 # office\r\n"]],
			'options' => ['pfB_Whitelist_v4'],
		];

		$icon = pfb_whitelist_trash_icon($wlists, '192.0.2.7', 4, '192.0.2.7', '192.0.2.0/24');

		$this->assertNotNull($icon);
		$this->assertStringContainsString('id="DNSBLWT|delete_ipwhitelist|192.0.2.7|pfB_Whitelist_v4"', $icon);
		$this->assertStringContainsString('fa-trash-can', $icon);
		$this->assertStringContainsString('Permitted IP:&emsp;[ 192.0.2.7 # office ]', $icon);
		$this->assertStringContainsString('Evaluated IP:&emsp;[ 192.0.2.0/24 ]', $icon);
		$this->assertStringContainsString('IPv4 address is in a Permit Alias', $icon);
	}

	/**
	 * First matching alias wins (same order the retired blocks' break gave);
	 * a non-matching alias earlier in the array is skipped, not fatal.
	 */
	public function testFirstMatchingAliasWins(): void
	{
		$wlists = [
			'pfB_Other_v4' => ['data' => ['192.0.2.1' => "192.0.2.1\r\n"]],
			'pfB_First_v4' => ['data' => ['192.0.2.7' => "192.0.2.7\r\n"]],
			'pfB_Second_v4' => ['data' => ['192.0.2.7' => "192.0.2.7 # dup\r\n"]],
			'options' => ['pfB_Other_v4', 'pfB_First_v4', 'pfB_Second_v4'],
		];

		$icon = pfb_whitelist_trash_icon($wlists, '192.0.2.7', 6, '192.0.2.7', '192.0.2.7/32');

		$this->assertNotNull($icon);
		$this->assertStringContainsString('|pfB_First_v4"', $icon);
		$this->assertStringContainsString('IPv6 address is in a Permit Alias', $icon);
	}
}
