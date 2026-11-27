<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * #3977 (owner, 2026-11-27): after the cutover the Alerts page reaches pfB-DNS through Core alone. Its whitelist, TLD
 * Exclusion and custom-list edits ask Core for an `apply` Update (pfb_apply_update_start()), and Lock and Unlock change Core's
 * set of temporary unlocks (pfb_dnsbl_unlock_toggle()). pfB-DNS takes either on its next poll of Core and clears its own
 * decision cache then; it answers every query before Unbound does, so the page flushes no resolver cache and reloads nothing.
 * The page dispatch is top-level with no callable seam, so the wiring is pinned on php_strip_whitespace() output.
 */
final class AlertsCoreApplyWiringTest extends TestCase
{
	private static string $source;

	public static function setUpBeforeClass(): void
	{
		self::$source = php_strip_whitespace(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_alerts.php');
	}

	private function handler(string $post, string $next): string
	{
		$start = strpos(self::$source, "elseif (isset(\$_POST['{$post}'])");
		$end = strpos(self::$source, "elseif (isset(\$_POST['{$next}'])", $start === FALSE ? 0 : $start);
		$this->assertNotFalse($start, "{$post} handler");
		$this->assertNotFalse($end, "{$next} follows {$post}");
		return substr(self::$source, $start, $end - $start);
	}

	public function testNoResolverReloadFlushOrManifestPatchIsLeft(): void
	{
		foreach (['pfb_reload_unbound(', 'pfb_unbound_py_ccache_flush(', 'flush_zone', 'pfb_unbound_python_sources',
			'pfb_unbound_python_whitelist(', "pfb_unlock('lock', 'dnsbl'", "pfb_unlock(\$ua['mode'], 'dnsbl'"] as $gone) {
			$this->assertStringNotContainsString($gone, self::$source, "{$gone} is gone with the cutover");
		}
	}

	public function testTheEditsStartAnApplyUpdate(): void
	{
		foreach ([['dnsbl_add', 'addwhitelistdom'], ['addwhitelistdom', 'entry_delete'], ['entry_delete', 'dnsbl_remove']] as [$post, $next]) {
			$this->assertStringContainsString("pfb_apply_update_start('pfb_core_call')", $this->handler($post, $next), $post);
		}
	}

	public function testLockAndUnlockChangeCoresSet(): void
	{
		$region = $this->handler('dnsbl_remove', 'ip_remove');
		$this->assertStringContainsString("pfb_dnsbl_unlock_toggle('pfb_core_call', \$ua['mode'], \$domain, \$dnsbl_type)", $region);
		$this->assertStringContainsString("pfb_dnsbl_unlocks('pfb_core_call'", self::$source, 'the page reads Core\'s set');
	}
}
