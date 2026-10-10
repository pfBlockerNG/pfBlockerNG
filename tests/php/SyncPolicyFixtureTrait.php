<?php

declare(strict_types=1);

/**
 * Issue #3450 — the ownership oracle and the disk-shaped section fixture shared by the
 * sync ownership, projection and digest tests.
 *
 * The oracle is written down here from docs/specs/xmlrpc-per-field-sync.md ("Local keys"),
 * not read back from the registry: a registry that misclassifies a key must disagree with
 * this list instead of echoing it.
 *
 * diskFixture() mirrors what a node reads from config.xml: every leaf is a string. Each
 * leaf is declared as policy or non-policy at the point it is created, so the fixture
 * carries its own expected projection ('policy', in section order) and the exact set of
 * paths that must never be sent ('nonpolicy'). A non-policy value gets $variant appended,
 * which lets a second fixture differ from the first in non-policy content only.
 */
trait SyncPolicyFixtureTrait
{
	private const EMBEDDED_KEY_PATH  = 'installedpackages/pfblockerngdnsbl/config/1/row/1/url';
	private const EMBEDDED_KEY_VALUE = 'https://example.com/feed.txt?key=EMBEDDED-POLICY-KEY';

	/** @return list<string> alias-qualified registry keys the spec classifies local (60) */
	private static function localRegistryKeys(): array
	{
		$logs = [
			'log', 'errlog', 'extraslog', 'ip_blocklog', 'ip_permitlog', 'ip_matchlog',
			'ip_parse_err', 'dnslog', 'dnsbl_parse_err', 'dnsreplylog', 'unilog',
		];
		$keys = ['gen/settings_family'];
		foreach ($logs as $log) {
			$keys[] = "gen/log_max_{$log}";
		}
		foreach ($logs as $log) {
			$keys[] = "gen/log_max_days_{$log}";
		}

		return array_merge($keys, [
			'gen/pfb_log_trim_margin_pct',
			'gen/pfb_reentry_timeout',
			'gen/pfb_software_check',
			'gen/pfb_reuse',
			'gen/pfb_alias_delta_mode',
			'gen/pfb_alias_delta_batch',
			'gen/pfb_syntax_highlight',
			'gen/log_syslog',

			'ip/enable_rdns',
			'ip/maxmind_locale',
			'ip/asn_reporting',
			'ip/inbound_interface',
			'ip/outbound_interface',
			'ip/maxmind_account',
			'ip/maxmind_key',
			'ip/asn_token',

			'dnsbl/pfb_dnsvip_auto',
			'dnsbl/dnsbl_interface',
			'dnsbl/pfb_dnsvip4',
			'dnsbl/pfb_dnsvip6',
			'dnsbl/pfb_dnsport',
			'dnsbl/pfb_dnsport_ssl',
			'dnsbl/pfb_cache',
			'dnsbl/pfb_cache_flush',
			'dnsbl/pfb_py_reply',
			'dnsbl/pfb_py_nolog',
			'dnsbl/pfb_control',
			'dnsbl/pfb_control_legacy',
			'dnsbl/pfb_py_cache_max',
			'dnsbl/dnsbl_allow_int',
			'dnsbl/dnsbl_redir_int',
			'dnsbl/dnsbl_dot_block_int',
			'dnsbl/agateway_in',
			'dnsbl/agateway_out',
			'dnsbl/top1m_token',

			'global/alertrefresh',
			'sync/syncinterfaces',
		]);
	}

	/** @return array<string,string> credential registry key => real-looking value */
	private static function credentialValues(): array
	{
		return [
			'ip/maxmind_account' => '1234567',
			'ip/maxmind_key'     => 'Xk9mR2vQ7tLp3sWz8nB4cD6fH1jK5gT0aY2uE_mmk',
			'ip/asn_token'       => 'a1b2c3d4e5f607',
			'dnsbl/top1m_token'  => 'eyJhbGciOiJIUzI1NiJ9.cf-top1m.Q3J5cHRv',
		];
	}

	/** @return array<int,array{0:string,1:string}> Blacklist item index => [username, password] */
	private static function blacklistCredentials(): array
	{
		return [
			0 => ['bl-user-shalla', 'S3cr3t!bl-pass'],
			1 => ['bl-user-other', 'Other-S3cr3t!2'],
		];
	}

	/**
	 * Runs $fn and fails the test if PHP raised any diagnostic (warning, notice,
	 * deprecation): hostile section shapes must be handled, not tolerated by the engine.
	 */
	private function assertNoDiagnostics(callable $fn): mixed
	{
		$diagnostics = [];
		set_error_handler(static function (int $errno, string $errstr) use (&$diagnostics): bool {
			$diagnostics[] = $errstr;
			return TRUE;
		});
		try {
			$result = $fn();
		} finally {
			restore_error_handler();
		}
		$this->assertSame([], $diagnostics, 'must not raise a PHP diagnostic: ' . implode('; ', $diagnostics));
		return $result;
	}

	/**
	 * @param array<mixed> $tree
	 * @param list<string> $segments
	 */
	private static function setPath(array &$tree, array $segments, mixed $value): void
	{
		$last = array_pop($segments);
		$node = &$tree;
		foreach ($segments as $segment) {
			if (!isset($node[$segment]) || !is_array($node[$segment])) {
				$node[$segment] = [];
			}
			$node = &$node[$segment];
		}
		$node[$last] = $value;
	}

	/**
	 * @return array{sections: array<string,mixed>, policy: array<string,string>, nonpolicy: array<string,string>}
	 */
	private static function diskFixture(string $variant = ''): array
	{
		$fx  = ['sections' => [], 'policy' => [], 'nonpolicy' => []];
		$put = static function (bool $policy, string $path, string $value) use (&$fx, $variant): void {
			if (!$policy) {
				$value .= $variant;
			}
			self::setPath($fx['sections'], array_slice(explode('/', $path), 1), $value);
			$fx[$policy ? 'policy' : 'nonpolicy'][$path] = $value;
		};

		// Sections are built in pfblockerng_sync_sections(TRUE) order so that 'policy' is
		// already the expected projection order.
		$registry = pfb_cfg_registry();
		$local    = self::localRegistryKeys();
		$cred     = self::credentialValues();
		foreach (['gen', 'ip', 'dnsbl'] as $alias) {
			$base = PFB_SECTIONS[$alias];
			foreach (array_keys($registry) as $key) {
				if (str_starts_with($key, "{$alias}/") && !in_array($key, $local, TRUE)) {
					$put(TRUE, $base . '/' . substr($key, strlen($alias) + 1), "POLICY<{$key}>");
				}
			}
			foreach ($local as $key) {
				if (str_starts_with($key, "{$alias}/")) {
					$put(FALSE, $base . '/' . substr($key, strlen($alias) + 1), $cred[$key] ?? "LOCAL<{$key}>");
				}
			}
			$put(FALSE, "{$base}/zz_unknown_{$alias}", "UNKNOWN<{$alias}>");
			if ($alias === 'gen') {
				$put(FALSE, 'installedpackages/pfblockerng/hooks/row/0/script', 'HOOK<script>');
			}
			if ($alias === 'dnsbl') {
				foreach (['dnsbl_mode', 'pfb_py_block', 'pfb_control_legacy_seeded'] as $retired) {
					$put(FALSE, "{$base}/{$retired}", "RETIRED<{$retired}>");
				}
				$put(FALSE, "{$base}/dnsbl_webpage", 'FOREIGN<dnsbl_webpage>');
			}
		}

		$groupRow = static function (string $section, int $n) use ($put): void {
			$base = "installedpackages/{$section}/config/{$n}";
			$tag  = "{$section}.{$n}";
			$put(TRUE, "{$base}/aliasname", "POLICY<{$tag}.aliasname>");
			$put(TRUE, "{$base}/action", "POLICY<{$tag}.action>");
			$put(TRUE, "{$base}/cron", "POLICY<{$tag}.cron>");
			foreach (['srcint', 'script_pre', 'script_post', 'agateway_in', 'agateway_out'] as $leaf) {
				$put(FALSE, "{$base}/{$leaf}", "LOCAL<{$tag}.{$leaf}>");
			}
			foreach (['format', 'state', 'url', 'header'] as $leaf) {
				$put(TRUE, "{$base}/row/0/{$leaf}", "POLICY<{$tag}.row0.{$leaf}>");
			}
			$put(TRUE, "{$base}/row/1/url", "POLICY<{$tag}.row1.url>");
		};

		foreach (['pfblockernglistsv4', 'pfblockernglistsv6'] as $section) {
			$groupRow($section, 0);
			$groupRow($section, 1);
		}

		foreach (['enable_rep', 'enable_pdup', 'enable_dedup', 'et_header'] as $leaf) {
			$put(TRUE, "installedpackages/pfblockerngreputation/config/0/{$leaf}", "POLICY<rep.{$leaf}>");
		}

		foreach ([
			'pfblockerngtopspammers', 'pfblockerngafrica', 'pfblockerngantarctica', 'pfblockerngasia',
			'pfblockerngeurope', 'pfblockerngnorthamerica', 'pfblockerngoceania', 'pfblockerngsouthamerica',
			'pfblockerngproxyandsatellite',
		] as $section) {
			$base = "installedpackages/{$section}/config/0";
			$put(TRUE, "{$base}/aliasname", "POLICY<{$section}.aliasname>");
			$put(TRUE, "{$base}/action", "POLICY<{$section}.action>");
			$put(FALSE, "{$base}/agateway_in", "LOCAL<{$section}.agateway_in>");
			$put(FALSE, "{$base}/agateway_out", "LOCAL<{$section}.agateway_out>");
		}

		$groupRow('pfblockerngdnsbl', 0);
		$groupRow('pfblockerngdnsbl', 1);
		// The one policy leaf that embeds a provider key: it stays list policy (spec exception).
		$put(TRUE, self::EMBEDDED_KEY_PATH, self::EMBEDDED_KEY_VALUE);

		$bl = 'installedpackages/pfblockerngblacklist';
		foreach (['blacklist_enable', 'blacklist_freq', 'blacklist_lang', 'blacklist_logging', 'blacklist_selected'] as $leaf) {
			$put(TRUE, "{$bl}/{$leaf}", "POLICY<blacklist.{$leaf}>");
		}
		foreach (self::blacklistCredentials() as $n => [$user, $pass]) {
			foreach (['title', 'xml', 'feed', 'size', 'selected'] as $leaf) {
				$put(TRUE, "{$bl}/item/{$n}/{$leaf}", "POLICY<blacklist.item{$n}.{$leaf}>");
			}
			$put(FALSE, "{$bl}/item/{$n}/username", $user);
			$put(FALSE, "{$bl}/item/{$n}/password", $pass);
		}

		$gl = 'installedpackages/pfblockerngglobal';
		$put(FALSE, "{$gl}/alertrefresh", 'LOCAL<global.alertrefresh>');
		$put(TRUE, "{$gl}/feed_Foo", 'POLICY<global.feed_Foo>');
		$put(FALSE, "{$gl}/widget-pfblockerng", 'LOCAL<global.widget-pfblockerng>');
		$put(TRUE, "{$gl}/feed_alt_Foo", 'POLICY<global.feed_alt_Foo>');
		$put(FALSE, "{$gl}/pfbextdns", 'LOCAL<global.pfbextdns>');

		foreach (['safesearch_enable', 'safesearch_youtube', 'safesearch_doh', 'safesearch_doh_list'] as $leaf) {
			$put(TRUE, "installedpackages/pfblockerngsafesearch/{$leaf}", "POLICY<ss.{$leaf}>");
		}

		$sy = 'installedpackages/pfblockerngsync/config/0';
		$put(FALSE, "{$sy}/syncscope", 'SYNC<syncscope>');
		$put(FALSE, "{$sy}/varsynconchanges", 'SYNC<varsynconchanges>');
		$put(FALSE, "{$sy}/row/0/ip", 'SYNC<target.ip>');
		$put(FALSE, "{$sy}/row/0/password", 'TARGET-ROW-PASS');
		$put(FALSE, 'installedpackages/pfblockerngbogus/config/0/x', 'BOGUS<x>');

		return $fx;
	}
}
