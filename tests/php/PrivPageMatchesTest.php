<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Contract test for the pfBlockerNG privilege match list
 * (src/etc/inc/priv/pfblockerng.priv.inc), issue #707.
 *
 * pfSense authorises a GUI request by regex-matching REQUEST_URI (query string
 * INCLUDED) against a privilege's ['match'] entries via cmp_page_matches().
 * An entry WITHOUT a trailing '*' is anchored at both ends ("@^/{match}$@"), so
 * it authorises the bare page but 403s any "?query" variant. A delegated
 * operator who holds only the pfBlockerNG privilege (admins bypass privs) is
 * therefore locked out of every query-string surface -- Feeds sub-tabs
 * (?type=), the Update live-log tail (?ajax=tail), the SafeSearch save banner
 * (?savemsg=), and the General wizard hand-off (?wizard=). The wizard itself
 * runs at /wizard.php?xml=..., so the old "wizards/pfblockerng_wizard.xml"
 * entry never matched at all.
 *
 * This pins that every real pfBlockerNG URL a priv-only operator visits --
 * bare AND query variants -- is authorised by the firewall priv match list,
 * under a faithful reimplementation of pfSense's cmp_page_matches(). It is
 * red before the '*'/wizard fix and green after.
 */
final class PrivPageMatchesTest extends TestCase
{
	/** @var string[] The page-firewall-pfblockerng match list, from the real priv file. */
	private array $fwMatch;

	/** @var string[] The page-dashboard-pfblockerng (widget) match list. */
	private array $dashMatch;

	/** Temp www root mirroring the appliance layout so the realpath() gate resolves. */
	private string $wwwRoot;

	/** Files the cases below request, relative to $wwwRoot. */
	private const WWW_FILES = [
		'pfblockerng/pfblockerng_general.php',
		'pfblockerng/pfblockerng_update.php',
		'pfblockerng/pfblockerng_feeds.php',
		'pfblockerng/pfblockerng_safesearch.php',
		'widgets/widgets/pfblockerng.widget.php',
		'wizard.php', // core pfSense page, present on the appliance
	];

	protected function setUp(): void
	{
		// Load the shipped privilege definitions ($priv_list is a global there).
		unset($GLOBALS['priv_list']);
		require dirname(__DIR__, 2) . '/src/etc/inc/priv/pfblockerng.priv.inc';
		$this->fwMatch   = $GLOBALS['priv_list']['page-firewall-pfblockerng']['match'];
		$this->dashMatch = $GLOBALS['priv_list']['page-dashboard-pfblockerng']['match'];

		// cmp_page_matches() realpath()s the requested file under www_path and 403s
		// if it does not exist. Recreate just the files the cases below request so
		// the gate behaves exactly as on the appliance.
		$wwwRoot = sys_get_temp_dir() . '/pfb_priv_www_' . getmypid();
		@mkdir($wwwRoot . '/pfblockerng', 0777, true);
		@mkdir($wwwRoot . '/widgets/widgets', 0777, true);
		// Canonicalise: on macOS sys_get_temp_dir() is under /var, a symlink to
		// /private/var, so realpath()d file paths would not share this prefix and
		// the www_path strip below would fail. The appliance's /usr/local/www has
		// no such symlink; this keeps the oracle faithful on either host.
		$this->wwwRoot = realpath($wwwRoot);
		foreach (self::WWW_FILES as $rel) {
			@touch($this->wwwRoot . '/' . $rel);
		}
	}

	protected function tearDown(): void
	{
		foreach (self::WWW_FILES as $rel) {
			@unlink($this->wwwRoot . '/' . $rel);
		}
		@rmdir($this->wwwRoot . '/widgets/widgets');
		@rmdir($this->wwwRoot . '/widgets');
		@rmdir($this->wwwRoot . '/pfblockerng');
		@rmdir($this->wwwRoot);
	}

	/**
	 * Faithful reimplementation of pfSense cmp_page_matches()
	 * (src/etc/inc/auth_func.inc, master), minus the debug-logging branch and the
	 * $fullwc lone-"*" skip (our list has no lone "*"). Verified verbatim against
	 * upstream: the file part is realpath()-resolved under $wwwPath; the query is
	 * re-appended; each match string has '.'->'\.', '*'->'.*', '?'->'\?', then is
	 * anchored "@^/{match}$@" against "/{page}".
	 *
	 * @param string[] $matches
	 */
	private static function cmpPageMatches(string $page, array $matches, string $wwwPath): bool
	{
		$seg = explode('?', $page);
		$file = $seg[0];
		$query = $seg[1] ?? '';
		$real = realpath($wwwPath . '/' . ltrim($file, '/'));
		if ($real === false) {
			return FALSE;
		}
		$page = str_replace($wwwPath . '/', '', $real);
		$page .= ($query !== '') ? "?{$query}" : '';
		foreach ($matches as $match) {
			$re = str_replace(['.', '*', '?'], ['\.', '.*', '\?'], $match);
			if (preg_match("@^/{$re}$@", "/{$page}") === 1) {
				return TRUE;
			}
		}
		return FALSE;
	}

	/**
	 * Every URL a priv-only pfBlockerNG operator legitimately visits -- the bare
	 * pages plus the query-string surfaces #707 regressed on.
	 *
	 * @return array<string, array{string}>
	 */
	public static function operatorUrls(): array
	{
		return [
			// Bare pages: authorised before AND after the fix (baseline).
			'general (bare)'      => ['/pfblockerng/pfblockerng_general.php'],
			'update (bare)'       => ['/pfblockerng/pfblockerng_update.php'],
			'feeds (bare)'        => ['/pfblockerng/pfblockerng_feeds.php'],
			'safesearch (bare)'   => ['/pfblockerng/pfblockerng_safesearch.php'],
			// Query-string surfaces: 403 before the fix, authorised after.
			'general wizard hand-off' => ['/pfblockerng/pfblockerng_general.php?wizard=1'],
			'update live-log tail'    => ['/pfblockerng/pfblockerng_update.php?ajax=tail'],
			'feeds type sub-tab'      => ['/pfblockerng/pfblockerng_feeds.php?type=IPv4'],
			'safesearch save banner'  => ['/pfblockerng/pfblockerng_safesearch.php?savemsg=Saved'],
			// The wizard runs at /wizard.php?xml=..., not /wizards/...xml.
			'setup wizard'            => ['/wizard.php?xml=pfblockerng_wizard.xml'],
			// The dashboard widget auto-refreshes via GET (pfblockerng.js) — a
			// page-firewall operator viewing the dashboard hits these too.
			'widget getNewFailed'     => ['/widgets/widgets/pfblockerng.widget.php?getNewFailed=1'],
			'widget getNewWidget'     => ['/widgets/widgets/pfblockerng.widget.php?getNewWidget=1'],
		];
	}

	#[DataProvider('operatorUrls')]
	public function testPrivOnlyOperatorIsAuthorised(string $url): void
	{
		$ok = self::cmpPageMatches($url, $this->fwMatch, $this->wwwRoot);
		$this->assertTrue(
			$ok,
			"Priv-only operator must be authorised for {$url}, but no page-firewall-pfblockerng"
			. " match authorised it.\n  URL:     {$url}\n  matches: "
			. implode(', ', $this->fwMatch)
		);
	}

	/**
	 * The dashboard-widget privilege exists so a non-admin can see the pfBlockerNG
	 * widget; its JS auto-refreshes via GET ?getNewFailed=/?getNewWidget= (widgets/
	 * javascript/pfblockerng.js), which the widget reads from $_GET. The
	 * page-dashboard-pfblockerng match entry must authorise those query URLs, else a
	 * dashboard-only operator 403s on every refresh. Red before the widget '*' fix.
	 *
	 * @return array<string, array{string}>
	 */
	public static function widgetRefreshUrls(): array
	{
		return [
			'widget getNewFailed' => ['/widgets/widgets/pfblockerng.widget.php?getNewFailed=1'],
			'widget getNewWidget' => ['/widgets/widgets/pfblockerng.widget.php?getNewWidget=1'],
		];
	}

	#[DataProvider('widgetRefreshUrls')]
	public function testDashboardOnlyOperatorCanRefreshWidget(string $url): void
	{
		$ok = self::cmpPageMatches($url, $this->dashMatch, $this->wwwRoot);
		$this->assertTrue(
			$ok,
			"Dashboard-only operator must be authorised for {$url}, but no"
			. " page-dashboard-pfblockerng match authorised it.\n  URL:     {$url}\n  matches: "
			. implode(', ', $this->dashMatch)
		);
	}

	public function testNoDuplicateMatchEntries(): void
	{
		// Two identical pfblockerng_reputation.php entries existed pre-#707.
		$dupes = array_keys(array_filter(array_count_values($this->fwMatch), static fn(int $n): bool => $n > 1));
		$this->assertSame(
			[],
			$dupes,
			"Duplicate priv match entries: " . implode(', ', $dupes)
		);
	}
}
