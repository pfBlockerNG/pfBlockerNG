<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-65 Phase 4 (D2): convert_dnsbl_log() stops calling pfb_dnsbl_parse('alerts', ...)
 * for DNSBL rows -- Reports/Unified rows render the LOGGED group/feed directly (no
 * "currently listed / feed-changed" strikethrough refinement), and feed-name
 * filtering matches the LOGGED feed, not a re-derived current one.
 *
 * Sandbox: AlertsPageLoader's off-appliance function load (AlertsRowOutputEncodingTest
 * shape) PLUS the grep-path globals, so the OLD re-check actually runs
 * on a RED pass -- an NDJSON row seeds a DIFFERENT ("Cur*") group/feed for the row's
 * domain than the LOGGED ("Logged*") fields carry, so old code's compare/rewrite is
 * exercised and observable.
 */
#[CoversFunction('convert_dnsbl_log')]
final class AlertsDnsblLoggedFieldsRenderTest extends TestCase
{
	private string $tmp;

	/** @var array<string,mixed> saved globals restored in tearDown */
	private array $saved = [];

	public static function setUpBeforeClass(): void
	{
		require_once __DIR__ . '/AlertsPageLoader.php';
		pfb_test_load_alerts_page_functions();
	}

	protected function setUp(): void
	{
		foreach ([
			'pfb', 'local_hosts', 'dnsbl_int', 'filterfieldsarray', 'clists',
			'dnsbl_unlock', 'dup', 'counter', 'pfbentries', 'skipcount',
			'dnsblfilterlimit', 'dnsblfilterlimitentries', 'config',
		] as $g) {
			$this->saved[$g] = $GLOBALS[$g] ?? null;
		}

		$this->tmp = sys_get_temp_dir() . '/pfb_alerts_logged_' . uniqid('', true);
		mkdir($this->tmp, 0777, true);

		$GLOBALS['local_hosts'] = [];
		$GLOBALS['dnsbl_int'] = [];
		$GLOBALS['filterfieldsarray'] = [];
		$GLOBALS['clists'] = ['dnsbl' => ['options' => []], 'dnsblwhitelist' => ['data' => []]];
		$GLOBALS['dnsbl_unlock'] = [];
		$GLOBALS['dup'] = ['DNSBL' => 0];
		$GLOBALS['counter'] = ['DNSBL' => 0, 'Unified' => 0];
		$GLOBALS['pfbentries'] = 1000;
		$GLOBALS['skipcount'] = 0;
		$GLOBALS['dnsblfilterlimit'] = false;
		$GLOBALS['dnsblfilterlimitentries'] = 100;
		// 'Unified' mode reads this pfSense-core key for its row background colour.
		$GLOBALS['config'] = ['system' => ['webgui' => ['webguicss' => '']]];

		$GLOBALS['pfb'] = [
			'filterlogentries' => false,
			// grep-path sandbox -- exercises the OLD re-check on RED.
			'grep'            => '/usr/bin/grep',
			'extdns'          => '203.0.113.53',
			'unbound_py_data' => "{$this->tmp}/pfb_py_data.txt",
			'unbound_py_zone' => "{$this->tmp}/pfb_py_zone.txt",
			'errlog'          => "{$this->tmp}/error.log",
			'sqlite_timeout'  => 2000,
			// 'Unified' mode row-background colours.
			'unidnsbl'      => '#f0f0f0',
			'unidnsbl2'     => '#202020',
			'uniupstream'   => '#f0f0f0',
			'uniupstream2'  => '#202020',
		];
		touch($GLOBALS['pfb']['unbound_py_zone']);
	}

	protected function tearDown(): void
	{
		foreach ($this->saved as $g => $v) {
			if ($v === null) {
				unset($GLOBALS[$g]);
			} else {
				$GLOBALS[$g] = $v;
			}
		}
		rmdir_recursive($this->tmp);
	}

	/** Seed the OLD grep path's data file with one NDJSON row for $domain (schema v1). */
	private function seedGrepRow(string $domain, string $group, string $feed): void
	{
		$row = json_encode(['kind' => 'domain', 'domain' => $domain, 'log' => 'DNSBL', 'feed' => $feed, 'group' => $group]);
		file_put_contents($GLOBALS['pfb']['unbound_py_data'], "{$row}\n");
	}

	/**
	 * Build a NON-python, non-upstream, non-whitelisted dnsbl.log $fields row (field
	 * layout per convert_dnsbl_log()'s reference comment) blocked by $loggedGroup/
	 * $loggedFeed for $domain.
	 */
	private function dnsblFields(string $domain, string $loggedGroup, string $loggedFeed, string $src_ip = '10.0.0.5'): array
	{
		return [
			0 => 'DNSBL-Full',	// Unbound-mode prefix (not '...python') -> exercises the re-check
			1 => '2026-01-01 00:00:00',
			2 => $domain,
			3 => $src_ip,
			4 => '',
			5 => 'DNSBL',		// Mode: no 'TLD'/'_CNAME'/'Python' substring
			6 => $loggedGroup,
			7 => $domain,		// Evaluated Domain
			8 => $loggedFeed,
			9 => 0,
			10 => 'A',
		];
	}

	private function render(string $mode, array $fields): string
	{
		ob_start();
		convert_dnsbl_log($mode, $fields);
		return (string) ob_get_clean();
	}

	// -------------------------------------------------------------------
	// Reports (non-unified): renders the LOGGED fields, no strike, no Cur* leak
	// -------------------------------------------------------------------

	public function testReportsRenderShowsLoggedFieldsNoStrikeNoCurrentValue(): void
	{
		$domain = 'uuid-render-reports-1a2b.example.com';
		$this->seedGrepRow($domain, 'CurGroup', 'CurFeed');
		$fields = $this->dnsblFields($domain, 'LoggedGroup', 'LoggedFeed');

		$html = $this->render('Reports', $fields);

		$this->assertStringContainsString('LoggedFeed', $html, 'expected the LOGGED feed to render');
		$this->assertStringContainsString('LoggedGroup', $html, 'expected the LOGGED group to render');
		$this->assertStringNotContainsString('CurFeed', $html, 'the re-check must never rewrite to the current feed');
		$this->assertStringNotContainsString('CurGroup', $html, 'the re-check must never rewrite to the current group');
		$this->assertStringNotContainsString('<s>', $html, 'no "previously listed" strikethrough may render');
		$this->assertStringNotContainsString('Previous Feed', $html, 'no drift refinement text may render');
		$this->assertStringNotContainsString('Previous Group', $html, 'no drift refinement text may render');
		$this->assertStringNotContainsString('Previous Domain', $html, 'no drift refinement text may render');
	}

	// -------------------------------------------------------------------
	// Unified: same contract, exercised via the Unified dispatch's code path
	// -------------------------------------------------------------------

	public function testUnifiedRenderShowsLoggedFieldsNoStrike(): void
	{
		$domain = 'uuid-render-unified-3c4d.example.com';
		$this->seedGrepRow($domain, 'CurGroupU', 'CurFeedU');
		$fields = $this->dnsblFields($domain, 'LoggedGroupU', 'LoggedFeedU');

		$html = $this->render('Unified', $fields);

		$this->assertStringContainsString('LoggedFeedU', $html, 'expected the LOGGED feed to render in Unified mode');
		$this->assertStringContainsString('LoggedGroupU', $html, 'expected the LOGGED group to render in Unified mode');
		$this->assertStringNotContainsString('CurFeedU', $html, 'Unified mode must never rewrite to the current feed');
		$this->assertStringNotContainsString('CurGroupU', $html, 'Unified mode must never rewrite to the current group');
		$this->assertStringNotContainsString('<s>', $html, 'no strikethrough may render in Unified mode');
	}

	// -------------------------------------------------------------------
	// Filter mode: feed-name filtering matches the LOGGED feed
	// -------------------------------------------------------------------

	public function testFilterModeMatchesLoggedFeedNotCurrentFeed(): void
	{
		$domain = 'uuid-render-filter-5e6f.example.com';
		$this->seedGrepRow($domain, 'CurGroupF', 'CurFeedF');
		$fields = $this->dnsblFields($domain, 'LoggedGroupF', 'LoggedFeedF');

		$GLOBALS['pfb']['filterlogentries'] = true;
		// Field key 15 = Feed Name (convert_dnsbl_log()'s $pfbalertdnsbl reference
		// comment). Filter on the CURRENT (re-derived) feed value -- today's
		// re-check rewrites field[8] to it (embedding it in the cell even under a
		// strike), so a filter for it still matches; once nothing re-derives a
		// current value, this filter must MISS -- the row is logged under a
		// DIFFERENT feed entirely.
		$GLOBALS['filterfieldsarray'][1] = [15 => 'CurFeedF'];

		$result = $this->render('Reports', $fields);
		$rowRendered = $GLOBALS['counter']['DNSBL'] === 1;

		$this->assertFalse($rowRendered, 'a filter on the CURRENT (re-derived) feed must no longer match a row logged under a different feed');
		$this->assertSame('', $result, 'a non-matching row must render nothing');
	}

	// -------------------------------------------------------------------
	// fields[6]=='Unknown' with no .txt files on disk at all -> renders from
	// the log line, no warning/error (brief: check red status honestly).
	// -------------------------------------------------------------------

	public function testUnknownGroupRendersWithoutAnyDiskFilesNoWarning(): void
	{
		$domain = 'uuid-render-nofile-7a8b.example.com';
		// No .txt files at all -- point the grep-path globals at a directory that
		// was never created (distinct from setUp()'s touched-but-empty zone file).
		$GLOBALS['pfb']['unbound_py_data'] = "{$this->tmp}/does-not-exist/pfb_py_data.txt";
		$GLOBALS['pfb']['unbound_py_zone'] = "{$this->tmp}/does-not-exist/pfb_py_zone.txt";

		$fields = $this->dnsblFields($domain, 'Unknown', 'Unknown');

		$caught = [];
		set_error_handler(function (int $errno, string $errstr) use (&$caught): bool {
			$caught[] = $errstr;
			return true;
		});
		try {
			$html = $this->render('Reports', $fields);
		} finally {
			restore_error_handler();
		}
		$unexpected = array_values(array_filter($caught, static function (string $msg): bool {
			return !str_contains($msg, 'Unable to find uid for unbound')
				&& !str_contains($msg, 'Unable to find gid for unbound');
		}));

		$this->assertSame([], $unexpected, 'expected no PHP warning/error rendering an Unknown row with no interchange files; got: ' . var_export($unexpected, true));
		$this->assertStringContainsString('Unknown', $html, "expected the 'Unknown' group to render from the log line");
	}
}
