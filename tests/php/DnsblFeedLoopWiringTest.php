<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

/**
 * The DNSBL download loop in sync_package_pfblockerng() around pfb_dnsbl_parse_line() (issue #3921): the
 * per-feed ctx build, the hpHosts `stop` break, the row write to `<header>.bk` and the hand-off of the IPs
 * found and of `updateip`. The parser itself is covered by its corpus; this pins the wiring around it.
 *
 * The loop sits deep inside sync_package_pfblockerng(), so its real region is extracted from the shipped
 * source and evaluated (PageStatementLoader.php) over a feed file in a scratch folder.
 */
#[CoversNothing]
final class DnsblFeedLoopWiringTest extends TestCase
{
	private const APPLY = 'src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc';

	// One line per ctx field the loop builds, then the hpHosts end marker and a line past it.
	private const FEED = "example.com\n"
		. "10.0.0.1\n"				// private: suppressed unless the list is custom
		. "2001:4860:4860::8888\n"
		. "http://evil.example/path\n"		// a URL path: strict parsing skips it, lenient keeps the host
		. "||9.9.9.9^\n"			// an IP anchor: an IP when dnsbl_ip is on, an ABP row when off
		. "# Append critical updates below\n"
		. "after.example\n";

	private string $tmp;
	private bool $hadPfb;
	/** @var array<string, mixed> */
	private array $originalPfb;

	public static function setUpBeforeClass(): void
	{
		require_once __DIR__ . '/PageStatementLoader.php';
		require_once dirname(__DIR__, 2) . '/' . self::APPLY;
	}

	protected function setUp(): void
	{
		$this->tmp = sys_get_temp_dir() . '/pfb_dnsbl_loop_' . getmypid() . '_' . bin2hex(random_bytes(4));
		$this->assertTrue(mkdir($this->tmp, 0700, TRUE));
		$this->hadPfb = array_key_exists('pfb', $GLOBALS);
		$this->originalPfb = $GLOBALS['pfb'] ?? [];
		$GLOBALS['pfb'] = array_merge($this->originalPfb, [
			'log'    => "{$this->tmp}/pfblockerng.log",
			'errlog' => "{$this->tmp}/error.log",
			'supp'   => PfbToggle::On,
		]);
	}

	protected function tearDown(): void
	{
		if ($this->hadPfb) {
			$GLOBALS['pfb'] = $this->originalPfb;
		} else {
			unset($GLOBALS['pfb']);
		}
		foreach (glob("{$this->tmp}/*") ?: [] as $file) {
			@unlink($file);
		}
		@rmdir($this->tmp);
	}

	/**
	 * Run the loop over FEED; returns the rows written and the IPs / updateip handed on.
	 *
	 * @return array{rows: list<string>, ip4: mixed, ip6: mixed, updateip: mixed}
	 */
	private function runLoop(bool $custom, string $dnsbl_ip, PfbToggle $lenient): array
	{
		file_put_contents("{$this->tmp}/feed.txt", self::FEED);
		$scope = pfb_test_page_eval(
			pfb_test_page_region(self::APPLY,
				'$pfb_dnsbl_state = pfb_dnsbl_parse_state();',
				'// issue #1926: the staged pre-script copy is transient'),
			[
				'header'		=> 'Feed',
				'custom'		=> $custom,
				'pfbfolder'		=> $this->tmp,
				'pfb_parse_path'	=> "{$this->tmp}/feed.txt",
				'pfb'			=> $GLOBALS['pfb'] + [
					'dnsbl_ip'		=> $dnsbl_ip,
					'dnsbl_lenient'		=> $lenient,
					'dnsbl_parse_err'	=> "{$this->tmp}/parse_err.log",
					'updateip'		=> FALSE,
				],
			]
		);
		return [
			'rows'		=> file("{$this->tmp}/Feed.bk", FILE_IGNORE_NEW_LINES),
			'ip4'		=> $scope['domain_data_ip'],
			'ip6'		=> $scope['domain_data_ip6'],
			'updateip'	=> $scope['pfb']['updateip'],
		];
	}

	public function testRowsUpToTheEndMarkerAreWrittenAndIpsHandedOn(): void
	{
		$this->assertSame([
			'rows'		=> ['["d","example.com"]'],
			'ip4'		=> ['9.9.9.9'],
			'ip6'		=> ['2001:4860:4860::8888'],
			'updateip'	=> TRUE,
		], $this->runLoop(FALSE, 'Enabled', PfbToggle::Off));
	}

	public function testCustomListKeepsPrivateIp(): void
	{
		$this->assertSame(['10.0.0.1', '9.9.9.9'], $this->runLoop(TRUE, 'Enabled', PfbToggle::Off)['ip4']);
	}

	public function testDnsblIpDisabledCollectsNoIps(): void
	{
		$this->assertSame([
			'rows'		=> ['["d","example.com"]', '["a","||9.9.9.9^"]'],
			'ip4'		=> [],
			'ip6'		=> [],
			'updateip'	=> FALSE,
		], $this->runLoop(FALSE, 'Disabled', PfbToggle::Off));
	}

	public function testLenientKeepsUrlHost(): void
	{
		$this->assertSame(
			['["d","example.com"]', '["d","evil.example"]'],
			$this->runLoop(FALSE, 'Enabled', PfbToggle::On)['rows']
		);
	}
}
