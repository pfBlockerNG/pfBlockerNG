<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3976 -- the two download loops hand each downloaded feed to a per-feed function, pfb_ip_parse_feed() and
 * pfb_dnsbl_parse_feed(). The corpus runners and the line-parser tests call those functions directly; the loops are
 * monoliths unsafe off-appliance (#993), so what pins the HAND-OFF (which variable fills which parameter, which key of
 * the result the loop keeps) is the statement of each call, eval-extracted from pfblockerng_apply.inc and run here with
 * distinct values for every variable it reads. A call that passes the IPv6 limit as the IPv4 one, a constant for `custom`,
 * the alias for the header, or the stop flag for the row count therefore fails these tests.
 *
 * Each scenario compares the call site with a direct call that uses the intended arguments, and with a direct call that
 * swaps one of them: the second comparison proves the scenario can tell the two apart.
 */
#[CoversFunction('pfb_ip_parse_feed')]
#[CoversFunction('pfb_dnsbl_parse_feed')]
final class FeedParseCallSitesWiringTest extends TestCase
{
	private const APPLY = 'src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc';
	private const STAMP = '/^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d /m';

	private string $dir;
	private mixed $savedPfb = NULL;
	private mixed $savedConfig = NULL;

	public static function setUpBeforeClass(): void
	{
		if (function_exists('pfb_test_ip_call_site')) {
			return;
		}
		$src = php_strip_whitespace(dirname(__DIR__, 2) . '/' . self::APPLY);
		if ($src === '') {
			throw new RuntimeException('test bootstrap: failed to read pfblockerng_apply.inc');
		}
		if (!preg_match('/\[\'ip_data\' => \$ip_data, \'ip_suppressed\' => \$ip_suppressed, \'parse_fail\' => \$parse_fail\] = pfb_ip_parse_feed\([^;]*;/', $src, $ip)) {
			throw new RuntimeException('test bootstrap: the IP download loop call of pfb_ip_parse_feed() not found');
		}
		if (!preg_match('/\$domain_data = pfb_dnsbl_parse_feed\([^;]*;/', $src, $dnsbl)) {
			throw new RuntimeException('test bootstrap: the DNSBL download loop call of pfb_dnsbl_parse_feed() not found');
		}
		// Every variable either statement may read is a parameter with a value of its own: a call that names another one
		// reads that value, never an undefined one. The alias and the escaped header are the loop's look-alikes of the header.
		eval(
			'function pfb_test_ip_call_site($fhandle, $header, $list, $pftype, $custom, $pfbcidr, $pfbcidr_v6, $pfb, $alias, $header_esc, $file_dwn): array {'
			. ' $ip_data = $ip_suppressed = $parse_fail = NULL; ' . $ip[0] . ' return compact(\'ip_data\', \'ip_suppressed\', \'parse_fail\'); }'
		);
		eval(
			'function pfb_test_dnsbl_call_site($fhandle, $dhandle, array &$pfb_dnsbl_state, array $pfb_dnsbl_ctx, $header): mixed {'
			. ' $domain_data = NULL; ' . $dnsbl[0] . ' return $domain_data; }'
		);
	}

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_fpwire_' . getmypid() . '_' . bin2hex(random_bytes(4));
		mkdir($this->dir, 0700, TRUE);
		$this->savedPfb = $GLOBALS['pfb'] ?? NULL;
		$this->savedConfig = $GLOBALS['config'] ?? NULL;
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_file_notices'] = [];
	}

	protected function tearDown(): void
	{
		foreach (glob("{$this->dir}/*") ?: [] as $f) {
			@unlink($f);
		}
		@rmdir($this->dir);
		$GLOBALS['pfb'] = $this->savedPfb;
		$GLOBALS['config'] = $this->savedConfig;
	}

	/** The arguments of pfb_ip_parse_feed(), by the names the loop gives them. @return array<string, mixed> */
	private function ipArgs(array $over = []): array
	{
		return $over + [
			'header' => 'HEADER', 'list' => ['vtype' => '_v4'], 'pftype' => 'auto', 'custom' => FALSE,
			'pfbcidr' => '8', 'pfbcidr_v6' => '48', 'supp' => PfbToggle::On,
		];
	}

	/** One run: the feed through the call site ($site) or the function itself, with the parse-error log it wrote. @return array{0: array<string, mixed>, 1: string} */
	private function runIp(bool $site, array $a, string $feed): array
	{
		$fail = "{$this->dir}/" . ($site ? 'site' : 'direct') . '.err';
		$main = "{$this->dir}/" . ($site ? 'site' : 'direct') . '.log';
		file_put_contents($fail, '');
		file_put_contents($main, '');
		$pfb = [
			'log' => $main, 'errlog' => "{$this->dir}/err.log", 'supp' => $a['supp'], 'ip_parse_err' => $fail, 'ip_ph' => '127.1.7.7', 'grep' => 'grep',
		] + pfb_ip_regex_config();
		$GLOBALS['pfb'] = $pfb;
		$fh = fopen('php://memory', 'w+');
		fwrite($fh, $feed);
		rewind($fh);
		$result = $site
			? pfb_test_ip_call_site($fh, $a['header'], $a['list'], $a['pftype'], $a['custom'], $a['pfbcidr'], $a['pfbcidr_v6'], $pfb, 'ALIAS', 'HEADER_ESC', "{$this->dir}/feed")
			: pfb_ip_parse_feed($fh, $a['header'], $a['list'], $a['pftype'], $a['custom'], $a['pfbcidr'], $a['pfbcidr_v6'], $pfb);
		fclose($fh);
		$logs = (string) preg_replace(self::STAMP, '', (string) file_get_contents($fail) . '|' . (string) file_get_contents($main));
		return [$result, $logs];
	}

	/** The call site does what the function does with $a, and a call with $other would have done something else. */
	private function assertIpWired(string $feed, array $a, array $other, string $what): void
	{
		$site = $this->runIp(TRUE, $a, $feed);
		$this->assertSame($this->runIp(FALSE, $a, $feed), $site, "{$what}: the call site does not hand the loop's values to pfb_ip_parse_feed()");
		$this->assertNotSame($this->runIp(FALSE, $other, $feed), $site, "{$what}: the scenario cannot tell the intended argument from the swapped one");
	}

	public function testIpCallSiteHandsTheIpv4LimitToTheIpv4Parameter(): void
	{
		$this->assertIpWired("1.2.3.0/1\n1.2.3.0/12\n", $this->ipArgs(), $this->ipArgs(['pfbcidr' => '48', 'pfbcidr_v6' => '8']), 'IPv4 limit');
	}

	public function testIpCallSiteHandsTheIpv6LimitToTheIpv6Parameter(): void
	{
		$a = $this->ipArgs(['list' => ['vtype' => '_v6']]);
		$this->assertIpWired("2606:4700:4700::/32\n2606:4700:4700::/56\n", $a, ['pfbcidr' => '48', 'pfbcidr_v6' => '8'] + $a, 'IPv6 limit');
	}

	public function testIpCallSiteHandsTheCustomFlagThrough(): void
	{
		$feed = "10.0.0.1\n8.8.8.8\n";
		$this->assertIpWired($feed, $this->ipArgs(['custom' => TRUE]), $this->ipArgs(['custom' => FALSE]), 'custom list');
		$this->assertIpWired($feed, $this->ipArgs(['custom' => FALSE]), $this->ipArgs(['custom' => TRUE]), 'downloaded list');
	}

	public function testIpCallSiteHandsThePftypeThrough(): void
	{
		$feed = "1.2.3.4 5.6.7.8\n"; // the regex parser keeps both addresses, the auto parser the first
		$this->assertIpWired($feed, $this->ipArgs(['pftype' => 'regex']), $this->ipArgs(['pftype' => 'auto']), 'regex parser');
		$this->assertIpWired($feed, $this->ipArgs(['pftype' => 'auto']), $this->ipArgs(['pftype' => 'regex']), 'auto parser');
	}

	public function testIpCallSiteNamesTheFeedByItsHeaderInTheParseErrorLog(): void
	{
		$feed = "999.999.999.999\n";
		$this->assertIpWired($feed, $this->ipArgs(), $this->ipArgs(['header' => 'OTHER']), 'header');
		[, $logs] = $this->runIp(TRUE, $this->ipArgs(), $feed);
		$this->assertStringContainsString(',HEADER,', $logs, 'the parse-error record names the loop\'s header');
	}

	public function testIpCallSiteKeepsEveryKeyOfTheResult(): void
	{
		$a = $this->ipArgs(['list' => ['vtype' => '_v6']]);
		[$result] = $this->runIp(TRUE, $a, "2001:db8::1\n999.999.999.999\n2606:4700:4700::1111\n");
		$this->assertSame(['ip_data' => "2606:4700:4700::1111\n", 'ip_suppressed' => TRUE, 'parse_fail' => 1], $result);
	}

	/** One DNSBL feed through the call site or the function: what came back, the rows written, and the feed state. @return array{0: mixed, 1: string, 2: array<string, mixed>} */
	private function runDnsbl(bool $site, string $feed, array $ctxOver = []): array
	{
		$main = "{$this->dir}/main.log";
		file_put_contents($main, '');
		$GLOBALS['pfb'] = ['log' => $main, 'errlog' => "{$this->dir}/err.log", 'supp' => PfbToggle::Off];
		$fh = fopen('php://memory', 'w+');
		fwrite($fh, $feed);
		rewind($fh);
		$out = fopen('php://memory', 'w+');
		$state = pfb_dnsbl_parse_state();
		$ctx = $ctxOver + ['header' => 'HEADER', 'custom' => FALSE, 'dnsbl_ip' => TRUE, 'lenient' => TRUE, 'parse_err' => "{$this->dir}/parse.err"];
		$result = $site ? pfb_test_dnsbl_call_site($fh, $out, $state, $ctx, 'ALIAS') : pfb_dnsbl_parse_feed($fh, $out, $state, $ctx)['rows'];
		rewind($out);
		$rows = (string) stream_get_contents($out);
		fclose($fh);
		fclose($out);
		return [$result, $rows, $state];
	}

	public function testDnsblCallSiteKeepsTheRowCountAndFillsTheOutputAndState(): void
	{
		$feed = "example.org\n1.2.3.4\nexample.net\ninvalid_domain\n";
		$site = $this->runDnsbl(TRUE, $feed);
		$this->assertSame($this->runDnsbl(FALSE, $feed), $site, 'the call site does not hand the loop\'s values to pfb_dnsbl_parse_feed()');
		$this->assertSame(2, $site[0], 'the loop keeps the number of rows written (its `!empty()` tests whether the feed had any)');
		$this->assertSame("[\"d\",\"example.org\"]\n[\"d\",\"example.net\"]\n", $site[1], 'the rows go to the stream the loop opened for the .bk');
		$this->assertSame(['1.2.3.4'], $site[2]['ip4'], 'the IPs found accumulate in the loop\'s state');
	}

	public function testDnsblCallSiteIsTheRowCountNotTheStopFlag(): void
	{
		// An empty feed and one that ends at the hpHosts marker: the stop flag is a bool, the row count an int, never alike.
		foreach (["# nothing\n", "# Title: hpHosts\nexample.org\n# Append critical updates below\nexample.net\n"] as $feed) {
			$site = $this->runDnsbl(TRUE, $feed);
			$this->assertSame($this->runDnsbl(FALSE, $feed), $site);
			$this->assertIsInt($site[0]);
		}
	}
}
