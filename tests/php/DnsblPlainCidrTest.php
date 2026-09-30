<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3366: a scheme-less DNSBL line that is exactly '<canonical IP>/<digits>' is a CIDR the
 * DNSBL IP path cannot honour; collecting it as the bare address blocks one host while the feed
 * claims a whole network. It is rejected into the parse-error log instead, in both parse modes,
 * whatever the DNSBL IP setting.
 *
 * The feed loop is not unit-reachable, so the hosts-line + plain-line region is eval-extracted
 * verbatim from the REAL source (same pattern as DnsblNumericHostTest).
 */
#[CoversFunction('pfb_dnsbl_extract_host')]
final class DnsblPlainCidrTest extends TestCase
{
	private static string $hostsRegion;

	private string $failLog = '';
	private string $mainLog = '';
	private mixed $savedPfb = NULL;

	public static function setUpBeforeClass(): void
	{
		$src = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc');
		if ($src === FALSE) {
			throw new RuntimeException('test bootstrap: failed to read pfblockerng_apply.inc');
		}
		if (!preg_match('/(\t+\/\/ Typical Host Feed format.*?@fwrite\(\$dhandle, \$domain_data\);)/s', $src, $hosts)) {
			throw new RuntimeException('test bootstrap: DNSBL hosts-line region not found');
		}
		self::$hostsRegion = "\$rev_format = FALSE;\nforeach ([0] as \$pfb_test_iter) {\n{$hosts[1]}\n}\n";
	}

	protected function setUp(): void
	{
		$this->failLog = (string) tempnam(sys_get_temp_dir(), 'pfb_cidr_fail_');
		$this->mainLog = (string) tempnam(sys_get_temp_dir(), 'pfb_cidr_log_');
		$this->savedPfb = $GLOBALS['pfb'] ?? NULL;
	}

	protected function tearDown(): void
	{
		@unlink($this->failLog);
		@unlink($this->mainLog);
		$GLOBALS['pfb'] = $this->savedPfb;
	}

	/** @return array{ip4: list<string>, ip6: list<string>, rows: list<mixed>, fail: string} */
	private function runRegion(string $feedLine, bool $lenient, string $dnsblIp): array
	{
		$pfb = $GLOBALS['pfb'] = [
			'dnsbl_lenient'   => $lenient ? PfbToggle::On : PfbToggle::Off,
			'dnsbl_parse_err' => $this->failLog,
			'dnsbl_ip'        => $dnsblIp,
			'supp'            => PfbToggle::Off,
			'log'             => $this->mainLog,
		];
		$line = $feedLine;
		$oline = $feedLine;
		$header = 'testfeed';
		$dnsbl_lineno = 1;
		$pfb_scheme_skipped = 0;
		$domain_data_ip = [];
		$domain_data_ip6 = [];
		$ipcount = 0;
		$custom = TRUE;
		$dnsbl_skip = [];
		$dhandle = fopen('php://memory', 'w+');
		eval(self::$hostsRegion);
		rewind($dhandle);
		$rows = [];
		while (($row = fgets($dhandle)) !== FALSE) {
			$rows[] = json_decode($row, TRUE, 512, JSON_THROW_ON_ERROR);
		}
		fclose($dhandle);
		return [
			'ip4'  => $domain_data_ip,
			'ip6'  => $domain_data_ip6,
			'rows' => $rows,
			'fail' => (string) file_get_contents($this->failLog),
		];
	}

	/** @return array<string, array{string, bool, string}> */
	public static function rejectProvider(): array
	{
		$rows = [];
		foreach (['192.168.1.0/24', '2001:db8::/32', '::ffff:192.168.1.0/120', '0.0.0.0 192.168.1.0/24'] as $line) {
			foreach ([TRUE, FALSE] as $lenient) {
				foreach (['Deny_Both', 'Disabled'] as $ip) {
					$rows["{$line} " . ($lenient ? 'lenient' : 'strict') . " {$ip}"] = [$line, $lenient, $ip];
				}
			}
		}
		return $rows;
	}

	#[DataProvider('rejectProvider')]
	public function testPlainCidrLineCollectsNothingAndWritesParseError(string $feedLine, bool $lenient, string $ip): void
	{
		$out = $this->runRegion($feedLine, $lenient, $ip);

		$this->assertSame([[], [], []], [$out['ip4'], $out['ip6'], $out['rows']]);
		$this->assertStringContainsString(
			trim(substr($feedLine, (int) strrpos($feedLine, ' '))),
			$out['fail'],
			'the rejected line must be in the DNSBL parse-error log'
		);
	}

	/** @return array<string, array{string, bool, list<string>}> */
	public static function controlProvider(): array
	{
		$rows = [];
		foreach ([TRUE, FALSE] as $lenient) {
			$m = $lenient ? 'lenient' : 'strict';
			$rows["192.168.1.0/ {$m}"] = ['192.168.1.0/', $lenient, ['192.168.1.0']];
			$rows["3232235876/ {$m}"] = ['3232235876/', $lenient, ['192.168.1.100']];
			$rows["http://192.168.1.0/24 {$m}"] = ['http://192.168.1.0/24', $lenient, ['192.168.1.0']];
		}
		return $rows;
	}

	/** @param list<string> $expected */
	#[DataProvider('controlProvider')]
	public function testNearMissShapesAreStillCollected(string $feedLine, bool $lenient, array $expected): void
	{
		$out = $this->runRegion($feedLine, $lenient, 'Deny_Both');

		$this->assertSame($expected, $out['ip4']);
		$this->assertSame('', $out['fail']);
	}
}
