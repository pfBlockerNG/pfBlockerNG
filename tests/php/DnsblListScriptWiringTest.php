<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/** DNSBLIP transforms must preserve the feed parser's observable counts. */
#[CoversFunction('pfb_dnsbl_abp_extract_ip')]
#[CoversFunction('pfb_dnsbl_collect_feed_ip')]
#[CoversFunction('pfb_list_pre_script_run')]
final class DnsblListScriptWiringTest extends TestCase
{
	private string $tmp;
	/** @var array<string, mixed> */
	private array $originalPfb;
	private bool $hadPfb;

	protected function setUp(): void
	{
		$this->tmp = sys_get_temp_dir() . '/pfb_dnsbl_script_' . getmypid() . '_' . bin2hex(random_bytes(4));
		$this->assertTrue(mkdir($this->tmp, 0700, TRUE));
		$this->hadPfb = array_key_exists('pfb', $GLOBALS);
		$this->originalPfb = $GLOBALS['pfb'] ?? [];
		$GLOBALS['pfb'] = array_merge($GLOBALS['pfb'] ?? [], ['supp' => PfbToggle::Off]);
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

	private function makeScript(string $name, string $body): string
	{
		$path = "{$this->tmp}/{$name}";
		file_put_contents($path, "#!/bin/sh\n{$body}\n");
		chmod($path, 0755);
		return $path;
	}

	/** @return list<string> */
	private function mixedFeedLines(): array
	{
		return [
			'example.com', 'sub.example.org', '192.0.2.10', '198.51.100.20',
			'2001:db8::1', '2001:db8::dead:beef', '||ads.example.net^',
			'@@||allow.example.net^', 'another-domain.test', '203.0.113.5',
			'||192.0.2.9^', '||2001:db8::9^',
		];
	}

	/** @return array{v4:int,v6:int} */
	private function collectIpCounts(string $content): array
	{
		$ip4 = [];
		$ip6 = [];
		foreach (preg_split('/\R/', $content) as $line) {
			if ($line === '') {
				continue;
			}
			$abpIp = pfb_dnsbl_abp_extract_ip($line);
			if ($abpIp !== '') {
				pfb_dnsbl_collect_feed_ip($abpIp, $abpIp, FALSE, $ip4, $ip6);
				continue;
			}
			pfb_dnsbl_collect_feed_ip($line, $line, FALSE, $ip4, $ip6);
		}
		return ['v4' => count($ip4), 'v6' => count($ip6)];
	}

	public function testIdentityPreScriptPreservesDnsblipExtractionCounts(): void
	{
		$content = implode("\n", $this->mixedFeedLines()) . "\n";
		$before  = $this->collectIpCounts($content);
		$this->assertSame(4, $before['v4']);
		$this->assertSame(3, $before['v6']);

		$norm   = "{$this->tmp}/feed.norm";
		$staged = "{$this->tmp}/feed.pre";
		file_put_contents($norm, $content);
		$script = $this->makeScript('identity.sh', 'exit 0');
		$result = pfb_list_pre_script_run($norm, $staged, $script, 'identity.sh', 'MyFeed', escapeshellarg($staged) . ' dnsbl', '');

		$this->assertTrue($result['ok']);
		$after = $this->collectIpCounts((string) file_get_contents($result['path']));
		$this->assertSame($before, $after);
	}

	public function testStrippingPreScriptShrinksDnsblipExtractionCounts(): void
	{
		$content = implode("\n", $this->mixedFeedLines()) . "\n";
		$before  = $this->collectIpCounts($content);
		$norm    = "{$this->tmp}/feed.norm";
		$staged  = "{$this->tmp}/feed.pre";
		file_put_contents($norm, $content);
		$script = $this->makeScript('strip.sh', "grep -Ev '^(\\|\\|)?[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+\\^?\$|^(\\|\\|)?[0-9a-fA-F:]+\\^?\$' \"\$1\" > \"\$1.tmp\" && mv \"\$1.tmp\" \"\$1\"");
		$result = pfb_list_pre_script_run($norm, $staged, $script, 'strip.sh', 'MyFeed', escapeshellarg($staged) . ' dnsbl', '');

		$this->assertTrue($result['ok']);
		$after = $this->collectIpCounts((string) file_get_contents($result['path']));
		$this->assertLessThan($before['v4'], $after['v4']);
		$this->assertLessThan($before['v6'], $after['v6']);
		$this->assertSame(0, $after['v4']);
		$this->assertSame(0, $after['v6']);
	}

	public function testHelpNoteRemainsDnsblOnly(): void
	{
		$options = ['' => 'None', 'pre.sh' => 'pre.sh'];
		$dnsbl   = pfb_category_script_pre_settings('dnsbl', $options);
		$ip      = pfb_category_script_pre_settings('ip', $options);

		$this->assertSame(2, $dnsbl['size']);
		$this->assertSame(2, $ip['size']);
		$this->assertStringContainsString('DNSBLIP', $dnsbl['help']);
		$this->assertStringContainsString('silently shrink', $dnsbl['help']);
		$this->assertStringNotContainsString('DNSBLIP', $ip['help']);
		$this->assertStringNotContainsString('silently shrink', $ip['help']);
	}
}
