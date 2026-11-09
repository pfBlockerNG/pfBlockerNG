<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class AlertsTransportTest extends TestCase
{
	private array $saved;

	public static function setUpBeforeClass(): void
	{
		require_once __DIR__ . '/AlertsPageLoader.php';
		pfb_test_load_alerts_page_functions();
	}

	protected function setUp(): void
	{
		$this->saved = $GLOBALS;
		$GLOBALS['pfb'] = ['filterlogentries' => false, 'unidnsbl' => 'none', 'unidnsbl2' => 'none'];
		$GLOBALS['local_hosts'] = ['10.0.0.5' => ''];
		$GLOBALS['dnsbl_int'] = [];
		$GLOBALS['filterfieldsarray'] = [];
		$GLOBALS['clists'] = ['dnsbl' => ['options' => []], 'dnsblwhitelist' => ['data' => []]];
		$GLOBALS['dnsbl_unlock'] = [];
		$GLOBALS['dup'] = ['DNSBL' => 0];
		$GLOBALS['counter'] = ['DNSBL' => 0, 'DNS' => 0, 'Unified' => 0];
		$GLOBALS['pfbentries'] = 1000;
		$GLOBALS['skipcount'] = 0;
		$GLOBALS['dnsblfilterlimit'] = $GLOBALS['dnsfilterlimit'] = false;
		$GLOBALS['dnsblfilterlimitentries'] = $GLOBALS['dnsfilterlimitentries'] = 100;
	}

	protected function tearDown(): void
	{
		foreach (array_diff_key($GLOBALS, $this->saved) as $key => $_) {
			unset($GLOBALS[$key]);
		}
		foreach ($this->saved as $key => $value) {
			$GLOBALS[$key] = $value;
		}
	}

	private function row(bool $reply): array
	{
		return $reply
			? ['DNS-reply', '2026-01-01 00:00:00', 'reply', 'A', 'A', '123', 'a,"b.test', '10.0.0.5', '1.2.3.4', 'US']
			: ['DNSBL-Full', '2026-01-01 00:00:00', 'a,"b.test', '10.0.0.5', '', 'DNSBL', 'Group', 'a,"b.test', 'Feed', '0', 'A'];
	}

	private function render(bool $reply, string $mode, array $row): string
	{
		ob_start();
		$reply ? convert_dns_reply_log($mode, $row) : convert_dnsbl_log($mode, $row);
		return (string) ob_get_clean();
	}

	public function testCanonicalTransportColumnsAndFiltersPreserveLoggedFields(): void
	{
		foreach ([false, true] as $reply) {
			foreach (['Reports', 'Unified'] as $mode) {
				foreach (['TCP', 'UDP', 'DoT', 'DoH', 'DoQ'] as $transport) {
					$row = [...$this->row($reply), $transport];
					$GLOBALS['pfb']['filterlogentries'] = true;
					$GLOBALS['filterfieldsarray'][$reply ? 2 : 1] = [$reply ? 90 : 21 => '^' . $transport . '$'];
					$html = $this->render($reply, $mode, $row);
					$this->assertStringContainsString('<td>' . $transport . '</td>', $html);
					$this->assertStringContainsString(pfb_hsc('a,"b.test'), $html);
					$this->assertStringContainsString('10.0.0.5', $html);
					if ($reply) {
						$this->assertStringContainsString('123', $html);
						$this->assertStringContainsString('1.2.3.4', $html);
						$this->assertStringContainsString('<td>US</td>', $html);
					}
					$GLOBALS['filterfieldsarray'][$reply ? 2 : 1] = [$reply ? 90 : 21 => '^—$'];
					$this->assertSame('', $this->render($reply, $mode, $row));
				}
			}
		}
	}

	public function testUnavailableAndHostileTransportUsesDashWithoutMarkup(): void
	{
		foreach ([false, true] as $reply) {
			foreach (['Reports', 'Unified'] as $mode) {
				foreach ([null, '', [], 1, '<script>x</script>', 'DoH,UDP', "UDP\r\n", "\tUDP", ' UDP ', str_repeat('x', 10000), 'ＤｏＨ'] as $value) {
					$row = $this->row($reply);
					if ($value !== null) {
						$row[] = $value;
					}
					$GLOBALS['pfb']['filterlogentries'] = true;
					$GLOBALS['filterfieldsarray'][$reply ? 2 : 1] = [$reply ? 90 : 21 => '^—$'];
					$html = $this->render($reply, $mode, $row);
					$this->assertStringContainsString('<td>—</td>', $html);
					$this->assertStringNotContainsString('<script>', $html);
				}
			}
		}
	}

	public function testReceivingEndpointsPreserveEventSnapshotAndAnswerAcrossReportsAndFilters(): void
	{
		foreach ([false, true] as $reply) {
			foreach (['Reports', 'Unified'] as $mode) {
				foreach (['TCP', 'UDP', 'DoT', 'DoH', 'DoQ'] as $transport) {
					foreach (['192.0.2.53', '2001:db8::53'] as $ip) {
						$interface = 'LAN, "旧" <b>event</b>';
						$row = [...$this->row($reply), $transport, $ip, $interface];
						$stream = fopen('php://temp', 'w+');
						fputcsv($stream, $row, ',', '"', '');
						rewind($stream);
						$fields = fgetcsv($stream, 0, ',', '"', '');
						fclose($stream);
						$GLOBALS['dnsbl_int'] = [$ip => 'renamed-today'];
						$GLOBALS['pfb']['filterlogentries'] = true;
						$keys = $reply ? [91, 92] : [22, 23];
						$GLOBALS['filterfieldsarray'][$reply ? 2 : 1] = [$keys[0] => '^' . preg_quote($ip, '/') . '$', $keys[1] => '^' . preg_quote($interface, '/') . '$'];
						$html = $this->render($reply, $mode, $fields);
						$this->assertStringContainsString('<td>' . $ip . '</td>', $html);
						$this->assertStringContainsString('<td>' . pfb_hsc($interface) . '</td>', $html);
						$this->assertStringNotContainsString('<b>event</b>', $html);
						$this->assertStringNotContainsString('renamed-today', $html);
						$this->assertSame($mode === 'Unified' ? 12 : ($reply ? 13 : 9), substr_count($html, '<td'));
						$this->assertStringContainsString('10.0.0.5', $html);
						if ($reply) {
							$this->assertStringContainsString('<td title="">1.2.3.4</td>', $html);
						}
						foreach ($keys as $key) {
							$GLOBALS['filterfieldsarray'][$reply ? 2 : 1] = [$key => '^not-this-endpoint$'];
							$this->assertSame('', $this->render($reply, $mode, $fields));
						}
					}
				}
			}
		}
	}

	public function testHistoricalAndInvalidReceivingEndpointsRemainUnavailable(): void
	{
		foreach ([false, true] as $reply) {
			foreach (['Reports', 'Unified'] as $mode) {
				$base = $this->row($reply);
				$rows = [$base, [...$base, 'UDP']];
				if (!$reply) {
					$rows[] = array_slice($base, 0, 10);
				}
				foreach (['', '0.0.0.0', '::', '192.0.2.1/32', '[::1]', 'fe80::1%em0', '<script>', "192.0.2.1\0", []] as $bad) {
					$rows[] = [...$base, 'UDP', $bad, 'LAN'];
				}
				$rows[] = [...$base, 'UDP', '192.0.2.53', "bad\ninterface"];
				foreach ($rows as $row) {
					$keys = $reply ? [91, 92] : [22, 23];
					$GLOBALS['pfb']['filterlogentries'] = true;
					$GLOBALS['filterfieldsarray'][$reply ? 2 : 1] = [$keys[1] => '^—$'];
					$html = $this->render($reply, $mode, $row);
					$this->assertStringContainsString('<td>—</td>', $html);
					$this->assertSame($mode === 'Unified' ? 12 : ($reply ? 13 : 9), substr_count($html, '<td'));
					$this->assertStringNotContainsString('<script>', $html);
				}
			}
		}
	}

	public function testUnsafeReceivingInterfaceIsUnavailableWithoutLosingListenerIp(): void
	{
		foreach ([FALSE, TRUE] as $reply) {
			foreach (['Reports', 'Unified'] as $mode) {
				foreach (["\u{0080}", "\u{0085}", "\u{009f}", "\u{200D}", "\u{200E}", "\u{2028}", "\u{2029}", "\u{FEFF}"] as $control) {
					$row = [...$this->row($reply), 'UDP', '192.0.2.53', 'bad' . $control . 'interface'];
					$GLOBALS['pfb']['filterlogentries'] = TRUE;
					$GLOBALS['filterfieldsarray'][$reply ? 2 : 1] = [$reply ? 92 : 23 => '^—$'];
					$html = $this->render($reply, $mode, $row);
					$this->assertStringContainsString('<td>192.0.2.53</td>', $html);
					$this->assertStringContainsString('<td>—</td>', $html);
					$this->assertSame($mode === 'Unified' ? 12 : ($reply ? 13 : 9), substr_count($html, '<td'));
				}
			}
		}
	}

}
