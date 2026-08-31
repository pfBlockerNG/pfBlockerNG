<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

#[CoversFunction('pfb_determine_list_detail')]
#[CoversFunction('pfb_logger')]
final class UpdateLogAlignmentTest extends TestCase
{
	/** @var array<string,array{bool,mixed}> */
	private array $saved = [];
	private string $log;

	protected function setUp(): void
	{
		foreach (['pfb', 'pfbarr', 'config'] as $name) {
			$this->saved[$name] = [array_key_exists($name, $GLOBALS), $GLOBALS[$name] ?? NULL];
		}

		$this->log = (string) tempnam(sys_get_temp_dir(), 'pfb_update_alignment_');
		$this->assertNotSame('', $this->log, 'failed to create update-log fixture');
		$GLOBALS['pfb']['log'] = $this->log;
		$GLOBALS['pfb']['denydir'] = '/tmp/pfb_deny';
		$GLOBALS['pfb']['origdir'] = '/tmp/pfb_orig';
		$GLOBALS['pfb']['nativedir'] = '/tmp/pfb_native';
		$GLOBALS['pfb']['reuse'] = '';
		$GLOBALS['pfb']['runlog_active'] = FALSE;

		$off = [];
		foreach (['autoproto', 'autonot', 'autoaddrnot', 'agateway', 'autoports', 'autoaddr'] as $key) {
			$off["{$key}_in"] = '';
			$off["{$key}_out"] = '';
		}
		$GLOBALS['config'] = ['installedpackages' => ['pfblockerngtest' => ['config' => [0 => $off]]]];
	}

	protected function tearDown(): void
	{
		if (is_file($this->log)) {
			$this->assertTrue(unlink($this->log), 'failed to remove update-log fixture');
		}
		foreach ($this->saved as $name => [$existed, $value]) {
			if ($existed) {
				$GLOBALS[$name] = $value;
			} else {
				unset($GLOBALS[$name]);
			}
		}
	}

	/** @return list<string> */
	private function loggedLines(array $headers): array
	{
		foreach ($headers as $header) {
			$detail = pfb_determine_list_detail('Deny_Both', $header, 'pfblockerngtest', '0');
			pfb_logger("[ {$header} ]{$detail['logtab']} exists.\n", 1);
		}
		return explode("\n", rtrim((string) file_get_contents($this->log), "\n"));
	}

	public function testFeedStatusesAlignAcrossSupportedHeaderLengths(): void
	{
		$headers = [
			'abc',
			'abcd',
			str_repeat('a', 11),
			str_repeat('a', 12),
			str_repeat('a', 19),
			str_repeat('a', 20),
			str_repeat('a', 27),
			str_repeat('a', 28),
		];

		foreach ($this->loggedLines($headers) as $line) {
			$this->assertSame(53, strpos($line, 'exists.'), "status must start in column 54: {$line}");
		}
	}

	public function testLongFeedHeaderKeepsOneSeparatingSpace(): void
	{
		$header = str_repeat('a', 29);
		[$line] = $this->loggedLines([$header]);

		$this->assertStringContainsString("[ {$header} ] exists.", $line);
	}
}
