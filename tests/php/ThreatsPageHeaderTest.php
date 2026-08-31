<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** Runtime coverage for the Threats page request and head.inc boundary. */
final class ThreatsPageHeaderTest extends TestCase
{
	private const LINKS = [
		'',
		'/pfblockerng/pfblockerng_general.php',
		'/pfblockerng/pfblockerng_alerts.php',
		'@self',
	];

	private string $shim = '';

	protected function setUp(): void
	{
		$this->shim = sys_get_temp_dir() . '/pfb_threats_' . bin2hex(random_bytes(8));
		$this->assertTrue(mkdir($this->shim, 0700, TRUE));

		$this->assertNotFalse(file_put_contents($this->shim . '/guiconfig.inc', <<<'PHP'
<?php
$GLOBALS['pfb_threats_auth_loaded'] = TRUE;
if (!function_exists('print_info_box')) {
	function print_info_box($message): void
	{
		echo 'PFB_INFO:' . $message;
	}
}
PHP));
		$this->assertNotFalse(file_put_contents($this->shim . '/head.inc', <<<'PHP'
<?php
$state = [
	'auth_loaded' => $GLOBALS['pfb_threats_auth_loaded'] ?? FALSE,
	'pgtitle' => $pgtitle ?? NULL,
	'pglinks' => $pglinks ?? NULL,
	'shortcut_section' => $shortcut_section ?? NULL,
];
echo 'PFB_HEAD_STATE:' . base64_encode(json_encode($state, JSON_THROW_ON_ERROR)) . "\n";
PHP));
		$this->assertNotFalse(file_put_contents($this->shim . '/foot.inc', "<?php echo '\nPFB_FOOT';"));
	}

	protected function tearDown(): void
	{
		foreach (glob($this->shim . '/*') ?: [] as $path) {
			@unlink($path);
		}
		@rmdir($this->shim);
	}

	/** @return iterable<string,array{0:array<string,string>,1:string}> */
	public static function validLookupProvider(): iterable
	{
		yield 'host' => [['host' => '203.0.113.5'], 'Threat Source IP Lookup'];
		yield 'domain' => [['domain' => 'lookup.example.com'], 'Threat Domain Lookup'];
		yield 'port' => [['port' => '8443'], 'Threat Port Lookup'];
	}

	#[DataProvider('validLookupProvider')]
	public function testValidLookupSuppliesTitleAndLinksBeforeHead(array $request, string $lookupTitle): void
	{
		$result = $this->request($request);

		$this->assertSame(0, $result['status'], $result['stderr']);
		$this->assertSame('', $result['stderr'], $result['stderr']);
		$this->assertStringStartsWith(
			'PFB_HEAD_STATE:',
			$result['stdout'],
			'valid request parsing must not emit output before the authenticated page header'
		);
		$state = $this->headState($result['stdout']);
		$this->assertTrue($state['auth_loaded'], 'guiconfig authentication must load before head.inc');
		$this->assertSame(['Firewall', 'pfBlockerNG', 'Alerts', $lookupTitle], $state['pgtitle']);
		$this->assertSame(self::LINKS, $state['pglinks']);
		$this->assertSame('pfblockerng', $state['shortcut_section']);
		$this->assertStringContainsString('PFB_FOOT', $result['stdout']);
		$this->assertStringContainsString('PFB_AFTER_PAGE', $result['stdout']);
	}

	/** @return iterable<string,array{0:array<string,mixed>,1:string}> */
	public static function rejectedLookupProvider(): iterable
	{
		yield 'invalid host' => [['host' => 'not-an-ip'], 'Invalid IP Address, cannot proceed!'];
		yield 'invalid domain' => [['domain' => 'not a domain'], 'Invalid Domain name, cannot proceed!'];
		yield 'invalid port' => [['port' => '99999'], 'Invalid Port cannot proceed!'];
		yield 'array port' => [['port' => ['8443']], 'Invalid Port cannot proceed!'];
		yield 'missing request' => [[], 'No Requests found, cannot proceed!'];
	}

	#[DataProvider('rejectedLookupProvider')]
	public function testRejectedLookupKeepsMessageAndExitsBeforeHead(array $request, string $message): void
	{
		$result = $this->request($request);

		$this->assertSame(0, $result['status'], $result['stderr']);
		$this->assertSame('', $result['stderr'], $result['stderr']);
		$this->assertSame('PFB_INFO:' . $message, $result['stdout']);
		$this->assertStringNotContainsString('PFB_HEAD_STATE:', $result['stdout']);
		$this->assertStringNotContainsString('PFB_FOOT', $result['stdout']);
		$this->assertStringNotContainsString('PFB_AFTER_PAGE', $result['stdout']);
	}

	/** @return array{auth_loaded:bool,pgtitle:list<string>,pglinks:list<string>,shortcut_section:string} */
	private function headState(string $stdout): array
	{
		$line = strtok($stdout, "\n");
		$this->assertIsString($line);
		$encoded = substr($line, strlen('PFB_HEAD_STATE:'));
		$decoded = base64_decode($encoded, TRUE);
		$this->assertIsString($decoded);
		$state = json_decode($decoded, TRUE, 512, JSON_THROW_ON_ERROR);
		$this->assertIsArray($state);
		return $state;
	}

	/** @param array<string,mixed> $request @return array{status:int,stdout:string,stderr:string} */
	private function request(array $request): array
	{
		$root = var_export(dirname(__DIR__, 2), TRUE);
		$page = var_export(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_threats.php', TRUE);
		$shim = var_export($this->shim, TRUE);
		$script = <<<PHP
\$_REQUEST = json_decode(stream_get_contents(STDIN), TRUE, 512, JSON_THROW_ON_ERROR);
require {$root} . '/tests/php/bootstrap.php';
error_reporting(E_ERROR | E_PARSE);
set_include_path({$shim} . PATH_SEPARATOR . get_include_path());
require {$page};
echo "\nPFB_AFTER_PAGE";
PHP;
		$descriptors = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
		$process = proc_open([PHP_BINARY, '-r', $script], $descriptors, $pipes);
		$this->assertIsResource($process);
		fwrite($pipes[0], json_encode($request, JSON_THROW_ON_ERROR));
		fclose($pipes[0]);
		$stdout = stream_get_contents($pipes[1]);
		$stderr = stream_get_contents($pipes[2]);
		fclose($pipes[1]);
		fclose($pipes[2]);
		$status = proc_close($process);

		return ['status' => $status, 'stdout' => (string) $stdout, 'stderr' => (string) $stderr];
	}
}
