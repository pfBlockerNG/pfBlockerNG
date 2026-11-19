<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #4071 -- edge cases of the CrowdSec Settings save and apply (docs/specs/crowdsec-integration.md, D2-D4).
 *
 *   - turning the bouncer off stops the service even while its own pidfile names no live bouncer: daemon(8)'s supervisor
 *     restarts a bouncer that exited 5 s later (-R 5), and would go on restarting it against a removed config file;
 *   - the page refuses every URL the bouncer's own check (`pfb_crowdsec -t`, go/pfb_crowdsec config.go) refuses, so a save
 *     never reports success for a config the bouncer will not start with;
 *   - the config file is only ever renamed into place from its own folder: when no temporary file can be made there,
 *     the write fails and leaves nothing behind;
 *   - a repeated interface is stored once.
 */
#[CoversFunction('pfb_crowdsec_apply')]
#[CoversFunction('pfb_crowdsec_validate')]
#[CoversFunction('pfb_crowdsec_config_write')]
final class CrowdsecHardeningTest extends TestCase
{
	private const SECTION = 'installedpackages/pfblockerngcrowdsec/config/0';

	private string $dir = '';
	private mixed $savedConfig;
	private mixed $savedPfb;

	protected function setUp(): void
	{
		$this->savedConfig = $GLOBALS['config'] ?? NULL;
		$this->savedPfb = $GLOBALS['pfb'] ?? NULL;
		$this->dir = sys_get_temp_dir() . '/pfb_crowdsec_hard_' . bin2hex(random_bytes(6));
		$this->assertTrue(mkdir($this->dir, 0755, TRUE));
		$GLOBALS['config'] = [];
		$GLOBALS['pfb']['crowdsec_config'] = "{$this->dir}/pfb_crowdsec.json";
		$GLOBALS['pfb_test_service_calls'] = [];
		$GLOBALS['pfb_test_service_running'] = ['pfb_crowdsec' => FALSE];
	}

	protected function tearDown(): void
	{
		@chmod($this->dir, 0755);
		rmdir_recursive($this->dir);
		$GLOBALS['config'] = $this->savedConfig;
		$GLOBALS['pfb'] = $this->savedPfb;
		unset($GLOBALS['pfb_test_service_calls'], $GLOBALS['pfb_test_service_running']);
	}

	public function testTurningOffStopsTheServiceEvenWhenNoBouncerIsAliveBetweenRestarts(): void
	{
		$GLOBALS['pfb']['enable'] = PfbToggle::Off;
		config_set_path(self::SECTION, ['enable' => 'on', 'lapi_url' => 'https://lapi.example.net', 'api_key' => 'KEY-1']);
		file_put_contents($GLOBALS['pfb']['crowdsec_config'], "{}\n");
		$this->assertFalse(is_service_running('pfb_crowdsec'), 'before-state: the bouncer pidfile names no live process');

		$this->assertTrue(pfb_crowdsec_apply());

		$this->assertSame([['stop_service', 'pfb_crowdsec']], $GLOBALS['pfb_test_service_calls'], 'the supervisor is stopped too');
		$this->assertFileDoesNotExist($GLOBALS['pfb']['crowdsec_config']);
	}

	/** @return iterable<string, array{string}> URLs go/pfb_crowdsec's config check refuses */
	public static function daemonRefuses(): iterable
	{
		yield 'bad escape'            => ['http://lapi.example/%zz'];
		yield 'lone percent'          => ['http://lapi.example/%'];
		yield 'escape in the host'    => ['http://lapi%41.example/'];
		yield 'unclosed IPv6 bracket' => ['http://[::1/'];
		yield 'user without password' => ['https://user@lapi.example/'];
	}

	#[DataProvider('daemonRefuses')]
	public function testAUrlTheBouncerRefusesIsRefusedOnSave(string $url): void
	{
		$out = pfb_crowdsec_validate(['enable' => 'on', 'lapi_url' => $url, 'api_key' => 'KEY-1', 'log_level' => 'info',
			'rules_all_interfaces' => 'on'], '', ['wan']);
		$this->assertCount(1, $out['errors'], $url);
		$this->assertStringContainsString('LAPI URL', $out['errors'][0]);
	}

	public function testAValidEscapeAndAnIpv6ZoneArePlainUrls(): void
	{
		foreach (['http://lapi.example/a%20b', 'http://[fe80::1%25em0]:8080/'] as $url) {
			$out = pfb_crowdsec_validate(['lapi_url' => $url, 'log_level' => 'info', 'rules_all_interfaces' => 'on'], '', ['wan']);
			$this->assertSame([], $out['errors'], $url);
		}
	}

	public function testNoTemporaryFileOutsideItsFolderIsEverRenamedIntoPlace(): void
	{
		if (function_exists('posix_getuid') && posix_getuid() === 0) {
			$this->markTestSkipped('root writes into a read-only folder');
		}
		$this->assertTrue(chmod($this->dir, 0555));
		$before = glob(sys_get_temp_dir() . '/.pfb_crowdsec.*') ?: [];

		$this->assertFalse(pfb_crowdsec_config_write("{}\n", "{$this->dir}/pfb_crowdsec.json"));

		$this->assertFileDoesNotExist("{$this->dir}/pfb_crowdsec.json");
		$this->assertSame($before, glob(sys_get_temp_dir() . '/.pfb_crowdsec.*') ?: [], 'no temporary file is left in the fallback folder');
	}

	public function testARepeatedInterfaceIsStoredOnce(): void
	{
		$out = pfb_crowdsec_validate(['log_level' => 'info', 'rules_interfaces' => ['lan', 'wan', 'lan']], '', ['wan', 'lan']);
		$this->assertSame([], $out['errors']);
		$this->assertSame('lan,wan', $out['values']['rules_interfaces']);
	}
}
