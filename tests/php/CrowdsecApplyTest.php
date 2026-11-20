<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #4071 -- the bouncer's config file and the "should run" decision (docs/specs/crowdsec-integration.md, D3 and D4).
 *
 * Pinned here:
 *   - the config file carries exactly the D3 values, is mode 0600 and replaced atomically (temporary file in the same folder,
 *     renamed over it), and a failed write leaves neither a temporary file nor a changed file;
 *   - pfb_crowdsec_apply(), which the Settings save and the other triggers call (CrowdsecTriggersTest): while the bouncer should run it
 *     writes the file and starts the service, restarts it when the file changed and leaves it alone otherwise; while it should
 *     not run it stops the service and removes the file. It answers whether the bouncer's on/off state changed (the caller then
 *     reloads the filter, so that the rules follow);
 *   - pfb_crowdsec_save(): the Settings save stores the section, applies at once, and reloads the filter when the enable or a
 *     rule setting changed, or the bouncer started or stopped, and only then.
 *
 * Off-appliance the services are the pfsense_doubles.php doubles: start/stop/restart are recorded, is_service_running() answers
 * from $GLOBALS['pfb_test_service_running'].
 */
#[CoversFunction('pfb_crowdsec_config_json')]
#[CoversFunction('pfb_crowdsec_config_write')]
#[CoversFunction('pfb_crowdsec_apply')]
#[CoversFunction('pfb_crowdsec_save')]
final class CrowdsecApplyTest extends TestCase
{
	private const SECTION = 'installedpackages/pfblockerngcrowdsec/config/0';
	private const KEY = 'Ab3-the_bouncer.KEY~0123456789';

	private string $dir = '';
	private string $config = '';
	private mixed $savedConfig;
	private mixed $savedPfb;

	protected function setUp(): void
	{
		$this->savedConfig = $GLOBALS['config'] ?? NULL;
		$this->savedPfb = $GLOBALS['pfb'] ?? NULL;
		$this->dir = sys_get_temp_dir() . '/pfb_crowdsec_apply_' . bin2hex(random_bytes(6));
		$this->assertTrue(mkdir("{$this->dir}/etc", 0755, TRUE));
		$this->config = "{$this->dir}/etc/pfb_crowdsec.json";

		$GLOBALS['config'] = [];
		$GLOBALS['pfb']['enable'] = PfbToggle::On;
		$GLOBALS['pfb']['crowdsec_config'] = $this->config;
		$GLOBALS['pfb_test_service_calls'] = [];
		$GLOBALS['pfb_test_service_running'] = ['pfb_crowdsec' => FALSE];
		$GLOBALS['pfb_test_filter_configure_calls'] = 0;
		$GLOBALS['pfb_test_write_config_calls'] = [];
	}

	protected function tearDown(): void
	{
		rmdir_recursive($this->dir);
		$GLOBALS['config'] = $this->savedConfig;
		$GLOBALS['pfb'] = $this->savedPfb;
		unset($GLOBALS['pfb_test_service_calls'], $GLOBALS['pfb_test_service_running'], $GLOBALS['pfb_test_filter_configure_calls'],
			$GLOBALS['pfb_test_write_config_calls']);
	}

	private static function stored(array $over = []): array
	{
		return array_replace(['enable' => 'on', 'lapi_url' => 'https://lapi.example.net:8080', 'api_key' => self::KEY, 'log_level' => 'info',
			'rules_all_interfaces' => 'on', 'rules_interfaces' => '', 'rules_log' => '', 'rules_tag' => '', 'rule_v4' => 'on', 'rule_v6' => 'on'], $over);
	}

	/** @return list<array{0: string, 1: string}> the service calls made for the bouncer */
	private function calls(): array
	{
		return array_values(array_filter($GLOBALS['pfb_test_service_calls'], static fn (array $c): bool => $c[1] === 'pfb_crowdsec'));
	}

	private function mode(string $path): string
	{
		clearstatcache();
		return sprintf('%04o', fileperms($path) & 0777);
	}

	// ---- D3: the file ---------------------------------------------------------------------

	public function testTheFileCarriesExactlyTheD3Values(): void
	{
		config_set_path(self::SECTION, self::stored(['log_level' => 'warning']));
		$json = pfb_crowdsec_config_json(pfb_crowdsec_settings());
		$this->assertSame([
			'api_url'          => 'https://lapi.example.net:8080',
			'api_key'          => self::KEY,
			'update_frequency' => '10s',
			'table_v4'         => 'crowdsec_v4',
			'table_v6'         => 'crowdsec_v6',
			'log_level'        => 'warning',
			'status_file'      => '/var/run/pfb_crowdsec.json',
		], json_decode($json, TRUE, 4, JSON_THROW_ON_ERROR));
	}

	public function testAKeyOfEveryPrintableCharacterSurvivesTheJsonRoundTrip(): void
	{
		$key = implode('', array_map('chr', range(0x21, 0x7e)));
		config_set_path(self::SECTION, self::stored(['api_key' => $key]));
		$this->assertSame($key, json_decode(pfb_crowdsec_config_json(pfb_crowdsec_settings()), TRUE)['api_key']);
	}

	public function testTheWriteLeavesA0600FileAndNoTemporaryFile(): void
	{
		file_put_contents($this->config, "old\n");
		chmod($this->config, 0644);
		$this->assertSame('0644', $this->mode($this->config), 'before-state: a world-readable file');

		$this->assertTrue(pfb_crowdsec_config_write("{\"api_key\":\"secret\"}\n", $this->config));

		$this->assertSame("{\"api_key\":\"secret\"}\n", file_get_contents($this->config));
		$this->assertSame('0600', $this->mode($this->config));
		$this->assertSame(['pfb_crowdsec.json'], array_values(array_diff(scandir("{$this->dir}/etc"), ['.', '..'])), 'only the file itself is left');
	}

	public function testTheWriteReplacesTheFileByRenameNeverInPlace(): void
	{
		file_put_contents($this->config, "old\n");
		$before = fileinode($this->config);
		$link = "{$this->dir}/hardlink";
		$this->assertTrue(link($this->config, $link), 'a second name for the old file');

		$this->assertTrue(pfb_crowdsec_config_write("new\n", $this->config));

		clearstatcache();
		$this->assertNotSame($before, fileinode($this->config), 'a new inode took the name');
		$this->assertSame("old\n", file_get_contents($link), 'the old file was never written into');
	}

	public function testAFailedWriteLeavesNoTemporaryFileAndNoFile(): void
	{
		$target = "{$this->dir}/etc/is_a_directory";
		$this->assertTrue(mkdir("{$target}/inside", 0755, TRUE), 'rename() cannot replace a non-empty directory');

		$this->assertFalse(pfb_crowdsec_config_write("{\"api_key\":\"secret\"}\n", $target));

		$this->assertDirectoryExists("{$target}/inside");
		$this->assertSame(['is_a_directory'], array_values(array_diff(scandir("{$this->dir}/etc"), ['.', '..'])), 'no temporary file is left');
	}

	// ---- D4: should run -------------------------------------------------------------------

	public function testAFirstEnableWritesTheFileAndStartsTheBouncer(): void
	{
		config_set_path(self::SECTION, self::stored());
		$this->assertFileDoesNotExist($this->config, 'before-state: never configured');

		$this->assertTrue(pfb_crowdsec_apply(), 'off -> on is a change');

		$this->assertSame(['start_service', 'pfb_crowdsec'], $this->calls()[0] ?? NULL);
		$this->assertCount(1, $this->calls());
		$this->assertSame('0600', $this->mode($this->config));
		$this->assertSame(self::KEY, json_decode((string) file_get_contents($this->config), TRUE)['api_key']);
	}

	public function testARunningBouncerWithAnUnchangedFileIsLeftAlone(): void
	{
		config_set_path(self::SECTION, self::stored());
		pfb_crowdsec_config_write(pfb_crowdsec_config_json(pfb_crowdsec_settings()), $this->config);
		$GLOBALS['pfb_test_service_running']['pfb_crowdsec'] = TRUE;

		$this->assertFalse(pfb_crowdsec_apply());

		$this->assertSame([], $this->calls());
	}

	public function testAChangedFileRestartsARunningBouncer(): void
	{
		config_set_path(self::SECTION, self::stored());
		pfb_crowdsec_config_write(pfb_crowdsec_config_json(pfb_crowdsec_settings()), $this->config);
		$GLOBALS['pfb_test_service_running']['pfb_crowdsec'] = TRUE;
		config_set_path(self::SECTION . '/log_level', 'debug');

		$this->assertFalse(pfb_crowdsec_apply(), 'on -> on is no change of state');

		$this->assertSame([['restart_service', 'pfb_crowdsec']], $this->calls());
		$this->assertSame('debug', json_decode((string) file_get_contents($this->config), TRUE)['log_level']);
	}

	public function testABouncerThatShouldRunButIsNotRunningIsStarted(): void
	{
		config_set_path(self::SECTION, self::stored());
		pfb_crowdsec_config_write(pfb_crowdsec_config_json(pfb_crowdsec_settings()), $this->config);

		$this->assertFalse(pfb_crowdsec_apply());

		$this->assertSame([['start_service', 'pfb_crowdsec']], $this->calls());
	}

	/** @return iterable<string, array{PfbToggle, array<string,string>}> */
	public static function offReasons(): iterable
	{
		yield 'pfBlockerNG off'     => [PfbToggle::Off, []];
		yield 'CrowdSec off'        => [PfbToggle::On, ['enable' => '']];
		yield 'no key on this node' => [PfbToggle::On, ['api_key' => '']];
	}

	#[DataProvider('offReasons')]
	public function testABouncerThatShouldNotRunIsStoppedAndItsFileRemoved(PfbToggle $master, array $over): void
	{
		config_set_path(self::SECTION, self::stored());
		pfb_crowdsec_config_write(pfb_crowdsec_config_json(pfb_crowdsec_settings()), $this->config);
		$GLOBALS['pfb_test_service_running']['pfb_crowdsec'] = TRUE;
		$GLOBALS['pfb']['enable'] = $master;
		config_set_path(self::SECTION, self::stored($over));

		$this->assertTrue(pfb_crowdsec_apply(), 'on -> off is a change');

		$this->assertSame([['stop_service', 'pfb_crowdsec']], $this->calls());
		$this->assertFileDoesNotExist($this->config);
	}

	public function testABouncerThatWasNeverOnStaysOffWithoutAnyServiceCall(): void
	{
		config_set_path(self::SECTION, self::stored(['enable' => '']));

		$this->assertFalse(pfb_crowdsec_apply());

		$this->assertSame([], $this->calls());
		$this->assertFileDoesNotExist($this->config);
	}

	public function testAFileThatCannotBeWrittenStartsNothing(): void
	{
		config_set_path(self::SECTION, self::stored());
		$GLOBALS['pfb']['crowdsec_config'] = "{$this->dir}/missing-folder/pfb_crowdsec.json";

		pfb_crowdsec_apply();

		$this->assertSame([], $this->calls(), 'no start without its config file');
	}

	// ---- the Settings save ------------------------------------------------------------------

	/** @return iterable<string, array{array<string,string>, array<string,string>, bool}> before, after, filter reload expected */
	public static function saves(): iterable
	{
		yield 'enable on'                    => [['enable' => ''], [], TRUE];
		yield 'enable off'                   => [[], ['enable' => ''], TRUE];
		yield 'log blocked packets'          => [[], ['rules_log' => 'on'], TRUE];
		yield 'tag'                          => [[], ['rules_tag' => 'cs'], TRUE];
		yield 'IPv4 rules off'               => [[], ['rule_v4' => ''], TRUE];
		yield 'IPv6 rules off'               => [[], ['rule_v6' => ''], TRUE];
		yield 'all interfaces off'           => [[], ['rules_all_interfaces' => '', 'rules_interfaces' => 'lan'], TRUE];
		yield 'another interface'            => [['rules_all_interfaces' => '', 'rules_interfaces' => 'lan'], ['rules_all_interfaces' => '', 'rules_interfaces' => 'lan,opt1'], TRUE];
		yield 'first key: it starts'         => [['api_key' => ''], [], TRUE];
		yield 'LAPI URL only'                => [[], ['lapi_url' => 'http://192.0.2.7:8080'], FALSE];
		yield 'log level only'               => [[], ['log_level' => 'debug'], FALSE];
		yield 'a new key only'               => [[], ['api_key' => 'Another-KEY'], FALSE];
		yield 'nothing'                      => [[], [], FALSE];
	}

	#[DataProvider('saves')]
	public function testTheSaveStoresAppliesAndReloadsTheFilterOnlyWhenTheRulesCanChange(array $before, array $after, bool $reload): void
	{
		config_set_path(self::SECTION, self::stored($before));
		pfb_crowdsec_apply();
		$GLOBALS['pfb_test_service_running']['pfb_crowdsec'] = pfb_crowdsec_should_run();
		$GLOBALS['pfb_test_service_calls'] = [];
		$this->assertSame(0, $GLOBALS['pfb_test_filter_configure_calls'], 'before-state: no reload yet');

		pfb_crowdsec_save(self::stored($after));

		$this->assertSame(self::stored($after), config_get_path(self::SECTION), 'the section holds what was saved');
		$this->assertCount(1, $GLOBALS['pfb_test_write_config_calls']);
		$this->assertSame($reload ? 1 : 0, $GLOBALS['pfb_test_filter_configure_calls']);
		$this->assertSame(pfb_crowdsec_should_run(), is_file($this->config), 'applied at once: the file exists exactly while it should run');
	}

	public function testTheSaveRestartsTheBouncerWhenOnlyItsFileChanged(): void
	{
		config_set_path(self::SECTION, self::stored());
		pfb_crowdsec_apply();
		$GLOBALS['pfb_test_service_running']['pfb_crowdsec'] = TRUE;
		$GLOBALS['pfb_test_service_calls'] = [];

		pfb_crowdsec_save(self::stored(['lapi_url' => 'http://192.0.2.7:8080']));

		$this->assertSame([['restart_service', 'pfb_crowdsec']], $this->calls());
	}

	public function testTheSaveKeepsUnregisteredSiblingsOfTheSection(): void
	{
		config_set_path(self::SECTION, self::stored() + ['future_key' => 'kept']);

		pfb_crowdsec_save(self::stored(['log_level' => 'error']));

		$this->assertSame('kept', config_get_path(self::SECTION . '/future_key'));
	}
}
