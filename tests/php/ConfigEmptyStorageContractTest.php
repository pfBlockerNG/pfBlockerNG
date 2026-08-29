<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/** Owner-ruled storage contract for adapter-bearing registry fields (issue #2120). */
final class ConfigEmptyStorageContractTest extends TestCase
{
	private const SECTIONS = [
		'gen'   => 'installedpackages/pfblockerng/config/0',
		'dnsbl' => 'installedpackages/pfblockerngdnsblsettings/config/0',
		'ip'    => 'installedpackages/pfblockerngipsettings/config/0',
	];

	/** @var array<string,array{section:string,bare:string}> */
	private const DEFAULT_ON_TOGGLES = [
		'gen/pfb_keep'                    => ['section' => 'gen', 'bare' => 'pfb_keep'],
		'gen/pfb_software_check'          => ['section' => 'gen', 'bare' => 'pfb_software_check'],
		'gen/pfb_feed_internal_filter'   => ['section' => 'gen', 'bare' => 'pfb_feed_internal_filter'],
		'gen/pfb_syntax_highlight'       => ['section' => 'gen', 'bare' => 'pfb_syntax_highlight'],
		'dnsbl/pfb_cache'                 => ['section' => 'dnsbl', 'bare' => 'pfb_cache'],
		'dnsbl/pfb_py_reply'              => ['section' => 'dnsbl', 'bare' => 'pfb_py_reply'],
		'dnsbl/pfb_hsts'                  => ['section' => 'dnsbl', 'bare' => 'pfb_hsts'],
		'dnsbl/pfb_idn_block_malicious'  => ['section' => 'dnsbl', 'bare' => 'pfb_idn_block_malicious'],
		'ip/suppression'                  => ['section' => 'ip', 'bare' => 'suppression'],
	];

	protected function setUp(): void
	{
		$GLOBALS['config'] = [];
	}

	private function path(string $key): string
	{
		[$section, $bare] = explode('/', $key, 2);
		return self::SECTIONS[$section] . '/' . $bare;
	}

	public function testDefaultOnTogglePresenceAndVocabulary(): void
	{
		foreach (self::DEFAULT_ON_TOGGLES as $key => $spec) {
			$path = $this->path($key);
			$this->assertSame(PfbToggle::On, PfbConfig::read($key), "{$key}: absent -> registered On");

			config_set_path($path, '');
			$this->assertSame(PfbToggle::Off, PfbConfig::read($key), "{$key}: present empty -> Off");
			config_set_path($path, 'off');
			$this->assertSame(PfbToggle::Off, PfbConfig::read($key), "{$key}: legacy off -> Off");
			foreach (['junk', 'yes', '1'] as $raw) {
				config_set_path($path, $raw);
				$this->assertSame(PfbToggle::Off, PfbConfig::read($key), "{$key}: {$raw} -> Off");
			}
			foreach (['on', 'On', 'ON'] as $raw) {
				config_set_path($path, $raw);
				$this->assertSame(PfbToggle::On, PfbConfig::read($key), "{$key}: {$raw} -> On");
			}

			PfbConfig::writeSystem($key, PfbToggle::On);
			$this->assertSame('on', config_get_path($path), "{$key}: write On -> on");
			PfbConfig::writeSystem($key, PfbToggle::Off);
			$this->assertSame('', config_get_path($path), "{$key}: write Off -> empty");
			PfbConfig::writeSystem($key, NULL);
			$this->assertNull(config_get_path($path), "{$key}: write NULL deletes");

			PfbConfig::writeSectionSystem(self::SECTIONS[$spec['section']], [$spec['bare'] => 'on']);
			$this->assertSame('on', config_get_path($path), "{$key}: section write On -> on");
			PfbConfig::writeSectionSystem(self::SECTIONS[$spec['section']], [$spec['bare'] => '']);
			$this->assertSame('', config_get_path($path), "{$key}: section write empty stays empty");
			PfbConfig::writeSectionSystem(self::SECTIONS[$spec['section']], [$spec['bare'] => NULL]);
			$this->assertNull(config_get_path($path), "{$key}: section write NULL deletes");
		}
	}

	public function testIdnModeEmptyAndJunkUseOffFallbackAndWritesEmpty(): void
	{
		$key  = 'dnsbl/pfb_idn';
		$path = $this->path($key);
		$this->assertSame(PfbIdnMode::Off, PfbConfig::read($key), 'IDN absent -> registered Off');
		foreach (['', 'off', 'all', 'yes', 'junk'] as $raw) {
			config_set_path($path, $raw);
			$this->assertSame(PfbIdnMode::Off, PfbConfig::read($key), "IDN {$raw} -> Off");
		}
		config_set_path($path, 'on');
		$this->assertSame(PfbIdnMode::All, PfbConfig::read($key));
		config_set_path($path, 'confusable');
		$this->assertSame(PfbIdnMode::Confusable, PfbConfig::read($key));

		PfbConfig::writeSystem($key, PfbIdnMode::Off);
		$this->assertSame('', config_get_path($path));
		PfbConfig::writeSystem($key, PfbIdnMode::All);
		$this->assertSame('on', config_get_path($path));
		PfbConfig::writeSystem($key, PfbIdnMode::Confusable);
		$this->assertSame('confusable', config_get_path($path));
		PfbConfig::writeSystem($key, NULL);
		$this->assertNull(config_get_path($path));

		PfbConfig::writeSectionSystem(self::SECTIONS['dnsbl'], ['pfb_idn' => PfbIdnMode::Off]);
		$this->assertSame('', config_get_path($path));
		PfbConfig::writeSectionSystem(self::SECTIONS['dnsbl'], ['pfb_idn' => NULL]);
		$this->assertNull(config_get_path($path));
	}

	public function testSiblingEnumsKeepExistingEmptyJunkFallbacks(): void
	{
		$alias = $this->path('gen/pfb_alias_delta_mode');
		$top1m = $this->path('dnsbl/top1m_source');
		foreach (['', 'junk'] as $raw) {
			config_set_path($alias, $raw);
			$this->assertSame(PfbAliasDeltaMode::Auto, PfbConfig::read('gen/pfb_alias_delta_mode'));
			config_set_path($top1m, $raw);
			$this->assertSame(PfbTop1mSource::Tranco, PfbConfig::read('dnsbl/top1m_source'));
		}
		config_set_path($top1m, 'domcop');
		$this->assertSame(PfbTop1mSource::OpenPageRank, PfbConfig::read('dnsbl/top1m_source'));
		config_set_path($top1m, 'alexa');
		$this->assertSame(PfbTop1mSource::Tranco, PfbConfig::read('dnsbl/top1m_source'));
		foreach (['auto', 'delta', 'replace'] as $raw) {
			config_set_path($alias, $raw);
			$this->assertSame($raw, PfbConfig::read('gen/pfb_alias_delta_mode')->value);
		}
	}

	public function testPlainScalarEmptyReadAndWriteContractsStayUnchanged(): void
	{
		$key  = 'dnsbl/dnsbl_interface';
		$path = $this->path($key);
		$this->assertSame('lo0', PfbConfig::read($key), 'plain scalar absent -> lo0');
		config_set_path($path, '');
		$this->assertSame('lo0', PfbConfig::read($key), 'plain scalar empty -> lo0');
		PfbConfig::writeSystem($key, '');
		$this->assertSame('lo0', config_get_path($path), 'single plain write keeps current defaulting');
		PfbConfig::writeSectionSystem(self::SECTIONS['dnsbl'], ['dnsbl_interface' => '']);
		$this->assertSame('', config_get_path($path), 'raw section plain write stays byte-identical');
		$this->assertSame('lo0', PfbConfig::read($key), 'plain scalar raw empty still reads lo0');
	}
}
