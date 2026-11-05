<?php

declare(strict_types=1);

/** Reflects unchanged production functions, replacing only subprocess, interface and clock boundaries. */
final class DdrProbeFixture
{
	public array $calls = [];
	public array $interfaces = [];
	public array $responses = [];
	public int $exit = 0;
	public int $now = 0;
	public int $elapsedPerQuery = 0;
	private static array $instances = [];
	public string $namespace;

	public function __construct()
	{
		$slot = count(self::$instances);
		self::$instances[$slot] = $this;
		$this->namespace = 'DdrProbe' . bin2hex(random_bytes(6));
		$source = '';
		foreach (['pfb_dns_ddr_result', 'pfb_dns_ddr_svcb', 'pfb_dns_ddr_compare', 'pfb_dns_ddr_probe', 'pfb_dns_ddr_status'] as $function) {
			$reflection = new ReflectionFunction($function);
			$source .= implode('', array_slice(file($reflection->getFileName()), $reflection->getStartLine() - 1,
				$reflection->getEndLine() - $reflection->getStartLine() + 1)) . "\n";
		}
		eval(<<<PHP
			namespace {$this->namespace};
			use \\PfbConfig;
			use \\PfbToggle;
			function proc_open(\$command, \$descriptors, &\$pipes) {
				return \\DdrProbeFixture::instance({$slot})->open(\$command, \$descriptors);
			}
			function proc_close(\$process) {
				fclose(\$process);
				\$fixture = \\DdrProbeFixture::instance({$slot});
				\$fixture->now += \$fixture->elapsedPerQuery;
				return \$fixture->exit;
			}
			function net_get_interfaces() { return \\DdrProbeFixture::instance({$slot})->interfaces; }
			function hrtime(\$number) { return \\DdrProbeFixture::instance({$slot})->now; }
			{$source}
			PHP);
	}

	public static function instance(int $slot): self
	{
		return self::$instances[$slot];
	}

	public function open(string $command, array $descriptors)
	{
		$args = str_getcsv($command, ' ', "'", '\\');
		$this->calls[] = $args;
		$type = $args[count($args) - 1];
		$name = $args[count($args) - 3];
		fwrite($descriptors[1], $this->responses[$name . ' ' . $type] ?? 'missing fixture');
		return tmpfile();
	}

	public function status(?string $only = NULL): array
	{
		return ($this->namespace . '\\pfb_dns_ddr_status')($only);
	}

	public function probe(string $at, float $budget): array
	{
		return ($this->namespace . '\\pfb_dns_ddr_probe')($at, $budget);
	}
}
