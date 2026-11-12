<?php

declare(strict_types=1);

/**
 * Child process for DnsProxyKeepRunningPkgTest: runs one pass of the shipped .inc over the PHPUnit doubles, as a descendant of a
 * process whose command line reads `pkg upgrade` (the test starts it that way), so that pfb_pkg_operation() reports what it reports
 * under a real package operation. Nothing is stubbed: the classification reads the live process table.
 * argv: scenario JSON (the KeepRunningScenario::krApply() keys, plus `op`: ensure | reload | tick), result file.
 */

$scenario = json_decode((string) $argv[1], TRUE, 8, JSON_THROW_ON_ERROR);
$resultFile = (string) $argv[2];

require_once dirname(__DIR__) . '/bootstrap.php';
require_once __DIR__ . '/KeepRunningScenario.php';

final class KeepRunningWorker
{
	use KeepRunningScenario;

	public function run(array $scenario, string $resultFile): void
	{
		$this->krSeed(sys_get_temp_dir() . '/pfb_keep_running_worker_' . getmypid() . '_' . bin2hex(random_bytes(4)));
		// The default dead backend proves a deferred pass needs no upstream confirmation; foreign-owner cases seed it explicitly.
		$scenario += ['serving' => FALSE];
		$this->krApply($scenario);
		$foreignFixture = !empty($scenario['foreign_upstream']);
		if ($foreignFixture) {
			file_put_contents($GLOBALS['pfb_test_sockstat_output'], "root nc 6161 3 tcp4 127.0.0.1:5353 *:*\nroot nc 6161 4 udp4 127.0.0.1:5353 *:*\n");
		}
		$unboundBefore = $foreignFixture ? isvalidpid($GLOBALS['g']['varrun_path'] . '/unbound.pid') : NULL;
		$gatewayBefore = $foreignFixture ? pfb_dns_proxy_ready() : NULL;
		$servingBefore = $foreignFixture ? pfb_dns_proxy_serving_ready() : NULL;
		$operation = pfb_pkg_operation();
		$savedBefore = PfbConfig::read('dns/pfb_dns_saved');
		$resolverBefore = config_get_path('unbound', []);
		$commandsBefore = count($GLOBALS['pfb_test_mwexec'] ?? []);
		$returned = NULL;
		if ($scenario['op'] === 'ensure') {
			$returned = $this->krEnsure();
		} elseif ($scenario['op'] === 'tick') {
			$this->krTick();
		} else {
			pfb_reload_unbound('enabled', TRUE);
		}
		$service = NULL;
		if ($foreignFixture) {
			pfb_global();
			$service = pfb_dns_status()['service'];
		}
		file_put_contents($resultFile, json_encode([
			'operation' => $operation,
			'returned' => $returned,
			'calls' => $this->krProxyCalls(),
			'marker' => $this->krMarker(),
			'log' => $this->krLog(),
			'saved_before' => $savedBefore,
			'saved_after' => PfbConfig::read('dns/pfb_dns_saved'),
			'resolver_before' => $resolverBefore,
			'resolver_after' => config_get_path('unbound', []),
			'running' => pfb_dns_proxy_running(),
			'stopped' => in_array(PFB_DNS_PROXY_RCFILE . ' stop', array_slice($GLOBALS['pfb_test_mwexec'] ?? [], $commandsBefore), TRUE),
			'unbound_before' => $unboundBefore,
			'gateway_before' => $gatewayBefore,
			'serving_before' => $servingBefore,
			'configures' => count($GLOBALS['pfb_test_unbound_configure_calls'] ?? []),
			'blocked' => file_exists($GLOBALS['pfb']['dns_proxy_backend_blocked']),
			'service' => $service,
		], JSON_THROW_ON_ERROR));
		$this->standInsStop();
		rmdir_recursive($this->krDir);
	}
}

(new KeepRunningWorker())->run($scenario, $resultFile);
