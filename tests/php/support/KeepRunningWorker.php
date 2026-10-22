<?php

declare(strict_types=1);

/**
 * Child process for DnsProxyKeepRunningPkgTest: runs one pass of the shipped .inc over the PHPUnit doubles, as a descendant of a
 * process whose command line reads `pkg upgrade` (the test starts it that way), so that pfb_pkg_operation() reports what it reports
 * under a real package operation. Nothing is stubbed: the classification reads the live process table.
 * argv: scenario JSON (the KeepRunningScenario::krApply() keys, plus `op`: ensure | reload), result file.
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
		// The package rows keep the Unbound backend dead: a deferred pass must need no confirmation to stand
		$scenario += ['serving' => FALSE];
		$this->krApply($scenario);
		$operation = pfb_pkg_operation();
		$returned = NULL;
		if ($scenario['op'] === 'ensure') {
			$returned = $this->krEnsure();
		} else {
			pfb_reload_unbound('enabled', FALSE, TRUE);
		}
		file_put_contents($resultFile, json_encode([
			'operation' => $operation,
			'returned' => $returned,
			'calls' => $this->krProxyCalls(),
			'marker' => $this->krMarker(),
			'log' => $this->krLog(),
		], JSON_THROW_ON_ERROR));
		rmdir_recursive($this->krDir);
	}
}

(new KeepRunningWorker())->run($scenario, $resultFile);
