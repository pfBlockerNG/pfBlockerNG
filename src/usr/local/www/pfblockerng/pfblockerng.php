<?php
/*
 * pfblockerng.php
 *
 * part of pfSense (https://www.pfsense.org)
 * Copyright (c) 2015-2026 Rubicon Communications, LLC (Netgate)
 * Copyright (c) 2015-2024 BBcan177@gmail.com
 * All rights reserved.
 *
 * Originally based upon pfBlocker by
 * Copyright (c) 2011 Marcello Coutinho
 * All rights reserved.
 *
 * Hour Schedule Convertor code by Snort Package
 * Copyright (c) 2016 Bill Meeks
 * All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

if ($_SERVER['REMOTE_ADDR'] == '127.0.0.1' && $_REQUEST && $_REQUEST['pfb']) {
	if (strpos($_REQUEST['pfb'], ' ') !== FALSE) {
		$query = basename(htmlspecialchars(trim(strstr($_REQUEST['pfb'], ' ', TRUE))));
	} else {
		$query = basename(htmlspecialchars($_REQUEST['pfb']));
	}

	if (!preg_match("/\W/", $query)) {
		foreach (array("{$query}.txt", "{$query}_v4.txt", "{$query}_v6.txt") as $file) {
			$file = "/var/db/aliastables/{$file}";
			if (file_exists($file)) {
				if (@filesize($file) > 0) {
					$return = @file_get_contents($file);
					print $return;
				}
				break;
			}
		}
	}
	return;
}

// CLI-only verb dispatcher served from the docroot; only the CLI SAPI fills the $argv global (issue #3469).
if (PHP_SAPI !== 'cli') {
	exit;
}

require_once('util.inc');
require_once('functions.inc');
require_once('pkg-utils.inc');
require_once('globals.inc');
require_once('services.inc');
require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');
require_once('/usr/local/pkg/pfblockerng/pfblockerng_extra.inc');	// 'include functions' not yet merged into pfSense

global $g, $pfb;
pfb_global();

// Clear IP/DNSBL counters by hand (Core runs the day-change lane through the core_counters verb)
if (isset($argv[1])) {
	if ($argv[1] == 'clearip') {
		pfBlockerNG_clearip();
		pfBlockerNG_clearsqlite('clearip');
		exit;
	}
	elseif ($argv[1] == 'cleardnsbl') {
		pfBlockerNG_clearsqlite('cleardnsbl');
		exit;
	}
	// ADR-12: manual hook test path. Usage: pfblockerng.php runhooks <pre|post> [trigger]. Runs the configured pre/post hooks
	// once with a synthetic context and no Update (#3977: through pfb-core --run-hooks, protocol "Hooks outside an Update"). The
	// change lists are '' because nothing was updated; post gets PFB_STATUS=ok from the one-shot.
	elseif ($argv[1] == 'runhooks') {
		$when = ($argv[2] ?? '') === 'post' ? 'post' : 'pre';
		$ctx = array('trigger' => ($argv[3] ?? 'manual-test'));
		if ($when == 'post') {
			$ctx += array('ipChanged' => FALSE, 'dnsblChanged' => FALSE, 'changedIpAliases' => '', 'changedDnsblGroups' => '');
		}
		exit(pfb_core_run_hooks($when, $ctx));
	}
	// issue #149: SafeSearch CNAME fallback freshness. Legacy direct verb:
	// re-resolves the SafeSearch CNAME targets (duckduckgo/pixabay) and
	// refreshes their baked #2-fallback IPs in the SafeSearch CSV, triggering a
	// python reload only on change. Does NOT run sync_package_pfblockerng.
	elseif ($argv[1] == 'ss_refresh') {
		pfblockerng_ss_refresh();
		exit;
	}
	// ADR-43: due-ledger trigger-tick. Reads the ledger, dispatches due Extras and feeds,
	// then runs due SafeSearch refresh work (cheap).
	elseif ($argv[1] == 'tick') {
		pfblockerng_tick();
		exit;
	}
	// issue #1204: scheduled-dispatch verb (no crontab entry runs it now). A present
	// .pfb_cron_disable sentinel suppresses just this scheduled dispatch -- the
	// direct 'tick' verb above stays fully live regardless.
	elseif ($argv[1] == 'cron-tick') {
		if (pfb_cron_disabled()) {
			print '[ Disabled by ' . pfb_cron_disable_path() . " ]\n";
			exit;
		}
		pfblockerng_tick();
		exit;
	}
	// PFBL-03: root-only DNSBL-control entrypoint. Writes a validated command to the
	// local privileged command channel consumed by the pfB-DNS gateway.
	// Usage: pfblockerng.php dnsbl-control <disable [sec] | enable |
	//        addbypass <ip> [sec] | removebypass <ip>>
	// The writer (pfb_unbound_py_write_control) re-validates the command + argument and
	// the reader re-validates again, so an invalid command prints an error and exits 1.
	elseif ($argv[1] == 'dnsbl-control') {
		$cmd = $argv[2] ?? '';
		$ip  = '';
		$dur = '';
		if ($cmd == 'addbypass' || $cmd == 'removebypass') {
			$ip  = $argv[3] ?? '';
			$dur = $argv[4] ?? '';	// only addbypass honours it; writer ignores it for removebypass
		} else {
			$dur = $argv[3] ?? '';	// disable [sec]; enable ignores it
		}
		$seq = pfb_unbound_py_write_control($cmd, $ip, $dur);
		if ($seq === FALSE) {
			echo "DNSBL control command failed (invalid command/argument or write error)\n";
			exit(1);
		}
		echo "DNSBL control command [ {$cmd} ] queued (seq {$seq})\n";
		exit;
	}
	// #3522: publishes pfblockerng.prom for node_exporter; Core runs this verb every minute through pfb_core_metrics.sh.
	elseif ($argv[1] == 'metrics') {
		pfb_metrics_write();
		exit;
	}
}

// Call include file and collect updated Global settings
if (isset($argv[1]) && in_array($argv[1], array('update', 'updateip', 'updatednsbl', 'cron', 'pfb_trigger', 'tick', 'forcecheck'))) {
	pfb_global();

	// issue #4260: the update verbs start an Update through Core and follow it to its end; Core runs it (before the cutover through
	// the PHP update program), so no pass runs here. A Core that is down or refuses the caller fails the verb, never a fallback.
	if (($pfb_update_request = pfb_cli_update_request($argv)) !== NULL) {
		pfb_cli_deprecate($argv[1], static function (string $text): void { fwrite(STDERR, $text); });
		exit(pfb_cli_update_run($pfb_update_request, 'pfb_core_call',
			pfb_stdout_is_terminal() ? static function (string $text): void { echo $text; } : NULL,
			static function (string $text): void { fwrite(STDERR, $text); },
			static function (): void { sleep(1); }));
	}
}



