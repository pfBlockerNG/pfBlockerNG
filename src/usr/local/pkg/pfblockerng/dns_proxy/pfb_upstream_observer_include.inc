<?php
/*
 * pfb_upstream_observer_include.inc
 * pfBlockerNG - pfB-DNS: start the DNS proxy whenever pfSense (re)starts Unbound
 *
 * part of pfSense (https://www.pfsense.org)
 * Copyright (c) 2015-2026 Rubicon Communications, LLC (Netgate)
 * Copyright (c) 2015-2024 BBcan177@gmail.com
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

/*
 * pfSense's services_unbound_configure() require_once's /var/unbound/<python_script>_include.inc right after it stopped
 * Unbound and before it starts it again, whenever Unbound has a python script: at boot (rc.bootup, once the interfaces
 * have their addresses) and at every Resolver restart. pfB-DNS keeps Unbound's python_script naming the upstream observer
 * (pfb_upstream_observer) in every mode, for exactly this file.
 *
 * With pfB-DNS on, Unbound has left the client-facing port, so nothing answers on it until the proxy does, and the
 * package's own service start (rc.start_packages) only runs after rc.bootup returns: the firewall's own lookups would
 * fail for the rest of boot. Start the proxy here, in the background, and only when it is not already serving
 * (a Resolver restart from the GUI must not bounce it). The rc script refuses to start without a moved-Resolver snapshot.
 *
 * The rc script serializes its starts (lockf), so this background start and an apply's start_service() cannot both launch a
 * proxy. This hook never waits for readiness (it must not hold up rc.bootup or a Resolver restart). A second background command confirms
 * the start as an apply does, told the gateway log's size from before the start: a start with problems, or one that does not become ready,
 * gets the pfB-DNS startup notice and the Resolver stays moved (pfb_dns_proxy_confirm_ready()). The ready marker says the front end can answer
 * queries; it is no proof that recursion works, which needs the Unbound this hook runs before.
 *
 * That command is bounded by timeout(1), 360 s: an outer salvage deadline, not a proved bound on normal completion. Its parts are the 30 s
 * readiness budget, the bounded status and socket probes of the startup check and, when another process holds Unbound's loopback backend ports
 * (issue #3848), a move of that pair: one bounded socket scan to find a free pair, the config lock wait (10 s) and a second 30 s wait for the
 * restarted gateway. pfSense's services_unbound_configure(), which the move calls, is outside any total. The move restarts Unbound and the gateway,
 * daemons meant to outlive the check, so timeout(1) runs in its --foreground mode: it signals only the check itself and never reaps what the check
 * started (docs/misc/external-process-waits.md, "Choosing the mode").
 *
 * Core functions only: on the non-verbose boot path none of pfBlockerNG's own includes are loaded. This file runs inside
 * pfSense's function, so it must leave no variable behind.
 */
$pfb_dns_rc = defined('PFB_DNS_PROXY_RCFILE') ? PFB_DNS_PROXY_RCFILE : '/usr/local/etc/rc.d/pfb_dns_proxy.sh';
if (is_executable($pfb_dns_rc) && !isvalidpid('/var/run/pfb_dns_proxy.pid') && !isvalidpid('/var/run/pfb_dns_proxy_daemon.pid')) {
	// The gateway log's size from before the start, handed to the check so that it judges only the lines this start writes: taken
	// after the start was backgrounded, it could already include them
	$pfb_dns_since = (int) @filesize(defined('PFB_DNS_PROXY_LOG') ? PFB_DNS_PROXY_LOG : '/var/log/pfblockerng/dns_proxy.log');
	mwexec_bg($pfb_dns_rc . ' start');
	mwexec_bg('/usr/bin/timeout --foreground -s TERM -k 5 360 /usr/local/bin/php -f /usr/local/pkg/pfblockerng/pfblockerng.inc dns_check ' . $pfb_dns_since);
}
unset($pfb_dns_rc, $pfb_dns_since);
