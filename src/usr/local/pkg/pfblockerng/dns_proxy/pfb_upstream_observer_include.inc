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
 * proxy. This hook never waits for readiness (it must not hold up rc.bootup or a Resolver restart): the package's own apply
 * confirms the proxy with its listener-ready marker and rolls pfB-DNS back when it does not come up. That marker says the
 * front end can answer queries; it is no proof that recursion works, which needs the Unbound this hook runs before. A second
 * background command, bounded by timeout(1) (60 s: the 30 s readiness budget plus the check) and dead with its task, runs the check
 * that turns a start that fails into the pfB-DNS startup notice; the hook still waits for nothing.
 *
 * Core functions only: on the non-verbose boot path none of pfBlockerNG's own includes are loaded. This file runs inside
 * pfSense's function, so it must leave no variable behind.
 */
$pfb_dns_rc = defined('PFB_DNS_PROXY_RCFILE') ? PFB_DNS_PROXY_RCFILE : '/usr/local/etc/rc.d/pfb_dns_proxy.sh';
if (is_executable($pfb_dns_rc) && !isvalidpid('/var/run/pfb_dns_proxy.pid') && !isvalidpid('/var/run/pfb_dns_proxy_daemon.pid')) {
	mwexec_bg($pfb_dns_rc . ' start');
	mwexec_bg('/usr/bin/timeout -s TERM -k 5 60 /usr/local/bin/php -f /usr/local/pkg/pfblockerng/pfblockerng.inc dns_check');
}
unset($pfb_dns_rc);
