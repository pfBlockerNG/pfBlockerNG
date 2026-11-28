<?php
/*
 * pfblockerng_spoa.inc
 *
 * part of pfSense (https://www.pfsense.org)
 * Copyright (c) 2015-2026 Rubicon Communications, LLC (Netgate)
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

// HAProxy SPOP (SPOA) helpers: listen-address validation, AppSec duration validation, and HAProxy snippet generation (#4309).

const PFB_CORE_SPOA_DEFAULT_LISTEN = '127.0.0.1:10090';
const PFB_CROWDSEC_SPOA_DEFAULT_LISTEN = '127.0.0.1:10091';
const PFB_CROWDSEC_APPSEC_DEFAULT_TIMEOUT = '500ms';
const PFB_CROWDSEC_APPSEC_FAILURE_ACTIONS = ['passthrough', 'deny'];

/**
 * Validate a SPOA listen address: loopback TCP (127.0.0.1:<port> or [::1]:<port>, port 1..65535)
 * or a clean absolute Unix domain socket path (unix:/abs/path, no whitespace, control chars, or '..' segments).
 */
function pfb_spoa_listen_valid(string $listen): bool {
	if ($listen === '' || strlen($listen) > 256 || preg_match('/[\x00-\x20\x7f]/', $listen)) {
		return FALSE;
	}
	if (str_starts_with($listen, 'unix:')) {
		$path = substr($listen, 5);
		if ($path === '' || $path[0] !== '/' || str_contains($path, '//') || str_ends_with($path, '/')) {
			return FALSE;
		}
		foreach (explode('/', ltrim($path, '/')) as $seg) {
			if ($seg === '' || $seg === '.' || $seg === '..') {
				return FALSE;
			}
		}
		return TRUE;
	}
	if (preg_match('/^(127\.0\.0\.1|\[::1\]):([0-9]{1,5})$/D', $listen, $m)) {
		$port = (int) $m[2];
		return $port >= 1 && $port <= 65535;
	}
	return FALSE;
}

/**
 * Validate an optional comma-separated list of IP alias/feed names exposed via pfb-core SPOA.
 */
function pfb_spoa_aliases_valid(string $csv): bool {
	if ($csv === '') {
		return TRUE;
	}
	if (strlen($csv) > 4096) {
		return FALSE;
	}
	foreach (explode(',', $csv) as $part) {
		$name = trim($part);
		if ($name === '' || !preg_match('/^[A-Za-z0-9_-]{1,64}$/D', $name)) {
			return FALSE;
		}
	}
	return TRUE;
}

/**
 * Validate a Go duration string for AppSec timeout (50ms to 30s).
 */
function pfb_spoa_timeout_valid(string $dur): bool {
	if (!preg_match('/^([0-9]+)(ms|s)$/D', $dur, $m)) {
		return FALSE;
	}
	$ms = $m[2] === 's' ? ((int) $m[1]) * 1000 : (int) $m[1];
	return $ms >= 50 && $ms <= 30000;
}

/**
 * Format an HAProxy backend server address from a validated SPOA listen address.
 */
function pfb_spoa_haproxy_server_addr(string $listen): string {
	if (str_starts_with($listen, 'unix:')) {
		return 'unix@' . substr($listen, 5);
	}
	return $listen;
}

/**
 * Build copyable HAProxy SPOE configuration snippets for pfb-core and pfb_crowdsec (#4309).
 *
 * @return array{spoe_core: string, spoe_crowdsec: string, haproxy_backends: string, haproxy_frontend: string}
 */
function pfb_spoa_haproxy_snippets(
	string $coreListen = PFB_CORE_SPOA_DEFAULT_LISTEN,
	string $crowdsecListen = PFB_CROWDSEC_SPOA_DEFAULT_LISTEN,
	bool $appsecEnabled = FALSE
): array {
	$coreAddr = pfb_spoa_haproxy_server_addr($coreListen);
	$csAddr = pfb_spoa_haproxy_server_addr($crowdsecListen);

	$spoeCore = <<<EOF
[pfb-core]
spoe-agent pfb-core-agent
    messages pfb-check
    option var-prefix pfb
    option set-on-error error
    timeout hello      100ms
    timeout idle       30s
    timeout processing 100ms
    use-backend be_pfb_core_spoa
    log global

spoe-group pfb-check
    messages pfb-check

spoe-message pfb-check
    args src-ip=src
EOF;

	$csArgs = $appsecEnabled
		? "    args src-ip=src method=method host=req.hdr(Host) uri=url version=req.ver user-agent=req.hdr(User-Agent)"
		: "    args src-ip=src";

	$spoeCrowdSec = <<<EOF
[pfb-crowdsec]
spoe-agent pfb-crowdsec-agent
    messages cs-check
    option var-prefix crowdsec
    option set-on-error error
    timeout hello      100ms
    timeout idle       30s
    timeout processing 500ms
    use-backend be_pfb_crowdsec_spoa
    log global

spoe-group cs-check
    messages cs-check

spoe-message cs-check
{$csArgs}
EOF;

	$backends = <<<EOF
backend be_pfb_core_spoa
    mode tcp
    timeout connect 1s
    timeout server  30s
    server pfb-core {$coreAddr} check

backend be_pfb_crowdsec_spoa
    mode tcp
    timeout connect 1s
    timeout server  30s
    server pfb-crowdsec {$csAddr} check
EOF;

	$frontend = <<<EOF
# Attach both SPOE engines in your frontend:
filter spoe engine pfb-core     config /var/etc/haproxy/spoe-pfb-core.conf
filter spoe engine pfb-crowdsec config /var/etc/haproxy/spoe-pfb-crowdsec.conf

# Evaluate pfBlockerNG IP lists first, short-circuiting before CrowdSec:
http-request set-src req.hdr_ip(CF-Connecting-IP) if from_cloudflare
http-request send-spoe-group pfb-core pfb-check if !from_trusted_subnets
http-request deny deny_status 403 if { var(txn.pfb.blocked) -m bool }
http-request send-spoe-group pfb-crowdsec cs-check if !from_trusted_subnets
http-request deny deny_status 403 if { var(txn.crowdsec.remediation) -m str ban }
EOF;

	return [
		'spoe_core'        => $spoeCore,
		'spoe_crowdsec'    => $spoeCrowdSec,
		'haproxy_backends' => $backends,
		'haproxy_frontend' => $frontend,
	];
}
