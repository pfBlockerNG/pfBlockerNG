<?php
/*
 * pkg_pfblockerng.inc
 *
 * part of pfSense (https://www.pfsense.org)
 * Copyright (c) 2016-2026 Rubicon Communications, LLC (Netgate)
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

global $shortcuts;

$shortcuts['pfblockerng'] = array();

// pfBlockerNG's syslog (ADR-38) is a <logging>-registered package log, surfaced under
// Status > System Logs > Packages. Resolve the channel-correct package name
// (pfBlockerNG vs pfBlockerNG-devel) from its configurationfile so the link is right on
// either channel. installedpackages/package is a pfSense-core section (not a registered
// pfblockerng config scalar), so this read is outside the ADR-29 config-gateway scope.
foreach (config_get_path('installedpackages/package', array()) as $pfb_pkg) {
	if (($pfb_pkg['configurationfile'] ?? '') === 'pfblockerng.xml') {
		$shortcuts['pfblockerng']['log'] = 'status_logs_packages.php?pkg=' . $pfb_pkg['name'];
		break;
	}
}
