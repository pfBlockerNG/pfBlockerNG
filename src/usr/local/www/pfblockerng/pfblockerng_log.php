<?php
/*
 * pfblockerng_log.php
 *
 * part of pfSense (https://www.pfsense.org)
 * Copyright (c) 2016-2026 Rubicon Communications, LLC (Netgate)
 * Copyright (c) 2015-2024 BBcan177@gmail.com
 * All rights reserved.
 *
 * Portions of this code are based on original work done for the
 * Snort package for pfSense from the following contributors:
 *
 * Copyright (c) 2009 Robert Zelaya Sr. Developer
 * Copyright (c) 2005 Bill Marquette
 * Copyright (c) 2004 Manuel Kasper (BSD 2 clause)
 * All rights reserved.
 *
 * Adapted for Suricata by:
 * Copyright (c) 2016 Bill Meeks
 * All rights reserved.
 *
 * Javascript and Integration modifications by J. Nieuwenhuizen and J. Van Breedam
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

require_once('guiconfig.inc');
require_once('globals.inc');
require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');

global $pfb;
pfb_global();

// Get log files from directory
function getlogs($logdir, $log_extentions = array('log')) {
	if (!is_array($log_extentions)) {
		$log_extentions = array($log_extentions);
	}

	// Get logfiles
	$log_filenames = array();
	foreach ($log_extentions as $extention) {
		if ($extention != '*') {
			$log_filenames = array_merge($log_filenames, glob($logdir . '*' . $extention));
		} else {
			$log_filenames = array_merge($log_filenames, glob($logdir . '*'));
		}
	}

	// Convert to filenames only
	$log_filenames = array_map('basename', $log_filenames);

	asort($log_filenames);
	return $log_filenames;
}

/*	Define logtypes:
		name	=>	Displayname of the type
		ext	=>	Log extentions (array for multiple extentions)
		logdir	=>	Log directory
		clear	=>	Add clear button (TRUE/FALSE)
		download=>	Add download button (TRUE/FALSE)	*/

$pfb_logtypes = array(	'defaultlogs'	=> array('name'		=> 'Log Files',
						'logdir'	=> "{$pfb['logdir']}/",
						'logs'		=> array('pfblockerng.log', 'error.log', 'ip_block.log', 'ip_permit.log', 'ip_match.log',
									'dnsbl.log', 'unified.log', 'extras.log', 'dnsbl_parsed_error.log', 'ip_parsed_error.log', 'dns_reply.log',
									'py_error.log', 'maxmind_ver', 'wizard.log'),
						'download'	=> TRUE,
						'clear'		=> TRUE
						),
			'masterfiles'	=> array('name'		=> 'Masterfiles',
						'logdir'	=> "{$pfb['dbdir']}/",
						'logs'		=> array('masterfile', 'mastercat'),
						'download'	=> TRUE,
						'clear'		=> FALSE
						),
			'originallogs'	=> array('name'		=> 'Original IP Files',
						'ext'		=> array('orig', 'raw'),
						'logdir'	=> "{$pfb['origdir']}/",
						'download'	=> TRUE,
						'clear'		=> TRUE
						),
			'origdnslogs'	=> array('name'		=> 'Original DNSBL Files',
						'ext'		=> array('orig', 'raw'),
						'logdir'	=> "{$pfb['dnsorigdir']}/",
						'download'	=> TRUE,
						'clear'		=> TRUE
						),	
			'denylogs'	=> array('name'		=> 'Deny Files',
						'ext'		=> 'txt',
						'txt'		=> 'deny',
						'logdir'	=> "{$pfb['denydir']}/",
						'download'	=> TRUE,
						'clear'		=> TRUE
						),
			'dnsbl'		=> array('name'		=> 'DNSBL Files',
						'ext'		=> array('txt', 'ip'),
						'txt'		=> 'dnsbl',
						'logdir'	=> "{$pfb['dnsdir']}/",
						'download'	=> TRUE,
						'clear'		=> TRUE
						),
			'permitlogs'	=> array('name'		=> 'Permit Files',
						'ext'		=> 'txt',
						'txt'		=> 'permit',
						'logdir'	=> "{$pfb['permitdir']}/",
						'download'	=> TRUE,
						'clear'		=> TRUE
						),
			'matchlogs'	=> array('name'		=> 'Match Files',
						'ext'		=> 'txt',
						'txt'		=> 'match',
						'logdir'	=> "{$pfb['matchdir']}/",
						'download'	=> TRUE,
						'clear'		=> TRUE
						),
			'nativelogs'	=> array('name'		=> 'Native Files',
						'ext'		=> 'txt',
						'logdir'	=> "{$pfb['nativedir']}/",
						'download'	=> TRUE,
						'clear'		=> TRUE
						),
			'aliaslogs'	=> array('name'		=> 'Alias Files',
						'ext'		=> 'txt',
						'logdir'	=> "{$pfb['aliasdir']}/",
						'download'	=> TRUE,
						'clear'		=> FALSE
						),
			'etiprep'	=> array('name'		=> 'Proofpoint/ET IPRep Files',
						'ext'		=> '.*',
						'logdir'	=> "{$pfb['etdir']}/",
						'download'	=> TRUE,
						'clear'		=> FALSE
						),
			'GeoIP'		=> array('name'		=> 'GeoIP Files',
						'ext'		=> 'txt',
						'logdir'	=> "{$pfb['ccdir']}/",
						'download'	=> TRUE,
						'clear'		=> FALSE
						),
			'python'	=> array('name'		=> 'DNSBL mode',
						'ext'		=> array('pfb_py*.txt'),
						'logdir'	=> "{$pfb['dnsbldir']}/",
						'download'	=> TRUE,
						'clear'		=> FALSE
						),
			'dnsbl_tld'	=> array('name'		=> 'DNSBL TLD List',
						'ext'		=> array('dnsbl_tld'),
						'logdir'	=> '/usr/local/pkg/pfblockerng/',
						'download'	=> TRUE,
						'clear'		=> FALSE
						),
			'dnsbl_safe'	=> array('name'		=> 'DNSBL Safe Search',
						'ext'		=> array('pfb_dnsbl*.conf'),
						'logdir'	=> '/usr/local/pkg/pfblockerng/',
						'download'	=> TRUE,
						'clear'		=> FALSE
						),
			'top1m'		=> array('name'		=> 'TOP1M Whitelist',
						'ext'		=> array('pfbalexawhitelist.txt'),
						'logdir'	=> "{$pfb['dbdir']}/",	
						'download'	=> TRUE,
						'clear'		=> TRUE
						)
		);

// Dynamically add any configured DNSBL Categeory Feeds
if ($pfb['blconfig'] &&
    !empty($pfb['blconfig']['blacklist_selected']) &&
    isset($pfb['blconfig']['item'])) {
	foreach ($pfb['blconfig']['item'] as $item) {
		$bl_title = htmlspecialchars($item['title']);
		$log = array( $bl_title . 'logs' => array(	'name'		=> 'Original ' . $bl_title . ' Files',
								'ext'		=> '*',
								'logdir'	=> "{$pfb['dbdir']}/" . strtolower($bl_title) . '/',
								'download'	=> TRUE,
								'clear'		=> FALSE));
		$pfb_logtypes = array_merge($pfb_logtypes, $log);
	}
}

// Function to validate file/path
function pfb_validate_filepath($validate, $pfb_logtypes) {

	// issue #1126: a NUL rides the basename, unseen by the dirname check below, and
	// throws at fopen()/glob()/unlink() -- an @-unsuppressible ValueError raised
	// INSIDE the call, so no FALSE-return guard can catch it. Reject ahead of them.
	if (str_contains($validate, "\0")) {
		return FALSE;
	}

	$allowed_path = array();
	foreach ($pfb_logtypes as $type) {
		$allowed_path[$type['logdir']] = '';
	}

	$path = pathinfo($validate, PATHINFO_DIRNAME) . '/';
	$file = basename($validate);

	if ($path == '/var/unbound/' && !str_starts_with($file, 'pfb_') && !file_exists("{$file}")) {
		return FALSE;
	}

	return isset($allowed_path[$path]);
}

$pconfig = array();
if ($_POST) {
	$pconfig = $_POST;
}

// issue #1183: an array-valued logtype/logFile POST field reaches string
// sinks (htmlspecialchars(), an array offset) below -- normalize here.
if (!isset($pconfig['logtype']) || !is_string($pconfig['logtype'])) {
	$pconfig['logtype'] = '';
}
if (!isset($pconfig['logFile']) || !is_string($pconfig['logFile'])) {
	$pconfig['logFile'] = '';
}

// Send logfile to screen
if (isset($_REQUEST) && isset($_REQUEST['ajax'])) {

	clearstatcache();
	// issue #1183: an array-valued file request field TypeErrors htmlspecialchars() -- guard it.
	$pfb_logfilename = htmlspecialchars(is_string($_REQUEST['file'] ?? null) ? $_REQUEST['file'] : '');
	if (!pfb_validate_filepath($pfb_logfilename, $pfb_logtypes)) {
		print ("|3|" . gettext('Invalid filename/path') . "|IA==|");
		exit;
	}

	// Load log
	if ($_REQUEST['action'] == 'load') {
		if (!file_exists($pfb_logfilename)) {
			print ("|1|" . gettext('Log file does not exist') . "|IA==|");
		}
		elseif (($fhandle = @fopen("{$pfb_logfilename}", 'r')) !== FALSE) {

			$linecnt = pfb_count_lines($pfb_logfilename);

			// issue #1156/#1261: pfb_count_lines() returns NULL on a read failure (e.g.
			// a TOCTOU race after the fopen() above); silently skipping the cap would
			// stream the whole file unbounded, so answer with the handler's error convention.
			if ($linecnt === NULL) {
				print ("|2|" . gettext('Failed to determine log line count') . "|IA==|");
				exit;
			}
			$maxcnt = 10000; // Max line limit

			$validate = FALSE;
			$line_limit = '';
			if ($linecnt > $maxcnt) {
				$validate = TRUE;
				$skipcnt = ($linecnt - $maxcnt);
				$line_limit = " [ Displaying last {$maxcnt} lines only ]";
			}

			$data = '';
			$linecnt = 0;
			while (($line = @fgets($fhandle)) !== FALSE) {
				if ($validate && $skipcnt >= $linecnt) {
					$linecnt++;
					continue;
				}

				// Raw: this only ever feeds the #fileContent <textarea> via JS .val()
				// (never HTML-parsed). A future .html()/innerHTML consumer must escape
				// at that point instead.
				$data .= $line;
				$linecnt++;
			}

			if ($linecnt > 0) {
				$data = base64_encode($data);
				print ("|0|File successfully loaded: Total Lines: {$linecnt}{$line_limit}|{$data}|");
				if (isset($data)) {
					unset($data);
				}
			}
			else {
				print ("|0|File successfully loaded: Total Lines: 0|IA==|");
			}
		}
		else {
			print ("|2|" . gettext('Failed to read log file') . "|IA==|");
		}
		exit;
	}
}

// Download/Clear logfile
if (isset($pconfig['logFile']) && !empty($pconfig['logFile']) && (isset($pconfig['download']) || isset($pconfig['clear']))) {
	
	$s_logfile = htmlspecialchars($pconfig['logFile']);
	if (!pfb_validate_filepath($s_logfile, $pfb_logtypes)) {
		print ("|3|" . gettext('Invalid filename/path') . "|IA==|");
		exit;
	}

	// Clear selected file
	if ($pconfig['clear']) {

		// Python log file must be truncated to not lose python file pointer
		if (strpos($s_logfile, 'py_error.log') !== FALSE) {
			// issue #1097: 'r+' never creates -- ftruncate(FALSE) throws TypeError on PHP 8, '@' only silences warnings
			if (($fp = @fopen("{$s_logfile}", 'r+')) !== FALSE) {
				@ftruncate($fp, 0);
				@fclose($fp);
			}
		} else {
			unlink_if_exists($s_logfile);

			if (strpos($s_logfile, 'dnsbl.log') !== FALSE ||
			    strpos($s_logfile, 'unified.log') !== FALSE ||
			    strpos($s_logfile, 'dns_reply.log') !== FALSE) {

				touch($s_logfile);
				@chown($s_logfile, 'unbound');
				@chgrp($s_logfile, 'unbound');
			}
		}
	}

	// Download log
	elseif($pconfig['download']) {
		if (file_exists($s_logfile)) {
			session_cache_limiter('public');
			// issue #1097: a lost TOCTOU race must skip headers/exit, not throw on fpassthru(FALSE)
			if (($fd = @fopen($s_logfile, "rb")) !== FALSE) {
				header("Content-Type: application/octet-stream");
				// issue #1097: size from the open handle -- the path can vanish after fopen()
				if (($fd_stat = fstat($fd)) !== FALSE) {
					header("Content-Length: " . $fd_stat['size']);
				}
				header("Content-Disposition: attachment; filename=\"" .
					trim(htmlentities(basename($s_logfile))) . "\"");
				if (isset($_SERVER['HTTPS'])) {
					header('Pragma: ');
					header('Cache-Control: ');
				} else {
					header("Pragma: private");
					header("Cache-Control: private, must-revalidate");
				}
				@fpassthru($fd);
				@fclose($fd);
				exit;
			}
		}
	}
} else {
	$s_logfile = '';
}

$pgtitle = array(gettext('Firewall'), gettext('pfBlockerNG'), gettext('Log Browser'));
$pglinks = array('', '/pfblockerng/pfblockerng_general.php', '@self');
$shortcut_section = 'pfblockerng';
include_once('head.inc');

// Define default Alerts Tab href link (Top row)
$get_req = pfb_alerts_default_page();

$tab_array	= array();
$tab_array[]	= array(gettext('General'),	FALSE,	'/pfblockerng/pfblockerng_general.php');
$tab_array[]	= array(gettext('IP'),		FALSE,	'/pfblockerng/pfblockerng_ip.php');
$tab_array[]	= array(gettext('DNSBL'),	FALSE,	'/pfblockerng/pfblockerng_dnsbl.php');
$tab_array[]	= array(gettext('Update'),	FALSE,	'/pfblockerng/pfblockerng_update.php');
$tab_array[]	= array(gettext('Reports'),	FALSE,	"/pfblockerng/pfblockerng_alerts.php{$get_req}");
$tab_array[]	= array(gettext('Feeds'),	FALSE,	'/pfblockerng/pfblockerng_feeds.php');
$tab_array[]	= array(gettext('Logs'),	TRUE,	'/pfblockerng/pfblockerng_log.php');
$tab_array[]	= array(gettext('Sync'),	FALSE,	'/pfblockerng/pfblockerng_sync.php');
pfb_software_add_tab($tab_array);
display_top_tabs($tab_array, TRUE);
pfb_print_pending_changes_box();

// Create Form
$form = new Form(FALSE);

// Build 'Shortcut Links' section
$section = new Form_Section('Log/File Browser selections');

// Collect main logtypes
$options = array();
foreach ($pfb_logtypes as $type => $log_type) {
	$options[$type] = $log_type['name'];
}

$section->addInput(new Form_Select(
	'logtype',
	'Log/File type:',
	$pconfig['logtype'],
	$options
))->setHelp('Choose which type of log/file you want to view.');

// Collect selected logs
$logs = array();
$clearable = $downloadable = FALSE;
// issue #1198: a scalar logtype that is not a key here warns at the offset below -- fall back.
$selected = array_key_exists($pconfig['logtype'], $pfb_logtypes) ? $pconfig['logtype'] : 'defaultlogs';
$pfb_sel = $pfb_logtypes[$selected];

if (isset($pfb_sel['logs'])) {
	$logs = $pfb_sel['logs'];
} else {
	$logs = getlogs($pfb_sel['logdir'], $pfb_sel['ext']);
}

$logdir		= $pfb_sel['logdir'] ?: '/var/db/pfblockerng';
$clearable	= $pfb_sel['clear'] ?: FALSE;
$downloadable	= $pfb_sel['download'] ?: FALSE;

// Add filepath to selected logs
$options = array();
$options[''] = 'Select Log/File to load';
foreach ($logs as $id => $log) {
	if ($id == 'logs' && is_array($log)) {
		foreach ($log as $opt) {
			$options["{$logdir}" . "{$opt}"] = $opt;
		}
	} else {
		$options["{$logdir}" . "{$log}"] = $log;
	}
}

$section->addInput(new Form_Select(
	'logFile',
	'Log/File selection:',
	$pconfig['logFile'],
	$options
))->setHelp('Choose which log/file you want to view.');
$form->add($section);

// Add appropriate buttons for logfile
$logbtns = '&emsp;&nbsp;<i class="fa-solid fa-arrows-rotate icon-pointer" onclick="loadFile()" title="Refresh current logfile."></i>';
if ($downloadable) {
	$logbtns .= '&emsp;<i class="fa-solid fa-download icon-pointer" name="download[]" id="downloadicon" title="Download current logfile."></i>';
}
if ($clearable) {
	$logbtns .= '&emsp;<i class="fa-solid fa-trash-can icon-pointer no-confirm" name="clear[]" id="clearicon" title="Clear selected logfile."></i>';
}

$section = new Form_Section('Log/File Details');
$section->addInput(new Form_StaticText(
	NULL,
	'<div style="display:none;" id="fileStatusBox"><strong id="fileStatus"></strong></div>'
	. '<div style="display:none;" id="filePathBox"><strong>Log/File Path:&emsp;</strong>'
	. '<div style="display:inline;" id="fbTarget"></div>'
	. '<div style="display:inline; margin-right:10px;" class="pull-right" id="fileRefreshBtn">'
	. $logbtns . '</div></div>'
));
$form->add($section);


$section = new Form_Section('Log');
$section->addInput(new Form_Textarea(
	'fileContent',
	NULL,
	''
))->removeClass('form-control')->addClass('row-fluid col-sm-12')->setAttribute('rows', '30')->setAttribute('wrap', 'off')
  ->setAttribute('readonly', 'readonly')->setAttribute('style', 'background:#fafafa; width: 100%');

// Scroll to end of page when loading logs
$section->addInput(new Form_StaticText(
	NULL,
	'<div id="endofpage"></div>'));

$form->add($section);

$form->addGlobal(new Form_Input('download', 'download', 'hidden', ''));
$form->addGlobal(new Form_Input('clear', 'clear', 'hidden', ''));

$form->addGlobal(new Form_Input('action', 'action', 'hidden', ''));
$form->addGlobal(new Form_Input('load', 'load', 'hidden', ''));
$form->addGlobal(new Form_Input('file', 'file', 'hidden', ''));

print($form);
?>

<script type="text/javascript">	
//<![CDATA[

function loadFile() {
	$("#fileStatus").html("<?=gettext("Loading file, please wait"); ?> ...");
	$("#fileStatusBox").show(250);
	$("#filePathBox").show(250);
	$("#fbTarget").html("");
	var ajaxRequest

	ajaxRequest = $.ajax({
			url: "/pfblockerng/pfblockerng_log.php",
			type: "post",
			data: { ajax: "ajax",
					action: "load",
					file: $("#logFile").val()
				},
			complete: loadComplete
	});
}

function loadComplete(req) {
	$("#fileContent").show(250);
	var values = req.responseText.split("|");
	values.shift(); values.pop();
	fileText = values[1];

	if (values.shift() == "0") {
		var fileinfo = values.shift();
		var fileContent = window.atob(values[0]);
		$("#fileStatus").html(fileinfo);
		$("#fbTarget").html($("#logFile").val());
		$("#fileRefreshBtn").show();
		$("#fileContent").prop("disabled", false);
		$("#fileContent").val(fileContent);
		$("#fileContent").css("overflow", "scroll");

		var endofpage = document.getElementById("endofpage")
		endofpage.scrollIntoView();
	} else {
		$("#fileStatus").html(fileText);
		$("#fbTarget").html("");
		$("#fileRefreshBtn").hide();
		$("#fileContent").val("");
		$("#fileContent").prop("disabled", true);
	}
	values = null;
}

events.push(function() {

	// Expand textarea to full width
	$('label[class="col-sm-2 control-label"]:eq(3)').remove();
	$('div[class="col-sm-10"]:eq(3)').removeClass('col-sm-10').addClass('col-sm-12');

	// Select log type and clear download variable
	$('#logtype').on('click', function() {
		$('#download').val('');
	});
	$('#logtype').on('change', function() {
		$('form').submit();
	});

	$('#logFile').on('change', function() {
		$("option[value='']").remove();
		loadFile();
	});

	// Download selected logfile 
	$('[id^=downloadicon]').click(function(event) {
		if (confirm(event.target.title)) {
			$('#download').val('download');
			$('#fileContent').val('');
			$('form').submit();
		}
	});

	// Clear selected logfile
	$('[id^=clearicon]').click(function(event) {
		if (confirm(event.target.title)) {
			$('#clear').val('clear');
			$('#fileContent').val('');
			$('form').submit();
		}
	});
});
//]]>
</script>
<?php include('foot.inc'); ?>
