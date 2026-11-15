"""Temporary read-only image-source evidence; no cron control or sentinel exception."""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
from typing import TYPE_CHECKING

import pytest

from . import helpers as h

if TYPE_CHECKING:
    from .conftest import SmokeVM

pytestmark = pytest.mark.smoke


@pytest.fixture(scope="module")
def cron_audit_vm(smoke_vm: SmokeVM) -> SmokeVM:
    h.deploy(smoke_vm)
    h.wait_no_active_pfb_task(smoke_vm)
    return smoke_vm


_CRON_SUMMARY_PHP = r"""
function sol_cron_lines($text) {
    $noncomment=0; $jobs=0;
    foreach (preg_split('/\r?\n/', $text) as $line) {
        $line=trim($line);
        if ($line==='' || $line[0]==='#') { continue; }
        $noncomment++;
        if (!preg_match('/^[A-Za-z_][A-Za-z0-9_]*\s*=/', $line)) { $jobs++; }
    }
    return array('noncommentLineCount'=>$noncomment,'jobCount'=>$jobs);
}
function sol_cron_rows($rows) {
    $out=array();
    foreach ($rows as $row) {
        $entry=array();
        foreach (array('minute','hour','mday','month','wday') as $key) {
            $entry[$key]=$row[$key] ?? NULL;
        }
        $entry['user']=$row['who'] ?? NULL;
        $entry['commandSha256']=hash('sha256', $row['command'] ?? '');
        $out[]=$entry;
    }
    return array('rowCount'=>count($rows),'rows'=>$out);
}
function sol_cron_file($path) {
    clearstatcache(TRUE, $path);
    if (!file_exists($path) && !is_link($path)) { return array('exists'=>FALSE); }
    $out=array('exists'=>TRUE,'type'=>@filetype($path));
    if (is_file($path)) {
        $text=@file_get_contents($path);
        $out['sizeBytes']=@filesize($path);
        $out['sha256']=$text===FALSE ? NULL : hash('sha256', $text);
        $out['noncommentLineCount']=$text===FALSE ? NULL : sol_cron_lines($text)['noncommentLineCount'];
    }
    return $out;
}
"""

_CRON_INVENTORY_PHP = r"""
$out=array('config'=>sol_cron_rows(config_get_path('cron/item', array())),
    'crontab'=>sol_cron_file('/etc/crontab'),
    'configFile'=>sol_cron_file('/conf/config.xml'),
    'sentinel'=>sol_cron_file('/var/db/pfblockerng/.pfb_cron_disable'),
    'directories'=>array());
foreach (array('/etc/cron.d','/usr/local/etc/cron.d','/var/cron/tabs') as $dir) {
    $entry=sol_cron_file($dir);
    if (is_dir($dir)) {
        $names=@scandir($dir);
        $entry['readable']=$names!==FALSE;
        $entry['files']=array();
        foreach ($names===FALSE ? array() : $names as $name) {
            if ($name==='.' || $name==='..') { continue; }
            $entry['files'][]=array('basename'=>$name,'metadata'=>sol_cron_file($dir.'/'.$name));
        }
    }
    $out['directories'][$dir]=$entry;
}
$pipe=@popen('/usr/bin/crontab -l 2>/dev/null', 'r');
$text=$pipe===FALSE ? '' : stream_get_contents($pipe);
$rc=$pipe===FALSE ? NULL : pclose($pipe);
$out['crontabList']=array('exitCode'=>$rc,'stdoutSha256'=>hash('sha256',$text),
    'hashEncoding'=>'exact stdout bytes',
    'counts'=>sol_cron_lines($text),'userScope'=>'SSH effective user only');
$binary='/usr/sbin/cron';
$out['binary']=array('path'=>$binary,'metadata'=>sol_cron_file($binary),
    'source'=>'exact installed binary strings; running executable not established',
    'pathConstants'=>array());
$strings=array(); $stringsRc=0;
@exec('command -v strings 2>/dev/null', $strings, $stringsRc);
if ($stringsRc===0 && count($strings)===1 && is_executable($strings[0]) && is_file($binary)) {
    $lines=array();
    @exec(escapeshellarg($strings[0]).' -a '.escapeshellarg($binary).' 2>/dev/null', $lines, $stringsRc);
    $out['binary']['stringsExitCode']=$stringsRc;
    foreach ($lines as $line) {
        if (preg_match_all('~/(?:[A-Za-z0-9_.%-]+/)*[A-Za-z0-9_.%-]*cron[A-Za-z0-9_./%-]*~', $line, $matches)) {
            foreach ($matches[0] as $path) { $out['binary']['pathConstants'][]=$path; }
        }
    }
    $out['binary']['pathConstants']=array_values(array_unique($out['binary']['pathConstants']));
    sort($out['binary']['pathConstants']);
} else { $out['binary']['stringsExitCode']=NULL; }
$out['pathScope']='candidate paths inspected directly; existence does not establish daemon consumption';
echo '<<<CRON_SURFACES>>>'.base64_encode(json_encode($out,JSON_THROW_ON_ERROR)).'<<<END_CRON_SURFACES>>>';
"""


def _read_cron_surfaces(vm: SmokeVM) -> dict[str, object]:
    result = h.php_eval(vm, _CRON_SUMMARY_PHP + _CRON_INVENTORY_PHP)
    if result.returncode != 0:
        pytest.fail("cron inventory failed (output suppressed)")
    if "<<<CRON_SURFACES>>>" not in result.stdout:
        pytest.fail("missing cron inventory envelope (output suppressed)")
    encoded = result.stdout.split("<<<CRON_SURFACES>>>", 1)[1].split("<<<END_CRON_SURFACES>>>", 1)[0]
    data: dict[str, object] = json.loads(base64.b64decode(encoded))
    return data


def _cron_status(vm: SmokeVM) -> dict[str, object]:
    result = vm.ssh("service", "cron", "onestatus")
    return {
        "exitCode": result.returncode,
        "stdoutSha256": hashlib.sha256(result.stdout.encode()).hexdigest(),
        "stderrSha256": hashlib.sha256(result.stderr.encode()).hexdigest(),
    }


def test_sol_cron_surface_serialization() -> None:
    """Catch raw-command disclosure, miscounted jobs, and absent-file failures."""
    # No VM transport: execute the same serializers with adversarial fixture data.
    program = (
        _CRON_SUMMARY_PHP
        + """
if (function_exists('sol_cron_rows')) {
    $rows=array(array('minute'=>'*/5','hour'=>'*','mday'=>'*','month'=>'*','wday'=>'*',
        'who'=>'root','command'=>'TOKEN=secret command'));
    echo json_encode(array('rows'=>sol_cron_rows($rows),
        'empty'=>sol_cron_rows(array()),
        'lines'=>sol_cron_lines("# comment\\n\\nFOO=secret\\n* * * * * run secret\\n@reboot run secret\\n"),
        'missing'=>sol_cron_file('/nonexistent/sol-cron-surface-fixture')), JSON_THROW_ON_ERROR);
}
"""
    )
    result = subprocess.run(
        ["/var/tmp/agents/cfpc2/bsdunzip-run.sh", "php", "-r", program],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, "hermetic PHP serialization failed (output suppressed)"
    assert result.stdout, "cron surface serializers are missing"
    data = json.loads(result.stdout)
    assert data["empty"] == {"rowCount": 0, "rows": []}
    assert data["rows"] == {
        "rowCount": 1,
        "rows": [
            {
                "minute": "*/5",
                "hour": "*",
                "mday": "*",
                "month": "*",
                "wday": "*",
                "user": "root",
                "commandSha256": "4ace741f75a223a3d530918fa8180306691db0ed39b00aadf24fd6172267a519",
            }
        ],
    }
    assert data["lines"] == {"noncommentLineCount": 3, "jobCount": 2}
    assert data["missing"] == {"exists": False}
    assert "secret" not in result.stdout


@pytest.mark.timeout(300)
def test_sol_read_native_cron_sources(cron_audit_vm: SmokeVM) -> None:
    vm = cron_audit_vm
    assert vm.host in ("127.0.0.1", "localhost"), "read-only probe requires the owned disposable VM"
    assert vm.ssh("test", "-f", h.PFB_CRON_DISABLE_PATH).returncode == 0, "sentinel must stay present"
    original_status = _cron_status(vm)
    before = _read_cron_surfaces(vm)
    result = h.php_eval(
        vm,
        "require_once('/etc/inc/services.inc'); $out=array();"
        "foreach (array('configure_cron','install_cron_job','is_process_running','get_process_pid') as $name) {"
        " if (!function_exists($name)) { $out[$name]=array('defined'=>FALSE); continue; }"
        " $r=new ReflectionFunction($name); $lines=file($r->getFileName());"
        " $code=implode('',array_slice($lines,$r->getStartLine()-1,$r->getEndLine()-$r->getStartLine()+1));"
        " $out[$name]=array('defined'=>TRUE,'file'=>$r->getFileName(),'start'=>$r->getStartLine(),"
        " 'end'=>$r->getEndLine(),'sha256'=>hash('sha256',$code),'code'=>$code);"
        "} echo '<<<CRON_SOURCE>>>' . base64_encode(json_encode($out,JSON_THROW_ON_ERROR)) . '<<<END_CRON_SOURCE>>>';",
    )
    if result.returncode != 0:
        pytest.fail("source reflection failed (output suppressed)")
    if "<<<CRON_SOURCE>>>" not in result.stdout:
        pytest.fail("missing source envelope (output suppressed)")
    encoded = result.stdout.split("<<<CRON_SOURCE>>>", 1)[1].split("<<<END_CRON_SOURCE>>>", 1)[0]
    sources = json.loads(base64.b64decode(encoded))
    for name in ("configure_cron", "install_cron_job"):
        assert sources[name]["defined"], f"actual image lacks {name}"
    for record in sources.values():
        if record["defined"]:
            assert hashlib.sha256(record["code"].encode()).hexdigest() == record["sha256"], "source hash mismatch"
    after = _read_cron_surfaces(vm)
    final_status = _cron_status(vm)
    assert before == after, "read-only probe observed cron/config/sentinel surface mutation"
    assert original_status == final_status, "read-only probe observed cron service status mutation"
    assert vm.ssh("test", "-f", h.PFB_CRON_DISABLE_PATH).returncode == 0, "read-only probe lost sentinel"
    print(
        "SOL_NATIVE_CRON_SOURCE="
        + json.dumps(
            {
                "originalServiceCronStatus": original_status,
                "surfaces": before,
                "surfacesUnchanged": True,
                "sources": sources,
                "preparation": "ordinary package deployment and idle wait completed before audit snapshots",
                "isolation": "audit window read-only; no signal, daemon replacement or sentinel removal",
            },
            sort_keys=True,
        ),
        flush=True,
    )
    assert vm.ssh("test", "-f", h.PFB_CRON_DISABLE_PATH).returncode == 0, "read-only probe lost sentinel"
