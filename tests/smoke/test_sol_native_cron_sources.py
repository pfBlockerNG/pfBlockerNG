"""Temporary read-only image-source evidence; no cron control or sentinel exception."""

from __future__ import annotations

import base64
import hashlib
import json
from typing import TYPE_CHECKING

import pytest

from . import helpers as h

if TYPE_CHECKING:
    from .conftest import SmokeVM

pytestmark = pytest.mark.smoke


@pytest.mark.timeout(300)
def test_sol_read_native_cron_sources(smoke_vm: SmokeVM) -> None:
    vm = smoke_vm
    assert vm.host in ("127.0.0.1", "localhost"), "read-only probe requires the owned disposable VM"
    h.deploy(vm)
    assert vm.ssh("test", "-f", h.PFB_CRON_DISABLE_PATH).returncode == 0, "sentinel must stay present"
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
    assert result.returncode == 0, f"source reflection failed: {result.stdout!r} {result.stderr!r}"
    assert "<<<CRON_SOURCE>>>" in result.stdout, f"missing source envelope: {result.stdout!r}"
    encoded = result.stdout.split("<<<CRON_SOURCE>>>", 1)[1].split("<<<END_CRON_SOURCE>>>", 1)[0]
    sources = json.loads(base64.b64decode(encoded))
    for name in ("configure_cron", "install_cron_job"):
        assert sources[name]["defined"], f"actual image lacks {name}: {sources}"
    for record in sources.values():
        if record["defined"]:
            assert hashlib.sha256(record["code"].encode()).hexdigest() == record["sha256"], record
    status = vm.ssh("service", "cron", "onestatus")
    version = vm.ssh("cat", "/etc/version")
    print(
        "SOL_NATIVE_CRON_SOURCE="
        + json.dumps(
            {
                "version": version.stdout.strip(),
                "statusCode": status.returncode,
                "statusOut": status.stdout,
                "statusErr": status.stderr,
                "sources": sources,
                "isolation": "read-only; no signal, daemon replacement or sentinel removal",
            },
            sort_keys=True,
        ),
        flush=True,
    )
    assert vm.ssh("test", "-f", h.PFB_CRON_DISABLE_PATH).returncode == 0, "read-only probe lost sentinel"
