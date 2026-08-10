from __future__ import annotations

import builtins
import sys
from pathlib import Path


class _DNSMessage:
    def __init__(self, *_args: object) -> None:
        self.answer: list[str] = []

    def set_return_msg(self, qstate: object) -> bool:
        qstate.return_msg.rep.security = 0
        return True


builtins.log_info = lambda _message: None
builtins.DNSMessage = _DNSMessage
for name, value in {
    "MODULE_EVENT_NEW": 0,
    "MODULE_EVENT_PASS": 1,
    "RR_TYPE_AAAA": 28,
    "RR_TYPE_TXT": 16,
    "RR_TYPE_A": 1,
    "RR_CLASS_IN": 1,
    "PKT_QR": 0x8000,
    "PKT_RA": 0x80,
    "RCODE_NOERROR": 0,
    "MODULE_ERROR": 3,
    "MODULE_FINISHED": 4,
}.items():
    setattr(builtins, name, value)

sys.path.insert(0, str(Path(__file__).parents[1] / "src/usr/local/pkg/pfblockerng"))
