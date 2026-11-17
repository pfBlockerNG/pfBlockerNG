#!/bin/sh
# pfBlockerNG Core's day-change counters program (--counters-cmd): argv is the counters due, clearip and/or cleardnsbl
exec /usr/local/bin/php -d display_errors=stderr -f /usr/local/pkg/pfblockerng/pfblockerng.inc core_counters "$@"
