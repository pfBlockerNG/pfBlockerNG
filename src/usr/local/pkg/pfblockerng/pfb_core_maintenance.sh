#!/bin/sh
# pfBlockerNG Core's quarter-hour maintenance program (--maintenance-cmd): no stdin request or fd 3 result
exec /usr/local/bin/php -d display_errors=stderr -f /usr/local/pkg/pfblockerng/pfblockerng.inc core_maintenance
