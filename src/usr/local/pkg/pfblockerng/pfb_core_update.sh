#!/bin/sh
# pfBlockerNG Core's update program (--update-cmd): one JSON request on stdin, the progress on stdout, the result on fd 3
exec /usr/local/bin/php -d display_errors=stderr -f /usr/local/pkg/pfblockerng/pfblockerng.inc core_update
