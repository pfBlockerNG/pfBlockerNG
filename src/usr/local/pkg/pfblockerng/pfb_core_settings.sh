#!/bin/sh
# pfBlockerNG Core's settings adapter (--settings-backend-cmd): one JSON request on stdin, one JSON reply on stdout
exec /usr/local/bin/php -f /usr/local/pkg/pfblockerng/pfblockerng.inc core_settings
