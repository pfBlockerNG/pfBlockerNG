#!/bin/sh
# pfBlockerNG Core's every-minute metrics program (--metrics-cmd): publishes the export while the enabled marker exists
[ -e /usr/local/etc/pfb_metrics_enabled ] || exit 0
exec /usr/bin/timeout -s TERM -k 5 50 /usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php metrics
