#!/bin/sh
# pfBlockerNG Core's every-minute metrics program (--metrics-cmd): Core calls it only while the export is on
exec /usr/bin/timeout -s TERM -k 5 50 /usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php metrics
