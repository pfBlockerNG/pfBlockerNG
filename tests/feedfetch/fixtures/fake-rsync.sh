#!/bin/sh
# Stand-in rsync for the feed-transfer parity corpus (tests/feedfetch/fixtures/parity). Both runners copy it next to
# rsync.body and rsync.exit: it records its arguments one per line in rsync.argv, writes rsync.body to its last
# argument (the destination) only when it exits 0, as rsync renames its temp file only on success, and exits with rsync.exit.
here=$(dirname "$0")
: >"${here}/rsync.argv"
for arg; do
	printf '%s\n' "${arg}" >>"${here}/rsync.argv"
done
rc=$(cat "${here}/rsync.exit")
if [ "${rc}" -eq 0 ]; then
	eval "dst=\${$#}"
	cat "${here}/rsync.body" >"${dst}"
fi
exit "${rc}"
