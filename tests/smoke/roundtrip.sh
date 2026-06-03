#!/bin/sh
# roundtrip.sh — drive the booted pfSense guest and prove the control path
# the ADR-04 harness depends on (SSH + pfctl + the pfBlockerNG PHP CLI + dig
# + WebUI reachability). Phase-1 spike only — NOT the real per-case matrix.
#
# Usage:
#   tests/smoke/roundtrip.sh <ssh-key> <local-data-name> [local-data-ip] \
#       [host] [ssh-port] [dns-port] [web-port]
#
# Defaults: host 127.0.0.1, ssh-port 2222, dns-port 5353, web-port 8080.
#
# Checks (each fatal unless noted):
#   1. pfctl -sr returns a non-empty ruleset over SSH.
#   2. /usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php update
#      exits 0 over SSH (the production reload entry point).
#   3. Inject a control local-data record into the RUNNING Unbound over SSH
#      (unbound-control, AFTER the update so the reload doesn't wipe it), then
#      resolve it against the guest's own resolver (127.0.0.1:53, over SSH) and
#      assert the injected IP. This is the spike stand-in for Phase-4 per-case
#      config-API injection. The external runner->hostfwd DNS path is also tried
#      but is NON-FATAL (it depends on the image baking WAN pass :53 + Unbound
#      access-control for 10.0.2.0/24 — a Phase-2 image concern).
#   4. curl http://127.0.0.1:<web-port>/ returns the WebUI login page.
#
# POSIX sh; quoted expansions; absolute binary paths.

set -eu

SSH=/usr/bin/ssh
DIG=/usr/bin/dig
CURL=/usr/bin/curl
PHP_CLI="/usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php"

usage() {
    echo "Usage: $0 <ssh-key> <local-data-name> [local-data-ip] [host] [ssh-port] [dns-port] [web-port]" >&2
    exit 2
}

[ "$#" -ge 2 ] || usage

SSH_KEY="$1"
LOCAL_DATA_NAME="$2"
LOCAL_DATA_IP="${3:-}"
HOST="${4:-127.0.0.1}"
SSH_PORT="${5:-2222}"
DNS_PORT="${6:-5353}"
WEB_PORT="${7:-8080}"

# Resolve each tool by name if the pfSense-convention absolute path is absent
# (the GH-hosted ubuntu-latest layout differs).
[ -x "$SSH" ] || SSH="$(command -v ssh || true)"
[ -x "$DIG" ] || DIG="$(command -v dig || true)"
[ -x "$CURL" ] || CURL="$(command -v curl || true)"

for bin in "$SSH" "$DIG" "$CURL"; do
    if [ -z "$bin" ] || [ ! -x "$bin" ]; then
        echo "roundtrip: a required tool (ssh/dig/curl) was not found" >&2
        exit 1
    fi
done

if [ ! -f "$SSH_KEY" ]; then
    echo "roundtrip: ssh key not found: $SSH_KEY" >&2
    exit 1
fi

SSH_OPTS="-i ${SSH_KEY} -p ${SSH_PORT} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o BatchMode=yes -o LogLevel=ERROR"

run_ssh() {
    # shellcheck disable=SC2086
    "$SSH" $SSH_OPTS "root@${HOST}" "$@"
}

FAILED=0

echo "==> [1/4] pfctl -sr (ruleset dump over SSH)"
if RULES="$(run_ssh /sbin/pfctl -sr 2>/dev/null)" && [ -n "$RULES" ]; then
    echo "    OK: $(printf '%s\n' "$RULES" | wc -l | tr -d ' ') rules returned"
else
    echo "    FAIL: pfctl -sr returned no rules" >&2
    FAILED=1
fi

echo "==> [2/4] pfblockerng.php update (production reload entry point)"
if run_ssh "$PHP_CLI update"; then
    echo "    OK: update exited 0"
else
    echo "    FAIL: pfblockerng.php update exited non-zero" >&2
    FAILED=1
fi

echo "==> [3/4] inject local-data + resolve via the guest's Unbound"
# Fail fast: without an IP the steps below would call unbound-control with an
# empty A record and produce avoidable follow-on errors (no trap to skip).
[ -n "$LOCAL_DATA_IP" ] || { echo "    FAIL: a local-data IP is required (got empty)" >&2; exit 1; }

# [2/4]'s `pfblockerng.php update` reconfigures + restarts Unbound; the restart
# is async, so wait for the resolver to answer again before injecting/querying.
UB_READY=0
ub_i=0
while [ "$ub_i" -lt 30 ]; do
    if run_ssh '/usr/local/sbin/unbound-control -c /var/unbound/unbound.conf status >/dev/null 2>&1'; then
        UB_READY=1
        break
    fi
    ub_i=$((ub_i + 1))
    sleep 2
done
if [ "$UB_READY" -ne 1 ]; then
    echo "    FAIL: Unbound did not become ready after the reload" >&2
    FAILED=1
fi

# Inject into the RUNNING resolver. unbound-control talks to the live Unbound;
# pfSense runs it against /var/unbound/unbound.conf. Done after [2/4] so the
# pfBlockerNG reload doesn't wipe the record.
if run_ssh "/usr/local/sbin/unbound-control -c /var/unbound/unbound.conf local_data '${LOCAL_DATA_NAME}. 3600 IN A ${LOCAL_DATA_IP}'"; then
    echo "    injected ${LOCAL_DATA_NAME} -> ${LOCAL_DATA_IP}"
else
    echo "    FAIL: could not inject local-data via unbound-control" >&2
    FAILED=1
fi

# Ensure a DNS query tool on the guest (a fresh pfSense may ship neither drill
# nor host). Check-then-install (bind-tools provides host/dig) rather than
# assuming presence; needs egress, open during the spike.
if ! run_ssh 'command -v drill >/dev/null 2>&1 || command -v host >/dev/null 2>&1'; then
    echo "    no drill/host on guest — installing bind-tools via pkg"
    run_ssh 'env ASSUME_ALWAYS_YES=yes pkg install -y bind-tools' >/dev/null 2>&1 \
        || echo "    WARN: could not install a DNS query tool on the guest" >&2
fi

# Resolve against the guest's own resolver (127.0.0.1:53) over SSH — reliable
# regardless of WAN firewall/listen/access-control. drill (ldns) preferred,
# host as fallback.
DNS_OUT="$(run_ssh "if command -v drill >/dev/null 2>&1; then drill ${LOCAL_DATA_NAME} @127.0.0.1 A; elif command -v host >/dev/null 2>&1; then host -t A ${LOCAL_DATA_NAME} 127.0.0.1; else echo NO_GUEST_DNS_TOOL; fi" 2>/dev/null || true)"
if printf '%s' "$DNS_OUT" | grep -q NO_GUEST_DNS_TOOL; then
    echo "    FAIL: no DNS query tool (drill/host) on the guest to verify resolution" >&2
    FAILED=1
elif printf '%s' "$DNS_OUT" | grep -qw "${LOCAL_DATA_IP}"; then
    echo "    OK: guest Unbound resolves ${LOCAL_DATA_NAME} -> ${LOCAL_DATA_IP}"
else
    echo "    FAIL: guest Unbound did not return ${LOCAL_DATA_IP} for ${LOCAL_DATA_NAME}" >&2
    printf '%s\n' "$DNS_OUT" | sed 's/^/      /' >&2
    FAILED=1
fi

# Non-fatal: also probe the external path the real harness will use
# (runner -> udp hostfwd :${DNS_PORT} -> guest:53). It only works once the
# image bakes WAN pass :53 + Unbound access-control 10.0.2.0/24 (Phase 2).
EXT="$("$DIG" +short +time=3 +tries=1 "@${HOST}" -p "${DNS_PORT}" "${LOCAL_DATA_NAME}" A 2>/dev/null || true)"
if printf '%s' "$EXT" | grep -qw "${LOCAL_DATA_IP}"; then
    echo "    note: external hostfwd DNS path also works (:${DNS_PORT})"
else
    echo "    note: external hostfwd DNS path not working yet — image must bake WAN pass :53 + Unbound access-control 10.0.2.0/24 (not fatal for the spike)"
fi

echo "==> [4/4] curl http://${HOST}:${WEB_PORT}/ (WebUI reachability)"
PAGE="$("$CURL" -fsSL --max-time 15 "http://${HOST}:${WEB_PORT}/" 2>/dev/null || true)"
if printf '%s' "$PAGE" | grep -qiE 'login|pfsense'; then
    echo "    OK: WebUI login page reachable"
else
    echo "    FAIL: WebUI did not return a recognisable login page" >&2
    FAILED=1
fi

if [ "$FAILED" -ne 0 ]; then
    echo "==> round-trip FAILED" >&2
    exit 1
fi
echo "==> round-trip PASSED"
