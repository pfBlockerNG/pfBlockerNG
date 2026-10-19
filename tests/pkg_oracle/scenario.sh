#!/bin/sh
# scenario.sh -- runs INSIDE the oracle container (see run.sh). One real removal with the FreeBSD pkg, the pinned pfSense core
# in front of the shipped hook, a real Unbound and the real DNS proxy:
#   1. pfB-DNS serves (module mode: blocked.example is answered with the DNSBL VIP, probe.example is forwarded);
#   2. `pkg delete` while another save holds the config lock until the Resolver restore gives up: the removal aborts (exit
#      3 inside pkg's DEINSTALL script; pkg exits 0 and leaves the package installed);
#   3. what is left: is the proxy answering, is the package still registered, does a retry remove it.
# ORACLE_EXPECT=recovered (the fixed code) or broken (the base: the defect reproduces); the exit status says whether it held.
set -u
label=${1:-lock}
expect=${ORACLE_EXPECT:-recovered}
out=/results/$label
mkdir -p "$out"
export RACE_DIR=/sandbox/state ORACLE_REPO=/repo CORE_DIR=/core CORE_LABEL=${CORE_LABEL:-master}
export PFB_PYTHON_DEPENDENCIES=py313 PFB_PYTHON_DIR=/opt/pybin PYTHONDONTWRITEBYTECODE=1
fail=0
holder=
trap 'if [ -n "$holder" ]; then kill "$holder" 2>/dev/null; wait "$holder" 2>/dev/null; fi' EXIT
note() { printf '%s\n' "$*" | tee -a "$out/summary.txt"; }
check() { # description, command...
	desc=$1; shift
	if "$@"; then note "  ok    $desc"; else note "  FAIL  $desc"; fail=$((fail + 1)); fi
}
dns() { python3 /oracle/q.py 127.0.0.1 "$1"; }
state() { php -f /oracle/probe.php state 2>/dev/null | tail -1; }
has() { printf '%s' "$1" | grep -q -- "$2"; }
# Every wait observes an event under one outer cap (300 polls, 0.2 s apart). Expiry is an environment stall: STUCK/ENVIRONMENT,
# never a product verdict.
stuck() { note "STUCK/ENVIRONMENT: $*"; exit 8; }
await() { # description, command...: poll the command until it succeeds
	desc=$1; shift
	n=0
	until "$@"; do
		n=$((n + 1)); [ "$n" -le 300 ] || stuck "$desc was not observed"
		sleep 0.2
	done
}
unbound_up() { grep -q "start of service" /tmp/unbound.log 2>/dev/null; }
answered() { case "$(dns "$1")" in ANSWERED*) ;; *) return 1 ;; esac; }
absent() { case "$(dns probe.example.)" in *ConnectionRefusedError*) ;; *) return 1 ;; esac; }
holder_settled() { [ -f "$RACE_DIR/holder.ready" ] || [ -f "$RACE_DIR/holder.failed" ]; }

rm -rf /usr/local/pkg && ln -s /repo/src/usr/local/pkg /usr/local/pkg
mkdir -p /var/log/pfblockerng /var/unbound && chown unbound /var/log/pfblockerng /var/unbound
rm -rf "$RACE_DIR" && mkdir -p "$RACE_DIR"
cat > /tmp/unbound.conf <<C
server:
    username: ""
    chroot: ""
    directory: "/tmp"
    pidfile: "/tmp/unbound.pid"
    do-ip6: no
    port: 5354
    interface: 127.0.0.1@5353
    proxy-protocol-port: 5353
    access-control: 127.0.0.0/8 allow
    use-syslog: no
    local-zone: "example." transparent
    local-data: "probe.example. 60 IN A 192.0.2.7"
C
unbound -d -c /tmp/unbound.conf >/tmp/unbound.log 2>&1 &
await "Unbound starts serving (its start-of-service line)" unbound_up

note "== $label: core $CORE_LABEL, pkg $(/work/prefix/sbin/pkg --version), repo ${ORACLE_REV:-unknown}"
php -f /oracle/probe.php seed 2>&1 | grep -v "Warning\|Deprecated" | tail -1 > "$out/seed.txt"
php -f /oracle/probe.php start 2>&1 | grep -v "Warning\|Deprecated" | tail -1 > "$out/start.txt"
await "pfB-DNS answers probe.example. before the removal" answered probe.example.
before_ok=$(dns probe.example.); before_blocked=$(dns blocked.example.)
note "before: probe.example. -> $before_ok | blocked.example. -> $before_blocked"
check "pfB-DNS answers before the removal" has "$before_ok" "ANSWERED rcode=0 answers=1 last4=192.0.2.7"
check "and blocks a listed name with the DNSBL VIP" has "$before_blocked" "last4=10.10.10.1"

# The real package manager and a package whose scripts are what pfSense's package builder ships: rc.packages DEINSTALL / POST-DEINSTALL.
P=/sandbox/pkg
OPTS="-o ABI=FreeBSD:15:amd64 -o OSVERSION=1500000 -o IGNORE_OSVERSION=yes -o REPOS_DIR=/nonexistent -o PKG_DBDIR=$P/db -o PKG_CACHEDIR=$P/cache -o ASSUME_ALWAYS_YES=yes"
PKG=/work/prefix/sbin/pkg
rm -rf $P && mkdir -p $P/stage/usr/local/share/pfblockerng-oracle $P/meta $P/out $P/root
echo runtime > $P/stage/usr/local/share/pfblockerng-oracle/runtime.txt
echo share/pfblockerng-oracle/runtime.txt > $P/plist
cat > $P/meta/+MANIFEST <<M
name: "pfSense-pkg-pfBlockerNG-devel"
version: "1.0"
origin: "net/pfSense-pkg-pfBlockerNG-devel"
comment: "oracle"
maintainer: "oracle@example.org"
www: "http://example.org"
prefix: "/usr/local"
desc: "oracle"
M
for script in DEINSTALL POST-DEINSTALL; do
	# pfSense's package scripts name the package themselves (pkg does not pass its name in $1): rc.packages NAME PHASE
	printf '#!/bin/sh\ncase "${2}" in DEINSTALL|POST-DEINSTALL) php -f /oracle/probe.php rc_packages pfSense-pkg-pfBlockerNG-devel "${2}" ;; esac\n' > "$P/meta/+$script"
done
$PKG $OPTS create -m $P/meta -r $P/stage -p $P/plist -o $P/out > "$out/create.log" 2>&1 && $PKG $OPTS -r $P/root add $P/out/*.pkg > "$out/add.log" 2>&1 || { note "package build failed"; cat "$out/create.log" "$out/add.log"; exit 9; }
installed() { $PKG $OPTS -r $P/root info -q 2>/dev/null | tr '\n' ' '; }
check "the package is installed" has "$(installed)" pfSense-pkg-pfBlockerNG-devel

note "-- removal 1: another save holds the config lock until the removal's Resolver restore gives up"
# The holder lets go when a lock wait gives up (the lock double leaves $lock.refused), so the service registration that follows
# can take the lock, as it can on the appliance once the save ends. pkg delete returning is the backstop: no holder outlives it.
php -r '$d = getenv("RACE_DIR"); register_shutdown_function(function () use ($d) { if (!file_exists("$d/holder.ready")) { touch("$d/holder.failed"); } }); $k = fopen("$d/pfb_dns_config.lock", "c"); flock($k, LOCK_EX) or exit(1); touch("$d/holder.ready"); for ($i = 0; !file_exists("$d/pfb_dns_config.refused") && !file_exists("$d/holder.go") && $i < 1800; $i++) { usleep(100000); }' &
holder=$!
await "the lock holder took pfb_dns_config" holder_settled
[ -f "$RACE_DIR/holder.ready" ] || stuck "the lock holder could not take pfb_dns_config"
$PKG $OPTS -r $P/root delete -y pfSense-pkg-pfBlockerNG-devel > "$out/delete1.out" 2>&1; rc1=$?
touch "$RACE_DIR/holder.go"
wait "$holder"; holder=
note "pkg delete exit status: $rc1; installed after: [$(installed)]"
if [ "$expect" = recovered ]; then
	await "pfB-DNS answers probe.example. after the aborted removal" answered probe.example.
	await "pfB-DNS answers blocked.example. after the aborted removal" answered blocked.example.
else
	# The defect's proxy is down: a NO ANSWER proves the defect only once nothing listens on its port any more
	await "the proxy is confirmed absent (its port refuses)" absent
fi
s1=$(state); note "state: $s1"
after_ok=$(dns probe.example.); after_blocked=$(dns blocked.example.)
note "after the aborted removal: probe.example. -> $after_ok | blocked.example. -> $after_blocked"
sed 's/^/  | /' "$out/delete1.out" | tail -12

if [ "$expect" = recovered ]; then
	check "pkg leaves the package installed (the hook exited 3)" has "$(installed)" pfSense-pkg-pfBlockerNG-devel
	check "pfB-DNS still answers a forwarded name" has "$after_ok" "ANSWERED rcode=0 answers=1 last4=192.0.2.7"
	check "and still blocks the listed name with the DNSBL VIP" has "$after_blocked" "last4=10.10.10.1"
	check "the three services are registered again" has "$s1" '"registered_services":\["pfb_dnsbl","pfb_dns_proxy","pfb_filter"\]'
	check "and the menu entry" has "$s1" 'Firewall:pfBlockerNG'
	check "the proxy runs in module mode" has "$s1" '"rc_no_module":false'
	check "the module's manifest is kept" has "$s1" '"manifest":true'
	check "the Resolver is still moved, the snapshot kept" has "$s1" '"snapshot":true'
else
	check "the defect reproduces: the proxy does not answer" has "$after_ok" "NO ANSWER"
	check "and nothing is registered" has "$s1" '"registered_services":\[\]'
	check "and the DNSBL manifest the proxy loads from is gone" has "$s1" '"manifest":false'
fi

note "-- removal 2 (retry): the lock is free"
$PKG $OPTS -r $P/root delete -y pfSense-pkg-pfBlockerNG-devel > "$out/delete2.out" 2>&1; rc2=$?
note "pkg delete exit status: $rc2; installed after: [$(installed)]"
s2=$(state); note "state: $s2"
sed 's/^/  | /' "$out/delete2.out" | tail -8
if [ "$expect" = recovered ]; then
	check "the retry removes the package" test -z "$(installed)"
	check "the Resolver is restored and the snapshot cleared" has "$s2" '"snapshot":false'
	check "the proxy is stopped" has "$s2" '"proxy_running":false'
else
	check "the base's retry removes the package only because nothing serves the Resolver any more (the outage is the defect)" test -z "$(installed)"
fi
note "== $label: $([ $fail -eq 0 ] && echo PASS || echo "FAIL ($fail)") (expect=$expect)"
exit $fail
