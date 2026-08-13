#!/bin/sh
# install_deps_CE_2.8.sh — install pfBlockerNG's runtime dependencies on a
# pfSense CE 2.8.x box, for preparing the ADR-04 smoke-test base image.
#
# Run this ON the pfSense box as root before snapshotting/publishing the image.
# With these baked in, the harness `pkg add` of the branch .pkg resolves its
# RUN_DEPENDS from the local pkg db OFFLINE (no repo round-trip) — a stable
# deploy. A "Missing dependency" at `pkg add` means this step was skipped.
#
# The list is EXACTLY the port RUN_DEPENDS for
# net/pfSense-pkg-pfBlockerNG[-devel] (see docs/misc/pfSense_versions.md and
# legacy/ADRs/ADR_04_VM_Smoke_Tests/IMAGE_RUNBOOK.md §3). The py311-* packages are
# pinned to CE 2.8.x's Python 3.11 — a pfSense base on a different Python needs
# the matching py3XX-* (add a sibling install_deps_CE_<ver>.sh for it).
#
# POSIX sh.

set -eu

# Package names map 1:1 to the port RUN_DEPENDS origins:
#   libmaxminddb             net/libmaxminddb              (mmdblookup — GeoIP)
#   py311-maxminddb          net/py-maxminddb              (GeoIP reader in pfb_unbound.py)
#   py311-sqlite3            databases/py-sqlite3          (DNSBL / reports DB)
#   py311-charset-normalizer textproc/py-charset-normalizer (feed encoding detection, issue #1797)
#   lighttpd                 www/lighttpd                  (DNSBL sinkhole webserver)
#   jq                       textproc/jq                   (feeds, AWS IP-prefix pre-scripts)
#   rsync                    net/rsync                     (rsync-format feed lists)
#   grepcidr                 net-mgmt/grepcidr             (IP path)
#   iprange                  net-mgmt/iprange              (IP path)
#   gnugrep                  textproc/gnugrep              (ggrep — list pipeline)
env ASSUME_ALWAYS_YES=yes pkg install -y \
    libmaxminddb \
    py311-maxminddb \
    py311-sqlite3 \
    py311-charset-normalizer \
    lighttpd \
    jq \
    rsync \
    grepcidr \
    iprange \
    gnugrep

echo "pfBlockerNG CE 2.8.x runtime dependencies installed."
