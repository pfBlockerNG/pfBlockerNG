#!/bin/sh
# ip_pre_AWS_EU_SOUTH.sh - Amazon AWS Region (Europe - South)
# Thin wrapper: the parse/aggregate logic lives in aws_region_prefixes.sh;
# this only supplies the jq region filter. The shared script is resolved
# relative to THIS script's own location ($0), so it works regardless of the
# install path or a chroot - no hard-coded absolute path.
# Copyright (c) 2015-2024 BBcan177@gmail.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License Version 2 as
# published by the Free Software Foundation.  You may not use, modify or
# distribute this program under any other version of the GNU General
# Public License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

exec sh "$(dirname "$0")/aws_region_prefixes.sh" "${1}" "${2}" 'eu-south-'
