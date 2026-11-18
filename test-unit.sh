#!/usr/bin/env bash
# Unit tests: version ranges, version parsing, HTTP/2 detection in "nginx -T"
# output and verdicts. No Docker or cluster needed.
set -u
cd "$(dirname "$0")" || exit 1
# shellcheck source=check-nginx-http2.sh
. ./check-nginx-http2.sh __lib

PASS=0; FAIL=0
eq() { if [ "$2" = "$3" ]; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); echo "FAIL $1: expected [$2] got [$3]"; fi; }

# Affected: 1.9.5 - 1.30.6 and 1.31.0 - 1.31.8 (nginx.org, F5 K000163926).
for v in 1.9.5 1.10.3 1.18.0 1.22.1 1.24.0 1.26.3 1.27.1 1.28.0 1.29.4 1.30.0 1.30.6 1.31.0 1.31.7 1.31.8; do eq "vuln $v" vuln "$(version_status "$v")"; done
for v in 1.30.7 1.30.10 1.31.9 1.31.10 1.32.0 1.33.1 2.0.0; do eq "fixed $v" fixed "$(version_status "$v")"; done
for v in 1.9.4 1.8.1 1.4.6 0.8.55; do eq "old $v" old "$(version_status "$v")"; done
for v in "" 1.31 abc; do eq "unknown [$v]" unknown "$(version_status "$v")"; done

eq "core nginx" 1.27.1 "$(core_version 'nginx version: nginx/1.27.1')"
eq "core distro" 1.24.0 "$(core_version 'nginx version: nginx/1.24.0 (Ubuntu)')"
eq "core openresty" 1.27.1 "$(core_version 'nginx version: openresty/1.27.1.2')"
eq "core other" "" "$(core_version 'nginx version: Angie/1.9.0')"

T1=$'server {\n\tlisten 443 ssl;\n\thttp2 on;\n}'
eq "http2 on" "1 http2 on;" "$(http2_lines "$T1")"
T2=$'server {\n    listen 443 ssl http2;\n    listen [::]:443 ssl http2 default_server;\n}'
eq "listen http2" "1 listen 443 ssl http2;|1 listen [::]:443 ssl http2 default_server;" "$(http2_lines "$T2")"
T3=$'server {\n    listen 80;\n    # http2 on;\n    #listen 443 ssl http2;\n}'
eq "commented" "" "$(http2_lines "$T3")"
T4=$'server {\n    http2 off;\n    listen 80;\n    server_name http2.example.com;\n    http2_max_concurrent_streams 128;\n}'
eq "off and look-alikes" "" "$(http2_lines "$T4")"
T5=$'http { http2 on; server { listen 80; } }'
eq "one-line block" "1 http { http2 on; server { listen 80; } }" "$(http2_lines "$T5")"

eq "verdict exposed" EXPOSED "$(verdict vuln yes yes)"
eq "verdict h2 off" VULNERABLE-H2-OFF "$(verdict vuln yes no)"
eq "verdict no module" NOT-AFFECTED "$(verdict vuln no yes)"
eq "verdict config unread" UNDETERMINED "$(verdict vuln yes ?)"
eq "verdict fixed" FIXED "$(verdict fixed yes yes)"
eq "verdict old" NOT-AFFECTED "$(verdict old yes yes)"
eq "verdict unknown" UNDETERMINED "$(verdict unknown ? ?)"

echo "Result: $PASS ok, $FAIL failed"
[ "$FAIL" = 0 ]
