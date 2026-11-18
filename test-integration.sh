#!/usr/bin/env bash
# Integration test: real nginx containers (Docker Hub official images, pinned
# tags), one per case, checked by check-nginx-http2.sh in docker mode.
# Starts containers named h2it-* and removes them at the end.
set -u
cd "$(dirname "$0")" || exit 1
T=$(mktemp -d); trap 'docker rm -f h2it-on h2it-off h2it-fixed h2it-legacy h2it-comment >/dev/null 2>&1; rm -rf "$T"' EXIT
printf 'server {\n    listen 80;\n    http2 on;\n    location / { return 200; }\n}\n' > "$T/on.conf"
printf 'server {\n    listen 80 http2;\n    location / { return 200; }\n}\n' > "$T/legacy.conf"
printf 'server {\n    listen 80;\n    # http2 on;\n    location / { return 200; }\n}\n' > "$T/comment.conf"
chmod 644 "$T"/*.conf
run() { docker run -d --name "$1" ${3:+-v "$T/$3:/etc/nginx/conf.d/default.conf:ro"} "$2" >/dev/null; }
docker rm -f h2it-on h2it-off h2it-fixed h2it-legacy h2it-comment >/dev/null 2>&1
run h2it-on      nginx:1.31.8-alpine on.conf
run h2it-off     nginx:1.31.8-alpine
run h2it-fixed   nginx:1.31.9-alpine on.conf
run h2it-legacy  nginx:1.30.6-alpine legacy.conf
run h2it-comment nginx:1.31.8-alpine comment.conf
sleep 3

OUT=$(./check-nginx-http2.sh docker h2it-on h2it-off h2it-fixed h2it-legacy h2it-comment --out "$T/evidence.md"); RC=$?
echo "$OUT"
PASS=0; FAIL=0
eq() { if [ "$2" = "$3" ]; then PASS=$((PASS+1)); echo "  ok    $1"; else FAIL=$((FAIL+1)); echo "  FAIL  $1: expected [$2] got [$3]"; fi; }
v() { printf '%s\n' "$OUT" | awk -v t="$1" '$1==t{print $2}'; }
eq "1.31.8 + http2 on"        EXPOSED           "$(v h2it-on)"
eq "1.31.8 default config"    VULNERABLE-H2-OFF "$(v h2it-off)"
eq "1.31.9 + http2 on"        FIXED             "$(v h2it-fixed)"
eq "1.30.6 + listen ... http2" EXPOSED          "$(v h2it-legacy)"
eq "1.31.8 + commented http2" VULNERABLE-H2-OFF "$(v h2it-comment)"
eq "exit code"                2                 "$RC"
eq "evidence written"         yes               "$([ -s "$T/evidence.md" ] && echo yes)"
eq "checksum matches"         yes               "$(cd "$T" && { shasum -a 256 -c evidence.md.sha256 >/dev/null 2>&1 || sha256sum -c evidence.md.sha256 >/dev/null 2>&1; } && echo yes)"
echo "Result: $PASS ok, $FAIL failed"
[ "$FAIL" = 0 ]
