#!/usr/bin/env bash
# check-nginx-http2.sh - is this nginx exposed to CVE-2026-123007?
#
# CVE-2026-123007 is a memory corruption in nginx's HTTP/2 flow control
# (fixed in nginx 1.30.7 and 1.31.9, published 2026-11-18). A process is
# exposed when all of these hold:
#   1. it runs nginx 1.9.5 - 1.30.6 or 1.31.0 - 1.31.8
#   2. the binary has the HTTP/2 module (--with-http_v2_module)
#   3. HTTP/2 is turned on in the running configuration
#      ("http2 on;" or "listen ... http2")
#
# The script finds nginx processes in Kubernetes pods, Docker containers or on
# this host, reads the version and the effective configuration with nginx's
# own commands (nginx -v, nginx -V, nginx -T) and writes an evidence report.
# In Kubernetes it also checks which ingress hosts offer HTTP/2 (ALPN h2) to
# the outside.
#
# Read-only: it never changes configuration, never reloads nginx and never
# sends HTTP/2 frames. "nginx -T" only tests and prints the configuration.
#
# Exit codes: 0 nothing exposed, 2 at least one target exposed,
#             3 nothing exposed but some targets could not be determined,
#             1 usage or environment error.
set -u

VERSION="1.0.0"
CVE="CVE-2026-123007"
ME="$0"

usage() {
  cat <<EOF
check-nginx-http2.sh $VERSION - exposure check for $CVE (nginx HTTP/2)

Usage:
  $ME k8s    [--context CTX] [-n NAMESPACE | -A] [options]
  $ME docker [CONTAINER ...] [options]     (default: every running container)
  $ME local  [options]                     (nginx on this host)
  $ME probe  HOST[:PORT] ...               (does the endpoint offer HTTP/2?)

Options:
  --out FILE        evidence report path (default: nginx-http2-evidence-<target>-<UTC>.md)
  --no-report       print the result only, write no file
  --no-probe        k8s: do not test the ingress hosts for ALPN h2
  --no-controllers  k8s with -n: do not add the cluster's ingress controller pods
  --parallel N      targets checked at the same time (default 8)
  --timeout S       seconds per command (default 30)
  -h, --help        this help

Verdicts:
  EXPOSED           affected version, HTTP/2 module present and HTTP/2 turned on
  VULNERABLE-H2-OFF affected version, but HTTP/2 is off: not exposed to this CVE now
  FIXED             1.30.7+, 1.31.9+ or newer
  NOT-AFFECTED      older than 1.9.5, or built without the HTTP/2 module
  UNDETERMINED      version or configuration could not be read
EOF
}

# ---------------------------------------------------------------- helpers ---

# Runs a command with a time limit (works on macOS, which has no timeout(1)).
tmo() {
  local s=$1; shift
  "$@" & local p=$!
  ( sleep "$s"; kill -9 "$p" ) >/dev/null 2>&1 & local w=$!
  wait "$p"; local rc=$?
  kill "$w" >/dev/null 2>&1; wait "$w" 2>/dev/null
  return $rc
}

# Version triple of the nginx core from "nginx -v" output.
# nginx/1.27.1, nginx/1.24.0 (Ubuntu), openresty/1.27.1.2 -> 1.27.1
core_version() {
  local v
  v=$(printf '%s\n' "$1" | grep -oE '(nginx|openresty)/[0-9]+\.[0-9]+\.[0-9]+' | head -1)
  printf '%s' "${v#*/}"
}

# vuln | fixed | old | unknown
version_status() {
  local v=$1 a b c
  case "$v" in [0-9]*.[0-9]*.[0-9]*) ;; *) echo unknown; return;; esac
  IFS=. read -r a b c <<<"$v"
  c=${c%%[!0-9]*}
  if [ "$a" -gt 1 ]; then echo fixed; return; fi
  if [ "$a" -lt 1 ] || [ "$b" -lt 9 ] || { [ "$b" -eq 9 ] && [ "$c" -lt 5 ]; }; then echo old; return; fi
  if [ "$b" -lt 30 ]; then echo vuln; return; fi
  if [ "$b" -eq 30 ]; then [ "$c" -lt 7 ] && echo vuln || echo fixed; return; fi
  if [ "$b" -eq 31 ]; then [ "$c" -lt 9 ] && echo vuln || echo fixed; return; fi
  echo fixed
}

# Lines of an "nginx -T" dump that turn HTTP/2 on. Comments are ignored.
http2_lines() {
  printf '%s\n' "$1" | tr '\t' ' ' | sed -e 's/#.*//' |
    grep -E '(^|[;{ ])http2 +on *;|(^|[;{ ])listen [^;]* http2( |;)' |
    sed -e 's/^ *//' -e 's/ *$//' -e 's/ \{2,\}/ /g' | LC_ALL=C sort | uniq -c | sed -e 's/^ *//' | head -6 | paste -sd '|' -
}

verdict() { # verdict <status> <h2mod yes|no|?> <http2 yes|no|?>
  case "$1" in
    fixed) echo FIXED;;
    old) echo NOT-AFFECTED;;
    unknown) echo UNDETERMINED;;
    vuln)
      if [ "$2" = no ]; then echo NOT-AFFECTED
      elif [ "$3" = yes ]; then echo EXPOSED
      elif [ "$3" = no ]; then echo VULNERABLE-H2-OFF
      else echo UNDETERMINED; fi;;
  esac
}

# Runs a command in the target. Target formats: k8s ns/pod/container,
# docker <container>, local "-".
xrun() {
  local t=$1; shift
  case "$MODE" in
    k8s) local ns=${t%%/*} rest=${t#*/}; local pod=${rest%%/*} c=${rest#*/}
         kubectl ${KCTX:+--context="$KCTX"} exec -n "$ns" "$pod" -c "$c" -- "$@";;
    docker) docker exec "$t" "$@";;
    local) "$@";;
  esac
}

# ---------------------------------------------------------------- worker ---

# Checks one target and prints one tab-separated record:
# target verdict core version_raw h2mod http2 conf http2_lines note
# Prints nothing when the target has no nginx.
worker() {
  local t=$1 img=${2:-} bin="" vout="" b
  local cands="nginx"
  case "$img" in *nginx*|*openresty*|*ingress*) cands="nginx /usr/sbin/nginx /usr/local/nginx/sbin/nginx /usr/local/openresty/nginx/sbin/nginx";; esac
  [ "$MODE" = local ] && cands="nginx /usr/sbin/nginx /usr/local/nginx/sbin/nginx /usr/local/sbin/nginx /opt/homebrew/bin/nginx /usr/local/openresty/nginx/sbin/nginx"
  for b in $cands; do
    vout=$(tmo "$TIMEOUT" xrun "$t" "$b" -v 2>&1 </dev/null)
    case "$vout" in
      *"version:"*) bin=$b; break;;
      *"not found"*|*"no such file"*|*"No such file"*|*"exit code 127"*) ;;
      *) # exec itself failed (forbidden, timeout, container gone...)
         printf '%s\tUNDETERMINED\t\t\t?\t?\t\t\t%s\n' "$t" "exec failed: $(printf '%s' "$vout" | head -1 | cut -c1-120)"
         return;;
    esac
  done
  [ -n "$bin" ] || return 0

  local vline core st h2mod="?" conf="" dump http2="?" lines="" note=""
  vline=$(printf '%s\n' "$vout" | grep 'version:' | head -1 | sed 's/^nginx version: //')
  core=$(core_version "$vline")
  st=$(version_status "$core")
  case "$vline" in *Ubuntu*|*Debian*|*"(Red Hat"*|*CentOS*|*Fedora*) note="distro package: confirm the fix in the package changelog; backports keep the version number";; esac
  case "$vline" in *nginx/*|*openresty/*) ;; *) note="not upstream nginx ($vline): check the vendor advisory";; esac

  local vv
  vv=$(tmo "$TIMEOUT" xrun "$t" "$bin" -V 2>&1 </dev/null)
  case "$vv" in *http_v2_module*) h2mod=yes;; *"configure arguments"*) h2mod=no;; esac

  # Config file of the running master ("nginx: master process ... -c FILE").
  local ps
  if [ "$MODE" = local ]; then
    ps=$(ps -axo command 2>/dev/null | grep 'nginx: master' | grep -v grep | head -1)
  else
    ps=$(tmo "$TIMEOUT" xrun "$t" sh -c 'for d in /proc/[0-9]*; do c=$(tr "\000" " " < "$d/cmdline" 2>/dev/null); case "$c" in "nginx: master"*) echo "$c"; break;; esac; done' 2>/dev/null </dev/null)
  fi
  case "$ps" in *" -c "*) conf=${ps#* -c }; conf=${conf%% *};; esac

  if [ -n "$conf" ]; then
    dump=$(tmo "$TIMEOUT" xrun "$t" "$bin" -T -c "$conf" 2>&1 </dev/null)
  else
    dump=$(tmo "$TIMEOUT" xrun "$t" "$bin" -T 2>&1 </dev/null)
  fi
  case "$dump" in
    *"test is successful"*|*"# configuration file"*)
      lines=$(http2_lines "$dump")
      if [ -n "$lines" ]; then http2=yes; else http2=no; fi;;
    *) note="${note:+$note; }nginx -T failed: $(printf '%s\n' "$dump" | grep -m1 -E 'emerg|error|denied|failed' | cut -c1-140)";;
  esac
  [ -z "$ps" ] && [ "$MODE" != local ] && note="${note:+$note; }no running master seen (no shell in image or nginx not running): config read from the default path"

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$t" "$(verdict "$st" "$h2mod" "$http2")" "$core" "$vline" "$h2mod" "$http2" "${conf:-default}" "$lines" "$note"
}

# ALPN check of an endpoint: h2 | http/1.1 | none | unreachable
alpn() {
  local host=${1%%:*} port=443 out
  case "$1" in *:*) port=${1##*:};; esac
  out=$(echo | tmo 10 openssl s_client -connect "$host:$port" -servername "$host" -alpn h2,http/1.1 2>&1)
  case "$out" in
    *"ALPN protocol: h2"*) echo h2;;
    *"ALPN protocol: http/1.1"*) echo http/1.1;;
    *"No ALPN negotiated"*) echo none;;
    *) echo unreachable;;
  esac
}

# ------------------------------------------------------------------ main ---

# "__lib": only define the functions (used by test-unit.sh).
if [ "${1:-}" = "__lib" ]; then return 0 2>/dev/null || exit 0; fi
if [ "${1:-}" = "__worker" ]; then shift; worker "$@"; exit 0; fi

MODE=${1:-}; [ $# -gt 0 ] && shift
case "$MODE" in k8s|docker|local|probe) ;; -h|--help|"") usage; exit 0;; *) echo "unknown mode: $MODE" >&2; usage >&2; exit 1;; esac

KCTX="" NS="" ALLNS=0 OUT="" REPORT=1 PROBE=1 CONTROLLERS=1 PAR=8 TIMEOUT=30 ARGS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --context) KCTX=$2; shift;;
    -n|--namespace) NS=$2; shift;;
    -A|--all-namespaces) ALLNS=1;;
    --out) OUT=$2; shift;;
    --no-report) REPORT=0;;
    --no-probe) PROBE=0;;
    --no-controllers) CONTROLLERS=0;;
    --parallel) PAR=$2; shift;;
    --timeout) TIMEOUT=$2; shift;;
    -h|--help) usage; exit 0;;
    -*) echo "unknown option: $1" >&2; exit 1;;
    *) ARGS+=("$1");;
  esac
  shift
done
export MODE KCTX TIMEOUT

if [ "$MODE" = probe ]; then
  [ ${#ARGS[@]} -gt 0 ] || { echo "probe needs at least one HOST[:PORT]" >&2; exit 1; }
  for h in "${ARGS[@]}"; do printf '%-50s %s\n' "$h" "$(alpn "$h")"; done
  echo; echo "h2 means the endpoint accepts HTTP/2. Whether that is $CVE depends on what terminates it (run k8s/docker/local mode there)."
  exit 0
fi

WORK=$(mktemp -d 2>/dev/null || mktemp -d -t nginxh2)
trap 'rm -rf "$WORK"' EXIT
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
SCOPE="" CTXINFO=""

case "$MODE" in
  k8s)
    command -v kubectl >/dev/null || { echo "kubectl not found" >&2; exit 1; }
    KC=(kubectl ${KCTX:+--context="$KCTX"} --request-timeout="${TIMEOUT}s")
    CTXNAME=${KCTX:-$(kubectl config current-context 2>/dev/null)}
    SERVER=$(kubectl config view --minify ${KCTX:+--context="$KCTX"} -o jsonpath='{.clusters[0].cluster.server}' 2>/dev/null)
    CTXINFO="context: $CTXNAME | API server: $SERVER"
    if [ -n "$NS" ]; then SEL=(-n "$NS"); SCOPE="namespace $NS"; elif [ $ALLNS = 1 ]; then SEL=(-A); SCOPE="all namespaces"; else NS=$(kubectl config view --minify ${KCTX:+--context="$KCTX"} -o jsonpath='{..namespace}' 2>/dev/null); NS=${NS:-default}; SEL=(-n "$NS"); SCOPE="namespace $NS"; fi
    # one line per container: ns/pod/container image
    list_pods() {
      "${KC[@]}" get pods "$@" --field-selector=status.phase=Running \
        -o jsonpath='{range .items[*]}{.metadata.namespace}{"/"}{.metadata.name}{" "}{range .spec.containers[*]}{.name}{"="}{.image}{","}{end}{"\n"}{end}'
    }
    PODS=$(list_pods "${SEL[@]}") || { echo "could not list pods ($SCOPE)" >&2; exit 1; }
    if [ -n "$NS" ] && [ $CONTROLLERS = 1 ]; then
      # Ingress controllers usually live in another namespace and terminate the client's HTTP/2.
      CTRL=$(list_pods -A 2>/dev/null | grep -E 'ingress-nginx/controller|nginx-ingress|nginx/nginx-ingress|kubernetes-ingress' | grep -v "^$NS/")
      [ -n "$CTRL" ] && { PODS="$PODS
$CTRL"; SCOPE="$SCOPE + ingress controller pods"; }
    fi
    printf '%s\n' "$PODS" | while read -r pod cs; do
      [ -n "$pod" ] || continue
      printf '%s\n' "$cs" | tr ',' '\n' | while IFS='=' read -r c img; do [ -n "$c" ] && printf '%s/%s\t%s\n' "$pod" "$c" "$img"; done
    done | sort -u > "$WORK/targets"
    ;;
  docker)
    command -v docker >/dev/null || { echo "docker not found" >&2; exit 1; }
    CTXINFO="docker context: $(docker context show 2>/dev/null) | host: $(hostname)"
    if [ ${#ARGS[@]} -gt 0 ]; then for c in "${ARGS[@]}"; do printf '%s\t%s\n' "$c" "$(docker inspect -f '{{.Config.Image}}' "$c" 2>/dev/null)"; done > "$WORK/targets"
    else docker ps --format '{{.Names}}	{{.Image}}' > "$WORK/targets"; fi
    SCOPE="docker containers ($(wc -l < "$WORK/targets" | tr -d ' '))"
    ;;
  local)
    CTXINFO="host: $(hostname) | $(uname -sr)"
    printf -- '-\t\n' > "$WORK/targets"; SCOPE="this host"
    ;;
esac

NT=$(wc -l < "$WORK/targets" | tr -d ' ')
echo "check-nginx-http2 $VERSION | $CVE | $SCOPE | $NT container(s) to check" >&2
# Each target in its own worker process, PAR at a time.
tr '\t' '\037' < "$WORK/targets" | xargs -P "$PAR" -I{} bash -c 'IFS=$(printf "\037") read -r t i <<<"$1"; "$2" __worker "$t" "$i"' _ {} "$ME" > "$WORK/results"
sort -o "$WORK/results" "$WORK/results"

# ALPN of the ingress hosts in scope.
: > "$WORK/ingress"
if [ "$MODE" = k8s ] && [ $PROBE = 1 ]; then
  "${KC[@]}" get ingress "${SEL[@]}" -o jsonpath='{range .items[*]}{.metadata.namespace}{"/"}{.metadata.name}{" "}{.spec.ingressClassName}{" "}{range .spec.rules[*]}{.host}{","}{end}{"\n"}{end}' 2>/dev/null |
    while read -r ing cls hosts; do printf '%s\n' "$hosts" | tr ',' '\n' | while read -r h; do [ -n "$h" ] && printf '%s\t%s\t%s\n' "$h" "$cls" "$ing"; done; done |
    sort -u -k1,1 > "$WORK/hosts"
  while IFS=$'\t' read -r h cls ing; do printf '%s\t%s\t%s\t%s\n' "$h" "${cls:--}" "$ing" "$(alpn "$h")"; done < "$WORK/hosts" > "$WORK/ingress"
fi

# ---------------------------------------------------------------- output ---
count() { awk -F'\t' -v v="$1" '$2==v' "$WORK/results" | wc -l | tr -d ' '; }
NX=$(count EXPOSED); NV=$(count VULNERABLE-H2-OFF); NF=$(count FIXED); NN=$(count NOT-AFFECTED); NU=$(count UNDETERMINED)
NNG=$(wc -l < "$WORK/results" | tr -d ' ')

report() {
  echo "# nginx HTTP/2 exposure evidence - $CVE"
  echo
  echo "| | |"
  echo "| --- | --- |"
  echo "| Generated (UTC) | $NOW |"
  echo "| Tool | check-nginx-http2.sh $VERSION |"
  echo "| Run by | $(id -un 2>/dev/null)@$(hostname) |"
  echo "| Target | $MODE: $SCOPE |"
  echo "| Context | $CTXINFO |"
  echo "| Containers checked | $NT ($NNG with nginx) |"
  echo "| Result | **$NX exposed**, $NV vulnerable with HTTP/2 off, $NF fixed, $NN not affected, $NU undetermined |"
  echo
  echo "Exposed = nginx 1.9.5-1.30.6 or 1.31.0-1.31.8, built with the HTTP/2 module, with HTTP/2 turned on in the running configuration. Fixed in 1.30.7 and 1.31.9 (nginx.org, F5 K000163926)."
  echo
  echo "## nginx processes"
  echo
  if [ "$NNG" = 0 ]; then echo "No nginx found in the checked containers."; else
    echo "| Target | Verdict | nginx | HTTP/2 module | HTTP/2 on | Config |"
    echo "| --- | --- | --- | --- | --- | --- |"
    while IFS=$'\t' read -r t v core raw mod h2 conf lines note; do
      echo "| \`$t\` | **$v** | ${raw:-?} | $mod | $h2 | \`$conf\` |"
    done < "$WORK/results"
    echo
    echo "### Details"
    while IFS=$'\t' read -r t v core raw mod h2 conf lines note; do
      echo
      echo "- \`$t\` - **$v**"
      [ -n "$lines" ] && echo "  - lines that turn HTTP/2 on (count, line): \`$(printf '%s' "$lines" | sed 's/|/` · `/g')\`"
      [ -n "$note" ] && echo "  - note: $note"
    done < "$WORK/results"
  fi
  if [ -s "$WORK/ingress" ]; then
    echo
    echo "## Ingress hosts: does the endpoint offer HTTP/2?"
    echo
    echo "ALPN answer to a TLS handshake offering h2 and http/1.1 from the machine that ran this check."
    echo
    echo "| Host | Ingress class | Ingress | ALPN |"
    echo "| --- | --- | --- | --- |"
    while IFS=$'\t' read -r h cls ing a; do echo "| $h | $cls | $ing | $a |"; done < "$WORK/ingress"
  fi
  echo
  echo "## How this was checked"
  echo
  echo "- Read-only: \`nginx -v\`, \`nginx -V\` and \`nginx -T\` (configuration test and dump) run inside each container; the master's \`-c\` file is used when visible in /proc. No configuration change, no reload, no HTTP/2 traffic."
  [ "$MODE" = k8s ] && echo "- Kubernetes: \`kubectl exec\` into running containers; ingress controller pods from other namespaces included when a namespace was given."
  echo "- Distribution packages may carry the fix without a new version number: confirm in the package changelog."
  echo "- Until the upgrade, turning HTTP/2 off removes the precondition (researchers' advice; F5 lists no mitigation). In ingress-nginx: \`use-http2: \"false\"\` in the controller ConfigMap."
}

printf '\n%-60s %-18s %-16s %-6s %s\n' TARGET VERDICT NGINX H2MOD HTTP2
while IFS=$'\t' read -r t v core raw mod h2 conf lines note; do
  printf '%-60s %-18s %-16s %-6s %s\n' "$t" "$v" "${core:-?}" "$mod" "$h2"
done < "$WORK/results"
[ "$NNG" = 0 ] && echo "(no nginx found)"
if [ -s "$WORK/ingress" ]; then
  echo; printf '%-55s %-10s %s\n' "INGRESS HOST" CLASS ALPN
  while IFS=$'\t' read -r h cls ing a; do printf '%-55s %-10s %s\n' "$h" "$cls" "$a"; done < "$WORK/ingress"
fi
echo
echo "Result: $NX exposed, $NV vulnerable with HTTP/2 off, $NF fixed, $NN not affected, $NU undetermined"

if [ $REPORT = 1 ]; then
  if [ -z "$OUT" ]; then
    tag=$MODE; [ "$MODE" = k8s ] && tag="${CTXNAME##*/}-${NS:-all}"
    OUT="nginx-http2-evidence-$(printf '%s' "$tag" | tr -c 'A-Za-z0-9._-' '_')-$(date -u +%Y%m%dT%H%M%SZ).md"
  fi
  report > "$OUT"
  if command -v shasum >/dev/null; then SUM=$(shasum -a 256 "$OUT" | cut -d' ' -f1); else SUM=$(sha256sum "$OUT" | cut -d' ' -f1); fi
  printf '%s  %s\n' "$SUM" "$(basename "$OUT")" > "$OUT.sha256"
  echo "Evidence: $OUT"
  echo "SHA-256:  $SUM  (also in $OUT.sha256)"
fi

[ "$NX" -gt 0 ] && exit 2
[ "$NU" -gt 0 ] && exit 3
exit 0
