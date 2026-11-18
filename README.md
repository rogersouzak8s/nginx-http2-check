# nginx-http2-check

Read-only check for **CVE-2026-123007**, the memory corruption in nginx's HTTP/2 flow control that researchers showed can lead to remote code execution in the worker process. It finds nginx in Kubernetes pods (ingress-nginx included), Docker containers or on a host, decides whether each one is exposed, and writes a timestamped evidence report you can attach to a ticket or an audit.

```
TARGET                                          VERDICT            NGINX    H2MOD  HTTP2
web/frontend-7d9f8b6c5-x2k4p/frontend          VULNERABLE-H2-OFF  1.31.7   yes    no
ingress/ingress-nginx-controller-5f7c9-abcde/controller  EXPOSED  1.27.1   yes    yes

INGRESS HOST                    CLASS   ALPN
app.example.com                 nginx   h2

Result: 1 exposed, 1 vulnerable with HTTP/2 off, 0 fixed, 0 not affected, 0 undetermined
Evidence: nginx-http2-evidence-my-cluster-web-20261118T193338Z.md
SHA-256:  3b1f9c0e...  (also in nginx-http2-evidence-...md.sha256)
```

## When is nginx exposed?

All three must hold:

1. **Version** 1.9.5 – 1.30.6 or 1.31.0 – 1.31.8. Fixed in **1.30.7** (stable) and **1.31.9** (mainline), released 2026-11-18.
2. **The binary has the HTTP/2 module** (`--with-http_v2_module`; official builds do).
3. **HTTP/2 is turned on** in the running configuration: `http2 on;` (1.25.1+) or `listen ... http2`.

A version in the affected range with HTTP/2 off is not exposed to this CVE, but should still be upgraded: the same releases fix nine other CVEs.

## Usage

Needs `bash` (3.2+), plus `kubectl`, `docker` or `openssl` depending on the mode.

```bash
curl -fsSLO https://raw.githubusercontent.com/rogersouzak8s/nginx-http2-check/main/check-nginx-http2.sh
chmod +x check-nginx-http2.sh

./check-nginx-http2.sh k8s --context my-cluster -n my-namespace   # a namespace (+ the cluster's ingress controllers)
./check-nginx-http2.sh k8s --context my-cluster -A                # the whole cluster
./check-nginx-http2.sh docker                                     # every running container
./check-nginx-http2.sh docker my-container
./check-nginx-http2.sh local                                      # nginx on this host
./check-nginx-http2.sh probe app.example.com                      # does the endpoint offer HTTP/2?
```

| Option | |
| --- | --- |
| `--out FILE` | evidence report path (default `nginx-http2-evidence-<target>-<UTC>.md`) |
| `--no-report` | print only |
| `--no-probe` | k8s: skip the ALPN check of ingress hosts |
| `--no-controllers` | k8s with `-n`: do not add ingress controller pods from other namespaces |
| `--parallel N` | containers checked at the same time (default 8) |
| `--timeout S` | seconds per command (default 30) |

### Verdicts and exit codes

| Verdict | Meaning |
| --- | --- |
| `EXPOSED` | affected version, HTTP/2 module present, HTTP/2 on |
| `VULNERABLE-H2-OFF` | affected version, HTTP/2 off: not exposed to this CVE now |
| `FIXED` | 1.30.7+, 1.31.9+ or newer |
| `NOT-AFFECTED` | older than 1.9.5, or built without the HTTP/2 module |
| `UNDETERMINED` | version or configuration could not be read |

Exit code `2` if anything is exposed, `3` if nothing is exposed but something is undetermined, `0` otherwise, so it can gate a pipeline.

## How it works

- For each container it runs nginx's own commands: `nginx -v` (version), `nginx -V` (HTTP/2 module) and `nginx -T` (configuration test and dump). When `/proc` shows the master process started with `-c FILE`, that file is used. Comments are ignored when looking for `http2 on;` and `listen ... http2`.
- In Kubernetes it uses `kubectl exec` on running containers. With `-n`, it also checks ingress controller pods (ingress-nginx, NGINX Ingress Controller) elsewhere in the cluster, because they usually terminate the client's HTTP/2 for that namespace.
- It lists the namespace's ingress hosts and checks from your machine whether each one negotiates **ALPN h2**.
- The report is Markdown, with UTC time, the kube context and API server (no user or machine name), and a `.sha256` file next to it.

It never changes configuration, never reloads nginx and never sends HTTP/2 frames.

### Permissions

Kubernetes: `get`/`list` on pods and ingresses, and `create` on `pods/exec` in the namespaces checked (and in the ingress controller's namespace). Pods you cannot exec into show up as `UNDETERMINED`.

## Limits

- **Distribution packages** (Debian, Ubuntu, RHEL) may ship the fix without changing the version number. The report flags distro builds; confirm in the package changelog.
- **Forks**: OpenResty is mapped to its nginx core version. Angie, Tengine and other forks are reported for manual review.
- **Something in front**: a CDN, WAF or load balancer that terminates HTTP/2 and speaks HTTP/1.1 to nginx reduces exposure. The ALPN column shows what the public endpoint offers, not which process answers it.
- Images without nginx in `PATH` are only searched in the usual install paths when the image name mentions nginx, openresty or ingress.

## What to do when something is exposed

1. Upgrade to nginx 1.30.7 / 1.31.9 (or NGINX Plus 37.0.8.1 / 37.3.0.1), rebuild images on the fixed base and redeploy.
2. Until then, turning HTTP/2 off removes the precondition (`http2 off;`, or `use-http2: "false"` in the ingress-nginx ConfigMap). This is the researchers' advice; F5 lists no mitigation. It breaks clients that need HTTP/2, such as gRPC through the ingress.
3. Run the check again and keep the new report.

## References

- nginx security advisories: https://nginx.org/en/security_advisories.html
- F5 K000163926: https://my.f5.com/manage/s/article/K000163926
- Fix commit: https://github.com/nginx/nginx/commit/e27f5fa84fe6e98505e70bc543b748747dad0a3b
- Rapid7 analysis: https://www.rapid7.com/blog/post/ve-cve-2026-123007-critical-nginx-http-2-integer-underflow-leads-to-rce-fixed/

## Tests

```bash
./test-unit.sh          # version ranges, parsing, HTTP/2 detection, verdicts
./test-integration.sh   # real nginx containers (needs Docker)
```

CI runs shellcheck, the unit tests on bash 5.3 and 3.2, and the integration test.

## License

MIT
