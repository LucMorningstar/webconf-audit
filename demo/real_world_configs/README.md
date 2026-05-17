# Real-World-Like Config Samples

This directory contains a small defensive academic validation dataset for
`webconf-audit`. The samples are curated from public documentation, official
sample/default configurations, and open-source repositories, then minimized or
adapted so tests can run locally without contacting third-party infrastructure.

This is not a target list and not an invitation to scan public systems. The
source URLs identify documentation or repositories used for context only. The
fixtures are meant to exercise local static analysis behavior on configuration
shapes that resemble production, deployment, and development setups.

## Contents

| ID | Server | Origin | Source | Main features |
| --- | --- | --- | --- | --- |
| `nginx-docker-default` | Nginx | Derived | nginx Docker default layout | Includes, default server, access/error logging, static root |
| `nginx-docs-reverse-proxy` | Nginx | Derived | NGINX reverse proxy documentation | Upstream, proxy headers, request limits, admin path |
| `nginx-docs-tls-server` | Nginx | Derived | NGINX SSL/TLS documentation | TLS listener, inherited TLS policy, HSTS, HTTP/2 |
| `apache-docker-httpd-default` | Apache | Derived | Docker httpd default config | DocumentRoot, Directory, server tokens, logging |
| `apache-docs-vhost-htaccess` | Apache | Derived | Apache vhost and .htaccess docs | Include, VirtualHost, AllowOverride, .htaccess rewrite |
| `apache-docs-tls-vhost` | Apache | Derived | Apache SSL/TLS virtual host docs | TLS vhost, SSLProtocol, cipher suite, HSTS |
| `lighttpd-docs-default` | Lighttpd | Derived | Official lighttpd sample config | Includes, variables, access log, directory listing |
| `lighttpd-docs-fastcgi-tls` | Lighttpd | Derived | Official lighttpd module docs | FastCGI, TLS socket, status URL, host conditional |
| `iis-microsoft-request-filtering` | IIS | Derived | Microsoft Learn request filtering docs | Request filtering, request limits, custom headers |
| `iis-microsoft-aspnet-debug` | IIS | Derived | Microsoft Learn ASP.NET/IIS docs | Debug, custom errors, trace, SSL access flags |
| `iis-microsoft-applicationhost` | IIS | Derived | Microsoft Learn ApplicationHost/sites docs | Sites, bindings, app pools, global IIS settings |

The authoritative per-sample metadata is in `metadata.json`.

## Run Pytest Validation

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_real_world_config_fixtures.py
```

The tests assert that each local analyzer returns an `AnalysisResult`, reports
the expected mode/server type/target, returns findings and issues as lists, and
does not produce parser-level error issues. They intentionally avoid exact
finding counts because rule packs evolve.

## Generate Reports

```powershell
.\scripts\run_real_world_config_samples.ps1
```

The script writes text and JSON reports under
`demo/real_world_configs/reports/`. It runs only local analyzers and performs no
external probing. If one sample fails, the script continues with the remaining
samples and reports all failed IDs at the end.

## Limitations

- Most files are minimized derived fixtures, not full upstream configuration
  copies.
- Paths, domains, certificates, and credentials are placeholders.
- The dataset is static and does not prove that any real deployment is secure or
  insecure.
- Findings are heuristic rule results for research and hardening guidance, not a
  final security verdict.
