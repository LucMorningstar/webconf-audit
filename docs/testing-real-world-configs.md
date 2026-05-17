# Testing Real-World-Like Web Server Configs

This project includes two complementary local validation datasets:

- `demo/real_world_configs/` contains small public-source-derived examples for
  broad analyzer smoke validation across Nginx, Apache, Lighttpd, and IIS.
- `tests/fixtures/webserver-configs/` contains security-focused known-bad and
  known-good fixtures with explicit expected findings for regression tests.

Both datasets are defensive academic validation material for hardening research.
They are not a target list, and they do not require scanning third-party systems.

## Security Corpus Layout

```text
tests/fixtures/webserver-configs/
  nginx/
    vulnerable/
    secure/
  apache/
    vulnerable/
    secure/
  lighttpd/
    vulnerable/
    secure/
    edge-cases/
  iis/
    vulnerable/
    secure/
    inheritance-edge-cases/
  external-targets/
    badssl.json
  metadata/
    cases.json
```

All four supported servers (Nginx, Apache, Lighttpd, IIS) carry both
`vulnerable/` and `secure/` profiles plus optional `*-edge-cases/`
folders for parser/inheritance regression fixtures that have their
own targeted test files.

`metadata/cases.json` is the authoritative index. Each case records:

- `id`
- `server_type`
- `profile` (`vulnerable`, `secure`, or `edge-case`)
- `source` and `source_url`
- license or license note
- short description
- fixture entrypoint
- whether the config is original or synthetic-derived
- notes about modifications
- references
- `expected_findings`
- optional `expected_absent_rule_ids`

The fixtures are intentionally small. Where a public repository has no obvious
license, or where the original file is larger than needed, the corpus stores a
small synthetic-derived fixture instead of a verbatim copy.

## Sources Used

The security corpus uses these sources as public references:

- Detectify vulnerable-nginx and Detectify's Nginx misconfiguration research
- Vulhub Nginx insecure-configuration examples
- tkmru Nginx alias traversal sample
- Gixy rule concepts for Nginx misconfiguration analysis
- DevSec nginx-baseline, apache-baseline, and lighttpd-baseline
- CIS Apache HTTP Server Benchmark as hardening category reference
- CIS Microsoft IIS 10 Benchmark v1.2.1 as hardening category reference for IIS fixtures
- Lighttpd Security wiki and ``mod_*`` documentation
- Microsoft Learn IIS configuration documentation (httpErrors, requestFiltering, authentication, machineKey)
- OWASP Secure Headers Project
- Apache HTTP Server Security Tips and .htaccess documentation
- Mozilla SSL Configuration Generator
- testssl.sh and SSL Labs Rating Guide for TLS categories
- badssl.com for optional external TLS reference endpoints

## Covered Error Classes

Nginx fixtures cover:

- alias/trailing-slash path mistakes
- classic Gixy alias traversal slash mismatch
- CRLF/HTTP response construction from request-derived values
- proxy blocks missing source IP/protocol forwarding headers
- user-controlled `proxy_pass` destinations
- non-default server blocks accepting unexpected Host values
- autoindex enabled
- server token disclosure
- unsafe default server behavior
- disabled URI slash compression via `merge_slashes off`
- sensitive locations missing access restrictions or IP filtering
- missing request rate/connection limits
- missing browser security headers
- weak TLS protocol policy
- missing HTTP/2 on TLS listener
- missing HSTS on TLS listener

Apache fixtures cover:

- `Options Indexes`
- `Options ExecCGI`
- broad `AllowOverride All`
- risky `.htaccess` overrides
- rewrite rules without conditions
- disabled security headers from `.htaccess`
- exposed `server-status`
- `ServerTokens Full` and `ServerSignature On`
- weak TLS protocol/cipher configuration
- TLS compression
- insecure TLS renegotiation

Lighttpd fixtures cover:

- public `mod_status` exposure without `url.access-deny`
- directory listing enabled (`dir-listing.activate = "enable"`)
- non-blank `server.tag` (version disclosure)
- weak / permissive `ssl.cipher-list`
- explicit `UnsafeLegacyRenegotiation` in `ssl.openssl.ssl-conf-cmd`
- missing TLS protocol minimum pinning + missing `ssl.honor-cipher-order`
- HTTP Basic authentication on a plain-HTTP listener
- `mod_webdav` with write access enabled on a public path
- missing access log / error log destinations

IIS fixtures cover:

- ASP.NET `compilation debug="true"` and `<trace enabled="true"/>`
- `<httpErrors errorMode="Detailed"/>` and `<customErrors mode="Off"/>`
- `<directoryBrowse enabled="true"/>`
- `<deployment retail="false"/>`
- `requestFiltering` with `allowDoubleEscaping="true"`, `allowHighBitCharacters="true"`, `removeServerHeader="false"`, oversized `maxUrl` / `maxQueryString`, and `fileExtensions allowUnlisted="true"`
- anonymous authentication enabled under a specific privileged user
- `basicAuthentication` enabled without an SSL requirement
- `<authorization>` rule allowing anonymous users (`users="?"`)
- forms authentication without `requireSSL`, with `cookieless="UseUri"` and `protection="None"`
- weak `<machineKey validation="MD5"/>`

The secure baseline fixtures are positive controls. Tests assert that they do
not produce high or critical findings and that selected known-bad rule IDs stay
absent. They do not require a zero-finding report because the local hardening
rules intentionally include conservative low/medium heuristics.

## Known Reference Gaps

Some source classes are represented as documentation/reference notes, but are
not asserted as expected findings because webconf-audit does not currently have
dedicated local rules for them:

- raw backend response reading

These gaps stay as research notes; tests should not pretend that the current
analyzer detects them.

## Closed: not pursued

The following reference gaps are explicitly **closed as not pursued**
(decision recorded 2026-05-15). The project will not attempt these rules
unless the listed trigger conditions surface; the entries are kept here as
historical context for future auditors.

- **Raw backend response reading** (`research`, closed not-pursued).
  Reason: signal design is incomplete and there is no clear directive-level
  marker that survives normal proxy configurations. Reconsider when a
  concrete fixture with a confirmed false negative becomes available.

## Run Static Tests

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_webserver_config_security_corpus.py
```

This runs only local static analyzers against committed fixtures. It does not
make network requests.

To run the broader public-source-derived smoke dataset:

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_real_world_config_fixtures.py
```

## Optional External Reference Tests

External reference tests are disabled by default:

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/integration_optional_external/test_external_reference_targets.py
```

Expected default result: skipped tests.

To run them intentionally:

```powershell
$env:RUN_EXTERNAL_TESTS = "1"
.\.venv\Scripts\python.exe -m pytest -q tests/integration_optional_external/test_external_reference_targets.py
Remove-Item Env:\RUN_EXTERNAL_TESTS
```

These tests only use `badssl.com` endpoints that exist specifically for TLS
validation, and call `analyze_external_target(..., scan_ports=False)`. Do not add
random public hosts or IP addresses.

## Local Docker Scenarios

The repository already has localhost-only Docker-backed external integration
tests under `tests/integration_external/`. Those tests use local containers and
are separate from the static security corpus above.

If a future fixture needs external-mode validation, prefer a local container in
that integration harness over a public target. Keep the static fixture and
expected local findings in `tests/fixtures/webserver-configs/` so the normal
test suite remains offline.

## Adding a Fixture

1. Add the config under the matching server/profile directory.
2. Add a case entry to `tests/fixtures/webserver-configs/metadata/cases.json`.
3. Use `synthetic-derived` unless you are copying a small file under a clearly
   compatible license.
4. Replace real domains, tokens, credentials, certificates, and private paths
   with placeholders.
5. Run the targeted test and inspect the observed rule IDs.
6. Add only stable expected findings. Do not assert exact total finding counts.
7. For secure baselines, assert absence of selected known-bad rules and rely on
   the high/critical guard instead of expecting zero findings.

Findings are heuristic rule results for hardening research. They are not a final
security verdict on any real deployment.
