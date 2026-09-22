# Net Probe Metrics Stream Handler

This directory contains the Net Probe stream handler.

It can attach to netprobe input streams to summarize probe traffic.

[NetProbeStreamHandler.h](NetProbeStreamHandler.h) contains the list of metrics.

---

## Test Types

### ping

Sends ICMP echo requests to the configured targets and measures round-trip latency.
Requires raw-socket privileges.

### tcp

Opens a TCP connection to the configured target host+port and measures connect latency.

### http

Issues HTTP requests (default: GET) to one or more URL targets using a libcurl-backed async transport.
Unlike ping/tcp, HTTP targets are specified as full URLs.

#### Configuration

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `test_type` | string | — | Set to `"http"` to enable HTTP probing |
| `targets.<name>.target` | string | — | Full URL to probe, e.g. `http://example.com/health` |
| `interval_msec` | uint64 | 5000 | How often to issue a probe, in milliseconds |
| `timeout_msec` | uint64 | 2000 | Per-request timeout in milliseconds (must not exceed `interval_msec`). `0` disables the per-request timeout — not recommended for HTTP, where a slow/stalled server could leave a transfer pending; keep the default. |
| `http_method` | string | `"GET"` | HTTP method to use for all targets (`GET`, `HEAD`, `POST`, `PUT`, `PATCH`, …) |
| `expected_status` | list of strings | *(unset)* | Status codes/classes that count as a **success**. Entries: exact code (`"200"`), a class shorthand (`"2xx"`), or a range (`"200-299"`). When unset, the default is any `2xx`/`3xx` status. Overridden per-response by `failure_status` (see below). |
| `failure_status` | list of strings | *(unset)* | Status codes/classes that **always** count as a failure (`http_status_failures`), even if they also match `expected_status` or the default 2xx/3xx range. Same grammar as `expected_status`. Evaluation order per response: `failure_status` is checked first; if it matches, the response fails regardless of anything else. |
| `expected_body` | string | *(unset)* | Substring that must appear in the response body for the probe to succeed. Only evaluated when the HTTP status already passed (`expected_status`/`failure_status`/default). Combines with `expected_body_regex` using **AND** — both must match if both are set. A body-check failure on an otherwise-successful status is counted as `content_failures`, not `http_status_failures`. |
| `expected_body_regex` | string | *(unset)* | Regex (ECMAScript syntax) that must match somewhere in the response body. Same AND semantics and `content_failures` accounting as `expected_body`. |
| `body_check_max_bytes` | uint64 | 524288 (512 KiB) | Maximum number of response-body bytes captured for `expected_body`/`expected_body_regex` evaluation. If a response body exceeds this, it is truncated and the **body check is skipped** for that sample (classified on status alone, with a warning logged) rather than risk a false `content_failures` on a match that lives past the cap, or an anchored regex matching the truncation boundary. Raise it if your health endpoints return large bodies whose match text is deep in the response. |
| `body` | string | *(unset)* | Request body to send. Only valid when `http_method` is `POST`, `PUT`, or `PATCH` — set on any other method throws a config error at start. Like custom headers, a body-bearing probe does **not** follow redirects (a `307`/`308` preserves the method and body, which would resend the payload to the redirect target). |
| `targets.<name>.headers` | map | *(unset)* | Per-target HTTP headers (name → value), e.g. `Authorization: Bearer <token>`. Sent only on requests to that target. **Redaction note:** header *values* are never echoed back by `info_json`/status output — they're replaced with `<redacted>`. Header *names* (e.g. `Authorization`) are still surfaced (as `header_names`) since they're useful for debugging and carry no secret. **Redirects:** when a target has custom headers, the probe does **not** follow HTTP redirects — libcurl would otherwise re-send the headers to the redirect target (possibly another host), leaking secret headers. A `30x` is then reported as the response status (configure `expected_status` if a redirect should count as success). |
| `proxy` | string | *(unset)* | HTTP/HTTPS proxy URL for all targets, e.g. `http://user:pass@proxy.example:3128`. Applies to `http` and `doh` only (not `tcp`/`ping`). Like headers, the configured value is fully redacted (`<redacted>`) wherever config is echoed back — even the host/port, since the whole string can carry embedded credentials. When unset the probe connects **directly** and ignores ambient `http_proxy`/`https_proxy` environment variables, so results do not depend on the deployment environment. |
| `tls.verify` | bool | `true` | Whether to verify the target's TLS certificate/hostname. Set `false` only for testing against self-signed endpoints. |
| `tls.ca_file` | string | *(unset)* | Path to a CA bundle to trust in addition to (or instead of) the system store. Must exist at start time or the stream fails to start. |
| `tls.cert_file` / `tls.key_file` | string | *(unset)* | Client certificate + private key for mutual TLS (mTLS). Must be set together — setting one without the other is a config error. |
| `json_path` | string | *(unset)* | RFC 6901 JSON Pointer (e.g. `/data/status`) evaluated against the response body parsed as JSON. With `json_equals`, the value at the pointer must equal it; alone, the pointer must simply resolve. Non-JSON body, unresolved pointer, or value mismatch → `content_failures`. |
| `json_equals` | string | *(unset)* | Expected value at `json_path`, compared as a string (numbers/bools compared against their compact JSON text, so `"200"` matches `200`). Requires `json_path`. |
| `not_contains` | string | *(unset)* | The response body must **not** contain this substring (inverse of `expected_body`). A hit → `content_failures`. |
| `body_not_matches_regex` | string | *(unset)* | The response body must **not** match this ECMAScript regex (inverse of `expected_body_regex`). A match → `content_failures`. |
| `min_response_size_bytes` / `max_response_size_bytes` | uint64 | *(unset)* | Bound the response body size (true downloaded size, exact even if the captured body was truncated). Out of bounds → `content_failures`. If both set, `min ≤ max`. |
| `fail_if_header_matches` | map | *(unset)* | Map of `header-name: value_regex`. Fail (`content_failures`) if a response header with that name (case-insensitive) has a value matching the regex. |
| `fail_if_header_not_matches` | map | *(unset)* | Map of `header-name: value_regex`. Fail unless some response header with that name matches the regex (i.e. requires the match). |
| `max_last_modified_diff_secs` | uint64 | *(unset)* | Fail if the response `Last-Modified` is older than this many seconds, or is absent/unparseable. |
| `valid_http_versions` | list of strings | *(unset)* | Allowed negotiated HTTP versions (`"1.0"`, `"1.1"`, `"2"`, `"3"`). A negotiated version outside the set → `content_failures`. |
| `targets.<name>.ip_version` | uint64 (4 or 6) | *(unset)* | Force IPv4 or IPv6 resolution for that target (`CURLOPT_IPRESOLVE`). Per-target, same key ping/tcp already accept. |
| `targets.<name>.resolve` | list of strings | *(unset)* | Per-target `host:port:address` overrides — pin the connect address without changing the `Host`/SNI/cert verification. Applied via `CURLOPT_CONNECT_TO` (scoped to that target's request; it does not populate the shared DNS cache, so an override on one target never leaks to another target for the same `host:port`). IPv6 literals may be written with or without brackets (`host:443:2001:db8::1` or `host:443:[2001:db8::1]`). |

All of `json_path`/`json_equals`/`not_contains`/`body_not_matches_regex`/`min|max_response_size_bytes`/`fail_if_header_matches`/`fail_if_header_not_matches`/`max_last_modified_diff_secs`/`valid_http_versions` are **response assertions**: they run only after the status check passes, are ANDed together, and a failure of any is counted as `content_failures` (never `successes`, never `http_status_failures`). Body-reading assertions (`expected_body`/`expected_body_regex`/`not_contains`/`body_not_matches_regex`/`json_path`) are **skipped** (with a warning) when the response body exceeded `body_check_max_bytes`; size/header/version assertions are unaffected. Assertion string values (`not_contains`, `body_not_matches_regex`, `json_equals`, and the header `value_regex`s) are redacted from `info_json` like other secrets.

#### Success semantics

HTTP probes classify results, per response, in this order:

1. **`failure_status` match** → always `http_status_failures`, regardless of anything else below.
2. Otherwise, **status check**: `expected_status` if configured, else the default (**2xx**/**3xx** → pass, anything else → `http_status_failures`).
3. If the status check passed and `expected_body`/`expected_body_regex` are configured: body check failure → `content_failures`; body check pass (or no body check configured) → `successes`.

So the precedence is: `failure_status` wins over `expected_status`/default, and body checks are only ever evaluated on an already-passing status.

Transport errors (DNS resolution failure, TCP connect failure, timeout) are counted in the corresponding existing failure counter (`dns_lookup_failures`, `connect_failures`, `packets_timeout`) and never reach status/body evaluation.

**Default User-Agent:** unless a request otherwise sets its own, probes send `User-Agent: pktvisor/<version>`.

### doh

Issues DNS-over-HTTPS (DoH) queries to one or more URL targets using a libcurl-backed async transport (RFC 8484).
Like `http`, targets are specified as full URLs (e.g. `https://1.1.1.1/dns-query`).

#### Configuration

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `test_type` | string | — | Set to `"doh"` to enable DoH probing |
| `targets.<name>.target` | string | — | DoH URL to probe, e.g. `https://1.1.1.1/dns-query` |
| `qname` | string | **required** | DNS name to query (e.g. `example.com`) |
| `qtype` | string | `"A"` | DNS query type (e.g. `A`, `AAAA`, `MX`, `TXT`) |
| `interval_msec` | uint64 | 5000 | How often to issue a probe, in milliseconds |
| `timeout_msec` | uint64 | 2000 | Per-request timeout in milliseconds (must not exceed `interval_msec`) |
| `http_method` | string | `"POST"` | HTTP method to use for the DoH wire-format query (`POST` or `GET`) |
| `proxy` | string | *(unset)* | Same as the `http` test type — see above. |
| `tls.verify` / `tls.ca_file` / `tls.cert_file` / `tls.key_file` | — | *(unset)* | Same as the `http` test type — see above. |

`expected_status`, `failure_status`, `expected_body`, `expected_body_regex`, `body`, and per-target `headers` are **HTTP-only** and are rejected at config time for `test_type: doh` (a DoH response's "content" is the DNS answer, evaluated via `qname`/`qtype`/rcode instead — see below).

#### Success semantics

A DoH probe is counted as a **success** only when both of the following are true:

1. The HTTP response status is **2xx or 3xx**
2. The DNS response is parseable (QR=1, size ≥ 12 bytes) **and** the DNS rcode is **NOERROR** (0)

Other outcomes are classified as:

- **HTTP 4xx/5xx** → counted as `http_status_failures`
- **HTTP 2xx/3xx but non-NOERROR or unparseable DNS response** → counted as `dns_response_failures`
- **Transport errors** (DNS resolution failure, TCP connect failure, timeout) → counted in the corresponding failure counter (`dns_lookup_failures`, `connect_failures`, `packets_timeout`)

The `top_rcodes` TopN metric records the DNS rcode name (e.g. `NOERROR`, `NXDOMAIN`, `SRVFAIL`) for every response with a 2xx/3xx HTTP status. Unparseable responses are recorded as `PARSE_ERROR`.

Response-time metrics (`response_histogram_us`, `response_quantiles_us`, `response_min_us`, `response_max_us`) and HTTP response phase metrics (`response_dns_us`, `response_connect_us`, `response_tls_us`, `response_ttfb_us`) apply to DoH probes in exactly the same way as for `http` probes.

#### Example configuration (YAML policy)

```yaml
handlers:
  modules:
    netprobe_doh:
      type: netprobe

input:
  module: netprobe
  config:
    test_type: doh
    qname: example.com
    qtype: A
    http_method: POST
    interval_msec: 5000
    timeout_msec: 2000
    targets:
      cloudflare_doh:
        target: "https://1.1.1.1/dns-query"
      google_doh:
        target: "https://8.8.8.8/dns-query"
```

To enable HTTP response phase timing for DoH:

```yaml
handlers:
  modules:
    netprobe_doh:
      type: netprobe
      config:
        enable:
          - http_response_phases
```

---

## Metrics

All metrics are per-target (keyed by the name given in the `targets` config map).

### Counters (group: `counters`, default ON)

| Metric | Description |
|--------|-------------|
| `attempts` | Total probe attempts |
| `successes` | Total successful probes |
| `connect_failures` | TCP/socket connection failures |
| `dns_lookup_failures` | DNS resolution failures |
| `packets_timeout` | Probes that timed out |
| `http_status_failures` | HTTP/DoH responses whose HTTP status failed the configured status checks (default: any status outside 2xx/3xx). See [Success semantics](#success-semantics) above for the full `failure_status`/`expected_status` precedence — this counter fires whenever that evaluation lands on "fail," whether by the default 2xx/3xx rule, an `expected_status` miss, or a `failure_status` hit. |
| `content_failures` | HTTP responses whose status passed the status check but at least one configured response assertion failed — body (`expected_body`, `expected_body_regex`, `not_contains`, `body_not_matches_regex`), JSON (`json_path`/`json_equals`), size (`min_response_size_bytes`/`max_response_size_bytes`), header (`fail_if_header_matches`/`fail_if_header_not_matches`, `max_last_modified_diff_secs`) or protocol version (`valid_http_versions`). Never incremented together with `successes` or `http_status_failures` for the same response — HTTP-only (not applicable to `doh`, which has no response-assertion config). |
| `top_status_codes` | Top HTTP status codes observed (e.g. `"200"`, `"404"`, `"503"`) |
| `dns_response_failures` | DoH responses with HTTP 2xx/3xx but a non-NOERROR or unparseable DNS rcode |
| `top_rcodes` | Top DNS response codes observed in DoH probes (e.g. `"NOERROR"`, `"NXDOMAIN"`, `"SRVFAIL"`, `"PARSE_ERROR"`) |
| `tls_cert_expiry_epoch_sec` | Unix timestamp (seconds) of the earliest `notAfter` in the target's presented TLS certificate chain. Only present once at least one sample has carried cert info (absent entirely for plain-HTTP targets). On merge/rollup, the **latest non-zero value wins** (last-known-good, not max-of-window) — see the keep-alive note below for why this matters. Example alerting expression: fire a warning when `tls_cert_expiry_epoch_sec - time() < 14 * 86400` (certificate expires within 14 days). |

**Keep-alive / cert-cache note:** each netprobe input stream shares one libcurl multi-handle (connection pool) across all its `http`/`doh` targets, so TCP+TLS connections are reused (keep-alive) across probe intervals whenever the server allows it. libcurl's `CERTINFO` is only populated on transfers that actually perform a fresh TLS handshake — a request served over a reused pooled connection reports no cert info at all. To keep `tls_cert_expiry_epoch_sec` from flapping to "absent" every time a connection is reused, the probe caches the last known expiry per target and reports it on every sample until a fresh handshake supersedes it.

### Histograms (group: `histograms`, default ON)

| Metric | Description |
|--------|-------------|
| `response_histogram_us` | Histogram of total response times in microseconds |
| `response_min_us` | Minimum total response time in microseconds (within the reporting interval); derived from the histogram |
| `response_max_us` | Maximum total response time in microseconds; derived from the histogram |

### Quantiles (group: `quantiles`)

| Metric | Description |
|--------|-------------|
| `response_quantiles_us` | Quantiles of total response times in microseconds |
| `response_size_bytes` | Quantiles of HTTP response body size in bytes (`http` test type only) |

### HTTP response phases (group: `http_response_phases`, opt-in)

These metrics are only emitted when the `http_response_phases` group is explicitly enabled
(e.g. `enable: [http_response_phases]` in the handler config).

| Metric | Description |
|--------|-------------|
| `response_dns_us` | DNS resolution time quantiles in microseconds |
| `response_connect_us` | TCP connect time quantiles in microseconds |
| `response_tls_us` | TLS handshake time quantiles in microseconds |
| `response_ttfb_us` | Time-to-first-byte quantiles in microseconds |

---

## Example configuration (YAML policy)

```yaml
handlers:
  modules:
    netprobe_http:
      type: netprobe

input:
  module: netprobe
  config:
    test_type: http
    http_method: GET
    interval_msec: 5000
    timeout_msec: 2000
    targets:
      health_check:
        target: "http://my-service:8080/healthz"
      api_endpoint:
        target: "https://api.example.com/ping"
```

To enable HTTP response phase timing:

```yaml
handlers:
  modules:
    netprobe_http:
      type: netprobe
      config:
        enable:
          - http_response_phases
```

---

## Testing notes

Automated test coverage (`test_netprobe.cpp`) exercises the `tls.*` config-validation paths
(`tls.cert_file`/`tls.key_file` pairing, `tls.ca_file` existence, `tls`/`proxy` rejected for `tcp`), but does
**not** stand up a real TLS server or perform a live mTLS handshake — CI has no fixture for issuing/validating
certificates over the wire. If you change the mTLS wiring (`tls.cert_file`/`tls.key_file`/`tls.ca_file`/`tls.verify`
plumbing into libcurl), do a manual smoke test against a real mTLS-enabled endpoint (e.g. a local nginx/envoy with
`ssl_verify_client on`) before merging.
