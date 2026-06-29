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
| `http_method` | string | `"GET"` | HTTP method to use for all targets (`GET`, `HEAD`, `POST`, …) |

#### Success semantics

HTTP probes classify results by status code:

- **2xx / 3xx** → counted as a `success`
- **4xx / 5xx** (or any other non-2xx/3xx status including `0` / `1xx`) → counted as an `http_status_failures`
- Transport errors (DNS resolution failure, TCP connect failure, timeout) → counted in the corresponding existing failure counter (`dns_lookup_failures`, `connect_failures`, `packets_timeout`)

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
| `http_status_failures` | HTTP/DoH responses with any HTTP status outside 2xx/3xx (e.g. 4xx/5xx, and also 1xx or 0) |
| `top_status_codes` | Top HTTP status codes observed (e.g. `"200"`, `"404"`, `"503"`) |
| `dns_response_failures` | DoH responses with HTTP 2xx/3xx but a non-NOERROR or unparseable DNS rcode |
| `top_rcodes` | Top DNS response codes observed in DoH probes (e.g. `"NOERROR"`, `"NXDOMAIN"`, `"SRVFAIL"`, `"PARSE_ERROR"`) |

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
