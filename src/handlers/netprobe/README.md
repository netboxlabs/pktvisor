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
| `timeout_msec` | uint64 | 2000 | Per-request timeout in milliseconds (must not exceed `interval_msec`) |
| `http_method` | string | `"GET"` | HTTP method to use for all targets (`GET`, `HEAD`, `POST`, …) |

#### Success semantics

HTTP probes classify results by status code:

- **2xx / 3xx** → counted as a `success`
- **4xx / 5xx** (or any other non-2xx/3xx status including `0` / `1xx`) → counted as an `http_status_failure`
- Transport errors (DNS resolution failure, TCP connect failure, timeout) → counted in the corresponding existing failure counter (`dns_lookup_failures`, `connect_failures`, `packets_timeout`)

---

## Metrics

All metrics are per-target (keyed by the name given in the `targets` config map).

### Always-on counters (group: `counters`)

| Metric | Description |
|--------|-------------|
| `attempts` | Total probe attempts |
| `successes` | Total successful probes |
| `connect_failures` | TCP/socket connection failures |
| `dns_lookup_failures` | DNS resolution failures |
| `packets_timeout` | Probes that timed out |
| `http_status_failures` | HTTP responses with a 4xx/5xx (or unexpected) status code |
| `response_min_us` | Minimum total response time in microseconds (within the reporting interval) |
| `response_max_us` | Maximum total response time in microseconds |

### TopN (always-on)

| Metric | Description |
|--------|-------------|
| `top_status_codes` | Top HTTP status codes observed (e.g. `"200"`, `"404"`, `"503"`) |

### Histograms (group: `histograms`, default ON)

| Metric | Description |
|--------|-------------|
| `response_histogram_us` | Histogram of total response times in microseconds |

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
