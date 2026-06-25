# pktvisor on Kubernetes (sidecar)

Run `pktvisord` as a **sidecar** in a pod to observe that pod's network traffic
(`eth0`) and expose Prometheus metrics on `:10853`.

```
+------------------- Pod (shared network namespace) -------------------+
|                                                                      |
|   [ app ]      [ traffic-gen (optional) ]      [ pktvisord ]         |
|    nginx        wget loop -> external URL        sniffs eth0         |
|                                                  :10853/metrics      |
+----------------------------------------------------------------------+
                                 ^
                                 |  Prometheus scrapes via pod annotations
```

Containers in a pod share one network namespace, so the `pktvisord` sidecar sees
the same `eth0` as your application container.

## Prerequisites

- A Kubernetes cluster and `kubectl`.
- The target namespace must allow pods to **add the `NET_RAW` capability**. Under
  the Pod Security Standards only the `privileged` level permits this (or an
  exemption / custom admission policy that allows `NET_RAW`); both `baseline` and
  `restricted` reject it — `baseline` only allows adding `NET_BIND_SERVICE`. This
  is about the namespace PSS *level*; the container itself is **not** run as
  `privileged: true` — it only adds the single `NET_RAW` capability pktvisord
  needs to capture packets.
- Prometheus (or Grafana Agent) configured to scrape pods by annotation — see
  [Prometheus scrape configuration](#prometheus-scrape-configuration).
- The example captures `eth0`, the pod's primary interface on most CNIs. If your
  pods use a different name, change `eth0` in the manifest args (or use `auto` to
  let pktvisord pick the busiest interface). Find the name with
  `kubectl exec <pod> -c app -- ip -o link`.

## Deploy

```shell
# from the repo root (or use the bare filename from inside k8s/)
kubectl apply -f k8s/pktvisor-sidecar.yaml
```

Creates a `pktvisor-demo` Deployment with three containers: your app (`nginx`
placeholder), an optional traffic generator, and the `pktvisord` sidecar.

## Verify

```shell
kubectl rollout status deploy/pktvisor-demo
kubectl port-forward deploy/pktvisor-demo 10853:10853
# in another terminal:
curl -s localhost:10853/metrics | grep -E '^(dns|packets)_' | head
```

You should see non-zero `packets_*` and `dns_*` series (the traffic generator
drives them) — a populated `/metrics` is the "it's working" signal. pktvisord
aggregates over ~60s windows, so if the first scrape looks sparse, wait a few
seconds and retry. Note: the
published image redirects pktvisord's own stdout to a file, so
`kubectl logs deploy/pktvisor-demo -c pktvisord` is usually **empty** — rely on
`/metrics`, not logs. (If the sidecar `CrashLoopBackOff`s instead, re-check the
`NET_RAW` capability and the `-H .../32` CIDR.)

## Generating observable traffic

pktvisord watches **`eth0`**, so it sees the pod's **ingress/egress** — not
loopback. The optional `traffic-gen` container produces egress by `wget`-ing an
external URL (`TARGET_URL`, default `http://example.com`). To see ingress, send
requests to the app from outside the pod (e.g. the `port-forward` above, or a
Service). Repoint with `TARGET_URL`/`INTERVAL`, or delete the `traffic-gen`
container for real workloads.

No internet egress (air-gapped, or a default-deny `NetworkPolicy`)? The
per-iteration DNS lookups still go to cluster DNS over `eth0`, so `dns_*`
populates regardless; for richer `packets_*`, point `TARGET_URL` at an in-cluster
Service, or drive the app via the `port-forward` above.

## Prometheus scrape configuration

The pod carries the standard annotations:

```yaml
prometheus.io/scrape: "true"
prometheus.io/port: "10853"
prometheus.io/path: "/metrics"
```

A vanilla Prometheus discovers it with a pod job (no Prometheus Operator
required):

```yaml
scrape_configs:
  - job_name: kubernetes-pods
    kubernetes_sd_configs:
      - role: pod
    relabel_configs:
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_scrape]
        action: keep
        regex: "true"
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_path]
        action: replace
        target_label: __metrics_path__
        regex: (.+)
      - source_labels: [__address__, __meta_kubernetes_pod_annotation_prometheus_io_port]
        action: replace
        regex: ([^:]+)(?::\d+)?;(\d+)
        replacement: $1:$2
        target_label: __address__
      - source_labels: [__meta_kubernetes_namespace]
        target_label: namespace
      - source_labels: [__meta_kubernetes_pod_name]
        target_label: pod
```

`role: pod` generates one target per declared container port, so a
multi-container pod (here `app` + `pktvisord`) is discovered as several targets
that these rules all rewrite to the same `POD_IP:10853`. Prometheus deduplicates
targets whose final label sets are identical, so the endpoint is still scraped
only **once**. Don't add a container-name/port `keep` to this shared job to
"fix" the duplication — it would drop every other annotated pod; if you want
explicit selection, do it inside a pktvisor-only scrape job.

> Using the Prometheus Operator (kube-prometheus-stack)? Expose the sidecar with
> a `Service` on port `10853` and create a `ServiceMonitor` selecting it, instead
> of using annotations.

## Grafana dashboard

Import the community dashboard **ID 14221**, or the JSON at
`../centralized_collection/prometheus/grafana-dashboard-prometheus.json`.

## Use with your own workload

Add the sidecar to any existing pod spec:

1. Add the three `prometheus.io/*` pod annotations. For a Deployment/StatefulSet
   they go on the **pod template** (`spec.template.metadata.annotations`), not the
   top-level object metadata; for a bare Pod they go on `metadata.annotations`.
2. Add the `pktvisord` container — including the `POD_IP` downward-API env, the
   `NET_RAW` capability, and `args: ["pktvisord", "-l", "0.0.0.0", "-H", "$(POD_IP)/32", "eth0"]`.
3. Remove the demo `app` and `traffic-gen` containers.

## Security note

The sidecar adds only the `NET_RAW` capability (it is **not** run as a
`privileged` container) — the minimum libpcap/AF_PACKET needs to capture packets.
Promiscuous mode (which would need `NET_ADMIN`) is not required to see the pod's
own traffic. Under the Pod Security Standards, both the `baseline` and
`restricted` levels reject adding `NET_RAW` (baseline only allows adding
`NET_BIND_SERVICE`), so run this in a namespace at the `privileged` level or with
an exemption / custom policy that permits it. Note `-l 0.0.0.0` exposes
`/metrics` on the pod IP (no auth) so Prometheus can scrape it — restrict with a
`NetworkPolicy` if needed.
