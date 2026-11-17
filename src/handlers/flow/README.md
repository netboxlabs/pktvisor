# Flow Stream Handler

This directory contains the Flow stream handler

It can attach to flow input streams and process and summarize general flow traffic.

[FlowStreamHandler.h](FlowStreamHandler.h) contains the list of metrics.

## Policy attributes

A policy that runs a flow handler can set `attributes` at the top level of the policy. Every flow series carries them, in the
OpenTelemetry push and in the Prometheus output. Only policy-level attributes apply to flow; there are no per-target
attributes. The attributes cannot reuse a label the flow handler sets (`device`, `device_interface`, `lat`, `lon`,
`conversation`, `geo_loc`, `asn`, `ip`, `port`, `ip_port`, `dscp`, `ecn`, `interface`) or the common ones (`policy`,
`handler`, `tap`, `le`, `quantile`): the policy does not load. `device_map` is unchanged and still maps device addresses to
the `device` label. See the main [README](../../../README.md#policy-attributes).
