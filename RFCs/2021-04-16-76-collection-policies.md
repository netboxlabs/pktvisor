### pktvisor Collection Policies

## Status

**Experimental**: implemented and available for beta testing but the interface may still change

## Summary

Collection policies direct pktvisor to use Taps (#75) to create an instance of an input stream (possibly with a filter),
and attach handlers to it. Processing takes place, and the data is exposed for sinks to collect. These policies may be
given directly to pktvisor via command line or through the Admin API if available.

Pktvisor also supports a chain of handlers. Therefore, the output of a filtered handler can be the input stream of the
next handler. This requires that modules policy to use YAML sequence. For handlers to chain successfully, they must have
explicit support for the handler type upstream to them, otherwise the policy will fail.

Policies require a `kind` to indicate the type of policy being applied.

A policy may also have an `attributes` mapping at the top level, next to `kind`, `input`, `handlers` and `config`. Each
entry is added as a label (an attribute, in OTLP) to every series of every handler of the policy, in the OTLP push and in
the Prometheus output:

```yaml
    anycast_dns:
      kind: collection
      attributes:
        netbox.site.name: dc-west
        netbox.device.asset_tag: "007"
```

Values are scalars kept as the text written (a backslash followed by three digits is rewritten, as in every exported label
value). A map, list, null or empty value is refused. A key starts with an ASCII letter and is valid UTF-8; a null
`attributes` is none. OTLP uses the keys as written; Prometheus replaces every character outside `[A-Za-z0-9_]` in a key
with `_`, one per character. A policy does not load when two keys share a
Prometheus name, or when a key is, or becomes, a label pktvisor sets itself (`policy`, `handler`, `tap`, `le`, `quantile`,
`instance` with `--prom-instance` or `prom_instance`, and the labels of the policy's handlers). The `netprobe` handler also accepts
`attributes` per target under `input.config.targets.<name>.attributes`; see its README. A pktvisor that does not know
`attributes` ignores the policy's own, but reads per-target attributes as input config: an all-digit value past 2^64 makes it
refuse the policy, and policies that differ only in their target attributes get separate inputs.

NOTE: this is not yet a complete, formal specification, and not all of it is implemented. See
src/tests/test_policies.cpp for current, tested implementation.

`collection-policy-anycast.yaml`

```yaml
version: "1.0"

visor:
  policies:
    # policy name and description
    anycast_dns:
      kind: collection
      description: "base anycast DNS policy"
      # input stream to create based on the given tap and optional filter config
      input:
        # this must reference a tap name, or application of the policy will fail
        tap: anycast
        # this must match the input_type of the matching tap name, or application of the policy will fail
        input_type: pcap
        filter:
          bpf: "port 53"
        config:
          tcp_packet_reassembly_cache_limit: 100000
      # stream handlers to attach to this input stream
      # these decide exactly which data to summarize and expose for collection
      handlers:
        # default configuration for the stream handlers
        config:
          num_periods: 2 #default is 5
          deep_sample_rate: 50 #default is 100
          topn_count: 5 #default is 10
          topn_percentile_threshold: 20 #default is 0
        modules:
          # the keys at this level are unique identifiers
          default_net:
            type: net
          udp_traffic:
            type: net
            config:
              topn_count: 7
              topn_percentile_threshold: 10
            filter:
              protocols: [ udp ]
            metric_groups:
              enable:
                - top_ips
          default_dns:
            type: dns
            config:
              max_deep_sample: 75
            # time window analyzers
            analyzers:
              modules:
                nx_attack:
                  type: dns_random_label
          special_domain:
            type: dns
            # specify that the stream handler module requires >= specific version to be successfully applied 
            require_version: "1.0"
            filter:
              # must match the available configuration options for this version of this stream handler
              qname_suffix: .mydomain.com
            metric_groups:
              disable:
                - top_qname
                - dns_transaction
    chaning_handlers:
      kind: collection
      #policy configs
      config:
        merge_like_handlers: true
      description: "base chaning NET to DNS policy"
      # input stream to create based on the given tap and optional filter config
      input:
        # this must reference valid tags existent on applied taps, or application of the policy will fail
        tap_selector:
          # It can be either "any" or "all" and it must be a sequence
          any:
            - virtual: true
            - vhost: 1
        # this must match the input_type of the matching tap name, or application of the policy will fail
        input_type: pcap
        filter:
          bpf: "port 53"
      handlers:
        # default configuration for the stream handlers
        config:
          num_periods: 5
          deep_sample_rate: 50
        modules:
          # the keys at this level are unique identifiers
          # Chaning handlers example. It needs proper indentation as shown below
          - upstream_dns:
              type: dns
              metric_groups:
                # disable all metric groups - no metrics will be scraped for this handler
                disable:
                  - all
              filter:
                # must match the available configuration options for this version of this stream handler
                qname_suffix: .mydomain.com
          # net handler will only receive .mydomain.com packages
          - chain_net:
              type: net
              metric_groups:
                # enable all metric groups - all the handler metrics will be scraped 
                enable:
                  - all
```

## REST API

CRUD on Collection Policies for a running pktvisord instance is possible if the Admin API is active.

`/api/v1/policies`

`/api/v1/policies/:id:`

## Standalone Command Line Example

```shell
$ pktvisord --config taps.yaml --config collection-policy-anycast.yaml
```

They may also be combined into a single YAML file (the schemas will merge) and passed in with one `--config` option.

The REST API (or prometheus output, pktvisor-cli, etc) should then be used to collect the results manually.

