# Centralized Collection

This directory contains resources for centrally collecting and visualizing the metrics from pktvisor.

Because pktvisor exposes its metrics over a generic JSON interface, it is able to work with any time series or
relational database. This directory contains resources for interacting with common databases.

See the individual READMEs for more information:

* [Prometheus](prometheus/README.md)
* [Elasticsearch](elastic/README.md)
* [Kubernetes sidecar (scraped by Prometheus)](k8s/README.md)
