/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include <cstdint>
#include <opentelemetry/proto/metrics/v1/metrics.pb.h>
#include <string>

namespace visor::test {

// Walk an OTLP ScopeMetrics and return the first int gauge data point of the
// named metric, or -1 if not found. All pktvisor metrics are emitted as gauges
// (see Metric::to_opentelemetry in src/Metrics.cpp), so this covers Counters,
// Rates, Cardinalities, and the like uniformly.
inline int64_t otel_gauge_value(const opentelemetry::proto::metrics::v1::ScopeMetrics &scope, const std::string &name)
{
    for (int i = 0; i < scope.metrics_size(); ++i) {
        const auto &m = scope.metrics(i);
        if (m.name() == name && m.has_gauge() && m.gauge().data_points_size() > 0) {
            return m.gauge().data_points(0).as_int();
        }
    }
    return -1;
}

// Sum every int gauge data point of the named metric across all label sets.
// Useful for handlers (e.g. DNS v2, Net v2) that emit one data point per
// `direction` value — counters get sliced into per-direction series and a
// caller asking for the project total wants them summed.
inline int64_t otel_gauge_sum(const opentelemetry::proto::metrics::v1::ScopeMetrics &scope, const std::string &name)
{
    int64_t total = 0;
    bool found = false;
    for (int i = 0; i < scope.metrics_size(); ++i) {
        const auto &m = scope.metrics(i);
        if (m.name() == name && m.has_gauge()) {
            for (const auto &p : m.gauge().data_points()) {
                total += p.as_int();
                found = true;
            }
        }
    }
    return found ? total : -1;
}

}
