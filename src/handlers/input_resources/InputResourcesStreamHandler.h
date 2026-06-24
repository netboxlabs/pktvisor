/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "AbstractMetricsManager.h"
#include "PrometheusSerializer.h"
#include "DnstapInputStream.h"
#include "FlowInputStream.h"
#include "MockInputStream.h"
#include "NetProbeInputStream.h"
#include "PcapInputStream.h"
#include "StreamHandler.h"
#include "ThreadMonitor.h"
#include <limits>
#include <string>

namespace visor::handler::resources {

using namespace visor::input::pcap;
using namespace visor::input::dnstap;
using namespace visor::input::mock;
using namespace visor::input::flow;
using namespace visor::input::netprobe;

constexpr double MEASURE_INTERVAL = 5; // in seconds

class InputResourcesMetricsBucket final : public visor::AbstractMetricsBucket
{

protected:
    mutable std::shared_mutex _mutex;

    Quantile<double> _cpu_usage;
    Quantile<uint64_t> _memory_bytes;
    Counter _policy_count;
    Counter _handler_count;
    bool _merged;

public:
    InputResourcesMetricsBucket()
        : _cpu_usage("resources", {"cpu_usage"}, "Quantiles of 5s averages of percent cpu usage by the input stream")
        , _memory_bytes("resources", {"memory_bytes"}, "Quantiles  of 5s averages of memory usage (in bytes) by the input stream")
        , _policy_count("resources", {"policy_count"}, "Total number of policies attached to the input stream")
        , _handler_count("resources", {"handler_count"}, "Total number of handlers attached to the input stream")
        , _merged(false)
    {
    }

    // visor::AbstractMetricsBucket

    void specialized_merge(const AbstractMetricsBucket &other, Metric::Aggregate agg_operator) override;
    void to_json(json &j) const override;
    void to_prometheus(PrometheusSerializer &ser, Metric::LabelMap add_labels = {}) const override;
    void to_opentelemetry(metrics::v1::ScopeMetrics &scope, timespec &start_ts, timespec &end_ts, Metric::LabelMap add_labels = {}) const override;
    void update_topn_metrics(size_t, uint64_t) override
    {
    }

    void process_resources(double cpu_usage, uint64_t memory_usage);
    void process_policies(int16_t policy_count, int16_t handler_count);
};

class InputResourcesMetricsManager final : public visor::AbstractMetricsManager<InputResourcesMetricsBucket>
{
    int16_t policy_total;
    int16_t handler_total;

public:
    InputResourcesMetricsManager(const Configurable *window_config)
        : visor::AbstractMetricsManager<InputResourcesMetricsBucket>(window_config)
        , policy_total(0)
        , handler_total(0)
    {
    }

    void on_period_shift([[maybe_unused]] timespec stamp, [[maybe_unused]] const InputResourcesMetricsBucket *maybe_expiring_bucket) override
    {
        process_policies(policy_total, handler_total, true);
    }

    void process_resources(double cpu_usage, uint64_t memory_usage, timespec stamp = timespec());
    void process_policies(int16_t policy_count, int16_t handler_count, bool self = false);
};

class InputResourcesStreamHandler final : public visor::StreamMetricsHandler<InputResourcesMetricsManager>
{
    ThreadMonitor _monitor;
    time_t _timer;
    timespec _timestamp;

    PcapInputEventProxy *_pcap_proxy{nullptr};
    DnstapInputEventProxy *_dnstap_proxy{nullptr};
    MockInputEventProxy *_mock_proxy{nullptr};
    FlowInputEventProxy *_flow_proxy{nullptr};
    NetProbeInputEventProxy *_netprobe_proxy{nullptr};

    sigslot::connection _dnstap_connection;
    sigslot::connection _sflow_connection;
    sigslot::connection _netflow_connection;
    sigslot::connection _pkt_connection;
    sigslot::connection _policies_connection;

    sigslot::connection _heartbeat_connection;

    void process_sflow_cb(const SFSample &, size_t);
    void process_netflow_cb(const std::string &, const NFSample &, size_t);
    void process_dnstap_cb(const dnstap::Dnstap &, size_t);
    void process_policies_cb(const Policy *policy, Action action);
    void process_packet_cb(pcpp::Packet &payload, PacketDirection dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4, timespec stamp);

public:
    InputResourcesStreamHandler(const std::string &name, InputEventProxy *proxy, const Configurable *window_config);
    ~InputResourcesStreamHandler() = default;

    // visor::AbstractModule
    std::string schema_key() const override
    {
        return "input_resources";
    }

    void start() override;
    void stop() override;
};

}
