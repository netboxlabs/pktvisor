/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "AbstractMetricsManager.h"
#include "PrometheusSerializer.h"
#include "PcapInputStream.h"
#include "StreamHandler.h"
#include <limits>
#include <string>

namespace visor::handler::pcap {

using namespace visor::input::pcap;

static constexpr const char *PCAP_SCHEMA{"pcap"};

class PcapMetricsBucket final : public visor::AbstractMetricsBucket
{

protected:
    mutable std::shared_mutex _mutex;

    // total numPackets is tracked in base class num_events
    struct counters {

        Counter pcap_TCP_reassembly_errors;

        Counter pcap_os_drop;
        uint64_t pcap_last_os_drop{std::numeric_limits<uint64_t>::max()};

        Counter pcap_if_drop;
        uint64_t pcap_last_if_drop{std::numeric_limits<uint64_t>::max()};

        counters()
            : pcap_TCP_reassembly_errors(PCAP_SCHEMA, {"tcp_reassembly_errors"}, "Count of TCP reassembly errors")
            , pcap_os_drop(PCAP_SCHEMA, {"os_drops"}, "Count of packets dropped by the operating system (if supported)")
            , pcap_if_drop(PCAP_SCHEMA, {"if_drops"}, "Count of packets dropped by the interface (if supported)")
        {
        }
    };
    counters _counters;

public:
    PcapMetricsBucket()
    {
    }

    // get a copy of the counters
    counters counters() const
    {
        std::shared_lock lock(_mutex);
        return _counters;
    }

    // visor::AbstractMetricsBucket
    void specialized_merge(const AbstractMetricsBucket &other, Metric::Aggregate agg_operator) override;
    void to_json(json &j) const override;
    void to_prometheus(PrometheusSerializer &ser, Metric::LabelMap add_labels = {}) const override;
    void to_opentelemetry(metrics::v1::ScopeMetrics &scope, timespec &start_ts, timespec &end_ts, Metric::LabelMap add_labels = {}) const override;
    void update_topn_metrics(size_t, uint64_t) override
    {
    }

    void process_pcap_tcp_reassembly_error(bool deep, pcpp::Packet &payload, PacketDirection dir, pcpp::ProtocolType l3);
    void process_pcap_stats(const pcpp::IPcapDevice::PcapStats &stats);
};

class PcapMetricsManager final : public visor::AbstractMetricsManager<PcapMetricsBucket>
{
public:
    PcapMetricsManager(const Configurable *window_config)
        : visor::AbstractMetricsManager<PcapMetricsBucket>(window_config)
    {
    }

    void process_pcap_tcp_reassembly_error(pcpp::Packet &payload, PacketDirection dir, pcpp::ProtocolType l3, timespec stamp);
    void process_pcap_stats(const pcpp::IPcapDevice::PcapStats &stats);
};

class PcapStreamHandler final : public visor::StreamMetricsHandler<PcapMetricsManager>
{

    PcapInputEventProxy *_pcap_proxy;

    sigslot::connection _start_tstamp_connection;
    sigslot::connection _end_tstamp_connection;

    sigslot::connection _pcap_tcp_reassembly_errors_connection;
    sigslot::connection _pcap_stats_connection;

    sigslot::connection _heartbeat_connection;

    static const inline StreamMetricsHandler::ConfigsDefType _config_defs = {
        "recorded_stream"};

    void process_pcap_tcp_reassembly_error(pcpp::Packet &payload, PacketDirection dir, pcpp::ProtocolType l3, timespec stamp);
    void process_pcap_stats(const pcpp::IPcapDevice::PcapStats &stats);

    void set_start_tstamp(timespec stamp);
    void set_end_tstamp(timespec stamp);

public:
    PcapStreamHandler(const std::string &name, InputEventProxy *proxy, const Configurable *window_config);
    ~PcapStreamHandler() = default;

    // visor::AbstractModule
    std::string schema_key() const override
    {
        return PCAP_SCHEMA;
    }

    void start() override;
    void stop() override;
};

}
