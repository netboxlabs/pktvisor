/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "AbstractMetricsManager.h"
#include "PrometheusSerializer.h"
#include "PcapInputStream.h"
#include "StreamHandler.h"
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wzero-as-null-pointer-constant"
#endif
#include <pcapplusplus/BgpLayer.h>
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif
#include <limits>
#include <string>

namespace visor::handler::bgp {

using namespace visor::input::pcap;

static constexpr const char *BGP_SCHEMA{"bgp"};

class BgpMetricsBucket final : public visor::AbstractMetricsBucket
{

protected:
    mutable std::shared_mutex _mutex;

    // total numPackets is tracked in base class num_events
    struct counters {

        Counter OPEN;
        Counter UPDATE;
        Counter NOTIFICATION;
        Counter KEEPALIVE;
        Counter ROUTEREFRESH;
        Counter total;
        Counter filtered;

        counters()
            : OPEN(BGP_SCHEMA, {"wire_packets", "open"}, "Total BGP packets with message type OPEN")
            , UPDATE(BGP_SCHEMA, {"wire_packets", "update"}, "Total BGP packets with message type UPDATE")
            , NOTIFICATION(BGP_SCHEMA, {"wire_packets", "notification"}, "Total BGP packets with message type NOTIFICATION")
            , KEEPALIVE(BGP_SCHEMA, {"wire_packets", "keepalive"}, "Total BGP packets with message type KEEPALIVE")
            , ROUTEREFRESH(BGP_SCHEMA, {"wire_packets", "routerefresh"}, "Total BGP packets with message type ROUTEREFRESH")
            , total(BGP_SCHEMA, {"wire_packets", "total"}, "Total BGP wire packets matching the configured filter(s)")
            , filtered(BGP_SCHEMA, {"wire_packets", "filtered"}, "Total BGP wire packets seen that did not match the configured filter(s) (if any)")
        {
        }
    };
    counters _counters;
    Rate _rate_total;

public:
    BgpMetricsBucket()
        : _rate_total(BGP_SCHEMA, {"rates", "total"}, "Rate of all BGP wire packets (combined ingress and egress) in packets per second")
    {
        set_event_rate_info(BGP_SCHEMA, {"rates", "events"}, "Rate of all BGP wire packets before filtering per second");
        set_num_events_info(BGP_SCHEMA, {"wire_packets", "events"}, "Total BGP wire packets events");
        set_num_sample_info(BGP_SCHEMA, {"wire_packets", "deep_samples"}, "Total BGP wire packets that were sampled for deep inspection");
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

    void on_set_read_only() override
    {
        // stop rate collection
        _rate_total.cancel();
    }

    void process_filtered();
    void process_bgp_layer(bool deep, pcpp::BgpLayer *payload, pcpp::ProtocolType l3, pcpp::ProtocolType l4);
};

class BgpMetricsManager final : public visor::AbstractMetricsManager<BgpMetricsBucket>
{
public:
    BgpMetricsManager(const Configurable *window_config)
        : visor::AbstractMetricsManager<BgpMetricsBucket>(window_config)
    {
    }

    void process_filtered(timespec stamp);
    void process_bgp_layer(pcpp::BgpLayer *payload, PacketDirection dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4, uint32_t flowkey, timespec stamp);
};

class BgpTcpSessionData final : public TcpSessionData
{
public:
    BgpTcpSessionData(got_msg_cb got_data_handler)
        : TcpSessionData(got_data_handler)
    {
    }

    ~BgpTcpSessionData() = default;

    void receive_tcp_data(const uint8_t *data, size_t len) override;
};

class BgpStreamHandler final : public visor::StreamMetricsHandler<BgpMetricsManager>
{

    PcapInputEventProxy *_pcap_proxy;

    typedef uint32_t flowKey;
    std::unordered_map<flowKey, TcpFlowData> _tcp_connections;

    sigslot::connection _start_tstamp_connection;
    sigslot::connection _end_tstamp_connection;

    sigslot::connection _tcp_start_connection;
    sigslot::connection _tcp_end_connection;
    sigslot::connection _tcp_message_connection;

    sigslot::connection _heartbeat_connection;

    static const inline StreamMetricsHandler::ConfigsDefType _config_defs = {
        "recorded_stream"};

    void tcp_message_ready_cb(int8_t side, const pcpp::TcpStreamData &tcpData, PacketDirection dir);
    void tcp_connection_start_cb(const pcpp::ConnectionData &connectionData, PacketDirection dir);
    void tcp_connection_end_cb(const pcpp::ConnectionData &connectionData, pcpp::TcpReassembly::ConnectionEndReason reason);

    void set_start_tstamp(timespec stamp);
    void set_end_tstamp(timespec stamp);

    bool _filtering(pcpp::BgpLayer *payload, PacketDirection dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4, timespec stamp);

public:
    BgpStreamHandler(const std::string &name, InputEventProxy *proxy, const Configurable *window_config);
    ~BgpStreamHandler() = default;

    // visor::AbstractModule
    std::string schema_key() const override
    {
        return BGP_SCHEMA;
    }

    void start() override;
    void stop() override;
};

}
