/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "AbstractMetricsManager.h"
#include "DnstapInputStream.h"
#include "GeoDB.h"
#include "MockInputStream.h"
#include "PcapInputStream.h"
#include "StreamHandler.h"
#include <string>

namespace visor::handler::net::v2 {

using namespace visor::input::pcap;
using namespace visor::input::dnstap;
using namespace visor::input::mock;

static constexpr const char *NET_SCHEMA{"net"};

namespace group {
enum NetMetrics : visor::MetricGroupIntType {
    Counters,
    Cardinality,
    Quantiles,
    TopGeo,
    TopIps
};
}

enum NetworkPacketDirection {
    in,
    out,
    unknown
};

struct NetworkPacket {
    NetworkPacketDirection dir;
    pcpp::ProtocolType l3;
    pcpp::ProtocolType l4;
    size_t payload_size;
    bool syn_flag;
    pcpp::IPv4Address ipv4_src;
    pcpp::IPv4Address ipv4_dst;
    pcpp::IPv6Address ipv6_src;
    pcpp::IPv6Address ipv6_dst;

    NetworkPacket(NetworkPacketDirection dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4, size_t payload_size, bool syn_flag)
        : dir(dir)
        , l3(l3)
        , l4(l4)
        , payload_size(payload_size)
        , syn_flag(syn_flag)
    {
    }
};

struct NetworkDirection {
    // total numPackets is tracked in base class num_events
    struct Counters {
        Counter UDP;
        Counter TCP;
        Counter OtherL4;
        Counter IPv4;
        Counter IPv6;
        Counter TCP_SYN;
        Counter total;
        Counters()
            : UDP(NET_SCHEMA, {"udp_packets"}, "Count of UDP packets")
            , TCP(NET_SCHEMA, {"tcp_packets"}, "Count of TCP packets")
            , OtherL4(NET_SCHEMA, {"other_l4_packets"}, "Count of packets which are not UDP or TCP")
            , IPv4(NET_SCHEMA, {"ipv4_packets"}, "Count of IPv4 packets")
            , IPv6(NET_SCHEMA, {"ipv6_packets"}, "Count of IPv6 packets")
            , TCP_SYN(NET_SCHEMA, {"tcp", "syn_packets"}, "Count of TCP SYN packets")
            , total(NET_SCHEMA, {"total_packets"}, "Count of total packets matching the configured filter(s)")
        {
        }
        void operator+=(const Counters &other)
        {
            UDP += other.UDP;
            TCP += other.TCP;
            OtherL4 += other.OtherL4;
            IPv4 += other.IPv4;
            IPv6 += other.IPv6;
            TCP_SYN += other.TCP_SYN;
            total += other.total;
        }

        void to_json(json &j) const
        {
            UDP.to_json(j);
            TCP.to_json(j);
            OtherL4.to_json(j);
            IPv4.to_json(j);
            IPv6.to_json(j);
            TCP_SYN.to_json(j);
            total.to_json(j);
        }

        void to_prometheus(std::stringstream &out, const Metric::LabelMap &add_labels) const
        {
            UDP.to_prometheus(out, add_labels);
            TCP.to_prometheus(out, add_labels);
            OtherL4.to_prometheus(out, add_labels);
            IPv4.to_prometheus(out, add_labels);
            IPv6.to_prometheus(out, add_labels);
            TCP_SYN.to_prometheus(out, add_labels);
            total.to_prometheus(out, add_labels);
        }

        void to_opentelemetry(metrics::v1::ScopeMetrics &scope, timespec &start, timespec &end, Metric::LabelMap add_labels) const
        {
            UDP.to_opentelemetry(scope, start, end, add_labels);
            TCP.to_opentelemetry(scope, start, end, add_labels);
            OtherL4.to_opentelemetry(scope, start, end, add_labels);
            IPv4.to_opentelemetry(scope, start, end, add_labels);
            IPv6.to_opentelemetry(scope, start, end, add_labels);
            TCP_SYN.to_opentelemetry(scope, start, end, add_labels);
            total.to_opentelemetry(scope, start, end, add_labels);
        }
    };
    Counters counters;

    Cardinality ipCard;
    TopN<visor::geo::City> topGeoLoc;
    TopN<std::string> topASN;
    TopN<uint32_t> topIPv4;
    TopN<std::string> topIPv6;
    Quantile<std::size_t> payload_size;
    Rate rate;
    Rate throughput;

    NetworkDirection()
        : counters()
        , ipCard(NET_SCHEMA, {"cardinality", "ips"}, "IP cardinality")
        , topGeoLoc(NET_SCHEMA, "geo_loc", {"top_geo_loc_packets"}, "Top GeoIP locations")
        , topASN(NET_SCHEMA, "asn", {"top_asn_packets"}, "Top ASNs by IP")
        , topIPv4(NET_SCHEMA, "ipv4", {"top_ipv4_packets"}, "Top IPv4 addresses")
        , topIPv6(NET_SCHEMA, "ipv6", {"top_ipv6_packets"}, "Top IPv6 addresses")
        , payload_size(NET_SCHEMA, {"payload_size_bytes"}, "Quantiles of payload sizes, in bytes")
        , rate(NET_SCHEMA, {"rates", "pps"}, "Rate of packets per second")
        , throughput(NET_SCHEMA, {"rates", "bps"}, "Data rate of bits per second")
    {
    }

    void update_topn_metrics(size_t topn_count, uint64_t percentile_threshold)
    {
        topGeoLoc.set_settings(topn_count, percentile_threshold);
        topASN.set_settings(topn_count, percentile_threshold);
        topIPv4.set_settings(topn_count, percentile_threshold);
        topIPv6.set_settings(topn_count, percentile_threshold);
    }
};

class NetworkMetricsBucket final : public visor::AbstractMetricsBucket
{

protected:
    mutable std::shared_mutex _mutex;
    size_t _topn_count{10};
    uint64_t _topn_percentile_threshold{0};
    inline static const std::unordered_map<NetworkPacketDirection, std::string> _dir_str = {
        {NetworkPacketDirection::in, "in"},
        {NetworkPacketDirection::out, "out"},
        {NetworkPacketDirection::unknown, "unknown"}};
    Counter _filtered;
    std::map<NetworkPacketDirection, NetworkDirection> _net;

    void _process_geo_metrics(NetworkDirection &net, const pcpp::IPv4Address &ipv4);
    void _process_geo_metrics(NetworkDirection &net, const pcpp::IPv6Address &ipv6);

public:
    NetworkMetricsBucket()
        : _filtered(NET_SCHEMA, {"filtered_packets"}, "Total packets seen that did not match the configured filter(s) (if any)")
    {
        set_event_rate_info(NET_SCHEMA, {"rates", "observed_pps"}, "Rate of all packets before filtering per second");
        set_num_events_info(NET_SCHEMA, {"observed_packets"}, "Total packets events generated");
        set_num_sample_info(NET_SCHEMA, {"deep_sampled_packets"}, "Total packets that were sampled for deep inspection");
    }

    // get a copy of the counters
    NetworkDirection::Counters counters(NetworkPacketDirection dir) const
    {
        std::shared_lock lock(_mutex);
        return _net.at(dir).counters;
    }

    // visor::AbstractMetricsBucket
    void specialized_merge(const AbstractMetricsBucket &other, Metric::Aggregate agg_operator) override;
    void to_json(json &j) const override;
    void to_prometheus(std::stringstream &out, Metric::LabelMap add_labels = {}) const override;
    void to_opentelemetry(metrics::v1::ScopeMetrics &scope, timespec &start_ts, timespec &end_ts, Metric::LabelMap add_labels = {}) const override;
    void update_topn_metrics(size_t topn_count, uint64_t percentile_threshold) override
    {
        _topn_count = topn_count;
        _topn_percentile_threshold = percentile_threshold;
    }

    // must be thread safe as it is called from time window maintenance thread
    void on_set_read_only() override
    {
        // stop rate collection
        for (auto &net : _net) {
            net.second.rate.cancel();
            net.second.throughput.cancel();
        }
    }

    void process_filtered();
    void process_packet(bool deep, pcpp::Packet &payload, PacketDirection dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4);
    void process_dnstap(bool deep, const dnstap::Dnstap &payload, size_t size);
    void process_net_layer(NetworkPacketDirection dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4, size_t payload_size);
    void process_net_layer(NetworkPacket &packet);
};

class NetworkMetricsManager final : public visor::AbstractMetricsManager<NetworkMetricsBucket>
{
public:
    NetworkMetricsManager(const Configurable *window_config)
        : visor::AbstractMetricsManager<NetworkMetricsBucket>(window_config)
    {
    }

    void process_filtered(timespec stamp);
    void process_packet(pcpp::Packet &payload, PacketDirection dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4, timespec stamp);
    void process_dnstap(const dnstap::Dnstap &payload, size_t size);
};

class NetStreamHandler final : public visor::StreamMetricsHandler<NetworkMetricsManager>
{

    // the input event proxy we support (only one will be in use at a time)
    PcapInputEventProxy *_pcap_proxy{nullptr};
    DnstapInputEventProxy *_dnstap_proxy{nullptr};
    MockInputEventProxy *_mock_proxy{nullptr};

    sigslot::connection _dnstap_connection;

    sigslot::connection _pkt_connection;
    sigslot::connection _pkt_tcp_reassembled_connection;
    sigslot::connection _start_tstamp_connection;
    sigslot::connection _end_tstamp_connection;

    sigslot::connection _tcp_start_connection;
    sigslot::connection _tcp_end_connection;
    sigslot::connection _tcp_message_connection;

    sigslot::connection _heartbeat_connection;

    static const inline StreamMetricsHandler::ConfigsDefType _config_defs = {
        "geoloc_notfound",
        "asn_notfound",
        "only_geoloc_prefix",
        "only_asn_number",
        "recorded_stream"};

    static const inline StreamMetricsHandler::GroupDefType _group_defs = {
        {"cardinality", group::NetMetrics::Cardinality},
        {"counters", group::NetMetrics::Counters},
        {"quantiles", group::NetMetrics::Quantiles},
        {"top_geo", group::NetMetrics::TopGeo},
        {"top_ips", group::NetMetrics::TopIps}};

    void process_dnstap_cb(const dnstap::Dnstap &, size_t);
    void process_packet_cb(pcpp::Packet &payload, PacketDirection dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4, timespec stamp);
    void process_tcp_reassembled_packet_cb(pcpp::Packet &payload, PacketDirection dir, pcpp::ProtocolType l3, uint32_t flowkey, timespec stamp);
    void set_start_tstamp(timespec stamp);
    void set_end_tstamp(timespec stamp);
    bool validate_tcp_data(const pcpp::ConnectionData &connectionData, PacketDirection dir, timeval timeInterval);

    // Net Filters
    enum Filters {
        GeoLocNotFound,
        AsnNotFound,
        GeoLocPrefix,
        AsnNumber,
        FiltersMAX
    };

    std::bitset<Filters::FiltersMAX> _f_enabled;
    std::vector<std::string> _f_geoloc_prefix;
    std::vector<std::string> _f_asn_number;
    bool _filtering(pcpp::Packet &payload, PacketDirection dir, timespec stamp);

public:
    NetStreamHandler(const std::string &name, InputEventProxy *proxy, const Configurable *window_config);
    ~NetStreamHandler() override;

    // visor::AbstractModule
    std::string schema_key() const override
    {
        return NET_SCHEMA;
    }

    void start() override;
    void stop() override;
};

}
