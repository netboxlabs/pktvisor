/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "AbstractMetricsManager.h"
#include "PrometheusSerializer.h"
#include "DnstapInputStream.h"
#include "GeoDB.h"
#include "MockInputStream.h"
#include "PcapInputStream.h"
#include "StreamHandler.h"
#include <string>

namespace visor::handler::net {

using namespace visor::input::pcap;
using namespace visor::input::dnstap;
using namespace visor::input::mock;

static constexpr const char *NET_SCHEMA{"packets"};

namespace group {
enum NetMetrics : visor::MetricGroupIntType {
    Counters,
    Cardinality,
    TopGeo,
    TopIps
};
}

struct NetworkPacket {
    PacketDirection dir;
    pcpp::ProtocolType l3;
    pcpp::ProtocolType l4;
    size_t payload_size;
    bool syn_flag;
    pcpp::IPv4Address ipv4_in;
    pcpp::IPv4Address ipv4_out;
    pcpp::IPv6Address ipv6_in;
    pcpp::IPv6Address ipv6_out;

    NetworkPacket(PacketDirection dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4, size_t payload_size, bool syn_flag)
        : dir(dir)
        , l3(l3)
        , l4(l4)
        , payload_size(payload_size)
        , syn_flag(syn_flag)
    {
    }
};

class NetworkMetricsBucket final : public visor::AbstractMetricsBucket
{

protected:
    mutable std::shared_mutex _mutex;

    Cardinality _srcIPCard;
    Cardinality _dstIPCard;

    TopN<visor::geo::City> _topGeoLoc;
    TopN<std::string> _topASN;
    TopN<uint32_t> _topIPv4;
    TopN<std::string> _topIPv6;

    // total numPackets is tracked in base class num_events
    struct counters {
        Counter UDP;
        Counter TCP;
        Counter OtherL4;
        Counter IPv4;
        Counter IPv6;
        Counter TCP_SYN;
        Counter total_in;
        Counter total_out;
        Counter total_unk;
        Counter total;
        Counter filtered;
        counters()
            : UDP(NET_SCHEMA, {"udp"}, "Count of UDP packets")
            , TCP(NET_SCHEMA, {"tcp"}, "Count of TCP packets")
            , OtherL4(NET_SCHEMA, {"other_l4"}, "Count of packets which are not UDP or TCP")
            , IPv4(NET_SCHEMA, {"ipv4"}, "Count of IPv4 packets")
            , IPv6(NET_SCHEMA, {"ipv6"}, "Count of IPv6 packets")
            , TCP_SYN(NET_SCHEMA, {"protocol", "tcp", "syn"}, "Count of TCP SYN packets")
            , total_in(NET_SCHEMA, {"in"}, "Count of total ingress packets")
            , total_out(NET_SCHEMA, {"out"}, "Count of total egress packets")
            , total_unk(NET_SCHEMA, {"unknown_dir"}, "Count of total unknown direction packets")
            , total(NET_SCHEMA, {"total"}, "Count of total packets matching the configured filter(s)")
            , filtered(NET_SCHEMA, {"filtered"}, "Count of total packets that did not match the configured filter(s) (if any)")
        {
        }
    };
    counters _counters;

    Quantile<std::size_t> _payload_size;

    Rate _rate_in;
    Rate _rate_out;
    Rate _rate_total;
    Rate _throughput_in;
    Rate _throughput_out;
    Rate _throughput_total;

    void _process_geo_metrics(const pcpp::IPv4Address &ipv4);
    void _process_geo_metrics(const pcpp::IPv6Address &ipv6);

public:
    NetworkMetricsBucket()
        : _srcIPCard(NET_SCHEMA, {"cardinality", "src_ips_in"}, "Source IP cardinality")
        , _dstIPCard(NET_SCHEMA, {"cardinality", "dst_ips_out"}, "Destination IP cardinality")
        , _topGeoLoc(NET_SCHEMA, "geo_loc", {"top_geoLoc"}, "Top GeoIP locations")
        , _topASN(NET_SCHEMA, "asn", {"top_ASN"}, "Top ASNs by IP")
        , _topIPv4(NET_SCHEMA, "ipv4", {"top_ipv4"}, "Top IPv4 IP addresses")
        , _topIPv6(NET_SCHEMA, "ipv6", {"top_ipv6"}, "Top IPv6 IP addresses")
        , _payload_size(NET_SCHEMA, {"payload_size"}, "Quantiles of payload sizes, in bytes")
        , _rate_in(NET_SCHEMA, {"rates", "pps_in"}, "Rate of ingress in packets per second")
        , _rate_out(NET_SCHEMA, {"rates", "pps_out"}, "Rate of egress in packets per second")
        , _rate_total(NET_SCHEMA, {"rates", "pps_total"}, "Rate of all packets (combined ingress and egress) in packets per second")
        , _throughput_in("payload", {"rates", "bytes_in"}, "Data rate of ingress packets in bytes per second")
        , _throughput_out("payload", {"rates", "bytes_out"}, "Data rate of egress packets in bytes per second")
        , _throughput_total("payload", {"rates", "bytes_total"}, "Data rate of all packets (combined ingress and egress) in bytes per second")
    {
        set_event_rate_info(NET_SCHEMA, {"rates", "pps_events"}, "Rate of all packets before filtering in packets per second");
        set_num_events_info(NET_SCHEMA, {"events"}, "Total packets events generated");
        set_num_sample_info(NET_SCHEMA, {"deep_samples"}, "Total packets that were sampled for deep inspection");
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
    void update_topn_metrics(size_t topn_count, uint64_t percentile_threshold) override
    {
        _topGeoLoc.set_settings(topn_count, percentile_threshold);
        _topASN.set_settings(topn_count, percentile_threshold);
        _topIPv4.set_settings(topn_count, percentile_threshold);
        _topIPv6.set_settings(topn_count, percentile_threshold);
    }

    // must be thread safe as it is called from time window maintenance thread
    void on_set_read_only() override
    {
        // stop rate collection
        _rate_in.cancel();
        _rate_out.cancel();
        _rate_total.cancel();
        _throughput_in.cancel();
        _throughput_out.cancel();
        _throughput_total.cancel();
    }

    void process_filtered();
    void process_packet(bool deep, pcpp::Packet &payload, PacketDirection dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4);
    void process_dnstap(bool deep, const dnstap::Dnstap &payload, size_t size);
    void process_net_layer(PacketDirection dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4, size_t payload_size);
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
