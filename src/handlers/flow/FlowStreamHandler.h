/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "AbstractMetricsManager.h"
#include "FlowInputStream.h"
#include "GeoDB.h"
#include "IpPort.h"
#include "MockInputStream.h"
#include "StreamHandler.h"
#include "VisorLRUList.h"
#include "utils.h"
#include <Corrade/Utility/Debug.h>
#include <string>

namespace visor::handler::flow {

using namespace visor::input::mock;
using namespace visor::input::flow;

static constexpr const char *FLOW_SCHEMA{"flow"};

namespace group {
enum FlowMetrics : visor::MetricGroupIntType {
    ByPackets,
    ByBytes,
    Cardinality,
    Conversations,
    Counters,
    TopPorts,
    TopIPs,
    TopIPPorts,
    TopTos,
    TopGeo,
    TopInterfaces
};
}

enum class IpSummary {
    None,
    ByASN,
    BySubnet
};

enum FlowDirectionType {
    InBytes,
    OutBytes,
    InPackets,
    OutPackets
};

struct InterfaceEnrich {
    std::string name;
    std::string descr;
};

struct DeviceEnrich {
    std::string name;
    std::string descr;
    std::unordered_map<uint32_t, InterfaceEnrich> interfaces;
};

struct SummaryData {
    IpSummary type{IpSummary::None};
    bool exclude_unknown_asns{false};
    lib::utils::IPv4subnetList ipv4_exclude_summary;
    lib::utils::IPv6subnetList ipv6_exclude_summary;
    std::vector<std::string> asn_exclude_summary;
    lib::utils::IPv4subnetList ipv4_summary;
    lib::utils::IPv6subnetList ipv6_summary;
    std::optional<lib::utils::IPv4subnet> ipv4_wildcard;
    std::optional<lib::utils::IPv6subnet> ipv6_wildcard;
};

typedef std::unordered_map<std::string, DeviceEnrich> EnrichData;

struct FlowData {
    bool is_ipv6;
    FLOW_IP_PROTOCOL l4;
    size_t payload_size;
    uint32_t packets;
    uint8_t tos;
    pcpp::IPv4Address ipv4_in;
    pcpp::IPv4Address ipv4_out;
    pcpp::IPv6Address ipv6_in;
    pcpp::IPv6Address ipv6_out;
    uint16_t src_port;
    uint16_t dst_port;
    std::optional<uint32_t> if_in_index;
    std::optional<uint32_t> if_out_index;
};

struct FlowPacket {
    std::string device_id;
    timespec stamp;
    uint64_t filtered;
    std::vector<FlowData> flow_data;

    FlowPacket(std::string id, timespec stamp)
        : device_id(id)
        , stamp(stamp)
        , filtered(0)
    {
    }
};

struct FlowCache {
    LRUList<network::IpPort, std::string> lru_port_list{2000};
    LRUList<uint32_t, std::string> lru_ipv4_list{1000};
    LRUList<std::string, std::string> lru_ipv6_list{1000};
};

struct FlowTopN {
    TopN<std::string> topConversations;
    TopN<visor::geo::City> topGeoLoc;
    TopN<std::string> topASN;

    FlowTopN(std::string metric)
        : topConversations(FLOW_SCHEMA, "conversation", {"top_conversations_" + metric}, "Top source IP addresses and port by " + metric)
        , topGeoLoc(FLOW_SCHEMA, "geo_loc", {"top_geo_loc_" + metric}, "Top GeoIP locations by " + metric)
        , topASN(FLOW_SCHEMA, "asn", {"top_asn_" + metric}, "Top ASNs by IP by " + metric)
    {
    }

    void set_settings(size_t topn_count, uint64_t percentile_threshold)
    {
        topConversations.set_settings(topn_count, percentile_threshold);
        topGeoLoc.set_settings(topn_count, percentile_threshold);
        topASN.set_settings(topn_count, percentile_threshold);
    }
};

struct FlowDirectionTopN {
    TopN<std::string> topSrcIP;
    TopN<std::string> topDstIP;
    TopN<std::string> topSrcPort;
    TopN<std::string> topDstPort;
    TopN<std::string> topSrcIPPort;
    TopN<std::string> topDstIPPort;
    TopN<uint8_t> topDSCP;
    TopN<uint8_t> topECN;

    FlowDirectionTopN(std::string direction, std::string metric)
        : topSrcIP(FLOW_SCHEMA, "ip", {"top_" + direction + "_src_ips_" + metric}, "Top " + direction + " source IP addresses by " + metric)
        , topDstIP(FLOW_SCHEMA, "ip", {"top_" + direction + "_dst_ips_" + metric}, "Top " + direction + " destination IP addresses by " + metric)
        , topSrcPort(FLOW_SCHEMA, "port", {"top_" + direction + "_src_ports_" + metric}, "Top " + direction + " source ports by " + metric)
        , topDstPort(FLOW_SCHEMA, "port", {"top_" + direction + "_dst_ports_" + metric}, "Top " + direction + " destination ports by " + metric)
        , topSrcIPPort(FLOW_SCHEMA, "ip_port", {"top_" + direction + "_src_ip_ports_" + metric}, "Top " + direction + " source IP addresses and port by " + metric)
        , topDstIPPort(FLOW_SCHEMA, "ip_port", {"top_" + direction + "_dst_ip_ports_" + metric}, "Top " + direction + " destination IP addresses and port by " + metric)
        , topDSCP(FLOW_SCHEMA, "dscp", {"top_" + direction + "_dscp_" + metric}, "Top " + direction + " IP DSCP by " + metric)
        , topECN(FLOW_SCHEMA, "ecn", {"top_" + direction + "_ecn_" + metric}, "Top " + direction + " IP ECN by " + metric)
    {
    }

    void set_settings(size_t topn_count, uint64_t percentile_threshold)
    {
        topSrcIP.set_settings(topn_count, percentile_threshold);
        topDstIP.set_settings(topn_count, percentile_threshold);
        topSrcPort.set_settings(topn_count, percentile_threshold);
        topDstPort.set_settings(topn_count, percentile_threshold);
        topSrcIPPort.set_settings(topn_count, percentile_threshold);
        topDstIPPort.set_settings(topn_count, percentile_threshold);
    }
};

struct Counters {
    Counter UDP;
    Counter TCP;
    Counter OtherL4;
    Counter IPv4;
    Counter IPv6;
    Counter total;
    Counters(std::string direction, std::string metric)
        : UDP(FLOW_SCHEMA, {direction + "_udp_" + metric}, "Count of " + direction + " UDP by " + metric)
        , TCP(FLOW_SCHEMA, {direction + "_tcp_" + metric}, "Count of " + direction + " TCP by " + metric)
        , OtherL4(FLOW_SCHEMA, {direction + "_other_l4_" + metric}, "Count of " + direction + " " + metric + " which are not UDP or TCP")
        , IPv4(FLOW_SCHEMA, {direction + "_ipv4_" + metric}, "Count of " + direction + " IPv4 by " + metric)
        , IPv6(FLOW_SCHEMA, {direction + "_ipv6_" + metric}, "Count of " + direction + " IPv6 by " + metric)
        , total(FLOW_SCHEMA, {direction + "_" + metric}, "Count of " + direction + " " + metric)
    {
    }
};

struct FlowInterface {

    Cardinality conversationsCard;
    Cardinality srcIPCard;
    Cardinality dstIPCard;
    Cardinality srcPortCard;
    Cardinality dstPortCard;
    std::pair<FlowTopN, FlowTopN> topN{FlowTopN("bytes"), FlowTopN("packets")};
    std::unordered_map<FlowDirectionType, FlowDirectionTopN> directionTopN{
        {InBytes, FlowDirectionTopN("in", "bytes")},
        {OutBytes, FlowDirectionTopN("out", "bytes")},
        {InPackets, FlowDirectionTopN("in", "packets")},
        {OutPackets, FlowDirectionTopN("out", "packets")}};
    std::unordered_map<FlowDirectionType, Counters> counters{
        {InBytes, Counters("in", "bytes")},
        {OutBytes, Counters("out", "bytes")},
        {InPackets, Counters("in", "packets")},
        {OutPackets, Counters("out", "packets")}};

    FlowInterface()
        : conversationsCard(FLOW_SCHEMA, {"cardinality", "conversations"}, "Conversations cardinality")
        , srcIPCard(FLOW_SCHEMA, {"cardinality", "src_ips_in"}, "Source IP cardinality")
        , dstIPCard(FLOW_SCHEMA, {"cardinality", "dst_ips_out"}, "Destination IP cardinality")
        , srcPortCard(FLOW_SCHEMA, {"cardinality", "src_ports_in"}, "Source ports cardinality")
        , dstPortCard(FLOW_SCHEMA, {"cardinality", "dst_ports_out"}, "Destination ports cardinality")
    {
    }

    void set_topn_settings(size_t topn_count, uint64_t percentile_threshold)
    {
        for (auto &top : directionTopN) {
            top.second.set_settings(topn_count, percentile_threshold);
        }
        topN.first.set_settings(topn_count, percentile_threshold);
        topN.second.set_settings(topn_count, percentile_threshold);
    }
};

struct FlowDevice {

    Counter total;
    Counter filtered;

    TopN<uint32_t> topInIfIndexBytes;
    TopN<uint32_t> topOutIfIndexBytes;
    TopN<uint32_t> topInIfIndexPackets;
    TopN<uint32_t> topOutIfIndexPackets;

    std::map<uint32_t, std::unique_ptr<FlowInterface>> interfaces;

    FlowDevice()
        : total(FLOW_SCHEMA, {"records_flows"}, "Count of total flows records that match the configured filter(s) (if any)")
        , filtered(FLOW_SCHEMA, {"records_filtered"}, "Count of total flows records seen that did not match the configured filter(s) (if any)")
        , topInIfIndexBytes(FLOW_SCHEMA, "interface", {"top_in_interfaces_bytes"}, "Top input interfaces by bytes")
        , topOutIfIndexBytes(FLOW_SCHEMA, "interface", {"top_out_interfaces_bytes"}, "Top output interfaces by bytes")
        , topInIfIndexPackets(FLOW_SCHEMA, "interface", {"top_in_interfaces_packets"}, "Top input interfaces by packets")
        , topOutIfIndexPackets(FLOW_SCHEMA, "interface", {"top_out_interfaces_packets"}, "Top output interfaces by packets")
    {
    }

    void set_topn_settings(size_t topn_count, uint64_t percentile_threshold)
    {
        topInIfIndexBytes.set_settings(topn_count, percentile_threshold);
        topOutIfIndexBytes.set_settings(topn_count, percentile_threshold);
        topInIfIndexPackets.set_settings(topn_count, percentile_threshold);
        topOutIfIndexPackets.set_settings(topn_count, percentile_threshold);
    }
};

class FlowMetricsBucket final : public visor::AbstractMetricsBucket
{
protected:
    mutable std::shared_mutex _mutex;
    EnrichData *_enrich_data{nullptr};
    SummaryData *_summary_data{nullptr};
    size_t _topn_count{10};
    uint64_t _topn_percentile_threshold{0};
    //  <DeviceId, FlowDevice>
    std::map<std::string, std::unique_ptr<FlowDevice>> _devices_metrics;

    void _process_geo_metrics(FlowInterface *interface, FlowDirectionType type, const pcpp::IPv4Address &ipv4, uint64_t aggregator);
    void _process_geo_metrics(FlowInterface *interface, FlowDirectionType type, const pcpp::IPv6Address &ipv6, uint64_t aggregator);

public:
    FlowMetricsBucket()
    {
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

    inline void set_enrich_data(EnrichData *enrich_data)
    {
        _enrich_data = enrich_data;
    }

    inline void set_summary_data(SummaryData *summary_data)
    {
        _summary_data = summary_data;
    }

    inline void process_filtered(uint64_t filtered, const std::string &device)
    {
        std::unique_lock lock(_mutex);
        if (!_devices_metrics.count(device)) {
            _devices_metrics[device] = std::make_unique<FlowDevice>();
            _devices_metrics[device]->set_topn_settings(_topn_count, _topn_percentile_threshold);
        }
        _devices_metrics[device]->filtered += filtered;
    }
    void process_flow(bool deep, const FlowPacket &payload, FlowCache &cache);
    void process_interface(bool deep, FlowInterface *iface, const FlowData &flow, FlowCache &cache, FlowDirectionType type);
};

class FlowMetricsManager final : public visor::AbstractMetricsManager<FlowMetricsBucket>
{
    EnrichData _enrich_data;
    SummaryData _summary_data;
    FlowCache _cache;

public:
    FlowMetricsManager(const Configurable *window_config)
        : visor::AbstractMetricsManager<FlowMetricsBucket>(window_config)
    {
    }

    inline void set_enrich_data(EnrichData enrich_data)
    {
        _enrich_data = enrich_data;
        if (!_enrich_data.empty()) {
            live_bucket()->set_enrich_data(&_enrich_data);
        }
    }

    inline void set_summary_data(SummaryData summary_data)
    {
        _summary_data = summary_data;
        live_bucket()->set_summary_data(&_summary_data);
    }

    inline void process_filtered(timespec stamp, uint64_t filtered, const std::string &device)
    {
        // base event, no sample
        new_event(stamp, false);
        live_bucket()->process_filtered(filtered, device);
    }
    void process_flow(const FlowPacket &payload);

    void on_period_shift([[maybe_unused]] timespec stamp, [[maybe_unused]] const FlowMetricsBucket *maybe_expiring_bucket) override
    {
        if (!_enrich_data.empty()) {
            live_bucket()->set_enrich_data(&_enrich_data);
        }
        if (_summary_data.type != IpSummary::None) {
            live_bucket()->set_summary_data(&_summary_data);
        }
    }
};

class FlowStreamHandler final : public visor::StreamMetricsHandler<FlowMetricsManager>
{

    // the input stream event proxy we support (only one will be in use at a time)
    MockInputEventProxy *_mock_proxy{nullptr};
    FlowInputEventProxy *_flow_proxy{nullptr};

    sigslot::connection _sflow_connection;
    sigslot::connection _netflow_connection;
    sigslot::connection _heartbeat_connection;

    lib::utils::IPv4subnetList _only_ipv4_list;
    lib::utils::IPv6subnetList _only_ipv6_list;

    std::map<std::string, std::vector<std::pair<uint32_t, uint32_t>>> _device_interfaces_list;
    std::vector<std::pair<uint32_t, uint32_t>> _parsed_port_list;

    bool _sample_rate_scaling;

    enum Filters {
        OnlyIps,
        OnlyDeviceInterfaces,
        OnlyPorts,
        GeoLocNotFound,
        AsnNotFound,
        DisableIn,
        DisableOut,
        FiltersMAX
    };
    std::bitset<Filters::FiltersMAX> _f_enabled;

    static const inline StreamMetricsHandler::ConfigsDefType _config_defs = {
        "device_map",
        "enrichment",
        "only_device_interfaces",
        "only_ips",
        "only_ports",
        "only_directions",
        "geoloc_notfound",
        "asn_notfound",
        "summarize_ips_by_asn",
        "subnets_for_summarization",
        "exclude_asns_from_summarization",
        "exclude_unknown_asns_from_summarization",
        "exclude_ips_from_summarization",
        "sample_rate_scaling",
        "recorded_stream"};

    static const inline StreamMetricsHandler::GroupDefType _group_defs = {
        {"by_bytes", group::FlowMetrics::ByBytes},
        {"by_packets", group::FlowMetrics::ByPackets},
        {"cardinality", group::FlowMetrics::Cardinality},
        {"conversations", group::FlowMetrics::Conversations},
        {"top_ips", group::FlowMetrics::TopIPs},
        {"counters", group::FlowMetrics::Counters},
        {"top_ports", group::FlowMetrics::TopPorts},
        {"top_ips_ports", group::FlowMetrics::TopIPPorts},
        {"top_tos", group::FlowMetrics::TopTos},
        {"top_geo", group::FlowMetrics::TopGeo},
        {"top_interfaces", group::FlowMetrics::TopInterfaces}};

    void process_sflow_cb(const SFSample &, size_t);
    void process_netflow_cb(const std::string &, const NFSample &, size_t);
    void set_start_tstamp(timespec stamp);
    void set_end_tstamp(timespec stamp);

    void _parse_ports(const std::vector<std::string> &port_list);
    std::vector<std::pair<uint32_t, uint32_t>> _parse_interfaces(const std::vector<std::string> &interface_list);
    bool _filtering(FlowData &flow, const std::string &device_id);

public:
    FlowStreamHandler(const std::string &name, InputEventProxy *proxy, const Configurable *window_config);
    ~FlowStreamHandler() override;

    // visor::AbstractModule
    std::string schema_key() const override
    {
        return FLOW_SCHEMA;
    }

    void start() override;
    void stop() override;
};
}
