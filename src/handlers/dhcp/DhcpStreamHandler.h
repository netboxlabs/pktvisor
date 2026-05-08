/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "AbstractMetricsManager.h"
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wzero-as-null-pointer-constant"
#endif
#include <pcapplusplus/DhcpLayer.h>
#include <pcapplusplus/DhcpV6Layer.h>
#include <pcapplusplus/EthLayer.h>
#include <pcapplusplus/IPv6Layer.h>
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif
#include "PcapInputStream.h"
#include "StreamHandler.h"
#include "TransactionManager.h"
#include <limits>
#include <string>

namespace visor::handler::dhcp {

using namespace visor::lib::transaction;
using namespace visor::input::pcap;

static constexpr const char *DHCP_SCHEMA{"dhcp"};

struct DhcpTransaction : public Transaction {
    std::string hostname;
    std::string mac_address;
};

class DhcpMetricsBucket final : public visor::AbstractMetricsBucket
{

protected:
    mutable std::shared_mutex _mutex;

    TopN<std::string> _dhcp_topClients;
    TopN<std::string> _dhcp_topServers;

    // total numPackets is tracked in base class num_events
    struct counters {

        Counter DISCOVER;
        Counter OFFER;
        Counter REQUEST;
        Counter ACK;
        Counter SOLICIT;
        Counter ADVERTISE;
        Counter REQUESTV6;
        Counter REPLY;
        Counter total;
        Counter filtered;

        counters()
            : DISCOVER(DHCP_SCHEMA, {"wire_packets", "discover"}, "Total DHCP packets with message type DISCOVER")
            , OFFER(DHCP_SCHEMA, {"wire_packets", "offer"}, "Total DHCP packets with message type OFFER")
            , REQUEST(DHCP_SCHEMA, {"wire_packets", "request"}, "Total DHCP packets with message type REQUEST")
            , ACK(DHCP_SCHEMA, {"wire_packets", "ack"}, "Total DHCP packets with message type ACK")
            , SOLICIT(DHCP_SCHEMA, {"wire_packets", "solicit"}, "Total DHCPv6 packets with message type SOLICIT")
            , ADVERTISE(DHCP_SCHEMA, {"wire_packets", "advertise"}, "Total DHCPv6 packets with message type ADVERTISE")
            , REQUESTV6(DHCP_SCHEMA, {"wire_packets", "request_v6"}, "Total DHCPv6 packets with message type REQUEST")
            , REPLY(DHCP_SCHEMA, {"wire_packets", "reply"}, "Total DHCPv6 packets with message type REPLY")
            , total(DHCP_SCHEMA, {"wire_packets", "total"}, "Total DHCP/DHCPv6 wire packets matching the configured filter(s)")
            , filtered(DHCP_SCHEMA, {"wire_packets", "filtered"}, "Total DHCP/DHCPv6 wire packets seen that did not match the configured filter(s) (if any)")
        {
        }
    };
    counters _counters;
    Rate _rate_total;

public:
    DhcpMetricsBucket()
        : _dhcp_topClients(DHCP_SCHEMA, "client", {"top_clients"}, "Top DHCP clients")
        , _dhcp_topServers(DHCP_SCHEMA, "server", {"top_servers"}, "Top DHCP servers")
        , _rate_total(DHCP_SCHEMA, {"rates", "total"}, "Rate of all DHCP wire packets (combined ingress and egress) in packets per second")
    {
        set_event_rate_info(DHCP_SCHEMA, {"rates", "events"}, "Rate of all DHCP wire packets before filtering per second");
        set_num_events_info(DHCP_SCHEMA, {"wire_packets", "events"}, "Total DHCP wire packets events");
        set_num_sample_info(DHCP_SCHEMA, {"wire_packets", "deep_samples"}, "Total DHCP wire packets that were sampled for deep inspection");
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
    void to_prometheus(std::stringstream &out, Metric::LabelMap add_labels = {}) const override;
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
    void process_dhcp_layer(bool deep, pcpp::DhcpLayer *dhcp, pcpp::Packet *payload);
    void new_dhcp_transaction(bool deep, pcpp::DhcpLayer *payload, DhcpTransaction &xact);
    void process_dhcp_v6_layer(bool deep, pcpp::DhcpV6Layer *dhcp, pcpp::Packet *payload);
};

class DhcpMetricsManager final : public visor::AbstractMetricsManager<DhcpMetricsBucket>
{
    typedef TransactionManager<uint32_t, DhcpTransaction, std::hash<uint32_t>> DhcpTransactionManager;
    std::unique_ptr<DhcpTransactionManager> _request_ack_manager;

public:
    DhcpMetricsManager(const Configurable *window_config)
        : visor::AbstractMetricsManager<DhcpMetricsBucket>(window_config)
        , _request_ack_manager(std::make_unique<DhcpTransactionManager>())
    {
    }

    void on_period_shift(timespec stamp, [[maybe_unused]] const DhcpMetricsBucket *maybe_expiring_bucket) override
    {
        // Dhcp transaction support
        _request_ack_manager->purge_old_transactions(stamp);
    }

    void set_xact_ttl(uint32_t ttl)
    {
        _request_ack_manager = std::make_unique<DhcpTransactionManager>(ttl);
    }

    void process_filtered(timespec stamp);
    void process_dhcp_layer(pcpp::DhcpLayer *dhcp, pcpp::Packet *payload, timespec stamp);
    void process_dhcp_v6_layer(pcpp::DhcpV6Layer *dhcp, pcpp::Packet *payload, timespec stamp);
};

class DhcpStreamHandler final : public visor::StreamMetricsHandler<DhcpMetricsManager>
{

    PcapInputEventProxy *_pcap_proxy;

    sigslot::connection _pkt_udp_connection;
    sigslot::connection _start_tstamp_connection;
    sigslot::connection _end_tstamp_connection;

    sigslot::connection _heartbeat_connection;

    static const inline StreamMetricsHandler::ConfigsDefType _config_defs = {
        "recorded_stream",
        "xact_ttl_secs",
        "xact_ttl_ms"};

    void process_udp_packet_cb(pcpp::Packet &payload, PacketDirection dir, pcpp::ProtocolType l3, uint32_t flowkey, timespec stamp);

    void set_start_tstamp(timespec stamp);
    void set_end_tstamp(timespec stamp);

    bool _filtering(pcpp::DhcpLayer *payload, timespec stamp);
    bool _filtering_v6(pcpp::DhcpV6Layer *payload, timespec stamp);

public:
    DhcpStreamHandler(const std::string &name, InputEventProxy *proxy, const Configurable *window_config);
    ~DhcpStreamHandler() = default;

    // visor::AbstractModule
    std::string schema_key() const override
    {
        return DHCP_SCHEMA;
    }

    void start() override;
    void stop() override;
};

}
