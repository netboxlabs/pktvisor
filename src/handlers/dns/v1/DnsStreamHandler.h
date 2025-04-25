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
#include "TransactionManager.h"
#include "dns.h"
#include <Corrade/Utility/Debug.h>
#include <bitset>
#include <limits>
#include <string>

namespace visor::input::dnstap {
class DnstapInputEventProxy;
}

namespace visor::handler::dns {

using namespace visor::lib::dns;
using namespace visor::lib::transaction;
using namespace visor::input::pcap;
using namespace visor::input::dnstap;
using namespace visor::input::mock;

static constexpr const char *DNS_SCHEMA{"dns"};

// DNS Groups
namespace group {
enum DnsMetrics : visor::MetricGroupIntType {
    Cardinality,
    Counters,
    Quantiles,
    Histograms,
    DnsTransactions,
    TopEcs,
    TopQnames,
    TopQnamesDetails,
    TopPorts
};
}

struct DnsTransaction : public Transaction {
    size_t querySize;
};

enum Protocol : uint64_t {
    DNSTAP_UDP = dnstap::SocketProtocol::UDP,
    DNSTAP_TCP = dnstap::SocketProtocol::TCP,
    DNSTAP_DOT = dnstap::SocketProtocol::DOT,
    DNSTAP_DOH = dnstap::SocketProtocol::DOH,
    PCPP_TCP = pcpp::TCP,
    PCPP_UDP = pcpp::UDP,
    PCPP_UNKOWN = pcpp::UnknownProtocol
};

class DnsMetricsBucket final : public visor::AbstractMetricsBucket
{
protected:
    mutable std::shared_mutex _mutex;

    Quantile<uint64_t> _dnsXactFromTimeUs;
    Quantile<uint64_t> _dnsXactToTimeUs;
    Histogram<uint64_t> _dnsXactFromHistTimeUs;
    Histogram<uint64_t> _dnsXactToHistTimeUs;
    Quantile<double> _dnsXactRatio;

    Cardinality _dns_qnameCard;

    TopN<visor::geo::City> _dns_topGeoLocECS;
    TopN<std::string> _dns_topASNECS;
    TopN<std::string> _dns_topQueryECS;

    TopN<std::string> _dns_topQname2;
    TopN<std::string> _dns_topQname3;
    TopN<std::string> _dns_topNX;
    TopN<std::string> _dns_topREFUSED;
    TopN<std::string> _dns_topSizedQnameResp;
    TopN<std::string> _dns_topSRVFAIL;
    TopN<std::string> _dns_topNODATA;
    TopN<std::string> _dns_topNOERROR;
    TopN<uint16_t> _dns_topUDPPort;
    TopN<uint16_t> _dns_topQType;
    TopN<uint16_t> _dns_topRCode;
    TopN<std::string> _dns_slowXactIn;
    TopN<std::string> _dns_slowXactOut;

    struct counters {
        Counter xacts_total;
        Counter xacts_in;
        Counter xacts_out;
        Counter xacts_timed_out;
        Counter queries;
        Counter replies;
        Counter UDP;
        Counter TCP;
        Counter DOT;
        Counter DOH;
        Counter IPv4;
        Counter IPv6;
        Counter NX;
        Counter REFUSED;
        Counter SRVFAIL;
        Counter RNOERROR;
        Counter NODATA;
        Counter total;
        Counter filtered;
        Counter queryECS;
        counters()
            : xacts_total(DNS_SCHEMA, {"xact", "counts", "total"}, "Total DNS transactions (query/reply pairs)")
            , xacts_in(DNS_SCHEMA, {"xact", "in", "total"}, "Total ingress DNS transactions (host is server)")
            , xacts_out(DNS_SCHEMA, {"xact", "out", "total"}, "Total egress DNS transactions (host is client)")
            , xacts_timed_out(DNS_SCHEMA, {"xact", "counts", "timed_out"}, "Total number of DNS transactions that timed out")
            , queries(DNS_SCHEMA, {"wire_packets", "queries"}, "Total DNS wire packets flagged as query (ingress and egress)")
            , replies(DNS_SCHEMA, {"wire_packets", "replies"}, "Total DNS wire packets flagged as reply (ingress and egress)")
            , UDP(DNS_SCHEMA, {"wire_packets", "udp"}, "Total DNS wire packets received over UDP (ingress and egress)")
            , TCP(DNS_SCHEMA, {"wire_packets", "tcp"}, "Total DNS wire packets received over TCP (ingress and egress)")
            , DOT(DNS_SCHEMA, {"wire_packets", "dot"}, "Total DNS wire packets received over DNS over TLS")
            , DOH(DNS_SCHEMA, {"wire_packets", "doh"}, "Total DNS wire packets received over DNS over HTTPS")
            , IPv4(DNS_SCHEMA, {"wire_packets", "ipv4"}, "Total DNS wire packets received over IPv4 (ingress and egress)")
            , IPv6(DNS_SCHEMA, {"wire_packets", "ipv6"}, "Total DNS wire packets received over IPv6 (ingress and egress)")
            , NX(DNS_SCHEMA, {"wire_packets", "nxdomain"}, "Total DNS wire packets flagged as reply with response code NXDOMAIN (ingress and egress)")
            , REFUSED(DNS_SCHEMA, {"wire_packets", "refused"}, "Total DNS wire packets flagged as reply with response code REFUSED (ingress and egress)")
            , SRVFAIL(DNS_SCHEMA, {"wire_packets", "srvfail"}, "Total DNS wire packets flagged as reply with response code SRVFAIL (ingress and egress)")
            , RNOERROR(DNS_SCHEMA, {"wire_packets", "noerror"}, "Total DNS wire packets flagged as reply with response code NOERROR (ingress and egress)")
            , NODATA(DNS_SCHEMA, {"wire_packets", "nodata"}, "Total DNS wire packets flagged as reply with response code NOERROR and no answer section data (ingress and egress)")
            , total(DNS_SCHEMA, {"wire_packets", "total"}, "Total DNS wire packets matching the configured filter(s)")
            , filtered(DNS_SCHEMA, {"wire_packets", "filtered"}, "Total DNS wire packets seen that did not match the configured filter(s) (if any)")
            , queryECS(DNS_SCHEMA, {"wire_packets", "query_ecs"}, "Total queries that have EDNS Client Subnet (ECS) field set")
        {
        }
    };
    counters _counters;

    Rate _rate_total;

public:
    DnsMetricsBucket()
        : _dnsXactFromTimeUs(DNS_SCHEMA, {"xact", "out", "quantiles_us"}, "Quantiles of transaction timing (query/reply pairs) when host is client, in microseconds")
        , _dnsXactToTimeUs(DNS_SCHEMA, {"xact", "in", "quantiles_us"}, "Quantiles of transaction timing (query/reply pairs) when host is server, in microseconds")
        , _dnsXactFromHistTimeUs(DNS_SCHEMA, {"xact", "out", "histogram_us"}, "Histogram of transaction timing (query/reply pairs) when host is client, in microseconds")
        , _dnsXactToHistTimeUs(DNS_SCHEMA, {"xact", "in", "histogram_us"}, "Histogram of transaction timing (query/reply pairs) when host is server, in microseconds")
        , _dnsXactRatio(DNS_SCHEMA, {"xact", "ratio", "quantiles"}, "Quantiles of ratio of packet sizes in a DNS transaction (reply/query)")
        , _dns_qnameCard(DNS_SCHEMA, {"cardinality", "qname"}, "Cardinality of unique QNAMES, both ingress and egress")
        , _dns_topGeoLocECS(DNS_SCHEMA, "geo_loc", {"top_geoLoc_ecs"}, "Top GeoIP ECS locations")
        , _dns_topASNECS(DNS_SCHEMA, "asn", {"top_asn_ecs"}, "Top ASNs by ECS")
        , _dns_topQueryECS(DNS_SCHEMA, "ecs", {"top_query_ecs"}, "Top EDNS Client Subnet (ECS) observed in DNS queries")
        , _dns_topQname2(DNS_SCHEMA, "qname", {"top_qname2"}, "Top QNAMES, aggregated at a depth of two labels")
        , _dns_topQname3(DNS_SCHEMA, "qname", {"top_qname3"}, "Top QNAMES, aggregated at a depth of three labels")
        , _dns_topNX(DNS_SCHEMA, "qname", {"top_nxdomain"}, "Top QNAMES with result code NXDOMAIN")
        , _dns_topREFUSED(DNS_SCHEMA, "qname", {"top_refused"}, "Top QNAMES with result code REFUSED")
        , _dns_topSizedQnameResp(DNS_SCHEMA, "qname", {"top_qname_by_resp_bytes"}, "Top QNAMES by response volume in bytes")
        , _dns_topSRVFAIL(DNS_SCHEMA, "qname", {"top_srvfail"}, "Top QNAMES with result code SRVFAIL")
        , _dns_topNODATA(DNS_SCHEMA, "qname", {"top_nodata"}, "Top QNAMES with result code NOERROR and no answer section")
        , _dns_topNOERROR(DNS_SCHEMA, "qname", {"top_noerror"}, "Top QNAMES with result code NOERROR")
        , _dns_topUDPPort(DNS_SCHEMA, "port", {"top_udp_ports"}, "Top UDP source port on the query side of a transaction")
        , _dns_topQType(DNS_SCHEMA, "qtype", {"top_qtype"}, "Top query types")
        , _dns_topRCode(DNS_SCHEMA, "rcode", {"top_rcode"}, "Top result codes")
        , _dns_slowXactIn(DNS_SCHEMA, "qname", {"xact", "in", "top_slow"}, "Top QNAMES in transactions where host is the server and transaction speed is slower than p90")
        , _dns_slowXactOut(DNS_SCHEMA, "qname", {"xact", "out", "top_slow"}, "Top QNAMES in transactions where host is the client and transaction speed is slower than p90")
        , _rate_total(DNS_SCHEMA, {"rates", "total"}, "Rate of all DNS wire packets (combined ingress and egress) in packets per second")
    {
        set_event_rate_info(DNS_SCHEMA, {"rates", "events"}, "Rate of all DNS wire packets before filtering per second");
        set_num_events_info(DNS_SCHEMA, {"wire_packets", "events"}, "Total DNS wire packets events");
        set_num_sample_info(DNS_SCHEMA, {"wire_packets", "deep_samples"}, "Total DNS wire packets that were sampled for deep inspection");
    }

    auto get_xact_data_locked() const
    {
        std::shared_lock lock(_mutex);
        struct retVals {
            const Quantile<uint64_t> &xact_to;
            const Quantile<uint64_t> &xact_from;
            std::shared_lock<std::shared_mutex> lock;
        };
        return retVals{_dnsXactToTimeUs, _dnsXactFromTimeUs, std::move(lock)};
    }

    void inc_xact_timed_out(uint64_t c)
    {
        std::unique_lock lock(_mutex);
        _counters.xacts_timed_out += c;
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
    void update_topn_metrics(size_t topn_count, uint64_t percentile_threshold) override
    {
        _dns_topGeoLocECS.set_settings(topn_count, percentile_threshold);
        _dns_topASNECS.set_settings(topn_count, percentile_threshold);
        _dns_topQueryECS.set_settings(topn_count, percentile_threshold);
        _dns_topQname2.set_settings(topn_count, percentile_threshold);
        _dns_topQname3.set_settings(topn_count, percentile_threshold);
        _dns_topNX.set_settings(topn_count, percentile_threshold);
        _dns_topREFUSED.set_settings(topn_count, percentile_threshold);
        _dns_topSizedQnameResp.set_settings(topn_count, percentile_threshold);
        _dns_topSRVFAIL.set_settings(topn_count, percentile_threshold);
        _dns_topNODATA.set_settings(topn_count, percentile_threshold);
        _dns_topNOERROR.set_settings(topn_count, percentile_threshold);
        _dns_topUDPPort.set_settings(topn_count, percentile_threshold);
        _dns_topQType.set_settings(topn_count, percentile_threshold);
        _dns_topRCode.set_settings(topn_count, percentile_threshold);
        _dns_slowXactIn.set_settings(topn_count, percentile_threshold);
        _dns_slowXactOut.set_settings(topn_count, percentile_threshold);
    }

    void on_set_read_only() override
    {
        // stop rate collection
        _rate_total.cancel();
    }

    void process_filtered();
    void process_dns_layer(bool deep, DnsLayer &payload, pcpp::ProtocolType l3, Protocol l4, uint16_t port, size_t suffix_size = 0);
    void process_dns_layer(pcpp::ProtocolType l3, Protocol l4, QR side);
    void process_dnstap(bool deep, const dnstap::Dnstap &payload);

    void new_dns_transaction(bool deep, float to90th, float from90th, DnsLayer &dns, PacketDirection dir, DnsTransaction xact);
};

class DnsMetricsManager final : public visor::AbstractMetricsManager<DnsMetricsBucket>
{
    using DnsXactID = std::pair<uint32_t, uint16_t>;
    typedef lib::transaction::TransactionManager<DnsXactID, DnsTransaction> DnsTransactionManager;
    std::unique_ptr<DnsTransactionManager> _qr_pair_manager;
    float _to90th{0.0f};
    float _from90th{0.0f};

public:
    DnsMetricsManager(const Configurable *window_config)
        : visor::AbstractMetricsManager<DnsMetricsBucket>(window_config)
        , _qr_pair_manager(std::make_unique<DnsTransactionManager>())
    {
    }

    void on_period_shift(timespec stamp, [[maybe_unused]] const DnsMetricsBucket *maybe_expiring_bucket) override
    {
        // DNS transaction support
        auto timed_out = _qr_pair_manager->purge_old_transactions(stamp);
        if (timed_out) {
            live_bucket()->inc_xact_timed_out(timed_out);
        }
        // collect to/from 90th percentile every period shift to judge slow xacts
        auto [xact_to, xact_from, lock] = bucket(1)->get_xact_data_locked();
        if (xact_from.get_n()) {
            _from90th = xact_from.get_quantile(0.90);
        }
        if (xact_to.get_n()) {
            _to90th = xact_to.get_quantile(0.90);
        }
    }

    size_t num_open_transactions() const
    {
        return _qr_pair_manager->open_transaction_count();
    }

    void set_xact_ttl(uint32_t ttl)
    {
        _qr_pair_manager = std::make_unique<DnsTransactionManager>(ttl);
    }

    void process_filtered(timespec stamp);
    void process_dns_layer(DnsLayer &payload, PacketDirection dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4, uint32_t flowkey, uint16_t port, size_t suffix_size, timespec stamp);
    void process_dnstap(const dnstap::Dnstap &payload, bool filtered);
};

class DnsTcpSessionData final : public TcpSessionData
{
public:
    static constexpr size_t MIN_DNS_QUERY_SIZE = 17;

    DnsTcpSessionData(got_msg_cb got_data_handler)
        : TcpSessionData(got_data_handler)
    {
    }

    ~DnsTcpSessionData() = default;

    void receive_tcp_data(const uint8_t *data, size_t len) override;
};

class DnsStreamHandler final : public visor::StreamMetricsHandler<DnsMetricsManager>
{
    static constexpr size_t DNSTAP_TYPE_SIZE = 15;

    struct DnsCacheData {
        uint32_t flowKey = 0;
        timespec timestamp = timespec();
        std::unique_ptr<DnsLayer> dnsLayer;
    };
    static thread_local DnsCacheData _cached_dns_layer;

    // the input event proxy we support (only one will be in use at a time)
    PcapInputEventProxy *_pcap_proxy{nullptr};
    MockInputEventProxy *_mock_proxy{nullptr};
    DnstapInputEventProxy *_dnstap_proxy{nullptr};

    typedef uint32_t flowKey;
    std::unordered_map<flowKey, TcpFlowData> _tcp_connections;

    sigslot::connection _dnstap_connection;

    sigslot::connection _pkt_udp_connection;
    sigslot::connection _pkt_tcp_reassembled_connection;
    sigslot::connection _start_tstamp_connection;
    sigslot::connection _end_tstamp_connection;

    sigslot::connection _tcp_start_connection;
    sigslot::connection _tcp_end_connection;
    sigslot::connection _tcp_message_connection;

    sigslot::connection _heartbeat_connection;

    void process_udp_packet_cb(pcpp::Packet &payload, PacketDirection dir, pcpp::ProtocolType l3, uint32_t flowkey, timespec stamp);
    void process_tcp_reassembled_packet_cb(pcpp::Packet &payload, PacketDirection dir, pcpp::ProtocolType l3, uint32_t flowkey, timespec stamp);
    void process_dnstap_cb(const dnstap::Dnstap &, size_t);
    void tcp_message_ready_cb(int8_t side, const pcpp::TcpStreamData &tcpData, PacketDirection dir);
    void tcp_connection_start_cb(const pcpp::ConnectionData &connectionData, PacketDirection dir);
    void tcp_connection_end_cb(const pcpp::ConnectionData &connectionData, pcpp::TcpReassembly::ConnectionEndReason reason);
    void set_start_tstamp(timespec stamp);
    void set_end_tstamp(timespec stamp);

    static const inline std::map<std::string, std::pair<int, int>> _dnstap_map_types = {
        {"auth", {dnstap::Message_Type_AUTH_QUERY, dnstap::Message_Type_AUTH_RESPONSE}},
        {"resolver", {dnstap::Message_Type_RESOLVER_QUERY, dnstap::Message_Type_RESOLVER_RESPONSE}},
        {"client", {dnstap::Message_Type_CLIENT_QUERY, dnstap::Message_Type_CLIENT_RESPONSE}},
        {"forwarder", {dnstap::Message_Type_FORWARDER_QUERY, dnstap::Message_Type_FORWARDER_RESPONSE}},
        {"stub", {dnstap::Message_Type_STUB_QUERY, dnstap::Message_Type_STUB_RESPONSE}},
        {"tool", {dnstap::Message_Type_TOOL_QUERY, dnstap::Message_Type_TOOL_RESPONSE}},
        {"update", {dnstap::Message_Type_UPDATE_QUERY, dnstap::Message_Type_UPDATE_RESPONSE}}};

    // DNS Filters
    enum Filters {
        ExcludingRCode,
        OnlyRCode,
        OnlyQueries,
        OnlyResponses,
        OnlyQtype,
        AnswerCount,
        OnlyQName,
        OnlyQNameSuffix,
        OnlyDNSSECResponse,
        DnstapMsgType,
        GeoLocNotFound,
        AsnNotFound,
        FiltersMAX
    };
    std::bitset<Filters::FiltersMAX> _f_enabled;
    enum Configs {
        PublicSuffixList,
        ConfigsMAX
    };
    std::bitset<Configs::ConfigsMAX> _c_enabled;
    std::vector<uint16_t> _f_rcodes;
    uint64_t _f_answer_count{0};
    std::vector<std::string> _f_qnames_suffix;
    std::vector<std::string> _f_qnames;
    std::vector<uint16_t> _f_qtypes;
    size_t _static_suffix_size{0};
    std::bitset<DNSTAP_TYPE_SIZE> _f_dnstap_types;
    bool _using_predicate_signals{false};
    Filters _predicate_filter_type{Filters::FiltersMAX};

    static const inline StreamMetricsHandler::ConfigsDefType _config_defs = {
        "exclude_noerror",
        "only_rcode",
        "only_queries",
        "only_responses",
        "only_dnssec_response",
        "answer_count",
        "only_qtype",
        "only_qname",
        "only_qname_suffix",
        "geoloc_notfound",
        "asn_notfound",
        "dnstap_msg_type",
        "public_suffix_list",
        "recorded_stream",
        "xact_ttl_secs",
        "xact_ttl_ms"};

    static const inline StreamMetricsHandler::GroupDefType _group_defs = {
        {"cardinality", group::DnsMetrics::Cardinality},
        {"counters", group::DnsMetrics::Counters},
        {"quantiles", group::DnsMetrics::Quantiles},
        {"histograms", group::DnsMetrics::Histograms},
        {"dns_transaction", group::DnsMetrics::DnsTransactions},
        {"top_ecs", group::DnsMetrics::TopEcs},
        {"top_qnames", group::DnsMetrics::TopQnames},
        {"top_qnames_details", group::DnsMetrics::TopQnamesDetails},
        {"top_ports", group::DnsMetrics::TopPorts}};

    bool _filtering(DnsLayer &payload, PacketDirection dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4, uint16_t port, timespec stamp);
    bool _configs(DnsLayer &payload);
    void _register_predicate_filter(Filters filter, std::string f_key, std::string f_value);

public:
    DnsStreamHandler(const std::string &name, InputEventProxy *proxy, const Configurable *window_config);
    ~DnsStreamHandler() = default;

    // visor::AbstractModule
    std::string schema_key() const override
    {
        return DNS_SCHEMA;
    }

    void start() override;
    void stop() override;
    void info_json(json &j) const override;
};
}
