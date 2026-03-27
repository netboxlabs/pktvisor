/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "NetStreamHandler.h"
#include "Corrade/Utility/Debug.h"
#include "HandlerModulePlugin.h"
#include "utils.h"

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wzero-as-null-pointer-constant"
#pragma clang diagnostic ignored "-Wc99-extensions"
#endif
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/IPv6Layer.h>
#include <pcapplusplus/PacketUtils.h>
#include <pcapplusplus/TimespecTimeval.h>
#include "VisorTcpLayer.h"
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif
#include "cpc_union.hpp"
#include "fmt/format.h"

namespace visor::handler::net::v2 {

NetStreamHandler::NetStreamHandler(const std::string &name, InputEventProxy *proxy, const Configurable *window_config)
    : visor::StreamMetricsHandler<NetworkMetricsManager>(name, window_config)
{
    // figure out which input event proxy we have
    if (proxy) {
        _pcap_proxy = dynamic_cast<PcapInputEventProxy *>(proxy);
        _dnstap_proxy = dynamic_cast<DnstapInputEventProxy *>(proxy);
        _mock_proxy = dynamic_cast<MockInputEventProxy *>(proxy);
        if (!_pcap_proxy && !_dnstap_proxy && !_mock_proxy) {
            throw StreamHandlerException(fmt::format("NetStreamHandler: unsupported input event proxy {}", proxy->name()));
        }
    }
}

void NetStreamHandler::start()
{
    if (_running) {
        return;
    }

    validate_configs(_config_defs);

    // default enabled groups
    _groups.set(group::NetMetrics::Counters);
    _groups.set(group::NetMetrics::Cardinality);
    _groups.set(group::NetMetrics::Quantiles);
    _groups.set(group::NetMetrics::TopGeo);
    _groups.set(group::NetMetrics::TopIps);

    process_groups(_group_defs);

    // Setup Filters
    if (config_exists("geoloc_notfound") && config_get<bool>("geoloc_notfound")) {
        _f_enabled.set(Filters::GeoLocNotFound);
        _f_geoloc_prefix.push_back("Unknown");
    }

    if (config_exists("asn_notfound") && config_get<bool>("asn_notfound")) {
        _f_enabled.set(Filters::AsnNotFound);
        _f_asn_number.push_back("Unknown");
    }

    if (config_exists("only_geoloc_prefix")) {
        _f_enabled.set(Filters::GeoLocPrefix);
        for (const auto &prefix : config_get<StringList>("only_geoloc_prefix")) {
            _f_geoloc_prefix.push_back(prefix);
        }
    }

    if (config_exists("only_asn_number")) {
        _f_enabled.set(Filters::AsnNumber);
        for (const auto &number : config_get<StringList>("only_asn_number")) {
            if (std::all_of(number.begin(), number.end(), ::isdigit)) {
                _f_asn_number.push_back(number + '/');
            } else {
                throw ConfigException(fmt::format("NetStreamHandler: only_asn_number filter contained an invalid/unsupported value: {}", number));
            }
        }
    }

    if (config_exists("recorded_stream")) {
        _metrics->set_recorded_stream();
    }

    if (_pcap_proxy) {
        _pkt_connection = _pcap_proxy->packet_signal.connect(&NetStreamHandler::process_packet_cb, this);
        _pkt_tcp_reassembled_connection = _pcap_proxy->tcp_reassembled_signal.connect(&NetStreamHandler::process_tcp_reassembled_packet_cb, this);
        _start_tstamp_connection = _pcap_proxy->start_tstamp_signal.connect(&NetStreamHandler::set_start_tstamp, this);
        _end_tstamp_connection = _pcap_proxy->end_tstamp_signal.connect(&NetStreamHandler::set_end_tstamp, this);
        _heartbeat_connection = _pcap_proxy->heartbeat_signal.connect([this](const timespec stamp) {
            check_period_shift(stamp);
            _event_proxy ? _event_proxy->heartbeat_signal(stamp) : void();
        });
        // only connect to TCP reassembly data if it is in chaining mode
        if (_event_proxy) {
            _tcp_start_connection = _pcap_proxy->tcp_connection_start_signal.connect([this](const pcpp::ConnectionData &connectionData, PacketDirection dir) {
                if (validate_tcp_data(connectionData, dir, connectionData.startTime)) {
                    static_cast<PcapInputEventProxy *>(_event_proxy.get())->tcp_connection_start_signal(connectionData, dir);
                }
            });
            _tcp_message_connection = _pcap_proxy->tcp_message_ready_signal.connect([this](int8_t side, const pcpp::TcpStreamData &tcpData, PacketDirection dir) {
                if (validate_tcp_data(tcpData.getConnectionData(), dir, tcpData.getTimeStamp())) {
                    static_cast<PcapInputEventProxy *>(_event_proxy.get())->tcp_message_ready_signal(side, tcpData, dir);
                }
            });
            _tcp_end_connection = _pcap_proxy->tcp_connection_end_signal.connect([this](const pcpp::ConnectionData &connectionData, pcpp::TcpReassembly::ConnectionEndReason reason) {
                if (validate_tcp_data(connectionData, PacketDirection::unknown, connectionData.endTime)) {
                    static_cast<PcapInputEventProxy *>(_event_proxy.get())->tcp_connection_end_signal(connectionData, reason);
                }
            });
        }
    } else if (_dnstap_proxy) {
        _dnstap_connection = _dnstap_proxy->dnstap_signal.connect(&NetStreamHandler::process_dnstap_cb, this);
        _heartbeat_connection = _dnstap_proxy->heartbeat_signal.connect([this](const timespec stamp) {
            check_period_shift(stamp);
            _event_proxy ? _event_proxy->heartbeat_signal(stamp) : void();
        });
    }

    _running = true;
}

void NetStreamHandler::stop()
{
    if (!_running) {
        return;
    }

    if (_pcap_proxy) {
        _pkt_connection.disconnect();
        _start_tstamp_connection.disconnect();
        _end_tstamp_connection.disconnect();
        _pkt_tcp_reassembled_connection.disconnect();
        if (_event_proxy) {
            _tcp_start_connection.disconnect();
            _tcp_message_connection.disconnect();
            _tcp_end_connection.disconnect();
        }
    } else if (_dnstap_proxy) {
        _dnstap_connection.disconnect();
    }
    _heartbeat_connection.disconnect();

    _running = false;
}

NetStreamHandler::~NetStreamHandler()
{
}

// callback from input module
void NetStreamHandler::process_packet_cb(pcpp::Packet &payload, PacketDirection dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4, timespec stamp)
{
    if (!_filtering(payload, dir, stamp)) {
        _metrics->process_packet(payload, dir, l3, l4, stamp);
        if (_event_proxy && l4 == pcpp::UDP) {
            static_cast<PcapInputEventProxy *>(_event_proxy.get())->udp_signal(payload, dir, l3, pcpp::hash5Tuple(&payload), stamp);
        }
    }
}

void NetStreamHandler::process_tcp_reassembled_packet_cb(pcpp::Packet &payload, PacketDirection dir, pcpp::ProtocolType l3, uint32_t flowkey, timespec stamp)
{
    if (!_filtering(payload, dir, stamp)) {
        _metrics->process_packet(payload, dir, l3, pcpp::TCP, stamp);
        if (_event_proxy) {
            static_cast<PcapInputEventProxy *>(_event_proxy.get())->tcp_reassembled_signal(payload, dir, l3, flowkey, stamp);
        }
    }
}

void NetStreamHandler::set_start_tstamp(timespec stamp)
{
    _metrics->set_start_tstamp(stamp);
    if (_event_proxy) {
        static_cast<PcapInputEventProxy *>(_event_proxy.get())->start_tstamp_signal(stamp);
    }
}

void NetStreamHandler::set_end_tstamp(timespec stamp)
{
    _metrics->set_end_tstamp(stamp);
    if (_event_proxy) {
        static_cast<PcapInputEventProxy *>(_event_proxy.get())->end_tstamp_signal(stamp);
    }
}

bool NetStreamHandler::validate_tcp_data(const pcpp::ConnectionData &connectionData, PacketDirection dir, timeval timeInterval)
{
    pcpp::Packet packet;
    if (connectionData.srcIP.isIPv4()) {
        packet.addLayer(new pcpp::IPv4Layer(connectionData.srcIP.getIPv4(), connectionData.dstIP.getIPv4()), true);
    } else {
        packet.addLayer(new pcpp::IPv6Layer(connectionData.srcIP.getIPv6(), connectionData.dstIP.getIPv6()), true);
    }
    packet.addLayer(new pcpp::TcpLayer(connectionData.srcPort, connectionData.dstPort), true);

    timespec stamp;
    TIMEVAL_TO_TIMESPEC(&timeInterval, &stamp);

    return !_filtering(packet, dir, stamp);
}

void NetStreamHandler::process_dnstap_cb(const dnstap::Dnstap &payload, size_t size)
{
    _metrics->process_dnstap(payload, size);
}

static inline bool begins_with(std::string_view str, std::string_view prefix)
{
    return str.size() >= prefix.size() && 0 == str.compare(0, prefix.size(), prefix);
}

bool NetStreamHandler::_filtering(pcpp::Packet &payload, PacketDirection dir, timespec stamp)
{
    if (_f_enabled[Filters::GeoLocPrefix] || _f_enabled[Filters::GeoLocNotFound]) {
        if (!HandlerModulePlugin::city->enabled() || dir == PacketDirection::unknown) {
            goto will_filter;
        } else if (auto IPv4Layer = payload.getLayerOfType<pcpp::IPv4Layer>(); IPv4Layer) {
            struct sockaddr_in sa4;
            if (dir == PacketDirection::toHost && lib::utils::ipv4_to_sockaddr(IPv4Layer->getSrcIPv4Address(), &sa4) && std::none_of(_f_geoloc_prefix.begin(), _f_geoloc_prefix.end(), [sa4](const auto &prefix) {
                    return begins_with(HandlerModulePlugin::city->getGeoLoc(&sa4).location, prefix);
                })) {
                goto will_filter;
            } else if (dir == PacketDirection::fromHost && lib::utils::ipv4_to_sockaddr(IPv4Layer->getDstIPv4Address(), &sa4) && std::none_of(_f_geoloc_prefix.begin(), _f_geoloc_prefix.end(), [sa4](const auto &prefix) {
                           return begins_with(HandlerModulePlugin::city->getGeoLoc(&sa4).location, prefix);
                       })) {
                goto will_filter;
            }
        } else if (auto IPv6layer = payload.getLayerOfType<pcpp::IPv6Layer>(); IPv6layer) {
            struct sockaddr_in6 sa6;
            if (dir == PacketDirection::toHost && lib::utils::ipv6_to_sockaddr(IPv6layer->getSrcIPv6Address(), &sa6) && std::none_of(_f_geoloc_prefix.begin(), _f_geoloc_prefix.end(), [sa6](const auto &prefix) {
                    return begins_with(HandlerModulePlugin::city->getGeoLoc(&sa6).location, prefix);
                })) {
                goto will_filter;
            } else if (dir == PacketDirection::fromHost && lib::utils::ipv6_to_sockaddr(IPv6layer->getDstIPv6Address(), &sa6) && std::none_of(_f_geoloc_prefix.begin(), _f_geoloc_prefix.end(), [sa6](const auto &prefix) {
                           return begins_with(HandlerModulePlugin::city->getGeoLoc(&sa6).location, prefix);
                       })) {
                goto will_filter;
            }
        }
    }
    if (_f_enabled[Filters::AsnNumber] || _f_enabled[Filters::AsnNotFound]) {
        if (!HandlerModulePlugin::asn->enabled() || dir == PacketDirection::unknown) {
            goto will_filter;
        } else if (auto IPv4Layer = payload.getLayerOfType<pcpp::IPv4Layer>(); IPv4Layer) {
            struct sockaddr_in sa4;
            if (dir == PacketDirection::toHost && lib::utils::ipv4_to_sockaddr(IPv4Layer->getSrcIPv4Address(), &sa4) && std::none_of(_f_asn_number.begin(), _f_asn_number.end(), [sa4](const auto &prefix) {
                    return begins_with(HandlerModulePlugin::asn->getASNString(&sa4), prefix);
                })) {
                goto will_filter;
            } else if (dir == PacketDirection::fromHost && lib::utils::ipv4_to_sockaddr(IPv4Layer->getDstIPv4Address(), &sa4) && std::none_of(_f_asn_number.begin(), _f_asn_number.end(), [sa4](const auto &prefix) {
                           return begins_with(HandlerModulePlugin::asn->getASNString(&sa4), prefix);
                       })) {
                goto will_filter;
            }
        } else if (auto IPv6layer = payload.getLayerOfType<pcpp::IPv6Layer>(); IPv6layer) {
            struct sockaddr_in6 sa6;
            if (dir == PacketDirection::toHost && lib::utils::ipv6_to_sockaddr(IPv6layer->getSrcIPv6Address(), &sa6) && std::none_of(_f_asn_number.begin(), _f_asn_number.end(), [sa6](const auto &prefix) {
                    return begins_with(HandlerModulePlugin::asn->getASNString(&sa6), prefix);
                })) {
                goto will_filter;
            } else if (dir == PacketDirection::fromHost && lib::utils::ipv6_to_sockaddr(IPv6layer->getDstIPv6Address(), &sa6) && std::none_of(_f_asn_number.begin(), _f_asn_number.end(), [sa6](const auto &prefix) {
                           return begins_with(HandlerModulePlugin::asn->getASNString(&sa6), prefix);
                       })) {
                goto will_filter;
            }
        }
    }
    return false;
will_filter:
    _metrics->process_filtered(stamp);
    return true;
}

void NetworkMetricsBucket::specialized_merge(const AbstractMetricsBucket &o, Metric::Aggregate agg_operator)
{
    // static because caller guarantees only our own bucket type
    const auto &other = static_cast<const NetworkMetricsBucket &>(o);

    // generate transaction directions if they do not exist
    {
        std::unique_lock w_lock(_mutex);
        for (auto &net : other._net) {
            if (!_net.count(net.first)) {
                _net[net.first].update_topn_metrics(_topn_count, _topn_percentile_threshold);
            }
        }
    }

    // rates maintain their own thread safety
    if (group_enabled(group::NetMetrics::Quantiles)) {
        for (auto &net : other._net) {
            _net.at(net.first).rate.merge(net.second.rate, agg_operator);
            _net.at(net.first).throughput.merge(net.second.throughput, agg_operator);
        }
    }

    std::shared_lock r_lock(other._mutex);
    std::unique_lock w_lock(_mutex);

    group_enabled(group::NetMetrics::Counters) ? _filtered += other._filtered : void();

    for (auto &net : other._net) {
        group_enabled(group::NetMetrics::Counters) ? _net.at(net.first).counters += net.second.counters : void();

        group_enabled(group::NetMetrics::Cardinality) ? _net.at(net.first).ipCard.merge(net.second.ipCard) : void();

        if (group_enabled(group::NetMetrics::TopIps)) {
            _net.at(net.first).topIPv4.merge(net.second.topIPv4);
            _net.at(net.first).topIPv6.merge(net.second.topIPv6);
        }

        if (group_enabled(group::NetMetrics::TopGeo)) {
            _net.at(net.first).topGeoLoc.merge(net.second.topGeoLoc);
            _net.at(net.first).topASN.merge(net.second.topASN);
        }

        group_enabled(group::NetMetrics::Quantiles) ? _net.at(net.first).payload_size.merge(net.second.payload_size, agg_operator) : void();
    }
}

void NetworkMetricsBucket::to_prometheus(std::stringstream &out, Metric::LabelMap add_labels) const
{

    if (group_enabled(group::NetMetrics::Quantiles)) {
        for (auto &net : _net) {
            auto dir_labels = add_labels;
            dir_labels["direction"] = _dir_str.at(net.first);
            net.second.rate.to_prometheus(out, dir_labels);
            net.second.throughput.to_prometheus(out, dir_labels);
        }
    }

    {
        auto [num_events, num_samples, event_rate, event_lock] = event_data_locked(); // thread safe

        event_rate->to_prometheus(out, add_labels);
        num_events->to_prometheus(out, add_labels);
        num_samples->to_prometheus(out, add_labels);
    }

    std::shared_lock r_lock(_mutex);

    group_enabled(group::NetMetrics::Counters) ? _filtered.to_prometheus(out, add_labels) : void();

    for (auto &net : _net) {
        auto dir_labels = add_labels;
        dir_labels["direction"] = _dir_str.at(net.first);

        group_enabled(group::NetMetrics::Counters) ? net.second.counters.to_prometheus(out, dir_labels) : void();

        group_enabled(group::NetMetrics::Cardinality) ? net.second.ipCard.to_prometheus(out, dir_labels) : void();

        if (group_enabled(group::NetMetrics::TopIps)) {
            net.second.topIPv4.to_prometheus(out, dir_labels, [](const uint32_t &val) { return pcpp::IPv4Address(val).toString(); });
            net.second.topIPv6.to_prometheus(out, dir_labels);
        }

        if (group_enabled(group::NetMetrics::TopGeo)) {
            net.second.topGeoLoc.to_prometheus(out, dir_labels, [](Metric::LabelMap &l, const std::string &key, const visor::geo::City &val) {
                l[key] = val.location;
                if (!val.latitude.empty() && !val.longitude.empty()) {
                    l["lat"] = val.latitude;
                    l["lon"] = val.longitude;
                }
            });
            net.second.topASN.to_prometheus(out, dir_labels);
        }

        group_enabled(group::NetMetrics::Quantiles) ? net.second.payload_size.to_prometheus(out, dir_labels) : void();
    }
}

void NetworkMetricsBucket::to_opentelemetry(metrics::v1::ScopeMetrics &scope, timespec &start_ts, timespec &end_ts, Metric::LabelMap add_labels) const
{
    if (group_enabled(group::NetMetrics::Quantiles)) {
        for (auto &net : _net) {
            auto dir_labels = add_labels;
            dir_labels["direction"] = _dir_str.at(net.first);
            net.second.rate.to_opentelemetry(scope, start_ts, end_ts, dir_labels);
            net.second.throughput.to_opentelemetry(scope, start_ts, end_ts, dir_labels);
        }
    }

    {
        auto [num_events, num_samples, event_rate, event_lock] = event_data_locked(); // thread safe

        event_rate->to_opentelemetry(scope, start_ts, end_ts, add_labels);
        num_events->to_opentelemetry(scope, start_ts, end_ts, add_labels);
        num_samples->to_opentelemetry(scope, start_ts, end_ts, add_labels);
    }

    std::shared_lock r_lock(_mutex);

    group_enabled(group::NetMetrics::Counters) ? _filtered.to_opentelemetry(scope, start_ts, end_ts, add_labels) : void();

    for (auto &net : _net) {
        auto dir_labels = add_labels;
        dir_labels["direction"] = _dir_str.at(net.first);

        group_enabled(group::NetMetrics::Counters) ? net.second.counters.to_opentelemetry(scope, start_ts, end_ts, dir_labels) : void();

        group_enabled(group::NetMetrics::Cardinality) ? net.second.ipCard.to_opentelemetry(scope, start_ts, end_ts, dir_labels) : void();

        if (group_enabled(group::NetMetrics::TopIps)) {
            net.second.topIPv4.to_opentelemetry(scope, start_ts, end_ts, dir_labels, [](const uint32_t &val) { return pcpp::IPv4Address(val).toString(); });
            net.second.topIPv6.to_opentelemetry(scope, start_ts, end_ts, dir_labels);
        }

        if (group_enabled(group::NetMetrics::TopGeo)) {
            net.second.topGeoLoc.to_opentelemetry(scope, start_ts, end_ts, dir_labels, [](Metric::LabelMap &l, const std::string &key, const visor::geo::City &val) {
                l[key] = val.location;
                if (!val.latitude.empty() && !val.longitude.empty()) {
                    l["lat"] = val.latitude;
                    l["lon"] = val.longitude;
                }
            });
            net.second.topASN.to_opentelemetry(scope, start_ts, end_ts, dir_labels);
        }

        group_enabled(group::NetMetrics::Quantiles) ? net.second.payload_size.to_opentelemetry(scope, start_ts, end_ts, dir_labels) : void();
    }
}

void NetworkMetricsBucket::to_json(json &j) const
{

    // do rates first, which handle their own locking
    bool live_rates = !read_only() && !recorded_stream();
    if (group_enabled(group::NetMetrics::Quantiles)) {
        for (auto &net : _net) {
            net.second.rate.to_json(j[_dir_str.at(net.first)], live_rates);
            net.second.throughput.to_json(j[_dir_str.at(net.first)], live_rates);
        }
    }

    {
        auto [num_events, num_samples, event_rate, event_lock] = event_data_locked(); // thread safe

        event_rate->to_json(j, live_rates);
        num_events->to_json(j);
        num_samples->to_json(j);
    }

    std::shared_lock r_lock(_mutex);

    group_enabled(group::NetMetrics::Counters) ? _filtered.to_json(j) : void();

    for (auto &net : _net) {
        group_enabled(group::NetMetrics::Counters) ? net.second.counters.to_json(j[_dir_str.at(net.first)]) : void();

        group_enabled(group::NetMetrics::Cardinality) ? net.second.ipCard.to_json(j[_dir_str.at(net.first)]) : void();

        if (group_enabled(group::NetMetrics::TopIps)) {
            net.second.topIPv4.to_json(j[_dir_str.at(net.first)], [](const uint32_t &val) { return pcpp::IPv4Address(val).toString(); });
            net.second.topIPv6.to_json(j[_dir_str.at(net.first)]);
        }

        if (group_enabled(group::NetMetrics::TopGeo)) {
            net.second.topGeoLoc.to_json(j[_dir_str.at(net.first)], [](json &j, const std::string &key, const visor::geo::City &val) {
                j[key] = val.location;
                if (!val.latitude.empty() && !val.longitude.empty()) {
                    j["lat"] = val.latitude;
                    j["lon"] = val.longitude;
                }
            });
            net.second.topASN.to_json(j[_dir_str.at(net.first)]);
        }

        group_enabled(group::NetMetrics::Quantiles) ? net.second.payload_size.to_json(j[_dir_str.at(net.first)]) : void();
    }
}

// the main bucket analysis
void NetworkMetricsBucket::process_filtered()
{
    std::unique_lock lock(_mutex);
    if (group_enabled(group::NetMetrics::Counters)) {
        ++_filtered;
    }
}

void NetworkMetricsBucket::process_packet(bool deep, pcpp::Packet &payload, PacketDirection dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4)
{
    if (!deep) {
        process_net_layer(static_cast<NetworkPacketDirection>(dir), l3, l4, payload.getRawPacket()->getRawDataLen());
        return;
    }

    bool syn_flag = false;
    if (l4 == pcpp::TCP) {
        pcpp::TcpLayer *tcpLayer = payload.getLayerOfType<pcpp::TcpLayer>();
        if (tcpLayer) {
            syn_flag = tcpLayer->getTcpHeader()->synFlag;
        }
    }

    NetworkPacket packet(static_cast<NetworkPacketDirection>(dir), l3, l4, payload.getRawPacket()->getRawDataLen(), syn_flag);

    if (auto IP4layer = payload.getLayerOfType<pcpp::IPv4Layer>(); IP4layer) {
        if (dir == PacketDirection::toHost) {
            packet.ipv4_src = IP4layer->getSrcIPv4Address();
        } else if (dir == PacketDirection::fromHost) {
            packet.ipv4_dst = IP4layer->getDstIPv4Address();
        } else {
            packet.ipv4_src = IP4layer->getSrcIPv4Address();
            packet.ipv4_dst = IP4layer->getDstIPv4Address();
        }
    } else if (auto IP6layer = payload.getLayerOfType<pcpp::IPv6Layer>(); IP6layer) {
        if (dir == PacketDirection::toHost) {
            packet.ipv6_src = IP6layer->getSrcIPv6Address();
        } else if (dir == PacketDirection::fromHost) {
            packet.ipv6_dst = IP6layer->getDstIPv6Address();
        } else {
            packet.ipv6_src = IP6layer->getSrcIPv6Address();
            packet.ipv6_dst = IP6layer->getDstIPv6Address();
        }
    }

    process_net_layer(packet);
}
void NetworkMetricsBucket::process_dnstap(bool deep, const dnstap::Dnstap &payload, size_t size)
{
    pcpp::ProtocolType l3{pcpp::UnknownProtocol};
    if (payload.message().has_socket_family()) {
        if (payload.message().socket_family() == dnstap::INET6) {
            l3 = pcpp::IPv6;
        } else if (payload.message().socket_family() == dnstap::INET) {
            l3 = pcpp::IPv4;
        }
    }

    pcpp::ProtocolType l4{pcpp::UnknownProtocol};
    if (payload.message().has_socket_protocol()) {
        switch (payload.message().socket_protocol()) {
        case dnstap::UDP:
            l4 = pcpp::UDP;
            break;
        case dnstap::TCP:
            l4 = pcpp::TCP;
            break;
        case dnstap::DOT:
        case dnstap::DOH:
        case dnstap::DNSCryptUDP:
        case dnstap::DNSCryptTCP:
        case dnstap::DOQ:
            break;
        }
    }

    NetworkPacketDirection dir{NetworkPacketDirection::unknown};
    switch (payload.message().type()) {
    case dnstap::Message_Type_CLIENT_QUERY:
    case dnstap::Message_Type_STUB_RESPONSE:
    case dnstap::Message_Type_RESOLVER_RESPONSE:
    case dnstap::Message_Type_AUTH_QUERY:
    case dnstap::Message_Type_FORWARDER_RESPONSE:
    case dnstap::Message_Type_UPDATE_QUERY:
    case dnstap::Message_Type_TOOL_RESPONSE:
        dir = NetworkPacketDirection::in;
        break;
    case dnstap::Message_Type_STUB_QUERY:
    case dnstap::Message_Type_CLIENT_RESPONSE:
    case dnstap::Message_Type_RESOLVER_QUERY:
    case dnstap::Message_Type_AUTH_RESPONSE:
    case dnstap::Message_Type_FORWARDER_QUERY:
    case dnstap::Message_Type_UPDATE_RESPONSE:
    case dnstap::Message_Type_TOOL_QUERY:
        dir = NetworkPacketDirection::out;
        break;
    }

    if (!deep) {
        process_net_layer(dir, l3, l4, size);
        return;
    }
    NetworkPacket packet(dir, l3, l4, size, false);

    if (l3 == pcpp::IPv4 && payload.message().has_query_address() && payload.message().query_address().size() == 4) {
        packet.ipv4_src = pcpp::IPv4Address(reinterpret_cast<const uint8_t *>(payload.message().query_address().data()));
    } else if (l3 == pcpp::IPv6 && payload.message().has_query_address() && payload.message().query_address().size() == 16) {
        packet.ipv6_src = pcpp::IPv6Address(reinterpret_cast<const uint8_t *>(payload.message().query_address().data()));
    }

    if (l3 == pcpp::IPv4 && payload.message().has_response_address() && payload.message().response_address().size() == 4) {
        packet.ipv4_dst = pcpp::IPv4Address(reinterpret_cast<const uint8_t *>(payload.message().response_address().data()));
    } else if (l3 == pcpp::IPv6 && payload.message().has_response_address() && payload.message().response_address().size() == 16) {
        packet.ipv6_dst = pcpp::IPv6Address(reinterpret_cast<const uint8_t *>(payload.message().response_address().data()));
    }

    process_net_layer(packet);
}

void NetworkMetricsBucket::process_net_layer(NetworkPacketDirection dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4, size_t payload_size)
{
    std::unique_lock lock(_mutex);

    if (!_net.count(dir)) {
        _net[dir].update_topn_metrics(_topn_count, _topn_percentile_threshold);
    }

    auto &data = _net[dir];

    auto payload_size_bits = payload_size * sizeof(uint8_t);

    ++data.rate;
    data.throughput += payload_size_bits;

    if (group_enabled(group::NetMetrics::Counters)) {
        ++data.counters.total;

        switch (l3) {
        case pcpp::IPv6:
            ++data.counters.IPv6;
            break;
        case pcpp::IPv4:
            ++data.counters.IPv4;
            break;
        default:
            break;
        }

        switch (l4) {
        case pcpp::UDP:
            ++data.counters.UDP;
            break;
        case pcpp::TCP:
            ++data.counters.TCP;
            break;
        default:
            ++data.counters.OtherL4;
            break;
        }
    }

    data.payload_size.update(payload_size);
}

void NetworkMetricsBucket::process_net_layer(NetworkPacket &packet)
{
    std::unique_lock lock(_mutex);

    if (!_net.count(packet.dir)) {
        _net[packet.dir].update_topn_metrics(_topn_count, _topn_percentile_threshold);
    }

    auto &data = _net[packet.dir];

    auto payload_size_bits = packet.payload_size * sizeof(uint8_t);

    ++data.rate;
    data.throughput += payload_size_bits;

    if (group_enabled(group::NetMetrics::Counters)) {
        ++data.counters.total;

        switch (packet.l3) {
        case pcpp::IPv6:
            ++data.counters.IPv6;
            break;
        case pcpp::IPv4:
            ++data.counters.IPv4;
            break;
        default:
            break;
        }

        switch (packet.l4) {
        case pcpp::UDP:
            ++data.counters.UDP;
            break;
        case pcpp::TCP:
            ++data.counters.TCP;
            if (packet.syn_flag) {
                ++data.counters.TCP_SYN;
            }
            break;
        default:
            ++data.counters.OtherL4;
            break;
        }
    }

    data.payload_size.update(packet.payload_size);

    if (packet.l3 == pcpp::IPv4 && packet.ipv4_src != pcpp::IPv4Address::Zero) {
        group_enabled(group::NetMetrics::Cardinality) ? data.ipCard.update(packet.ipv4_src.toInt()) : void();
        group_enabled(group::NetMetrics::TopIps) ? data.topIPv4.update(packet.ipv4_src.toInt()) : void();
        _process_geo_metrics(data, packet.ipv4_src);
    } else if (packet.l3 == pcpp::IPv6 && packet.ipv6_src != pcpp::IPv6Address::Zero) {
        group_enabled(group::NetMetrics::Cardinality) ? data.ipCard.update(reinterpret_cast<const void *>(packet.ipv6_src.toBytes()), 16) : void();
        group_enabled(group::NetMetrics::TopIps) ? data.topIPv6.update(packet.ipv6_src.toString()) : void();
        _process_geo_metrics(data, packet.ipv6_src);
    }

    if (packet.l3 == pcpp::IPv4 && packet.ipv4_dst != pcpp::IPv4Address::Zero) {
        group_enabled(group::NetMetrics::Cardinality) ? data.ipCard.update(packet.ipv4_dst.toInt()) : void();
        group_enabled(group::NetMetrics::TopIps) ? data.topIPv4.update(packet.ipv4_dst.toInt()) : void();
        _process_geo_metrics(data, packet.ipv4_dst);
    } else if (packet.l3 == pcpp::IPv6 && packet.ipv6_dst != pcpp::IPv6Address::Zero) {
        group_enabled(group::NetMetrics::Cardinality) ? data.ipCard.update(reinterpret_cast<const void *>(packet.ipv6_dst.toBytes()), 16) : void();
        group_enabled(group::NetMetrics::TopIps) ? data.topIPv6.update(packet.ipv6_dst.toString()) : void();
        _process_geo_metrics(data, packet.ipv6_dst);
    }
}

inline void NetworkMetricsBucket::_process_geo_metrics(NetworkDirection &net, const pcpp::IPv4Address &ipv4)
{
    if ((HandlerModulePlugin::asn->enabled() || HandlerModulePlugin::city->enabled()) && group_enabled(group::NetMetrics::TopGeo)) {
        sockaddr_in sa4{};
        if (lib::utils::ipv4_to_sockaddr(ipv4, &sa4)) {
            if (HandlerModulePlugin::city->enabled()) {
                net.topGeoLoc.update(HandlerModulePlugin::city->getGeoLoc(&sa4));
            }
            if (HandlerModulePlugin::asn->enabled()) {
                net.topASN.update(HandlerModulePlugin::asn->getASNString(&sa4));
            }
        }
    }
}

inline void NetworkMetricsBucket::_process_geo_metrics(NetworkDirection &net, const pcpp::IPv6Address &ipv6)
{
    if ((HandlerModulePlugin::asn->enabled() || HandlerModulePlugin::city->enabled()) && group_enabled(group::NetMetrics::TopGeo)) {
        sockaddr_in6 sa6{};
        if (lib::utils::ipv6_to_sockaddr(ipv6, &sa6)) {
            if (HandlerModulePlugin::city->enabled()) {
                net.topGeoLoc.update(HandlerModulePlugin::city->getGeoLoc(&sa6));
            }
            if (HandlerModulePlugin::asn->enabled()) {
                net.topASN.update(HandlerModulePlugin::asn->getASNString(&sa6));
            }
        }
    }
}

void NetworkMetricsManager::process_filtered(timespec stamp)
{
    // base event, no sample
    new_event(stamp, false);
    live_bucket()->process_filtered();
}

// the general metrics manager entry point
void NetworkMetricsManager::process_packet(pcpp::Packet &payload, PacketDirection dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4, timespec stamp)
{
    // base event
    new_event(stamp);
    // process in the "live" bucket
    live_bucket()->process_packet(_deep_sampling_now, payload, dir, l3, l4);
}

void NetworkMetricsManager::process_dnstap(const dnstap::Dnstap &payload, size_t size)
{
    // dnstap message type
    auto mtype = payload.message().type();
    // set proper timestamp. use dnstap version if available, otherwise "now"
    timespec stamp;
    switch (mtype) {
    case dnstap::Message_Type_CLIENT_RESPONSE:
    case dnstap::Message_Type_AUTH_RESPONSE:
    case dnstap::Message_Type_RESOLVER_RESPONSE:
        if (payload.message().has_response_time_sec()) {
            stamp.tv_sec = payload.message().response_time_sec();
            stamp.tv_nsec = payload.message().response_time_nsec();
        }
        break;
    case dnstap::Message_Type_CLIENT_QUERY:
    case dnstap::Message_Type_AUTH_QUERY:
    case dnstap::Message_Type_RESOLVER_QUERY:
        if (payload.message().has_query_time_sec()) {
            stamp.tv_sec = payload.message().query_time_sec();
            stamp.tv_nsec = payload.message().query_time_nsec();
        }
        break;
    default:
        // use now()
        std::timespec_get(&stamp, TIME_UTC);
    }
    // base event
    new_event(stamp);
    // process in the "live" bucket. this will parse the resources if we are deep sampling
    live_bucket()->process_dnstap(_deep_sampling_now, payload, size);
}

}
