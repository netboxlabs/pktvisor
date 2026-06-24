/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "NetStreamHandler.h"
#include "PrometheusSerializer.h"
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

namespace visor::handler::net {

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

    // rates maintain their own thread safety
    _rate_in.merge(other._rate_in, agg_operator);
    _rate_out.merge(other._rate_out, agg_operator);
    _rate_total.merge(other._rate_total, agg_operator);
    _throughput_in.merge(other._throughput_in, agg_operator);
    _throughput_out.merge(other._throughput_out, agg_operator);
    _throughput_total.merge(other._throughput_total, agg_operator);

    std::shared_lock r_lock(other._mutex);
    std::unique_lock w_lock(_mutex);

    if (group_enabled(group::NetMetrics::Counters)) {
        _counters.UDP += other._counters.UDP;
        _counters.TCP += other._counters.TCP;
        _counters.TCP_SYN += other._counters.TCP_SYN;
        _counters.OtherL4 += other._counters.OtherL4;
        _counters.IPv4 += other._counters.IPv4;
        _counters.IPv6 += other._counters.IPv6;
        _counters.total_in += other._counters.total_in;
        _counters.total_out += other._counters.total_out;
        _counters.total_unk += other._counters.total_unk;
        _counters.total += other._counters.total;
        _counters.filtered += other._counters.filtered;
    }

    if (group_enabled(group::NetMetrics::Cardinality)) {
        _srcIPCard.merge(other._srcIPCard);
        _dstIPCard.merge(other._dstIPCard);
    }

    if (group_enabled(group::NetMetrics::TopIps)) {
        _topIPv4.merge(other._topIPv4);
        _topIPv6.merge(other._topIPv6);
    }
    if (group_enabled(group::NetMetrics::TopGeo)) {
        _topGeoLoc.merge(other._topGeoLoc);
        _topASN.merge(other._topASN);
    }

    _payload_size.merge(other._payload_size, agg_operator);
}

void NetworkMetricsBucket::to_prometheus(PrometheusSerializer &ser, Metric::LabelMap add_labels) const
{

    _rate_in.to_prometheus(ser, add_labels);
    _rate_out.to_prometheus(ser, add_labels);
    _rate_total.to_prometheus(ser, add_labels);
    _throughput_in.to_prometheus(ser, add_labels);
    _throughput_out.to_prometheus(ser, add_labels);
    _throughput_total.to_prometheus(ser, add_labels);

    {
        auto [num_events, num_samples, event_rate, event_lock] = event_data_locked(); // thread safe

        event_rate->to_prometheus(ser, add_labels);
        num_events->to_prometheus(ser, add_labels);
        num_samples->to_prometheus(ser, add_labels);
    }

    std::shared_lock r_lock(_mutex);

    if (group_enabled(group::NetMetrics::Counters)) {
        _counters.UDP.to_prometheus(ser, add_labels);
        _counters.TCP.to_prometheus(ser, add_labels);
        _counters.TCP_SYN.to_prometheus(ser, add_labels);
        _counters.OtherL4.to_prometheus(ser, add_labels);
        _counters.IPv4.to_prometheus(ser, add_labels);
        _counters.IPv6.to_prometheus(ser, add_labels);
        _counters.total_in.to_prometheus(ser, add_labels);
        _counters.total_out.to_prometheus(ser, add_labels);
        _counters.total_unk.to_prometheus(ser, add_labels);
        _counters.total.to_prometheus(ser, add_labels);
        _counters.filtered.to_prometheus(ser, add_labels);
    }

    if (group_enabled(group::NetMetrics::Cardinality)) {
        _srcIPCard.to_prometheus(ser, add_labels);
        _dstIPCard.to_prometheus(ser, add_labels);
    }

    if (group_enabled(group::NetMetrics::TopIps)) {
        _topIPv4.to_prometheus(ser, add_labels, [](const uint32_t &val) { return pcpp::IPv4Address(val).toString(); });
        _topIPv6.to_prometheus(ser, add_labels);
    }

    if (group_enabled(group::NetMetrics::TopGeo)) {
        _topGeoLoc.to_prometheus(ser, add_labels, [](Metric::LabelMap &l, const std::string &key, const visor::geo::City &val) {
            l[key] = val.location;
            if (!val.latitude.empty() && !val.longitude.empty()) {
                l["lat"] = val.latitude;
                l["lon"] = val.longitude;
            }
        });
        _topASN.to_prometheus(ser, add_labels);
    }

    _payload_size.to_prometheus(ser, add_labels);
}

void NetworkMetricsBucket::to_opentelemetry(metrics::v1::ScopeMetrics &scope, timespec &start_ts, timespec &end_ts, Metric::LabelMap add_labels) const
{
    _rate_in.to_opentelemetry(scope, start_ts, end_ts, add_labels);
    _rate_out.to_opentelemetry(scope, start_ts, end_ts, add_labels);
    _rate_total.to_opentelemetry(scope, start_ts, end_ts, add_labels);
    _throughput_in.to_opentelemetry(scope, start_ts, end_ts, add_labels);
    _throughput_out.to_opentelemetry(scope, start_ts, end_ts, add_labels);
    _throughput_total.to_opentelemetry(scope, start_ts, end_ts, add_labels);

    {
        auto [num_events, num_samples, event_rate, event_lock] = event_data_locked(); // thread safe

        event_rate->to_opentelemetry(scope, start_ts, end_ts, add_labels);
        num_events->to_opentelemetry(scope, start_ts, end_ts, add_labels);
        num_samples->to_opentelemetry(scope, start_ts, end_ts, add_labels);
    }

    std::shared_lock r_lock(_mutex);

    if (group_enabled(group::NetMetrics::Counters)) {
        _counters.UDP.to_opentelemetry(scope, start_ts, end_ts, add_labels);
        _counters.TCP.to_opentelemetry(scope, start_ts, end_ts, add_labels);
        _counters.TCP_SYN.to_opentelemetry(scope, start_ts, end_ts, add_labels);
        _counters.OtherL4.to_opentelemetry(scope, start_ts, end_ts, add_labels);
        _counters.IPv4.to_opentelemetry(scope, start_ts, end_ts, add_labels);
        _counters.IPv6.to_opentelemetry(scope, start_ts, end_ts, add_labels);
        _counters.total_in.to_opentelemetry(scope, start_ts, end_ts, add_labels);
        _counters.total_out.to_opentelemetry(scope, start_ts, end_ts, add_labels);
        _counters.total_unk.to_opentelemetry(scope, start_ts, end_ts, add_labels);
        _counters.total.to_opentelemetry(scope, start_ts, end_ts, add_labels);
        _counters.filtered.to_opentelemetry(scope, start_ts, end_ts, add_labels);
    }

    if (group_enabled(group::NetMetrics::Cardinality)) {
        _srcIPCard.to_opentelemetry(scope, start_ts, end_ts, add_labels);
        _dstIPCard.to_opentelemetry(scope, start_ts, end_ts, add_labels);
    }

    if (group_enabled(group::NetMetrics::TopIps)) {
        _topIPv4.to_opentelemetry(scope, start_ts, end_ts, add_labels, [](const uint32_t &val) { return pcpp::IPv4Address(val).toString(); });
        _topIPv6.to_opentelemetry(scope, start_ts, end_ts, add_labels);
    }

    if (group_enabled(group::NetMetrics::TopGeo)) {
        _topGeoLoc.to_opentelemetry(scope, start_ts, end_ts, add_labels, [](Metric::LabelMap &l, const std::string &key, const visor::geo::City &val) {
            l[key] = val.location;
            if (!val.latitude.empty() && !val.longitude.empty()) {
                l["lat"] = val.latitude;
                l["lon"] = val.longitude;
            }
        });
        _topASN.to_opentelemetry(scope, start_ts, end_ts, add_labels);
    }

    _payload_size.to_opentelemetry(scope, start_ts, end_ts, add_labels);
}

void NetworkMetricsBucket::to_json(json &j) const
{

    // do rates first, which handle their own locking
    bool live_rates = !read_only() && !recorded_stream();
    _rate_in.to_json(j, live_rates);
    _rate_out.to_json(j, live_rates);
    _rate_total.to_json(j, live_rates);
    _throughput_in.to_json(j, live_rates);
    _throughput_out.to_json(j, live_rates);
    _throughput_total.to_json(j, live_rates);

    {
        auto [num_events, num_samples, event_rate, event_lock] = event_data_locked(); // thread safe

        event_rate->to_json(j, live_rates);
        num_events->to_json(j);
        num_samples->to_json(j);
    }

    std::shared_lock r_lock(_mutex);

    if (group_enabled(group::NetMetrics::Counters)) {
        _counters.UDP.to_json(j);
        _counters.TCP.to_json(j);
        _counters.TCP_SYN.to_json(j);
        _counters.OtherL4.to_json(j);
        _counters.IPv4.to_json(j);
        _counters.IPv6.to_json(j);
        _counters.total_in.to_json(j);
        _counters.total_out.to_json(j);
        _counters.total_unk.to_json(j);
        _counters.total.to_json(j);
        _counters.filtered.to_json(j);
    }

    if (group_enabled(group::NetMetrics::Cardinality)) {
        _srcIPCard.to_json(j);
        _dstIPCard.to_json(j);
    }

    if (group_enabled(group::NetMetrics::TopIps)) {
        _topIPv4.to_json(j, [](const uint32_t &val) { return pcpp::IPv4Address(val).toString(); });
        _topIPv6.to_json(j);
    }

    if (group_enabled(group::NetMetrics::TopGeo)) {
        _topGeoLoc.to_json(j, [](json &j, const std::string &key, const visor::geo::City &val) {
            j[key] = val.location;
            if (!val.latitude.empty() && !val.longitude.empty()) {
                j["lat"] = val.latitude;
                j["lon"] = val.longitude;
            }
        });
        _topASN.to_json(j);
    }

    _payload_size.to_json(j);
}

// the main bucket analysis
void NetworkMetricsBucket::process_filtered()
{
    std::unique_lock lock(_mutex);
    if (group_enabled(group::NetMetrics::Counters)) {
        ++_counters.filtered;
    }
}

void NetworkMetricsBucket::process_packet(bool deep, pcpp::Packet &payload, PacketDirection dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4)
{
    if (!deep) {
        process_net_layer(dir, l3, l4, payload.getRawPacket()->getRawDataLen());
        return;
    }

    bool syn_flag = false;
    if (l4 == pcpp::TCP) {
        pcpp::TcpLayer *tcpLayer = payload.getLayerOfType<pcpp::TcpLayer>();
        if (tcpLayer) {
            syn_flag = tcpLayer->getTcpHeader()->synFlag;
        }
    }

    NetworkPacket packet(dir, l3, l4, payload.getRawPacket()->getRawDataLen(), syn_flag);

    if (auto IP4layer = payload.getLayerOfType<pcpp::IPv4Layer>(); IP4layer) {
        if (dir == PacketDirection::toHost) {
            packet.ipv4_in = IP4layer->getSrcIPv4Address();
        } else if (dir == PacketDirection::fromHost) {
            packet.ipv4_out = IP4layer->getDstIPv4Address();
        }
    } else if (auto IP6layer = payload.getLayerOfType<pcpp::IPv6Layer>(); IP6layer) {
        if (dir == PacketDirection::toHost) {
            packet.ipv6_in = IP6layer->getSrcIPv6Address();
        } else if (dir == PacketDirection::fromHost) {
            packet.ipv6_out = IP6layer->getDstIPv6Address();
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

    PacketDirection dir{PacketDirection::unknown};
    switch (payload.message().type()) {
    case dnstap::Message_Type_CLIENT_QUERY:
    case dnstap::Message_Type_STUB_RESPONSE:
    case dnstap::Message_Type_RESOLVER_RESPONSE:
    case dnstap::Message_Type_AUTH_QUERY:
    case dnstap::Message_Type_FORWARDER_RESPONSE:
    case dnstap::Message_Type_UPDATE_QUERY:
    case dnstap::Message_Type_TOOL_RESPONSE:
        dir = PacketDirection::toHost;
        break;
    case dnstap::Message_Type_STUB_QUERY:
    case dnstap::Message_Type_CLIENT_RESPONSE:
    case dnstap::Message_Type_RESOLVER_QUERY:
    case dnstap::Message_Type_AUTH_RESPONSE:
    case dnstap::Message_Type_FORWARDER_QUERY:
    case dnstap::Message_Type_UPDATE_RESPONSE:
    case dnstap::Message_Type_TOOL_QUERY:
        dir = PacketDirection::fromHost;
        break;
    }

    if (!deep) {
        process_net_layer(dir, l3, l4, size);
        return;
    }
    NetworkPacket packet(dir, l3, l4, size, false);

    if (l3 == pcpp::IPv4 && payload.message().has_query_address() && payload.message().query_address().size() == 4) {
        packet.ipv4_in = pcpp::IPv4Address(reinterpret_cast<const uint8_t *>(payload.message().query_address().data()));
    } else if (l3 == pcpp::IPv6 && payload.message().has_query_address() && payload.message().query_address().size() == 16) {
        packet.ipv6_in = pcpp::IPv6Address(reinterpret_cast<const uint8_t *>(payload.message().query_address().data()));
    }

    if (l3 == pcpp::IPv4 && payload.message().has_response_address() && payload.message().response_address().size() == 4) {
        packet.ipv4_out = pcpp::IPv4Address(reinterpret_cast<const uint8_t *>(payload.message().response_address().data()));
    } else if (l3 == pcpp::IPv6 && payload.message().has_response_address() && payload.message().response_address().size() == 16) {
        packet.ipv6_out = pcpp::IPv6Address(reinterpret_cast<const uint8_t *>(payload.message().response_address().data()));
    }

    process_net_layer(packet);
}

void NetworkMetricsBucket::process_net_layer(PacketDirection dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4, size_t payload_size)
{
    std::unique_lock lock(_mutex);

    switch (dir) {
    case PacketDirection::fromHost:
        ++_rate_out;
        _throughput_out += payload_size;
        break;
    case PacketDirection::toHost:
        ++_rate_in;
        _throughput_in += payload_size;
        break;
    case PacketDirection::unknown:
        break;
    }
    ++_rate_total;
    _throughput_total += payload_size;

    if (group_enabled(group::NetMetrics::Counters)) {
        ++_counters.total;

        switch (dir) {
        case PacketDirection::fromHost:
            ++_counters.total_out;
            break;
        case PacketDirection::toHost:
            ++_counters.total_in;
            break;
        case PacketDirection::unknown:
            ++_counters.total_unk;
            break;
        }

        switch (l3) {
        case pcpp::IPv6:
            ++_counters.IPv6;
            break;
        case pcpp::IPv4:
            ++_counters.IPv4;
            break;
        default:
            break;
        }

        switch (l4) {
        case pcpp::UDP:
            ++_counters.UDP;
            break;
        case pcpp::TCP:
            ++_counters.TCP;
            break;
        default:
            ++_counters.OtherL4;
            break;
        }
    }

    _payload_size.update(payload_size);
}

void NetworkMetricsBucket::process_net_layer(NetworkPacket &packet)
{
    std::unique_lock lock(_mutex);

    switch (packet.dir) {
    case PacketDirection::fromHost:
        ++_rate_out;
        _throughput_out += packet.payload_size;
        break;
    case PacketDirection::toHost:
        ++_rate_in;
        _throughput_in += packet.payload_size;
        break;
    case PacketDirection::unknown:
        break;
    }
    ++_rate_total;
    _throughput_total += packet.payload_size;

    if (group_enabled(group::NetMetrics::Counters)) {
        ++_counters.total;

        switch (packet.dir) {
        case PacketDirection::fromHost:
            ++_counters.total_out;
            break;
        case PacketDirection::toHost:
            ++_counters.total_in;
            break;
        case PacketDirection::unknown:
            ++_counters.total_unk;
            break;
        }

        switch (packet.l3) {
        case pcpp::IPv6:
            ++_counters.IPv6;
            break;
        case pcpp::IPv4:
            ++_counters.IPv4;
            break;
        default:
            break;
        }

        switch (packet.l4) {
        case pcpp::UDP:
            ++_counters.UDP;
            break;
        case pcpp::TCP:
            ++_counters.TCP;
            if (packet.syn_flag) {
                ++_counters.TCP_SYN;
            }
            break;
        default:
            ++_counters.OtherL4;
            break;
        }
    }

    _payload_size.update(packet.payload_size);

    if (packet.l3 == pcpp::IPv4 && packet.ipv4_in != pcpp::IPv4Address::Zero) {
        group_enabled(group::NetMetrics::Cardinality) ? _srcIPCard.update(packet.ipv4_in.toInt()) : void();
        group_enabled(group::NetMetrics::TopIps) ? _topIPv4.update(packet.ipv4_in.toInt()) : void();
        _process_geo_metrics(packet.ipv4_in);
    } else if (packet.l3 == pcpp::IPv6 && packet.ipv6_in != pcpp::IPv6Address::Zero) {
        group_enabled(group::NetMetrics::Cardinality) ? _srcIPCard.update(reinterpret_cast<const void *>(packet.ipv6_in.toBytes()), 16) : void();
        group_enabled(group::NetMetrics::TopIps) ? _topIPv6.update(packet.ipv6_in.toString()) : void();
        _process_geo_metrics(packet.ipv6_in);
    }

    if (packet.l3 == pcpp::IPv4 && packet.ipv4_out != pcpp::IPv4Address::Zero) {
        group_enabled(group::NetMetrics::Cardinality) ? _dstIPCard.update(packet.ipv4_out.toInt()) : void();
        group_enabled(group::NetMetrics::TopIps) ? _topIPv4.update(packet.ipv4_out.toInt()) : void();
        _process_geo_metrics(packet.ipv4_out);
    } else if (packet.l3 == pcpp::IPv6 && packet.ipv6_out != pcpp::IPv6Address::Zero) {
        group_enabled(group::NetMetrics::Cardinality) ? _dstIPCard.update(reinterpret_cast<const void *>(packet.ipv6_out.toBytes()), 16) : void();
        group_enabled(group::NetMetrics::TopIps) ? _topIPv6.update(packet.ipv6_out.toString()) : void();
        _process_geo_metrics(packet.ipv6_out);
    }
}

inline void NetworkMetricsBucket::_process_geo_metrics(const pcpp::IPv4Address &ipv4)
{
    if ((HandlerModulePlugin::asn->enabled() || HandlerModulePlugin::city->enabled()) && group_enabled(group::NetMetrics::TopGeo)) {
        sockaddr_in sa4{};
        if (lib::utils::ipv4_to_sockaddr(ipv4, &sa4)) {
            if (HandlerModulePlugin::city->enabled()) {
                _topGeoLoc.update(HandlerModulePlugin::city->getGeoLoc(&sa4));
            }
            if (HandlerModulePlugin::asn->enabled()) {
                _topASN.update(HandlerModulePlugin::asn->getASNString(&sa4));
            }
        }
    }
}

inline void NetworkMetricsBucket::_process_geo_metrics(const pcpp::IPv6Address &ipv6)
{
    if ((HandlerModulePlugin::asn->enabled() || HandlerModulePlugin::city->enabled()) && group_enabled(group::NetMetrics::TopGeo)) {
        sockaddr_in6 sa6{};
        if (lib::utils::ipv6_to_sockaddr(ipv6, &sa6)) {
            if (HandlerModulePlugin::city->enabled()) {
                _topGeoLoc.update(HandlerModulePlugin::city->getGeoLoc(&sa6));
            }
            if (HandlerModulePlugin::asn->enabled()) {
                _topASN.update(HandlerModulePlugin::asn->getASNString(&sa6));
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
