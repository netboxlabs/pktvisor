/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "DhcpStreamHandler.h"
#include "PrometheusSerializer.h"

namespace visor::handler::dhcp {

DhcpStreamHandler::DhcpStreamHandler(const std::string &name, InputEventProxy *proxy, const Configurable *window_config)
    : visor::StreamMetricsHandler<DhcpMetricsManager>(name, window_config)
{
    assert(proxy);
    // figure out which input event proxy we have
    _pcap_proxy = dynamic_cast<PcapInputEventProxy *>(proxy);
    if (!_pcap_proxy) {
        throw StreamHandlerException(fmt::format("DhcpStreamHandler: unsupported input event proxy {}", proxy->name()));
    }
}

// callback from input module
void DhcpStreamHandler::process_udp_packet_cb(pcpp::Packet &payload, [[maybe_unused]] PacketDirection dir, [[maybe_unused]] pcpp::ProtocolType l3, [[maybe_unused]] uint32_t flowkey, timespec stamp)
{
    pcpp::UdpLayer *udpLayer = payload.getLayerOfType<pcpp::UdpLayer>();
    assert(udpLayer);

    auto dst_port = ntohs(udpLayer->getUdpHeader()->portDst);
    auto src_port = ntohs(udpLayer->getUdpHeader()->portSrc);
    if (dst_port == 67 || src_port == 67 || dst_port == 68 || src_port == 68) {
        pcpp::DhcpLayer dhcpLayer(udpLayer->getLayerPayload(), udpLayer->getLayerPayloadSize(), udpLayer, &payload);
        if (!_filtering(&dhcpLayer, stamp)) {
            _metrics->process_dhcp_layer(&dhcpLayer, &payload, stamp);
        }
    } else if (dst_port == 546 || src_port == 546 || dst_port == 547 || src_port == 547) {
        pcpp::DhcpV6Layer dhcpLayer(udpLayer->getLayerPayload(), udpLayer->getLayerPayloadSize(), udpLayer, &payload);
        if (!_filtering_v6(&dhcpLayer, stamp)) {
            _metrics->process_dhcp_v6_layer(&dhcpLayer, &payload, stamp);
        }
    }
}

void DhcpStreamHandler::start()
{
    if (_running) {
        return;
    }

    validate_configs(_config_defs);

    if (config_exists("recorded_stream")) {
        _metrics->set_recorded_stream();
    }

    if (config_exists("xact_ttl_ms")) {
        auto ttl = config_get<uint64_t>("xact_ttl_ms");
        _metrics->set_xact_ttl(static_cast<uint32_t>(ttl));
    } else if (config_exists("xact_ttl_secs")) {
        auto ttl = config_get<uint64_t>("xact_ttl_secs");
        _metrics->set_xact_ttl(static_cast<uint32_t>(ttl) * 1000);
    }

    if (_pcap_proxy) {
        _pkt_udp_connection = _pcap_proxy->udp_signal.connect(&DhcpStreamHandler::process_udp_packet_cb, this);
        _start_tstamp_connection = _pcap_proxy->start_tstamp_signal.connect(&DhcpStreamHandler::set_start_tstamp, this);
        _end_tstamp_connection = _pcap_proxy->end_tstamp_signal.connect(&DhcpStreamHandler::set_end_tstamp, this);
        _heartbeat_connection = _pcap_proxy->heartbeat_signal.connect(&DhcpStreamHandler::check_period_shift, this);
    }

    _running = true;
}

void DhcpStreamHandler::stop()
{
    if (!_running) {
        return;
    }

    if (_pcap_proxy) {
        _pkt_udp_connection.disconnect();
        _start_tstamp_connection.disconnect();
        _end_tstamp_connection.disconnect();
        _heartbeat_connection.disconnect();
    }

    _running = false;
}

// callback from input module
void DhcpStreamHandler::set_start_tstamp(timespec stamp)
{
    _metrics->set_start_tstamp(stamp);
}
void DhcpStreamHandler::set_end_tstamp(timespec stamp)
{
    _metrics->set_end_tstamp(stamp);
}

void DhcpMetricsBucket::specialized_merge(const AbstractMetricsBucket &o, Metric::Aggregate agg_operator)
{
    // static because caller guarantees only our own bucket type
    const auto &other = static_cast<const DhcpMetricsBucket &>(o);

    // rates maintain their own thread safety
    _rate_total.merge(other._rate_total, agg_operator);

    std::shared_lock r_lock(other._mutex);
    std::unique_lock w_lock(_mutex);

    _counters.DISCOVER += other._counters.DISCOVER;
    _counters.OFFER += other._counters.OFFER;
    _counters.REQUEST += other._counters.REQUEST;
    _counters.ACK += other._counters.ACK;
    _counters.SOLICIT += other._counters.SOLICIT;
    _counters.ADVERTISE += other._counters.ADVERTISE;
    _counters.REQUESTV6 += other._counters.REQUESTV6;
    _counters.REPLY += other._counters.REPLY;
    _counters.total += other._counters.total;
    _counters.filtered += other._counters.filtered;

    _dhcp_topClients.merge(other._dhcp_topClients);
    _dhcp_topServers.merge(other._dhcp_topServers);
}

void DhcpMetricsBucket::to_prometheus(PrometheusSerializer &ser, Metric::LabelMap add_labels) const
{

    _rate_total.to_prometheus(ser, add_labels);

    {
        auto [num_events, num_samples, event_rate, event_lock] = event_data_locked(); // thread safe

        event_rate->to_prometheus(ser, add_labels);
        num_events->to_prometheus(ser, add_labels);
        num_samples->to_prometheus(ser, add_labels);
    }

    std::shared_lock r_lock(_mutex);

    _counters.DISCOVER.to_prometheus(ser, add_labels);
    _counters.OFFER.to_prometheus(ser, add_labels);
    _counters.REQUEST.to_prometheus(ser, add_labels);
    _counters.ACK.to_prometheus(ser, add_labels);
    _counters.SOLICIT.to_prometheus(ser, add_labels);
    _counters.ADVERTISE.to_prometheus(ser, add_labels);
    _counters.REQUESTV6.to_prometheus(ser, add_labels);
    _counters.REPLY.to_prometheus(ser, add_labels);
    _counters.total.to_prometheus(ser, add_labels);
    _counters.filtered.to_prometheus(ser, add_labels);

    _dhcp_topClients.to_prometheus(ser, add_labels);
    _dhcp_topServers.to_prometheus(ser, add_labels);
}

void DhcpMetricsBucket::to_opentelemetry(metrics::v1::ScopeMetrics &scope, timespec &start_ts, timespec &end_ts, Metric::LabelMap add_labels) const
{
    _rate_total.to_opentelemetry(scope, start_ts, end_ts, add_labels);

    {
        auto [num_events, num_samples, event_rate, event_lock] = event_data_locked(); // thread safe

        event_rate->to_opentelemetry(scope, start_ts, end_ts, add_labels);
        num_events->to_opentelemetry(scope, start_ts, end_ts, add_labels);
        num_samples->to_opentelemetry(scope, start_ts, end_ts, add_labels);
    }

    std::shared_lock r_lock(_mutex);

    _counters.DISCOVER.to_opentelemetry(scope, start_ts, end_ts, add_labels);
    _counters.OFFER.to_opentelemetry(scope, start_ts, end_ts, add_labels);
    _counters.REQUEST.to_opentelemetry(scope, start_ts, end_ts, add_labels);
    _counters.ACK.to_opentelemetry(scope, start_ts, end_ts, add_labels);
    _counters.SOLICIT.to_opentelemetry(scope, start_ts, end_ts, add_labels);
    _counters.ADVERTISE.to_opentelemetry(scope, start_ts, end_ts, add_labels);
    _counters.REQUESTV6.to_opentelemetry(scope, start_ts, end_ts, add_labels);
    _counters.REPLY.to_opentelemetry(scope, start_ts, end_ts, add_labels);
    _counters.total.to_opentelemetry(scope, start_ts, end_ts, add_labels);
    _counters.filtered.to_opentelemetry(scope, start_ts, end_ts, add_labels);

    _dhcp_topClients.to_opentelemetry(scope, start_ts, end_ts, add_labels);
    _dhcp_topServers.to_opentelemetry(scope, start_ts, end_ts, add_labels);
}

void DhcpMetricsBucket::to_json(json &j) const
{

    bool live_rates = !read_only() && !recorded_stream();
    _rate_total.to_json(j, live_rates);

    {
        auto [num_events, num_samples, event_rate, event_lock] = event_data_locked(); // thread safe

        event_rate->to_json(j, live_rates);
        num_events->to_json(j);
        num_samples->to_json(j);
    }

    std::shared_lock r_lock(_mutex);

    _counters.DISCOVER.to_json(j);
    _counters.OFFER.to_json(j);
    _counters.REQUEST.to_json(j);
    _counters.ACK.to_json(j);
    _counters.SOLICIT.to_json(j);
    _counters.ADVERTISE.to_json(j);
    _counters.REQUESTV6.to_json(j);
    _counters.REPLY.to_json(j);
    _counters.total.to_json(j);
    _counters.filtered.to_json(j);

    _dhcp_topClients.to_json(j);
    _dhcp_topServers.to_json(j);
}

void DhcpMetricsBucket::process_filtered()
{
    std::unique_lock lock(_mutex);
    ++_counters.filtered;
}

bool DhcpStreamHandler::_filtering([[maybe_unused]] pcpp::DhcpLayer *payload, [[maybe_unused]] timespec stamp)
{
    // no filters yet
    return false;
}

bool DhcpStreamHandler::_filtering_v6([[maybe_unused]] pcpp::DhcpV6Layer *payload, [[maybe_unused]] timespec stamp)
{
    // no filters yet
    return false;
}

void DhcpMetricsBucket::process_dhcp_layer(bool deep, pcpp::DhcpLayer *dhcp, pcpp::Packet *payload)
{
    std::unique_lock lock(_mutex);

    ++_counters.total;
    ++_rate_total;

    auto type = dhcp->getMessageType();
    switch (type) {
    case pcpp::DHCP_DISCOVER:
        ++_counters.DISCOVER;
        break;
    case pcpp::DHCP_OFFER:
        ++_counters.OFFER;
        break;
    case pcpp::DHCP_REQUEST:
        ++_counters.REQUEST;
        break;
    case pcpp::DHCP_ACK:
        ++_counters.ACK;
        break;
    default:
        break;
    }

    if (!deep) {
        return;
    }

    if (type == pcpp::DHCP_OFFER) {
        pcpp::EthLayer *ethLayer = payload->getLayerOfType<pcpp::EthLayer>();
        if (auto option = dhcp->getOptionData(pcpp::DHCPOPT_DHCP_SERVER_IDENTIFIER); option.isNotNull() && ethLayer) {
            _dhcp_topServers.update(ethLayer->getSourceMac().toString() + "/" + option.getValueAsIpAddr().toString());
        }
    }
}
void DhcpMetricsBucket::new_dhcp_transaction(bool deep, pcpp::DhcpLayer *payload, DhcpTransaction &xact)
{
    if (!deep) {
        return;
    }
    // lock for write
    std::unique_lock lock(_mutex);

    if (auto client_ip = payload->getYourIpAddress(); client_ip != pcpp::IPv4Address::Zero) {
        _dhcp_topClients.update(xact.mac_address + "/" + xact.hostname + "/" + client_ip.toString());
    }
}

void DhcpMetricsBucket::process_dhcp_v6_layer(bool deep, pcpp::DhcpV6Layer *dhcp, pcpp::Packet *payload)
{
    auto type = dhcp->getMessageType();
    switch (type) {
    case pcpp::DHCPV6_SOLICIT:
        ++_counters.SOLICIT;
        break;
    case pcpp::DHCPV6_ADVERTISE:
        ++_counters.ADVERTISE;
        break;
    case pcpp::DHCPV6_REQUEST:
        ++_counters.REQUESTV6;
        break;
    case pcpp::DHCPV6_REPLY:
        ++_counters.REPLY;
        break;
    default:
        break;
    }

    if (!deep) {
        return;
    }

    if (type == pcpp::DHCPV6_REPLY || type == pcpp::DHCPV6_ADVERTISE) {
        // must have Server Id Layer
        if (auto option = dhcp->getOptionData(pcpp::DHCPV6_OPT_SERVERID); option.isNotNull()) {
            pcpp::EthLayer *ethLayer = payload->getLayerOfType<pcpp::EthLayer>();
            pcpp::IPv6Layer *ipv6Layer = payload->getLayerOfType<pcpp::IPv6Layer>();
            if (ethLayer && ipv6Layer) {
                if (auto ipv6 = ipv6Layer->getSrcIPv6Address(); ipv6 != pcpp::IPv6Address::Zero) {
                    _dhcp_topServers.update(ethLayer->getSourceMac().toString() + "/" + ipv6.toString());
                }
            }
        }
    }
}

void DhcpMetricsManager::process_dhcp_layer(pcpp::DhcpLayer *dhcp, pcpp::Packet *payload, timespec stamp)
{
    // base event
    new_event(stamp);
    // process in the "live" bucket. this will parse the resources if we are deep sampling
    live_bucket()->process_dhcp_layer(_deep_sampling_now, dhcp, payload);

    if (auto type = dhcp->getMessageType(); type == pcpp::DHCP_REQUEST) {
        std::string hostname{"Unknown"};
        if (auto option = dhcp->getOptionData(pcpp::DhcpOptionTypes::DHCPOPT_HOST_NAME); option.isNotNull()) {
            hostname = option.getValueAsString();
        }
        auto mac_address = dhcp->getClientHardwareAddress().toString();
        _request_ack_manager->start_transaction(dhcp->getDhcpHeader()->transactionID, {{stamp, {0, 0}}, hostname, mac_address});
    } else if (type == pcpp::DHCP_ACK) {
        auto xact = _request_ack_manager->maybe_end_transaction(dhcp->getDhcpHeader()->transactionID, stamp);
        if (xact.first == Result::Valid) {
            live_bucket()->new_dhcp_transaction(_deep_sampling_now, dhcp, xact.second);
        }
    }
}

void DhcpMetricsManager::process_dhcp_v6_layer(pcpp::DhcpV6Layer *dhcp, pcpp::Packet *payload, timespec stamp)
{
    // base event
    new_event(stamp);
    // process in the "live" bucket. this will parse the resources if we are deep sampling
    live_bucket()->process_dhcp_v6_layer(_deep_sampling_now, dhcp, payload);
}

void DhcpMetricsManager::process_filtered(timespec stamp)
{
    // base event, no sample
    new_event(stamp, false);
    live_bucket()->process_filtered();
}

}