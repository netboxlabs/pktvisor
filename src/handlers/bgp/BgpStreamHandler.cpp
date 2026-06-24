/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "BgpStreamHandler.h"
#include "PrometheusSerializer.h"
#include <pcapplusplus/TimespecTimeval.h>

namespace visor::handler::bgp {

BgpStreamHandler::BgpStreamHandler(const std::string &name, InputEventProxy *proxy, const Configurable *window_config)
    : visor::StreamMetricsHandler<BgpMetricsManager>(name, window_config)
{
    assert(proxy);
    // figure out which input event proxy we have
    _pcap_proxy = dynamic_cast<PcapInputEventProxy *>(proxy);
    if (!_pcap_proxy) {
        throw StreamHandlerException(fmt::format("BgpStreamHandler: unsupported input event proxy {}", proxy->name()));
    }
}

void BgpStreamHandler::start()
{
    if (_running) {
        return;
    }

    validate_configs(_config_defs);

    if (config_exists("recorded_stream")) {
        _metrics->set_recorded_stream();
    }

    if (_pcap_proxy) {
        _tcp_start_connection = _pcap_proxy->tcp_connection_start_signal.connect(&BgpStreamHandler::tcp_connection_start_cb, this);
        _tcp_end_connection = _pcap_proxy->tcp_connection_end_signal.connect(&BgpStreamHandler::tcp_connection_end_cb, this);
        _tcp_message_connection = _pcap_proxy->tcp_message_ready_signal.connect(&BgpStreamHandler::tcp_message_ready_cb, this);
        _start_tstamp_connection = _pcap_proxy->start_tstamp_signal.connect(&BgpStreamHandler::set_start_tstamp, this);
        _end_tstamp_connection = _pcap_proxy->end_tstamp_signal.connect(&BgpStreamHandler::set_end_tstamp, this);
        _heartbeat_connection = _pcap_proxy->heartbeat_signal.connect(&BgpStreamHandler::check_period_shift, this);
    }

    _running = true;
}

void BgpStreamHandler::stop()
{
    if (!_running) {
        return;
    }

    if (_pcap_proxy) {
        _tcp_start_connection.disconnect();
        _tcp_end_connection.disconnect();
        _tcp_message_connection.disconnect();
        _start_tstamp_connection.disconnect();
        _end_tstamp_connection.disconnect();
        _heartbeat_connection.disconnect();
    }

    _running = false;
}

void BgpStreamHandler::tcp_connection_start_cb(const pcpp::ConnectionData &connectionData, [[maybe_unused]] PacketDirection dir)
{
    // look for the connection
    auto iter = _tcp_connections.find(connectionData.flowKey);

    // note we want to capture metrics only when one of the ports is BGP
    if (iter == _tcp_connections.end() && pcpp::BgpLayer::isBgpPort(connectionData.srcPort, connectionData.dstPort)) {
        // add it to the connections
        _tcp_connections.emplace(connectionData.flowKey, TcpFlowData(connectionData.srcIP.getType() == pcpp::IPAddress::IPv4AddressType, true));
    }
}

void BgpStreamHandler::tcp_message_ready_cb(int8_t side, const pcpp::TcpStreamData &tcpData, PacketDirection dir)
{
    auto flowKey = tcpData.getConnectionData().flowKey;
    // check if this flow already appears in the connection manager. If not add it
    auto iter = _tcp_connections.find(flowKey);
    // if not tracking connection, and it's DNS, then start tracking.
    if (iter == _tcp_connections.end()) {
        // note we want to capture metrics only when one of the ports is BGP
        if (pcpp::BgpLayer::isBgpPort(tcpData.getConnectionData().srcPort, tcpData.getConnectionData().dstPort)) {
            _tcp_connections.emplace(flowKey, TcpFlowData(tcpData.getConnectionData().srcIP.getType() == pcpp::IPAddress::IPv4AddressType, true));
            iter = _tcp_connections.find(tcpData.getConnectionData().flowKey);
        } else {
            // not tracking
            return;
        }
    }

    pcpp::ProtocolType l3Type{iter->second.l3Type};
    timespec stamp{0, 0};
    // for tcp, endTime is updated by pcpp to represent the time stamp from the latest packet in the stream
    TIMEVAL_TO_TIMESPEC(&tcpData.getConnectionData().endTime, &stamp);

    auto got_bgp_message = [this, dir, l3Type, flowKey, stamp](std::unique_ptr<uint8_t[]> data, size_t size) {
        // this dummy packet prevents BgpLayer from owning and trying to free the data. it is otherwise unused by the BGP layer,
        // instead using the packet meta data we pass in
        pcpp::Packet dummy_packet;
        auto bgpLayer = pcpp::BgpLayer::parseBgpLayer(data.get(), size, nullptr, &dummy_packet);
        if (!_filtering(bgpLayer, dir, l3Type, pcpp::TCP, stamp)) {
            _metrics->process_bgp_layer(bgpLayer, dir, l3Type, pcpp::TCP, flowKey, stamp);
        }
        // data is freed upon return
    };

    if (!iter->second.sessionData[side]) {
        iter->second.sessionData[side] = std::make_unique<BgpTcpSessionData>(got_bgp_message);
    }

    iter->second.sessionData[side]->receive_tcp_data(tcpData.getData(), tcpData.getDataLength());
}

void BgpStreamHandler::tcp_connection_end_cb(const pcpp::ConnectionData &connectionData, [[maybe_unused]] pcpp::TcpReassembly::ConnectionEndReason reason)
{
    // find the connection in the connections by the flow key
    auto iter = _tcp_connections.find(connectionData.flowKey);
    // connection wasn't found, we didn't track
    if (iter == _tcp_connections.end()) {
        return;
    }
    // remove the connection from the connection manager
    _tcp_connections.erase(iter);
}

// callback from input module
void BgpStreamHandler::set_start_tstamp(timespec stamp)
{
    _metrics->set_start_tstamp(stamp);
}
void BgpStreamHandler::set_end_tstamp(timespec stamp)
{
    _metrics->set_end_tstamp(stamp);
}

void BgpTcpSessionData::receive_tcp_data(const uint8_t *data, size_t len)
{
    if (_invalid_data) {
        return;
    }

    auto bgp_data = std::make_unique<uint8_t[]>(len);
    std::memcpy(bgp_data.get(), data, len);
    _got_msg(std::move(bgp_data), len);
}

void BgpMetricsBucket::specialized_merge(const AbstractMetricsBucket &o, Metric::Aggregate agg_operator)
{
    // static because caller guarantees only our own bucket type
    const auto &other = static_cast<const BgpMetricsBucket &>(o);

    // rates maintain their own thread safety
    _rate_total.merge(other._rate_total, agg_operator);

    std::shared_lock r_lock(other._mutex);
    std::unique_lock w_lock(_mutex);

    _counters.OPEN += other._counters.OPEN;
    _counters.UPDATE += other._counters.UPDATE;
    _counters.NOTIFICATION += other._counters.NOTIFICATION;
    _counters.KEEPALIVE += other._counters.KEEPALIVE;
    _counters.ROUTEREFRESH += other._counters.ROUTEREFRESH;
    _counters.total += other._counters.total;
    _counters.filtered += other._counters.filtered;
}

void BgpMetricsBucket::to_prometheus(PrometheusSerializer &ser, Metric::LabelMap add_labels) const
{

    _rate_total.to_prometheus(ser, add_labels);

    {
        auto [num_events, num_samples, event_rate, event_lock] = event_data_locked(); // thread safe

        event_rate->to_prometheus(ser, add_labels);
        num_events->to_prometheus(ser, add_labels);
        num_samples->to_prometheus(ser, add_labels);
    }

    std::shared_lock r_lock(_mutex);

    _counters.OPEN.to_prometheus(ser, add_labels);
    _counters.UPDATE.to_prometheus(ser, add_labels);
    _counters.NOTIFICATION.to_prometheus(ser, add_labels);
    _counters.KEEPALIVE.to_prometheus(ser, add_labels);
    _counters.ROUTEREFRESH.to_prometheus(ser, add_labels);
    _counters.total.to_prometheus(ser, add_labels);
    _counters.filtered.to_prometheus(ser, add_labels);
}

void BgpMetricsBucket::to_opentelemetry(metrics::v1::ScopeMetrics &scope, timespec &start_ts, timespec &end_ts, Metric::LabelMap add_labels) const
{
    _rate_total.to_opentelemetry(scope, start_ts, end_ts, add_labels);

    {
        auto [num_events, num_samples, event_rate, event_lock] = event_data_locked(); // thread safe

        event_rate->to_opentelemetry(scope, start_ts, end_ts, add_labels);
        num_events->to_opentelemetry(scope, start_ts, end_ts, add_labels);
        num_samples->to_opentelemetry(scope, start_ts, end_ts, add_labels);
    }

    std::shared_lock r_lock(_mutex);

    _counters.OPEN.to_opentelemetry(scope, start_ts, end_ts, add_labels);
    _counters.UPDATE.to_opentelemetry(scope, start_ts, end_ts, add_labels);
    _counters.NOTIFICATION.to_opentelemetry(scope, start_ts, end_ts, add_labels);
    _counters.KEEPALIVE.to_opentelemetry(scope, start_ts, end_ts, add_labels);
    _counters.ROUTEREFRESH.to_opentelemetry(scope, start_ts, end_ts, add_labels);
    _counters.total.to_opentelemetry(scope, start_ts, end_ts, add_labels);
    _counters.filtered.to_opentelemetry(scope, start_ts, end_ts, add_labels);
}

void BgpMetricsBucket::to_json(json &j) const
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

    _counters.OPEN.to_json(j);
    _counters.UPDATE.to_json(j);
    _counters.NOTIFICATION.to_json(j);
    _counters.KEEPALIVE.to_json(j);
    _counters.ROUTEREFRESH.to_json(j);
    _counters.total.to_json(j);
    _counters.filtered.to_json(j);
}

void BgpMetricsBucket::process_filtered()
{
    std::unique_lock lock(_mutex);
    ++_counters.filtered;
}

bool BgpStreamHandler::_filtering([[maybe_unused]] pcpp::BgpLayer *payload, [[maybe_unused]] PacketDirection dir, [[maybe_unused]] pcpp::ProtocolType l3, [[maybe_unused]] pcpp::ProtocolType l4, [[maybe_unused]] timespec stamp)
{
    // no filters yet
    return false;
}

void BgpMetricsBucket::process_bgp_layer([[maybe_unused]] bool deep, pcpp::BgpLayer *payload, [[maybe_unused]] pcpp::ProtocolType l3, [[maybe_unused]] pcpp::ProtocolType l4)
{
    std::unique_lock lock(_mutex);

    ++_counters.total;
    ++_rate_total;

    switch (payload->getBgpMessageType()) {
    case pcpp::BgpLayer::Open:
        ++_counters.OPEN;
        break;
    case pcpp::BgpLayer::Update:
        ++_counters.UPDATE;
        break;
    case pcpp::BgpLayer::Notification:
        ++_counters.NOTIFICATION;
        break;
    case pcpp::BgpLayer::Keepalive:
        ++_counters.KEEPALIVE;
        break;
    case pcpp::BgpLayer::RouteRefresh:
        ++_counters.ROUTEREFRESH;
        break;
    }
}

void BgpMetricsManager::process_bgp_layer(pcpp::BgpLayer *payload, [[maybe_unused]] PacketDirection dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4, [[maybe_unused]] uint32_t flowkey, timespec stamp)
{
    // base event
    new_event(stamp);
    // process in the "live" bucket. this will parse the resources if we are deep sampling
    live_bucket()->process_bgp_layer(_deep_sampling_now, payload, l3, l4);
}

void BgpMetricsManager::process_filtered(timespec stamp)
{
    // base event, no sample
    new_event(stamp, false);
    live_bucket()->process_filtered();
}

}