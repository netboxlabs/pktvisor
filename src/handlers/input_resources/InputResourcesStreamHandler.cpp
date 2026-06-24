/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "InputResourcesStreamHandler.h"
#include "PrometheusSerializer.h"
#include "Policies.h"

namespace visor::handler::resources {

InputResourcesStreamHandler::InputResourcesStreamHandler(const std::string &name, InputEventProxy *proxy, const Configurable *window_config)
    : visor::StreamMetricsHandler<InputResourcesMetricsManager>(name, window_config)
    , _timer(0)
    , _timestamp(timespec())
{
    assert(proxy);
    // figure out which input stream we have
    if (proxy) {
        _pcap_proxy = dynamic_cast<PcapInputEventProxy *>(proxy);
        _dnstap_proxy = dynamic_cast<DnstapInputEventProxy *>(proxy);
        _mock_proxy = dynamic_cast<MockInputEventProxy *>(proxy);
        _flow_proxy = dynamic_cast<FlowInputEventProxy *>(proxy);
        _netprobe_proxy = dynamic_cast<NetProbeInputEventProxy *>(proxy);
        if (!_pcap_proxy && !_mock_proxy && !_dnstap_proxy && !_flow_proxy && !_netprobe_proxy) {
            throw StreamHandlerException(fmt::format("InputResourcesStreamHandler: unsupported input event proxy {}", proxy->name()));
        }
    }
}

void InputResourcesStreamHandler::start()
{
    if (_running) {
        return;
    }

    if (config_exists("recorded_stream")) {
        _metrics->set_recorded_stream();
    }

    if (_pcap_proxy) {
        _pkt_connection = _pcap_proxy->packet_signal.connect(&InputResourcesStreamHandler::process_packet_cb, this);
        _policies_connection = _pcap_proxy->policy_signal.connect(&InputResourcesStreamHandler::process_policies_cb, this);
        _heartbeat_connection = _pcap_proxy->heartbeat_signal.connect(&InputResourcesStreamHandler::check_period_shift, this);
    } else if (_dnstap_proxy) {
        _dnstap_connection = _dnstap_proxy->dnstap_signal.connect(&InputResourcesStreamHandler::process_dnstap_cb, this);
        _policies_connection = _dnstap_proxy->policy_signal.connect(&InputResourcesStreamHandler::process_policies_cb, this);
        _heartbeat_connection = _dnstap_proxy->heartbeat_signal.connect(&InputResourcesStreamHandler::check_period_shift, this);
    } else if (_flow_proxy) {
        _sflow_connection = _flow_proxy->sflow_signal.connect(&InputResourcesStreamHandler::process_sflow_cb, this);
        _netflow_connection = _flow_proxy->netflow_signal.connect(&InputResourcesStreamHandler::process_netflow_cb, this);
        _policies_connection = _flow_proxy->policy_signal.connect(&InputResourcesStreamHandler::process_policies_cb, this);
        _heartbeat_connection = _flow_proxy->heartbeat_signal.connect(&InputResourcesStreamHandler::check_period_shift, this);
    } else if (_netprobe_proxy) {
        _policies_connection = _netprobe_proxy->policy_signal.connect(&InputResourcesStreamHandler::process_policies_cb, this);
        _heartbeat_connection = _netprobe_proxy->heartbeat_signal.connect(&InputResourcesStreamHandler::check_period_shift, this);
    }

    _running = true;
}

void InputResourcesStreamHandler::stop()
{
    if (!_running) {
        return;
    }

    if (_pcap_proxy) {
        _pkt_connection.disconnect();
    } else if (_dnstap_proxy) {
        _dnstap_connection.disconnect();
    } else if (_flow_proxy) {
        _sflow_connection.disconnect();
        _netflow_connection.disconnect();
    }
    _policies_connection.disconnect();
    _heartbeat_connection.disconnect();

    _running = false;
}

void InputResourcesStreamHandler::process_policies_cb(const Policy *policy, Action action)
{
    int16_t policies_number = 0;
    int16_t handlers_count = 0;

    switch (action) {
    case Action::AddPolicy:
        policies_number = 1;
        handlers_count = policy->get_handlers_list_size();
        break;
    case Action::RemovePolicy:
        policies_number = -1;
        handlers_count = -policy->get_handlers_list_size();
        break;
    }

    _metrics->process_policies(policies_number, handlers_count);
}

void InputResourcesStreamHandler::process_sflow_cb([[maybe_unused]] const SFSample &, [[maybe_unused]] size_t)
{
    if (difftime(time(NULL), _timer) >= MEASURE_INTERVAL) {
        _timer = time(NULL);
        _metrics->process_resources(_monitor.cpu_percentage(), _monitor.memory_usage());
    }
}

void InputResourcesStreamHandler::process_netflow_cb([[maybe_unused]] const std::string &, [[maybe_unused]] const NFSample &, [[maybe_unused]] size_t)
{
    if (difftime(time(NULL), _timer) >= MEASURE_INTERVAL) {
        _timer = time(NULL);
        _metrics->process_resources(_monitor.cpu_percentage(), _monitor.memory_usage());
    }
}

void InputResourcesStreamHandler::process_dnstap_cb([[maybe_unused]] const dnstap::Dnstap &, [[maybe_unused]] size_t)
{
    if (difftime(time(NULL), _timer) >= MEASURE_INTERVAL) {
        _timer = time(NULL);
        _metrics->process_resources(_monitor.cpu_percentage(), _monitor.memory_usage());
    }
}

void InputResourcesStreamHandler::process_packet_cb([[maybe_unused]] pcpp::Packet &payload, [[maybe_unused]] PacketDirection dir, [[maybe_unused]] pcpp::ProtocolType l3, [[maybe_unused]] pcpp::ProtocolType l4, [[maybe_unused]] timespec stamp)
{
    if (stamp.tv_sec >= _timestamp.tv_sec + MEASURE_INTERVAL) {
        _timestamp = stamp;
        _metrics->process_resources(_monitor.cpu_percentage(), _monitor.memory_usage());
    }
}

void InputResourcesMetricsBucket::specialized_merge(const AbstractMetricsBucket &o, Metric::Aggregate agg_operator)
{
    // static because caller guarantees only our own bucket type
    const auto &other = static_cast<const InputResourcesMetricsBucket &>(o);

    std::shared_lock r_lock(other._mutex);
    std::unique_lock w_lock(_mutex);

    _cpu_usage.merge(other._cpu_usage, agg_operator);
    _memory_bytes.merge(other._memory_bytes, agg_operator);

    // Merge only the first bucket which is the more recent
    if (!_merged) {
        _policy_count += other._policy_count;
        _handler_count += other._handler_count;
        _merged = true;
    }
}

void InputResourcesMetricsBucket::to_prometheus(PrometheusSerializer &ser, Metric::LabelMap add_labels) const
{
    {
        auto [num_events, num_samples, event_rate, event_lock] = event_data_locked(); // thread safe

        event_rate->to_prometheus(ser, add_labels);
        num_events->to_prometheus(ser, add_labels);
        num_samples->to_prometheus(ser, add_labels);
    }

    std::shared_lock r_lock(_mutex);

    _cpu_usage.to_prometheus(ser, add_labels);
    _memory_bytes.to_prometheus(ser, add_labels);
    _policy_count.to_prometheus(ser, add_labels);
    _handler_count.to_prometheus(ser, add_labels);
}

void InputResourcesMetricsBucket::to_opentelemetry(metrics::v1::ScopeMetrics &scope, timespec &start_ts, timespec &end_ts, Metric::LabelMap add_labels) const
{
    {
        auto [num_events, num_samples, event_rate, event_lock] = event_data_locked(); // thread safe

        event_rate->to_opentelemetry(scope, start_ts, end_ts, add_labels);
        num_events->to_opentelemetry(scope, start_ts, end_ts, add_labels);
        num_samples->to_opentelemetry(scope, start_ts, end_ts, add_labels);
    }

    std::shared_lock r_lock(_mutex);

    _cpu_usage.to_opentelemetry(scope, start_ts, end_ts, add_labels);
    _memory_bytes.to_opentelemetry(scope, start_ts, end_ts, add_labels);
    _policy_count.to_opentelemetry(scope, start_ts, end_ts, add_labels);
    _handler_count.to_opentelemetry(scope, start_ts, end_ts, add_labels);
}

void InputResourcesMetricsBucket::to_json(json &j) const
{
    bool live_rates = !read_only() && !recorded_stream();

    {
        auto [num_events, num_samples, event_rate, event_lock] = event_data_locked(); // thread safe

        event_rate->to_json(j, live_rates);
        num_events->to_json(j);
        num_samples->to_json(j);
    }

    std::shared_lock r_lock(_mutex);

    _cpu_usage.to_json(j);
    _memory_bytes.to_json(j);
    _policy_count.to_json(j);
    _handler_count.to_json(j);
}

void InputResourcesMetricsBucket::process_resources(double cpu_usage, uint64_t memory_usage)
{
    std::unique_lock lock(_mutex);

    _cpu_usage.update(cpu_usage);
    _memory_bytes.update(memory_usage);
}

void InputResourcesMetricsBucket::process_policies(int16_t policy_count, int16_t handler_count)
{
    std::unique_lock lock(_mutex);

    if (policy_count < 0 && static_cast<uint64_t>(std::abs(policy_count)) > _policy_count.value()) {
        _policy_count.clear();
    } else {
        _policy_count += policy_count;
    }
    if (handler_count < 0 && static_cast<uint64_t>(std::abs(handler_count)) > _handler_count.value()) {
        _handler_count.clear();
    } else {
        _handler_count += handler_count;
    }
}

void InputResourcesMetricsManager::process_resources(double cpu_usage, uint64_t memory_usage, timespec stamp)
{
    if (stamp.tv_sec == 0) {
        // use now()
        std::timespec_get(&stamp, TIME_UTC);
    }
    // base event
    new_event(stamp);
    // process in the "live" bucket. this will parse the resources if we are deep sampling
    live_bucket()->process_resources(cpu_usage, memory_usage);
}

void InputResourcesMetricsManager::process_policies(int16_t policy_count, int16_t handler_count, bool self)
{
    if (!self) {
        policy_total += policy_count;
        handler_total += handler_count;
    }

    timespec stamp;
    // use now()
    std::timespec_get(&stamp, TIME_UTC);
    // base event
    new_event(stamp);
    // process in the "live" bucket. this will parse the resources if we are deep sampling
    live_bucket()->process_policies(policy_count, handler_count);
}
}