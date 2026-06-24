/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "NetProbeStreamHandler.h"
#include "PrometheusSerializer.h"

namespace visor::handler::netprobe {

NetProbeStreamHandler::NetProbeStreamHandler(const std::string &name, InputEventProxy *proxy, const Configurable *window_config)
    : visor::StreamMetricsHandler<NetProbeMetricsManager>(name, window_config)
{
    assert(proxy);
    // figure out which input event proxy we have
    _netprobe_proxy = dynamic_cast<NetProbeInputEventProxy *>(proxy);
    if (!_netprobe_proxy) {
        throw StreamHandlerException(fmt::format("NetProbeStreamHandler: unsupported input event proxy {}", proxy->name()));
    }
}

void NetProbeStreamHandler::start()
{
    if (_running) {
        return;
    }

    validate_configs(_config_defs);

    // default enabled groups
    _groups.set(group::NetProbeMetrics::Counters);
    _groups.set(group::NetProbeMetrics::Histograms);
    process_groups(_group_defs);

    if (config_exists("recorded_stream")) {
        _metrics->set_recorded_stream();
    }

    if (config_exists("xact_ttl_ms")) {
        auto ttl = config_get<uint64_t>("xact_ttl_ms");
        _metrics->set_xact_ttl(static_cast<uint32_t>(ttl));
    } else if (config_exists("xact_ttl_secs")) {
        auto ttl = config_get<uint64_t>("xact_ttl_secs");
        _metrics->set_xact_ttl(static_cast<uint32_t>(ttl) * 1000);
    } else if (_netprobe_proxy->config_exists("xact_ttl_ms")) {
        auto ttl = _netprobe_proxy->config_get<uint64_t>("xact_ttl_ms");
        _metrics->set_xact_ttl(static_cast<uint32_t>(ttl));
    }

    if (_netprobe_proxy) {
        _probe_send_connection = _netprobe_proxy->probe_send_signal.connect(&NetProbeStreamHandler::probe_signal_send, this);
        _probe_recv_connection = _netprobe_proxy->probe_recv_signal.connect(&NetProbeStreamHandler::probe_signal_recv, this);
        _probe_fail_connection = _netprobe_proxy->probe_fail_signal.connect(&NetProbeStreamHandler::probe_signal_fail, this);
        _heartbeat_connection = _netprobe_proxy->heartbeat_signal.connect(&NetProbeStreamHandler::check_period_shift, this);
    }

    _running = true;
}

void NetProbeStreamHandler::stop()
{
    if (!_running) {
        return;
    }

    if (_netprobe_proxy) {
        _probe_send_connection.disconnect();
        _probe_recv_connection.disconnect();
        _probe_fail_connection.disconnect();
        _heartbeat_connection.disconnect();
    }

    _running = false;
}

void NetProbeStreamHandler::probe_signal_send(pcpp::Packet &payload, TestType type, const std::string &name, timespec stamp)
{
    if (type == TestType::Ping) {
        if (auto icmp = payload.getLayerOfType<pcpp::IcmpLayer>(); icmp != nullptr) {
            _metrics->process_netprobe_icmp(icmp, name, stamp);
        } else if (auto icmp6 = payload.getLayerOfType<pcpp::ICMPv6EchoLayer>(); icmp6 != nullptr) {
            _metrics->process_netprobe_icmpv6(icmp6, name, stamp);
        }
    } else if (type == TestType::TCP) {
        if (auto tcp = payload.getLayerOfType<pcpp::TcpLayer>(); tcp != nullptr) {
            _metrics->process_netprobe_tcp(true, name, stamp);
        }
    }
}

void NetProbeStreamHandler::probe_signal_recv(pcpp::Packet &payload, TestType type, const std::string &name, timespec stamp)
{
    if (type == TestType::Ping) {
        if (auto icmp = payload.getLayerOfType<pcpp::IcmpLayer>(); icmp != nullptr) {
            _metrics->process_netprobe_icmp(icmp, name, stamp);
        } else if (auto icmp6 = payload.getLayerOfType<pcpp::ICMPv6EchoLayer>(); icmp6 != nullptr) {
            _metrics->process_netprobe_icmpv6(icmp6, name, stamp);
        }
    } else if (type == TestType::TCP) {
        if (auto tcp = payload.getLayerOfType<pcpp::TcpLayer>(); tcp != nullptr) {
            _metrics->process_netprobe_tcp(false, name, stamp);
        }
    }
}

void NetProbeStreamHandler::probe_signal_fail(ErrorType error, [[maybe_unused]] TestType type, const std::string &name)
{
    _metrics->process_failure(error, name);
}

void NetProbeMetricsBucket::specialized_merge(const AbstractMetricsBucket &o, Metric::Aggregate agg_operator)
{
    // static because caller guarantees only our own bucket type
    const auto &other = static_cast<const NetProbeMetricsBucket &>(o);

    std::shared_lock r_lock(other._mutex);
    std::unique_lock w_lock(_mutex);

    for (const auto &target : other._targets_metrics) {
        const auto &targetId = target.first;
        if (!_targets_metrics.count(targetId)) {
            _targets_metrics[targetId] = std::make_unique<Target>();
        }

        if (group_enabled(group::NetProbeMetrics::Counters)) {
            _targets_metrics[targetId]->attempts += target.second->attempts;
            _targets_metrics[targetId]->successes += target.second->successes;
            _targets_metrics[targetId]->connect_failures += target.second->connect_failures;
            _targets_metrics[targetId]->dns_failures += target.second->dns_failures;
            _targets_metrics[targetId]->timed_out += target.second->timed_out;
        }
        if (group_enabled(group::NetProbeMetrics::Histograms)) {
            _targets_metrics[targetId]->h_time_us.merge(target.second->h_time_us);
        }
        if (group_enabled(group::NetProbeMetrics::Quantiles)) {
            _targets_metrics[targetId]->q_time_us.merge(target.second->q_time_us, agg_operator);
        }
    }
}

void NetProbeMetricsBucket::to_prometheus(PrometheusSerializer &ser, Metric::LabelMap add_labels) const
{
    std::shared_lock r_lock(_mutex);

    for (const auto &target : _targets_metrics) {
        auto target_labels = add_labels;
        auto targetId = target.first;
        target_labels["target"] = targetId;

        if (group_enabled(group::NetProbeMetrics::Counters)) {
            target.second->attempts.to_prometheus(ser, target_labels);
            target.second->successes.to_prometheus(ser, target_labels);
            target.second->connect_failures.to_prometheus(ser, target_labels);
            target.second->dns_failures.to_prometheus(ser, target_labels);
            target.second->timed_out.to_prometheus(ser, target_labels);
        }

        bool h_max_min{true};
        if (group_enabled(group::NetProbeMetrics::Histograms)) {
            try {
                target.second->minimum.clear();
                target.second->maximum.clear();

                if (group_enabled(group::NetProbeMetrics::Counters)) {
                    target.second->minimum += target.second->h_time_us.get_min();
                    target.second->minimum.to_prometheus(ser, target_labels);
                    target.second->maximum += target.second->h_time_us.get_max();
                    target.second->maximum.to_prometheus(ser, target_labels);
                }

                target.second->h_time_us.to_prometheus(ser, target_labels);
            } catch (const std::exception &) {
                h_max_min = false;
            }
        } else {
            h_max_min = false;
        }

        if (group_enabled(group::NetProbeMetrics::Quantiles)) {
            try {
                if (!h_max_min && group_enabled(group::NetProbeMetrics::Counters)) {
                    target.second->minimum.clear();
                    target.second->maximum.clear();

                    target.second->minimum += target.second->q_time_us.get_min();
                    target.second->minimum.to_prometheus(ser, target_labels);
                    target.second->maximum += target.second->q_time_us.get_max();
                    target.second->maximum.to_prometheus(ser, target_labels);
                }
                target.second->q_time_us.to_prometheus(ser, target_labels);
            } catch (const std::exception &) {
            }
        }
    }
}

void NetProbeMetricsBucket::to_opentelemetry(metrics::v1::ScopeMetrics &scope, timespec &start_ts, timespec &end_ts, Metric::LabelMap add_labels) const
{
    std::shared_lock r_lock(_mutex);

    for (const auto &target : _targets_metrics) {
        auto target_labels = add_labels;
        auto targetId = target.first;
        target_labels["target"] = targetId;

        if (group_enabled(group::NetProbeMetrics::Counters)) {
            target.second->attempts.to_opentelemetry(scope, start_ts, end_ts, target_labels);
            target.second->successes.to_opentelemetry(scope, start_ts, end_ts, target_labels);
            target.second->connect_failures.to_opentelemetry(scope, start_ts, end_ts, target_labels);
            target.second->dns_failures.to_opentelemetry(scope, start_ts, end_ts, target_labels);
            target.second->timed_out.to_opentelemetry(scope, start_ts, end_ts, target_labels);
        }

        bool h_max_min{true};
        if (group_enabled(group::NetProbeMetrics::Histograms)) {
            try {
                target.second->minimum.clear();
                target.second->maximum.clear();

                if (group_enabled(group::NetProbeMetrics::Counters)) {
                    target.second->minimum += target.second->h_time_us.get_min();
                    target.second->minimum.to_opentelemetry(scope, start_ts, end_ts, target_labels);
                    target.second->maximum += target.second->h_time_us.get_max();
                    target.second->maximum.to_opentelemetry(scope, start_ts, end_ts, target_labels);
                }

                target.second->h_time_us.to_opentelemetry(scope, start_ts, end_ts, target_labels);
            } catch (const std::exception &) {
                h_max_min = false;
            }
        } else {
            h_max_min = false;
        }

        if (group_enabled(group::NetProbeMetrics::Quantiles)) {
            try {
                if (!h_max_min && group_enabled(group::NetProbeMetrics::Counters)) {
                    target.second->minimum.clear();
                    target.second->maximum.clear();

                    target.second->minimum += target.second->q_time_us.get_min();
                    target.second->minimum.to_opentelemetry(scope, start_ts, end_ts, target_labels);
                    target.second->maximum += target.second->q_time_us.get_max();
                    target.second->maximum.to_opentelemetry(scope, start_ts, end_ts, target_labels);
                }
                target.second->q_time_us.to_opentelemetry(scope, start_ts, end_ts, target_labels);
            } catch (const std::exception &) {
            }
        }
    }
}

void NetProbeMetricsBucket::to_json(json &j) const
{

    std::shared_lock r_lock(_mutex);

    for (const auto &target : _targets_metrics) {
        auto targetId = target.first;

        if (group_enabled(group::NetProbeMetrics::Counters)) {
            target.second->attempts.to_json(j["targets"][targetId]);
            target.second->successes.to_json(j["targets"][targetId]);
            target.second->connect_failures.to_json(j["targets"][targetId]);
            target.second->dns_failures.to_json(j["targets"][targetId]);
            target.second->timed_out.to_json(j["targets"][targetId]);
        }

        bool h_max_min{true};
        if (group_enabled(group::NetProbeMetrics::Histograms)) {
            try {
                target.second->minimum.clear();
                target.second->maximum.clear();

                if (group_enabled(group::NetProbeMetrics::Counters)) {
                    target.second->minimum += target.second->h_time_us.get_min();
                    target.second->minimum.to_json(j["targets"][targetId]);
                    target.second->maximum += target.second->h_time_us.get_max();
                    target.second->maximum.to_json(j["targets"][targetId]);
                }

                target.second->h_time_us.to_json(j["targets"][targetId]);
            } catch (const std::exception &) {
                h_max_min = false;
            }
        } else {
            h_max_min = false;
        }

        if (group_enabled(group::NetProbeMetrics::Quantiles)) {
            try {
                if (!h_max_min && group_enabled(group::NetProbeMetrics::Counters)) {
                    target.second->minimum.clear();
                    target.second->maximum.clear();

                    target.second->minimum += target.second->q_time_us.get_min();
                    target.second->minimum.to_json(j["targets"][targetId]);
                    target.second->maximum += target.second->q_time_us.get_max();
                    target.second->maximum.to_json(j["targets"][targetId]);
                }
                target.second->q_time_us.to_json(j["targets"][targetId]);
            } catch (const std::exception &) {
            }
        }
    }
}

void NetProbeMetricsBucket::process_filtered()
{
}

void NetProbeMetricsBucket::process_failure(ErrorType error, const std::string &target)
{
    if (!_targets_metrics.count(target)) {
        _targets_metrics[target] = std::make_unique<Target>();
    }
    if (group_enabled(group::NetProbeMetrics::Counters)) {
        switch (error) {
        case ErrorType::DnsLookupFailure:
            ++_targets_metrics[target]->dns_failures;
            break;
        case ErrorType::Timeout:
            ++_targets_metrics[target]->timed_out;
            break;
        case ErrorType::SocketError:
        case ErrorType::InvalidIp:
        case ErrorType::ConnectFailure:
            ++_targets_metrics[target]->connect_failures;
            break;
        default:
            break;
        }
    }
}

bool NetProbeStreamHandler::_filtering([[maybe_unused]] pcpp::Packet *payload)
{
    // no filters yet
    return false;
}

void NetProbeMetricsBucket::process_attempts([[maybe_unused]] bool deep, const std::string &target)
{
    if (!_targets_metrics.count(target)) {
        _targets_metrics[target] = std::make_unique<Target>();
    }
    if (group_enabled(group::NetProbeMetrics::Counters)) {
        ++_targets_metrics[target]->attempts;
    }
}

void NetProbeMetricsBucket::new_transaction(bool deep, NetProbeTransaction xact)
{
    std::unique_lock lock(_mutex);

    if (!_targets_metrics.count(xact.target)) {
        _targets_metrics[xact.target] = std::make_unique<Target>();
    }
    if (group_enabled(group::NetProbeMetrics::Counters)) {
        ++_targets_metrics[xact.target]->successes;
    }

    if (!deep) {
        return;
    }

    const uint64_t time_nsec = xact.totalTS.tv_sec * 1000000000ULL + xact.totalTS.tv_nsec;
    group_enabled(group::NetProbeMetrics::Histograms) ? _targets_metrics[xact.target]->h_time_us.update(time_nsec / 1000) : void();
    group_enabled(group::NetProbeMetrics::Quantiles) ? _targets_metrics[xact.target]->q_time_us.update(time_nsec / 1000) : void();
}

void NetProbeMetricsManager::process_failure(ErrorType error, const std::string &target)
{
    timespec stamp;
    // use now()
    std::timespec_get(&stamp, TIME_UTC);
    // base event
    new_event(stamp);

    live_bucket()->process_failure(error, target);
}

void NetProbeMetricsManager::process_netprobe_icmp(pcpp::IcmpLayer *layer, const std::string &target, timespec stamp)
{
    // base event
    new_event(stamp);

    if (layer->getMessageType() == pcpp::ICMP_ECHO_REQUEST) {
        if (auto request = layer->getEchoRequestData(); request != nullptr) {
            auto ping_id = (static_cast<uint32_t>(request->header->id) << 16) | request->header->sequence;
            _request_reply_manager->start_transaction(std::to_string(ping_id), {{stamp, {0, 0}}, target});
        }
        live_bucket()->process_attempts(_deep_sampling_now, target);
    } else if (layer->getMessageType() == pcpp::ICMP_ECHO_REPLY) {
        if (auto reply = layer->getEchoReplyData(); reply != nullptr) {
            auto ping_id = (static_cast<uint32_t>(reply->header->id) << 16) | reply->header->sequence;
            auto xact = _request_reply_manager->maybe_end_transaction(std::to_string(ping_id), stamp);
            if (xact.first == Result::Valid) {
                live_bucket()->new_transaction(_deep_sampling_now, xact.second);
            } else if (xact.first == Result::TimedOut) {
                live_bucket()->process_failure(ErrorType::Timeout, xact.second.target);
            }
        }
    }
}

void NetProbeMetricsManager::process_netprobe_icmpv6(pcpp::ICMPv6EchoLayer *layer, const std::string &target, timespec stamp)
{
    // base event
    new_event(stamp);
    // getIdentifier()/getSequenceNr() already byte-swap to host order inside pcpp (be16toh),
    // matching the htobe16 the send side used; do not add another ntohs.
    auto ping_id = (static_cast<uint32_t>(layer->getIdentifier()) << 16) | layer->getSequenceNr();
    if (layer->getMessageType() == pcpp::ICMPv6MessageType::ICMPv6_ECHO_REQUEST) {
        _request_reply_manager->start_transaction(std::to_string(ping_id), {{stamp, {0, 0}}, target});
        live_bucket()->process_attempts(_deep_sampling_now, target);
    } else if (layer->getMessageType() == pcpp::ICMPv6MessageType::ICMPv6_ECHO_REPLY) {
        auto xact = _request_reply_manager->maybe_end_transaction(std::to_string(ping_id), stamp);
        if (xact.first == Result::Valid) {
            live_bucket()->new_transaction(_deep_sampling_now, xact.second);
        } else if (xact.first == Result::TimedOut) {
            live_bucket()->process_failure(ErrorType::Timeout, xact.second.target);
        }
    }
}

void NetProbeMetricsManager::process_netprobe_tcp(bool send, const std::string &target, timespec stamp)
{
    // base event
    new_event(stamp);

    if (send) {
        _request_reply_manager->start_transaction(target, {{stamp, {0, 0}}, target});
        live_bucket()->process_attempts(_deep_sampling_now, target);
    } else {
        auto xact = _request_reply_manager->maybe_end_transaction(target, stamp);
        if (xact.first == Result::Valid) {
            live_bucket()->new_transaction(_deep_sampling_now, xact.second);
        } else if (xact.first == Result::TimedOut) {
            live_bucket()->process_failure(ErrorType::Timeout, xact.second.target);
        }
    }
}

void NetProbeMetricsManager::process_filtered(timespec stamp)
{
    // base event, no sample
    new_event(stamp, false);
    live_bucket()->process_filtered();
}

}