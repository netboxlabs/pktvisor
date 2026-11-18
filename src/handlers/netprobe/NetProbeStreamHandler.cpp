/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "NetProbeStreamHandler.h"
#include "PrometheusSerializer.h"
#include "dns.h"

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
        _heartbeat_connection = _netprobe_proxy->heartbeat_signal.connect(&NetProbeStreamHandler::heartbeat, this);
        _probe_http_result_connection = _netprobe_proxy->probe_http_result_signal.connect(&NetProbeStreamHandler::probe_signal_http_result, this);
        _probe_doh_result_connection = _netprobe_proxy->probe_doh_result_signal.connect(&NetProbeStreamHandler::probe_signal_doh_result, this);
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
        _probe_http_result_connection.disconnect();
        _probe_doh_result_connection.disconnect();
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
        // The shared ping receiver passes on every ICMPv4 packet the host receives, echo requests
        // included: a local target's own request looped back, or another host pinging this one.
        // Attempts are counted on send, so a received request is skipped. The ICMPv6 receiver
        // already passes only echo replies; its check here is defensive.
        if (auto icmp = payload.getLayerOfType<pcpp::IcmpLayer>(); icmp != nullptr) {
            if (icmp->getMessageType() != pcpp::ICMP_ECHO_REQUEST) {
                _metrics->process_netprobe_icmp(icmp, name, stamp);
            }
        } else if (auto icmp6 = payload.getLayerOfType<pcpp::ICMPv6EchoLayer>(); icmp6 != nullptr) {
            if (icmp6->getMessageType() != pcpp::ICMPv6MessageType::ICMPv6_ECHO_REQUEST) {
                _metrics->process_netprobe_icmpv6(icmp6, name, stamp);
            }
        }
    } else if (type == TestType::TCP) {
        if (auto tcp = payload.getLayerOfType<pcpp::TcpLayer>(); tcp != nullptr) {
            _metrics->process_netprobe_tcp(false, name, stamp);
        }
    }
}

// The ping receiver passes on what it read every 100 ms, so at a heartbeat it can still hold a reply it read
// before its request's TTL ran out. A heartbeat expires requests as of a second earlier, which covers that.
static constexpr time_t PING_REPLY_GRACE_SEC = 1;

void NetProbeStreamHandler::heartbeat(timespec stamp)
{
    auto as_of = stamp;
    as_of.tv_sec -= PING_REPLY_GRACE_SEC;
    // before the shift, so a request that expired in the closing window is counted there
    _metrics->expire_ping_requests(as_of);
    check_period_shift(stamp);
}

void NetProbeStreamHandler::probe_signal_fail(ErrorType error, TestType type, const std::string &name)
{
    if (type == TestType::HTTP) {
        _metrics->process_netprobe_http_failure(error, name);
    } else if (type == TestType::DOH) {
        _metrics->process_netprobe_doh_failure(error, name);
    } else {
        _metrics->process_failure(error, name);
    }
}

void NetProbeStreamHandler::probe_signal_http_result(visor::http::HttpSample sample, const std::string &name, timespec stamp)
{
    _metrics->process_netprobe_http_result(sample, name, stamp);
}

void NetProbeStreamHandler::probe_signal_doh_result(uint16_t http_status, uint8_t rcode, bool parse_ok, uint64_t cert_expiry_epoch, visor::http::HttpTimings timings, const std::string &name, timespec stamp)
{
    _metrics->process_netprobe_doh_result(http_status, rcode, parse_ok, cert_expiry_epoch, timings, name, stamp);
}

void NetProbeMetricsBucket::specialized_merge(const AbstractMetricsBucket &o, Metric::Aggregate agg_operator)
{
    // static because caller guarantees only our own bucket type
    const auto &other = static_cast<const NetProbeMetricsBucket &>(o);

    std::shared_lock r_lock(other._mutex);
    std::unique_lock w_lock(_mutex);

    // a merge starts from a fresh bucket, which has no target attributes until a bucket of the window hands it them
    if (!_target_attributes) {
        _target_attributes = other._target_attributes;
    }

    for (const auto &target : other._targets_metrics) {
        const auto &targetId = target.first;
        get_or_create_target(targetId);

        if (group_enabled(group::NetProbeMetrics::Counters)) {
            _targets_metrics[targetId]->attempts += target.second->attempts;
            _targets_metrics[targetId]->successes += target.second->successes;
            _targets_metrics[targetId]->connect_failures += target.second->connect_failures;
            _targets_metrics[targetId]->dns_failures += target.second->dns_failures;
            _targets_metrics[targetId]->timed_out += target.second->timed_out;
            _targets_metrics[targetId]->http_status_failures += target.second->http_status_failures;
            _targets_metrics[targetId]->content_failures += target.second->content_failures;
            _targets_metrics[targetId]->top_status_codes.merge(target.second->top_status_codes);
            _targets_metrics[targetId]->dns_response_failures += target.second->dns_response_failures;
            _targets_metrics[targetId]->top_rcodes.merge(target.second->top_rcodes);
            // Keep the NEWEST window's cert expiry. Buckets merge newest-first (window_merged_json /
            // multiple_merge iterate _metric_buckets, whose front is the live/newest bucket, into a
            // fresh accumulator), so the first non-zero value seen is the current certificate. Do NOT
            // take the max: a reissue or rollback to a shorter-lived cert must LOWER the reported
            // expiry — maxing would keep the old cert's later date and suppress expiry alerts.
            if (_targets_metrics[targetId]->tls_cert_expiry_epoch == 0) {
                _targets_metrics[targetId]->tls_cert_expiry_epoch = target.second->tls_cert_expiry_epoch;
            }
        }
        if (group_enabled(group::NetProbeMetrics::Histograms)) {
            _targets_metrics[targetId]->h_time_us.merge(target.second->h_time_us);
        }
        if (group_enabled(group::NetProbeMetrics::Quantiles)) {
            _targets_metrics[targetId]->q_time_us.merge(target.second->q_time_us, agg_operator);
            _targets_metrics[targetId]->q_response_size.merge(target.second->q_response_size, agg_operator);
        }
        if (group_enabled(group::NetProbeMetrics::HttpResponsePhases)) {
            _targets_metrics[targetId]->q_dns_us.merge(target.second->q_dns_us, agg_operator);
            _targets_metrics[targetId]->q_connect_us.merge(target.second->q_connect_us, agg_operator);
            _targets_metrics[targetId]->q_tls_us.merge(target.second->q_tls_us, agg_operator);
            _targets_metrics[targetId]->q_ttfb_us.merge(target.second->q_ttfb_us, agg_operator);
        }
    }
}

Metric::LabelMap NetProbeMetricsBucket::labels_for_target(const Metric::LabelMap &add_labels, const std::string &target) const
{
    auto labels = add_labels;
    if (_target_attributes) {
        if (auto attrs = _target_attributes->find(target); attrs != _target_attributes->end()) {
            for (const auto &[key, value] : attrs->second) {
                labels[key] = value;
            }
        }
    }
    labels["target"] = target;
    return labels;
}

void NetProbeMetricsBucket::to_prometheus(PrometheusSerializer &ser, Metric::LabelMap add_labels) const
{
    std::shared_lock r_lock(_mutex);

    for (const auto &target : _targets_metrics) {
        auto target_labels = labels_for_target(add_labels, target.first);

        if (group_enabled(group::NetProbeMetrics::Counters)) {
            target.second->attempts.to_prometheus(ser, target_labels);
            target.second->successes.to_prometheus(ser, target_labels);
            target.second->connect_failures.to_prometheus(ser, target_labels);
            target.second->dns_failures.to_prometheus(ser, target_labels);
            target.second->timed_out.to_prometheus(ser, target_labels);
            target.second->http_status_failures.to_prometheus(ser, target_labels);
            target.second->content_failures.to_prometheus(ser, target_labels);
            target.second->top_status_codes.to_prometheus(ser, target_labels);
            target.second->dns_response_failures.to_prometheus(ser, target_labels);
            target.second->top_rcodes.to_prometheus(ser, target_labels);
            if (target.second->tls_cert_expiry_epoch != 0) {
                target.second->tls_cert_expiry.clear();
                target.second->tls_cert_expiry += target.second->tls_cert_expiry_epoch;
                target.second->tls_cert_expiry.to_prometheus(ser, target_labels);
            }
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
                target.second->q_response_size.to_prometheus(ser, target_labels);
            } catch (const std::exception &) {
            }
        }

        if (group_enabled(group::NetProbeMetrics::HttpResponsePhases)) {
            try {
                target.second->q_dns_us.to_prometheus(ser, target_labels);
                target.second->q_connect_us.to_prometheus(ser, target_labels);
                target.second->q_tls_us.to_prometheus(ser, target_labels);
                target.second->q_ttfb_us.to_prometheus(ser, target_labels);
            } catch (const std::exception &) {
            }
        }
    }
}

void NetProbeMetricsBucket::to_opentelemetry(metrics::v1::ScopeMetrics &scope, timespec &start_ts, timespec &end_ts, Metric::LabelMap add_labels) const
{
    std::shared_lock r_lock(_mutex);

    for (const auto &target : _targets_metrics) {
        auto target_labels = labels_for_target(add_labels, target.first);

        if (group_enabled(group::NetProbeMetrics::Counters)) {
            target.second->attempts.to_opentelemetry(scope, start_ts, end_ts, target_labels);
            target.second->successes.to_opentelemetry(scope, start_ts, end_ts, target_labels);
            target.second->connect_failures.to_opentelemetry(scope, start_ts, end_ts, target_labels);
            target.second->dns_failures.to_opentelemetry(scope, start_ts, end_ts, target_labels);
            target.second->timed_out.to_opentelemetry(scope, start_ts, end_ts, target_labels);
            target.second->http_status_failures.to_opentelemetry(scope, start_ts, end_ts, target_labels);
            target.second->content_failures.to_opentelemetry(scope, start_ts, end_ts, target_labels);
            target.second->top_status_codes.to_opentelemetry(scope, start_ts, end_ts, target_labels);
            target.second->dns_response_failures.to_opentelemetry(scope, start_ts, end_ts, target_labels);
            target.second->top_rcodes.to_opentelemetry(scope, start_ts, end_ts, target_labels);
            if (target.second->tls_cert_expiry_epoch != 0) {
                target.second->tls_cert_expiry.clear();
                target.second->tls_cert_expiry += target.second->tls_cert_expiry_epoch;
                target.second->tls_cert_expiry.to_opentelemetry(scope, start_ts, end_ts, target_labels);
            }
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
                target.second->q_response_size.to_opentelemetry(scope, start_ts, end_ts, target_labels);
            } catch (const std::exception &) {
            }
        }

        if (group_enabled(group::NetProbeMetrics::HttpResponsePhases)) {
            try {
                target.second->q_dns_us.to_opentelemetry(scope, start_ts, end_ts, target_labels);
                target.second->q_connect_us.to_opentelemetry(scope, start_ts, end_ts, target_labels);
                target.second->q_tls_us.to_opentelemetry(scope, start_ts, end_ts, target_labels);
                target.second->q_ttfb_us.to_opentelemetry(scope, start_ts, end_ts, target_labels);
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
            target.second->http_status_failures.to_json(j["targets"][targetId]);
            target.second->content_failures.to_json(j["targets"][targetId]);
            target.second->top_status_codes.to_json(j["targets"][targetId]);
            target.second->dns_response_failures.to_json(j["targets"][targetId]);
            target.second->top_rcodes.to_json(j["targets"][targetId]);
            if (target.second->tls_cert_expiry_epoch != 0) {
                target.second->tls_cert_expiry.clear();
                target.second->tls_cert_expiry += target.second->tls_cert_expiry_epoch;
                target.second->tls_cert_expiry.to_json(j["targets"][targetId]);
            }
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
                target.second->q_response_size.to_json(j["targets"][targetId]);
            } catch (const std::exception &) {
            }
        }

        if (group_enabled(group::NetProbeMetrics::HttpResponsePhases)) {
            try {
                target.second->q_dns_us.to_json(j["targets"][targetId]);
                target.second->q_connect_us.to_json(j["targets"][targetId]);
                target.second->q_tls_us.to_json(j["targets"][targetId]);
                target.second->q_ttfb_us.to_json(j["targets"][targetId]);
            } catch (const std::exception &) {
            }
        }
    }
}

void NetProbeMetricsBucket::process_filtered()
{
}

Target &NetProbeMetricsBucket::get_or_create_target(const std::string &target)
{
    auto it = _targets_metrics.find(target);
    if (it == _targets_metrics.end()) {
        auto t = std::make_unique<Target>();
        // Honor topn_count / topn_percentile_threshold on the per-target TopN metrics.
        t->top_status_codes.set_settings(_topn_count, _topn_percentile_threshold);
        t->top_rcodes.set_settings(_topn_count, _topn_percentile_threshold);
        it = _targets_metrics.emplace(target, std::move(t)).first;
    }
    return *it->second;
}

void NetProbeMetricsBucket::process_failure(ErrorType error, const std::string &target)
{
    std::unique_lock lock(_mutex);
    get_or_create_target(target);
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
    std::unique_lock lock(_mutex);
    get_or_create_target(target);
    if (group_enabled(group::NetProbeMetrics::Counters)) {
        ++_targets_metrics[target]->attempts;
    }
}

void NetProbeMetricsBucket::new_transaction(bool deep, NetProbeTransaction xact)
{
    std::unique_lock lock(_mutex);

    get_or_create_target(xact.target);
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

void NetProbeMetricsManager::expire_ping_requests(timespec as_of)
{
    _ping_manager->expire_transactions(as_of, [this](const NetProbeTransaction &xact) {
        live_bucket()->process_failure(ErrorType::Timeout, xact.target);
    });
}

void NetProbeMetricsManager::process_netprobe_icmp(pcpp::IcmpLayer *layer, const std::string &target, timespec stamp)
{
    // A received packet: the receiver has passed on what it read before it, so a request with no reply by its
    // read time has none within the TTL. Before the base event, which may shift the period. A send expires
    // nothing: after the loop was held up, its stamp can be ahead of replies not yet passed on.
    if (layer->getMessageType() != pcpp::ICMP_ECHO_REQUEST) {
        expire_ping_requests(stamp);
    }
    // base event
    new_event(stamp);

    if (layer->getMessageType() == pcpp::ICMP_ECHO_REQUEST) {
        if (auto request = layer->getEchoRequestData(); request != nullptr) {
            auto ping_id = (static_cast<uint32_t>(request->header->id) << 16) | request->header->sequence;
            _ping_manager->start_transaction(std::to_string(ping_id), {{stamp, {0, 0}}, target});
        }
        live_bucket()->process_attempts(_deep_sampling_now, target);
    } else if (layer->getMessageType() == pcpp::ICMP_ECHO_REPLY) {
        if (auto reply = layer->getEchoReplyData(); reply != nullptr) {
            auto ping_id = (static_cast<uint32_t>(reply->header->id) << 16) | reply->header->sequence;
            auto xact = _ping_manager->maybe_end_transaction(std::to_string(ping_id), stamp);
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
    // a received packet expires requests as of its read time, as in process_netprobe_icmp
    if (layer->getMessageType() != pcpp::ICMPv6MessageType::ICMPv6_ECHO_REQUEST) {
        expire_ping_requests(stamp);
    }
    // base event
    new_event(stamp);
    // getIdentifier()/getSequenceNr() already byte-swap to host order inside pcpp (be16toh),
    // matching the htobe16 the send side used; do not add another ntohs.
    auto ping_id = (static_cast<uint32_t>(layer->getIdentifier()) << 16) | layer->getSequenceNr();
    if (layer->getMessageType() == pcpp::ICMPv6MessageType::ICMPv6_ECHO_REQUEST) {
        _ping_manager->start_transaction(std::to_string(ping_id), {{stamp, {0, 0}}, target});
        live_bucket()->process_attempts(_deep_sampling_now, target);
    } else if (layer->getMessageType() == pcpp::ICMPv6MessageType::ICMPv6_ECHO_REPLY) {
        auto xact = _ping_manager->maybe_end_transaction(std::to_string(ping_id), stamp);
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

void NetProbeMetricsBucket::process_netprobe_http(bool deep, const visor::http::HttpSample &sample, const std::string &target)
{
    // Take _mutex like new_transaction — both mutate q_time_us/h_time_us sketches
    // and the TopN which the scrape thread reads under shared_lock.
    // process_failure/process_attempts also lock _mutex (for their map insert), but
    // their callers always invoke them sequentially — never while this lock is held.
    std::unique_lock lock(_mutex);

    auto &t = get_or_create_target(target);

    // Counters (status outcome) are always recorded when the group is on —
    // like new_transaction's successes++ (not gated on `deep`).
    if (group_enabled(group::NetProbeMetrics::Counters)) {
        t.top_status_codes.update(std::to_string(sample.status));
        if (!sample.status_ok) {
            ++t.http_status_failures;
        } else if (sample.content_check == 2) {
            ++t.content_failures;
        } else {
            ++t.successes;
        }
        if (sample.cert_expiry_epoch != 0) {
            t.tls_cert_expiry_epoch = sample.cert_expiry_epoch; // latest non-zero wins
        }
    }

    // Sketches are gated on `deep` (deep sampling) exactly like new_transaction.
    // Histograms is default-ON and drives response_min_us/max_us via h_time_us.
    if (deep && group_enabled(group::NetProbeMetrics::Histograms)) {
        t.h_time_us.update(sample.timings.total_us);
    }
    if (deep && group_enabled(group::NetProbeMetrics::Quantiles)) {
        t.q_time_us.update(sample.timings.total_us);
        t.q_response_size.update(sample.response_size);
    }
    if (deep && group_enabled(group::NetProbeMetrics::HttpResponsePhases)) {
        t.q_dns_us.update(sample.timings.dns_us);
        t.q_connect_us.update(sample.timings.connect_us);
        t.q_tls_us.update(sample.timings.tls_us);
        t.q_ttfb_us.update(sample.timings.ttfb_us);
    }
}

void NetProbeMetricsManager::process_netprobe_http_result(const visor::http::HttpSample &sample, const std::string &target, timespec stamp)
{
    new_event(stamp);
    live_bucket()->process_attempts(_deep_sampling_now, target);
    live_bucket()->process_netprobe_http(_deep_sampling_now, sample, target);
}

void NetProbeMetricsManager::process_netprobe_http_failure(ErrorType error, const std::string &target)
{
    timespec stamp;
    std::timespec_get(&stamp, TIME_UTC);
    new_event(stamp);
    live_bucket()->process_attempts(_deep_sampling_now, target);
    live_bucket()->process_failure(error, target);
}

void NetProbeMetricsBucket::process_netprobe_doh(bool deep, uint16_t http_status, uint8_t rcode, bool parse_ok, uint64_t cert_expiry_epoch, const visor::http::HttpTimings &timings, const std::string &target)
{
    std::unique_lock lock(_mutex);

    auto &t = get_or_create_target(target);

    if (group_enabled(group::NetProbeMetrics::Counters)) {
        // DoH responses are HTTP responses too: record the HTTP status breakdown (like the HTTP
        // probe) in addition to the DNS rcode breakdown below.
        t.top_status_codes.update(std::to_string(http_status));
        if (cert_expiry_epoch != 0) {
            t.tls_cert_expiry_epoch = cert_expiry_epoch;
        }
        if (http_status >= 200 && http_status < 400) {
            std::string rname;
            if (!parse_ok) {
                rname = "PARSE_ERROR";
            } else {
                auto it = visor::lib::dns::RCodeNames.find(rcode);
                rname = (it != visor::lib::dns::RCodeNames.end()) ? it->second : std::to_string(rcode);
            }
            t.top_rcodes.update(rname);
            if (parse_ok && rcode == 0) {
                ++t.successes;
            } else {
                ++t.dns_response_failures;
            }
        } else {
            ++t.http_status_failures;
        }
    }

    if (deep && group_enabled(group::NetProbeMetrics::Histograms)) {
        t.h_time_us.update(timings.total_us);
    }
    if (deep && group_enabled(group::NetProbeMetrics::Quantiles)) {
        t.q_time_us.update(timings.total_us);
    }
    if (deep && group_enabled(group::NetProbeMetrics::HttpResponsePhases)) {
        t.q_dns_us.update(timings.dns_us);
        t.q_connect_us.update(timings.connect_us);
        t.q_tls_us.update(timings.tls_us);
        t.q_ttfb_us.update(timings.ttfb_us);
    }
}

void NetProbeMetricsManager::process_netprobe_doh_result(uint16_t http_status, uint8_t rcode, bool parse_ok, uint64_t cert_expiry_epoch, const visor::http::HttpTimings &timings, const std::string &target, timespec stamp)
{
    new_event(stamp);
    live_bucket()->process_attempts(_deep_sampling_now, target);
    live_bucket()->process_netprobe_doh(_deep_sampling_now, http_status, rcode, parse_ok, cert_expiry_epoch, timings, target);
}

void NetProbeMetricsManager::process_netprobe_doh_failure(ErrorType error, const std::string &target)
{
    timespec stamp;
    std::timespec_get(&stamp, TIME_UTC);
    new_event(stamp);
    live_bucket()->process_attempts(_deep_sampling_now, target);
    live_bucket()->process_failure(error, target);
}

}
