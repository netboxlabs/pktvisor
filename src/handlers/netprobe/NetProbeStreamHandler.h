/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "AbstractMetricsManager.h"
#include "HttpTypes.h"
#include "PrometheusSerializer.h"
#include "NetProbeInputStream.h"
#include "StreamHandler.h"
#include "TransactionManager.h"
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wzero-as-null-pointer-constant"
#endif
#include <pcapplusplus/IcmpLayer.h>
#include <pcapplusplus/IcmpV6Layer.h>
#include <VisorTcpLayer.h>
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif
#include <limits>
#include <string>

namespace visor::handler::netprobe {

using namespace visor::lib::transaction;
using namespace visor::input::netprobe;

static constexpr const char *NET_PROBE_SCHEMA{"netprobe"};

namespace group {
enum NetProbeMetrics : visor::MetricGroupIntType {
    Counters,
    Quantiles,
    Histograms,
    HttpResponsePhases
};
}

struct NetProbeTransaction : public Transaction {
    std::string target;
};

struct Target {
    Quantile<uint64_t> q_time_us;
    Histogram<uint64_t> h_time_us;
    Counter attempts;
    Counter successes;
    Counter minimum;
    Counter maximum;
    Counter connect_failures;
    Counter dns_failures;
    Counter timed_out;
    Counter http_status_failures;
    TopN<std::string> top_status_codes;
    Counter dns_response_failures;
    TopN<std::string> top_rcodes;
    Quantile<uint64_t> q_dns_us;
    Quantile<uint64_t> q_connect_us;
    Quantile<uint64_t> q_tls_us;
    Quantile<uint64_t> q_ttfb_us;

    Target()
        : q_time_us(NET_PROBE_SCHEMA, {"response_quantiles_us"}, "Net Probe quantile in microseconds")
        , h_time_us(NET_PROBE_SCHEMA, {"response_histogram_us"}, "Net Probe histogram in microseconds")
        , attempts(NET_PROBE_SCHEMA, {"attempts"}, "Total Net Probe attempts")
        , successes(NET_PROBE_SCHEMA, {"successes"}, "Total Net Probe successes")
        , minimum(NET_PROBE_SCHEMA, {"response_min_us"}, "Minimum response time measured in the reporting interval")
        , maximum(NET_PROBE_SCHEMA, {"response_max_us"}, "Maximum response time measured in the reporting interval")
        , connect_failures(NET_PROBE_SCHEMA, {"connect_failures"}, "Total Net Probe failures when performing a TCP socket connection")
        , dns_failures(NET_PROBE_SCHEMA, {"dns_lookup_failures"}, "Total Net Probe failures when performing a DNS lookup")
        , timed_out(NET_PROBE_SCHEMA, {"packets_timeout"}, "Total Net Probe timeout transactions")
        , http_status_failures(NET_PROBE_SCHEMA, {"http_status_failures"}, "Total HTTP responses with a 4xx/5xx status")
        , top_status_codes(NET_PROBE_SCHEMA, "status_code", {"top_status_codes"}, "Top HTTP status codes")
        , dns_response_failures(NET_PROBE_SCHEMA, {"dns_response_failures"}, "Total DoH responses with HTTP 2xx but a non-NOERROR or unparseable DNS rcode")
        , top_rcodes(NET_PROBE_SCHEMA, "rcode", {"top_rcodes"}, "Top DNS response codes observed")
        , q_dns_us(NET_PROBE_SCHEMA, {"response_dns_us"}, "DNS resolution time quantiles in microseconds")
        , q_connect_us(NET_PROBE_SCHEMA, {"response_connect_us"}, "TCP connect time quantiles in microseconds")
        , q_tls_us(NET_PROBE_SCHEMA, {"response_tls_us"}, "TLS handshake time quantiles in microseconds")
        , q_ttfb_us(NET_PROBE_SCHEMA, {"response_ttfb_us"}, "Time-to-first-byte quantiles in microseconds")
    {
    }
};

class NetProbeMetricsBucket final : public visor::AbstractMetricsBucket
{

protected:
    mutable std::shared_mutex _mutex;
    std::map<std::string, std::unique_ptr<Target>> _targets_metrics;

public:
    NetProbeMetricsBucket()
    {
    }

    // visor::AbstractMetricsBucket
    void specialized_merge(const AbstractMetricsBucket &other, Metric::Aggregate agg_operator) override;
    void to_json(json &j) const override;
    void to_prometheus(PrometheusSerializer &ser, Metric::LabelMap add_labels = {}) const override;
    void to_opentelemetry(metrics::v1::ScopeMetrics &scope, timespec &start_ts, timespec &end_ts, Metric::LabelMap add_labels = {}) const override;
    void update_topn_metrics(size_t, uint64_t) override
    {
    }

    void on_set_read_only() override
    {
    }

    void process_filtered();
    void process_failure(ErrorType error, const std::string &target);
    void process_attempts(bool deep, const std::string &target);
    void new_transaction(bool deep, NetProbeTransaction xact);
    void process_netprobe_http(bool deep, uint16_t status, const visor::http::HttpTimings &timings, const std::string &target);
    void process_netprobe_doh(bool deep, uint16_t http_status, uint8_t rcode, bool parse_ok, const visor::http::HttpTimings &timings, const std::string &target);
};

class NetProbeMetricsManager final : public visor::AbstractMetricsManager<NetProbeMetricsBucket>
{
    typedef TransactionManager<std::string, NetProbeTransaction, std::hash<std::string>> NetProbeTransactionManager;
    std::unique_ptr<NetProbeTransactionManager> _request_reply_manager;

public:
    NetProbeMetricsManager(const Configurable *window_config)
        : visor::AbstractMetricsManager<NetProbeMetricsBucket>(window_config)
        , _request_reply_manager(std::make_unique<NetProbeTransactionManager>())
    {
    }

    void on_period_shift([[maybe_unused]] timespec stamp, [[maybe_unused]] const NetProbeMetricsBucket *maybe_expiring_bucket) override
    {
        // Clear all old transactions
        _request_reply_manager->clear();
    }

    void set_xact_ttl(uint32_t ttl)
    {
        _request_reply_manager = std::make_unique<NetProbeTransactionManager>(ttl);
    }

    void process_filtered(timespec stamp);
    void process_failure(ErrorType error, const std::string &target);
    void process_netprobe_icmp(pcpp::IcmpLayer *layer, const std::string &target, timespec stamp);
    void process_netprobe_icmpv6(pcpp::ICMPv6EchoLayer *layer, const std::string &target, timespec stamp);
    void process_netprobe_tcp(bool send, const std::string &target, timespec stamp);
    void process_netprobe_http_result(uint16_t status, const visor::http::HttpTimings &timings, const std::string &target, timespec stamp);
    void process_netprobe_http_failure(ErrorType error, const std::string &target);
    void process_netprobe_doh_result(uint16_t http_status, uint8_t rcode, bool parse_ok, const visor::http::HttpTimings &timings, const std::string &target, timespec stamp);
    void process_netprobe_doh_failure(ErrorType error, const std::string &target);
};

class NetProbeStreamHandler final : public visor::StreamMetricsHandler<NetProbeMetricsManager>
{

    NetProbeInputEventProxy *_netprobe_proxy;

    sigslot::connection _probe_send_connection;
    sigslot::connection _probe_recv_connection;
    sigslot::connection _probe_fail_connection;
    sigslot::connection _heartbeat_connection;
    sigslot::connection _probe_http_result_connection;
    sigslot::connection _probe_doh_result_connection;

    static const inline StreamMetricsHandler::ConfigsDefType _config_defs = {
        "recorded_stream",
        "xact_ttl_secs",
        "xact_ttl_ms"};

    static const inline NetProbeStreamHandler::GroupDefType _group_defs = {
        {"counters", group::NetProbeMetrics::Counters},
        {"quantiles", group::NetProbeMetrics::Quantiles},
        {"histograms", group::NetProbeMetrics::Histograms},
        {"http_response_phases", group::NetProbeMetrics::HttpResponsePhases}};

    void probe_signal_send(pcpp::Packet &, TestType, const std::string &, timespec);
    void probe_signal_recv(pcpp::Packet &, TestType, const std::string &, timespec);
    void probe_signal_fail(ErrorType, TestType, const std::string &);
    void probe_signal_http_result(uint16_t, visor::http::HttpTimings, const std::string &, timespec);
    void probe_signal_doh_result(uint16_t, uint8_t, bool, visor::http::HttpTimings, const std::string &, timespec);

    bool _filtering(pcpp::Packet *payload);

public:
    NetProbeStreamHandler(const std::string &name, InputEventProxy *proxy, const Configurable *window_config);
    ~NetProbeStreamHandler() = default;

    // visor::AbstractModule
    std::string schema_key() const override
    {
        return NET_PROBE_SCHEMA;
    }

    void start() override;
    void stop() override;
};

}
