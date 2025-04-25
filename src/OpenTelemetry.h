/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "HttpServer.h"
#include <functional>
#include <timer.hpp>
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#pragma GCC diagnostic ignored "-Woverflow"
#pragma GCC diagnostic ignored "-Wzero-as-null-pointer-constant"
#endif
#include "opentelemetry/proto/collector/metrics/v1/metrics_service.pb.h"
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

namespace visor {

constexpr char BIN_CONTENT_TYPE[] = "application/x-protobuf";

using namespace opentelemetry::proto;

struct OtelConfig {
    bool enable{false};
    std::string endpoint{"localhost"};
    std::string path{"/v1/metrics"};
    uint32_t port_number{4318};
    uint64_t interval_sec{60};
    std::string tls_cert;
    std::string tls_key;
};

class OpenTelemetry
{
    std::unique_ptr<httplib::Client> _client;
    collector::metrics::v1::ExportMetricsServiceRequest _request;
    metrics::v1::ResourceMetrics *_resource;
    std::shared_ptr<timer::interval_handle> _timer_handle;
    std::function<bool(metrics::v1::ResourceMetrics &resource)> _callback;

public:
    OpenTelemetry(const OtelConfig &config)
    {
        if (!config.tls_cert.empty() && !config.tls_key.empty()) {
            _client = std::make_unique<httplib::Client>(config.endpoint, config.port_number, config.tls_cert, config.tls_key);
        } else {
            _client = std::make_unique<httplib::Client>(config.endpoint, config.port_number);
        }
        _resource = _request.add_resource_metrics();
        static timer timer_thread{std::chrono::seconds(config.interval_sec)};
        auto path = config.path;
        _timer_handle = timer_thread.set_interval(std::chrono::seconds(config.interval_sec), [path, this] {
            _resource->clear_scope_metrics();
            if (_callback && _callback(*_resource)) {
                if (auto body_size = _request.ByteSizeLong(); body_size > sizeof(_request)) {
                    auto body = std::make_unique<char[]>(body_size);
                    _request.SerializeToArray(body.get(), body_size);
                    auto result = _client->Post(path, body.get(), body_size, BIN_CONTENT_TYPE);
                }
            }
        });
    }

    ~OpenTelemetry()
    {
        _timer_handle->cancel();
        _resource->clear_resource();
        _resource = nullptr;
    }

    void OnInterval(std::function<bool(metrics::v1::ResourceMetrics &resource)> callback)
    {
        _callback = callback;
    }
};
}