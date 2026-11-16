/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "CoreRegistry.h"
#include "HttpServer.h"
#include "OpenTelemetry.h"
#include <chrono>
#include <spdlog/spdlog.h>
#include <string>
#include <vector>

namespace visor {

struct PrometheusConfig {
    std::string default_path;
    std::string instance_label;
};

// The admin API routes that read or remove one module, or the metrics of several policies. Each looks its modules
// up when it uses them, so one that does not exist answers 404, also when a concurrent request removed it.
namespace api {
void get_tap(TapManager &taps, const std::string &name, httplib::Response &res);
void delete_tap(PolicyManager &policies, const std::string &name, httplib::Response &res);
void get_policy(PolicyManager &policies, const std::string &name, httplib::Response &res);
void delete_policy(PolicyManager &policies, const std::string &name, httplib::Response &res);
void get_default_bucket(PolicyManager &policies, const std::string &period, httplib::Response &res);
void get_default_window(PolicyManager &policies, const std::string &period, httplib::Response &res);
void get_default_prometheus(PolicyManager &policies, httplib::Response &res);
// with all set, names is every policy, listed beforehand: one removed since, or without the period, is skipped
void get_policies_metrics(PolicyManager &policies, const std::vector<std::string> &names, bool all, const std::string &period, bool merge, httplib::Response &res);
void get_policies_prometheus(PolicyManager &policies, const std::vector<std::string> &names, bool all, httplib::Response &res);
}

class CoreServer
{

    HttpServer _svr;
    CoreRegistry *_registry;

    std::shared_ptr<spdlog::logger> _logger;
    std::chrono::system_clock::time_point _start_time;

    std::unique_ptr<OpenTelemetry> _otel;
    void _setup_routes(const PrometheusConfig &prom_config);

public:
    CoreServer(CoreRegistry *registry, std::shared_ptr<spdlog::logger> logger, const HttpConfig &http_config, const OtelConfig &otel_config, const PrometheusConfig &prom_config);
    ~CoreServer();

    void start(const std::string &host, int port);
    void stop();

    const CoreRegistry *registry() const
    {
        return _registry;
    }

    CoreRegistry *registry()
    {
        return _registry;
    }

    void set_http_logger(httplib::Logger logger)
    {
        _svr.set_logger(logger);
    }
};

}