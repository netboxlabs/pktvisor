/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "CoreServer.h"
#include "HandlerManager.h"
#include "Metrics.h"
#include "Policies.h"
#include "PrometheusSerializer.h"
#include "Taps.h"
#include "visor_config.h"
#include <chrono>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>
#include <spdlog/stopwatch.h>
#include <vector>

namespace visor {

visor::CoreServer::CoreServer(CoreRegistry *r, std::shared_ptr<spdlog::logger> logger, const HttpConfig &http_config, const OtelConfig &otel_config, const PrometheusConfig &prom_config)
    : _svr(http_config)
    , _registry(r)
    , _logger(logger)
    , _start_time(std::chrono::system_clock::now())
{

    _logger = spdlog::get("visor");
    if (!_logger) {
        _logger = spdlog::stderr_color_mt("visor");
    }

    _registry->start(&_svr);

    if (otel_config.enable) {
        _otel = std::make_unique<OpenTelemetry>(otel_config);
    }

    _setup_routes(prom_config);

    if (!prom_config.instance_label.empty()) {
        Metric::add_static_label("instance", prom_config.instance_label);
    }
}

void CoreServer::start(const std::string &host, int port)
{
    if (!_svr.bind_to_port(host.c_str(), port)) {
        throw std::runtime_error("unable to bind to " + host + ":" + std::to_string(port));
    }
    _logger->info("web server listening on {}:{}", host, port);
    if (!_svr.listen_after_bind()) {
        throw std::runtime_error("error during listen");
    }
}

void CoreServer::stop()
{
    _svr.stop();
    _registry->stop();
}

CoreServer::~CoreServer()
{
    stop();
}

void CoreServer::_setup_routes(const PrometheusConfig &prom_config)
{

    _logger->info("Initialize server control plane");

    // Stop the server
    _svr.Delete(
        "/api/v1/server", [&]([[maybe_unused]] const httplib::Request &req, [[maybe_unused]] httplib::Response &res) {
            stop();
        });

    // General metrics retriever
    _svr.Get("/api/v1/metrics/app", [&]([[maybe_unused]] const httplib::Request &req, httplib::Response &res) {
        json j;
        try {
            j["app"]["version"] = VISOR_VERSION_NUM;
            j["app"]["up_time_min"] = float(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now() - _start_time).count()) / 60;
            res.set_content(j.dump(), "text/json");
        } catch (const std::exception &e) {
            res.status = 500;
            j["error"] = e.what();
            res.set_content(j.dump(), "text/json");
        }
    });
    // rates, DEPRECATED
    _svr.Get("/api/v1/metrics/rates", [&]([[maybe_unused]] const httplib::Request &req, httplib::Response &res) {
        json j;
        try {
            // just backwards compatibility
            j["packets"]["in"] = 0;
            j["packets"]["out"] = 0;
            j["warning"] = "deprecated: use 'live' data from /api/v1/metrics/bucket/0 instead";
            res.set_content(j.dump(), "text/json");
        } catch (const std::exception &e) {
            res.status = 500;
            j["error"] = e.what();
            res.set_content(j.dump(), "text/json");
        }
    });
    // 3.0.x compatible: reference "default" policy
    _svr.Get(R"(/api/v1/metrics/bucket/(\d+))", [&](const httplib::Request &req, httplib::Response &res) {
        json j;
        bool bc_period{false};
        if (!_registry->policy_manager()->module_exists("default")) {
            res.status = 404;
            j["error"] = "no \"default\" policy exists";
            res.set_content(j.dump(), "text/json");
            return;
        }
        try {
            auto [policy, lock] = _registry->policy_manager()->module_get_locked("default");
            uint64_t period(std::stol(req.matches[1]));
            for (auto &mod : policy->modules()) {
                auto hmod = dynamic_cast<StreamHandler *>(mod);
                if (hmod) {
                    spdlog::stopwatch sw;
                    hmod->window_json(j["1m"], period, false);
                    // hoist up the first "period" we see for backwards compatibility with 3.0.x
                    if (!bc_period && j["1m"][hmod->schema_key()].contains("period")) {
                        j["1m"]["period"] = j["1m"][hmod->schema_key()]["period"];
                        bc_period = true;
                    }
                    _logger->debug("{} bucket window_json elapsed time: {}", hmod->name(), sw);
                }
            }
            res.set_content(j.dump(), "text/json");
        } catch (const std::exception &e) {
            res.status = 500;
            j["error"] = e.what();
            res.set_content(j.dump(), "text/json");
        }
    });
    // 3.0.x compatible: reference "default" policy
    _svr.Get(R"(/api/v1/metrics/window/(\d+))", [&](const httplib::Request &req, httplib::Response &res) {
        json j;
        if (!_registry->policy_manager()->module_exists("default")) {
            res.status = 404;
            j["error"] = "no \"default\" policy exists";
            res.set_content(j.dump(), "text/json");
            return;
        }
        try {
            auto [policy, lock] = _registry->policy_manager()->module_get_locked("default");
            uint64_t period(std::stol(req.matches[1]));
            for (auto &mod : policy->modules()) {
                auto hmod = dynamic_cast<StreamHandler *>(mod);
                if (hmod) {
                    spdlog::stopwatch sw;
                    auto key = fmt::format("{}m", period);
                    hmod->window_json(j[key], period, true);
                    _logger->debug("{} window_json {} elapsed time: {}", hmod->name(), period, sw);
                }
            }
            res.set_content(j.dump(), "text/json");
        } catch (const std::exception &e) {
            res.status = 500;
            j["error"] = e.what();
            res.set_content(j.dump(), "text/json");
        }
    });
    // "default" policy prometheus
    if (!prom_config.default_path.empty()) {
        _logger->info("enabling prometheus metrics for \"default\" policy on: {}", prom_config.default_path);
        _svr.Get(prom_config.default_path.c_str(), [&]([[maybe_unused]] const httplib::Request &req, httplib::Response &res) {
            if (!_registry->policy_manager()->module_exists("default")) {
                res.status = 404;
                return;
            }
            try {
                std::stringstream output;
                PrometheusSerializer ser;
                auto [policy, lock] = _registry->policy_manager()->module_get_locked("default");
                for (auto &mod : policy->modules()) {
                    auto hmod = dynamic_cast<StreamHandler *>(mod);
                    if (hmod) {
                        spdlog::stopwatch sw;
                        hmod->window_prometheus(ser, {{"policy", "default"}});
                        _logger->debug("{} window_prometheus elapsed time: {}", hmod->name(), sw);
                    }
                }
                output << ser.finalize();
                res.set_content(output.str(), "text/plain");
            } catch (const std::exception &e) {
                res.status = 500;
                res.set_content(e.what(), "text/plain");
            }
        });
    }
    // Taps
    _svr.Get(R"(/api/v1/taps)", [&]([[maybe_unused]] const httplib::Request &req, httplib::Response &res) {
        json j;
        try {
            auto [tap_modules, hm_lock] = _registry->tap_manager()->module_get_all_locked();
            for (auto &[name, mod] : tap_modules) {
                auto tmod = dynamic_cast<Tap *>(mod.get());
                if (tmod) {
                    tmod->info_json(j[tmod->name()]);
                }
            }
            res.set_content(j.dump(), "text/json");
        } catch (const std::exception &e) {
            res.status = 500;
            j["error"] = e.what();
            res.set_content(j.dump(), "text/json");
        }
    });
    _svr.Get(fmt::format("/api/v1/taps/({})", AbstractModule::MODULE_ID_REGEX).c_str(), [&](const httplib::Request &req, httplib::Response &res) {
        json j = json::object();
        auto name = req.matches[1];
        if (!_registry->tap_manager()->module_exists(name)) {
            res.status = 404;
            j["error"] = "tap does not exists";
            res.set_content(j.dump(), "text/json");
            return;
        }
        try {
            auto [tap, lock] = _registry->tap_manager()->module_get_locked(name);
            tap->info_json(j[name]);
            res.set_content(j.dump(), "text/json");
        } catch (const std::exception &e) {
            res.status = 500;
            j["error"] = e.what();
            res.set_content(j.dump(), "text/json");
        }
    });
    _svr.Post(R"(/api/v1/taps)", [&]([[maybe_unused]] const httplib::Request &req, httplib::Response &res) {
        json j = json::object();
        if (!req.has_header("Content-Type")) {
            res.status = 400;
            j["error"] = "must include Content-Type header";
            res.set_content(j.dump(), "text/json");
            return;
        }
        auto content_type = req.get_header_value("Content-Type");
        if (content_type != "application/x-yaml" && content_type != "application/json") {
            res.status = 400;
            j["error"] = "Content-Type not supported";
            res.set_content(j.dump(), "text/json");
            return;
        }
        try {
            auto taps = _registry->tap_manager()->load_from_str(req.body);
            for (auto &mod : taps) {
                mod->info_json(j[mod->name()]);
            }
            res.status = 201;
            res.set_content(j.dump(), "text/json");
        } catch (const std::exception &e) {
            (std::string(e.what()).find("already") != std::string::npos) ? res.status = 409 : res.status = 500;
            j["error"] = e.what();
            res.set_content(j.dump(), "text/json");
        }
    });
    _svr.Delete(fmt::format("/api/v1/taps/({})", AbstractModule::MODULE_ID_REGEX).c_str(), [&](const httplib::Request &req, httplib::Response &res) {
        json j = json::object();
        auto name = req.matches[1];
        if (!_registry->tap_manager()->module_exists(name)) {
            res.status = 404;
            j["error"] = "tap does not exists";
            res.set_content(j.dump(), "text/json");
            return;
        }
        try {
            auto [tap, lock] = _registry->tap_manager()->module_get_locked(name);
            auto [policy_modules, hm_lock] = _registry->policy_manager()->module_get_all_locked();
            for (auto &[name, mod] : policy_modules) {
                auto tmod = dynamic_cast<Policy *>(mod.get());
                if (tmod) {
                    tmod->remove_tap(tap);
                }
            }
            lock.unlock();
            _registry->tap_manager()->module_remove(name);
            res.status = 200;
            res.set_content(j.dump(), "text/json");
        } catch (const std::exception &e) {
            res.status = 500;
            j["error"] = e.what();
            res.set_content(j.dump(), "text/json");
        }
    });
    // Policies
    _svr.Get(R"(/api/v1/policies)", [&]([[maybe_unused]] const httplib::Request &req, httplib::Response &res) {
        json j = json::object();
        try {
            auto [policy_modules, hm_lock] = _registry->policy_manager()->module_get_all_locked();
            for (auto &[name, mod] : policy_modules) {
                auto tmod = dynamic_cast<Policy *>(mod.get());
                if (tmod) {
                    tmod->info_json(j[tmod->name()]);
                }
            }
            res.set_content(j.dump(), "text/json");
        } catch (const std::exception &e) {
            res.status = 500;
            j["error"] = e.what();
            res.set_content(j.dump(), "text/json");
        }
    });
    _svr.Post(R"(/api/v1/policies)", [&](const httplib::Request &req, httplib::Response &res) {
        json j = json::object();
        if (!req.has_header("Content-Type")) {
            res.status = 400;
            j["error"] = "must include Content-Type header";
            res.set_content(j.dump(), "text/json");
            return;
        }
        auto content_type = req.get_header_value("Content-Type");
        if (content_type != "application/x-yaml" && content_type != "application/json") {
            res.status = 400;
            j["error"] = "Content-Type not supported";
            res.set_content(j.dump(), "text/json");
            return;
        }
        try {
            auto policies = _registry->policy_manager()->load_from_str(req.body);
            for (auto &mod : policies) {
                mod->info_json(j[mod->name()]);
            }
            res.status = 201;
            res.set_content(j.dump(), "text/json");
        } catch (const std::invalid_argument &e) {
            res.status = 422;
            j["error"] = e.what();
            res.set_content(j.dump(), "text/json");
        } catch (const std::exception &e) {
            (std::string(e.what()).find("already") != std::string::npos) ? res.status = 409 : res.status = 500;
            j["error"] = e.what();
            res.set_content(j.dump(), "text/json");
        }
    });
    _svr.Get(fmt::format("/api/v1/policies/({})", AbstractModule::MODULE_ID_REGEX).c_str(), [&](const httplib::Request &req, httplib::Response &res) {
        json j = json::object();
        auto name = req.matches[1];
        if (!_registry->policy_manager()->module_exists(name)) {
            res.status = 404;
            j["error"] = "policy does not exists";
            res.set_content(j.dump(), "text/json");
            return;
        }
        try {
            auto [policy, lock] = _registry->policy_manager()->module_get_locked(name);
            policy->info_json(j[name]);
            res.set_content(j.dump(), "text/json");
        } catch (const std::exception &e) {
            res.status = 500;
            j["error"] = e.what();
            res.set_content(j.dump(), "text/json");
        }
    });
    _svr.Delete(fmt::format("/api/v1/policies/({})", AbstractModule::MODULE_ID_REGEX).c_str(), [&](const httplib::Request &req, httplib::Response &res) {
        json j = json::object();
        auto name = req.matches[1];
        if (!_registry->policy_manager()->module_exists(name)) {
            res.status = 404;
            j["error"] = "policy does not exists";
            res.set_content(j.dump(), "text/json");
            return;
        }
        try {
            _registry->policy_manager()->remove_policy(name);
            res.status = 200;
            res.set_content(j.dump(), "text/json");
        } catch (const std::exception &e) {
            res.status = 500;
            j["error"] = e.what();
            res.set_content(j.dump(), "text/json");
        }
    });
    _svr.Get(fmt::format("/api/v1/policies/({})/metrics/(window|bucket)/(\\d+)", AbstractModule::MODULE_ID_REGEX).c_str(), [&](const httplib::Request &req, httplib::Response &res) {
        json j = json::object();
        auto name = req.matches[1];
        std::vector<std::string> plist;
        if (name == "__all") {
            // special route to get all policy metrics in one call, for scraping performance reasons
            plist = _registry->policy_manager()->module_get_keys();
        } else if (!_registry->policy_manager()->module_exists(name)) {
            res.status = 404;
            j["error"] = "policy does not exist";
            res.set_content(j.dump(), "text/json");
            return;
        } else {
            plist.emplace_back(name);
        }
        try {
            uint64_t period(std::stol(req.matches[3]));
            auto merge = (req.matches[2] == "window");
            for (const auto &p_mname : plist) {
                spdlog::stopwatch psw;
                auto [policy, lock] = _registry->policy_manager()->module_get_locked(p_mname);
                try {
                    policy->json_metrics(j, period, merge);
                } catch (const PeriodException &e) {
                    // if period is bad for a single policy in __all mode, skip it. otherwise fail
                    if (name == "__all") {
                        j.erase(policy->name());
                        continue;
                    } else {
                        throw e;
                    }
                }
                _logger->debug("{} policy json metrics elapsed time: {}", policy->name(), psw);
            }
            res.set_content(j.dump(), "text/json");
        } catch (const PeriodException &e) {
            res.status = 425; // 425 Too Early
            j["error"] = e.what();
            res.set_content(j.dump(), "text/json");
        } catch (const std::exception &e) {
            res.status = 500;
            j["error"] = e.what();
            res.set_content(j.dump(), "text/json");
        }
    });
    _svr.Get(fmt::format("/api/v1/policies/({})/metrics/prometheus", AbstractModule::MODULE_ID_REGEX).c_str(), [&](const httplib::Request &req, httplib::Response &res) {
        std::vector<std::string> plist;
        {
            auto name = req.matches[1];
            if (name == "__all") {
                // special route to get all policy metrics in one call, for scraping performance reasons
                plist = _registry->policy_manager()->module_get_keys();
            } else if (!_registry->policy_manager()->module_exists(name)) {
                res.status = 404;
                res.set_content("policy does not exists", "text/plain");
                return;
            } else {
                plist.emplace_back(name);
            }
        }
        std::stringstream output;
        for (const auto &p_mname : plist) {
            try {
                auto [policy, lock] = _registry->policy_manager()->module_get_locked(p_mname);
                policy->prometheus_metrics(output);
            } catch (const std::exception &e) {
                res.status = 500;
                res.set_content(e.what(), "text/plain");
            }
            res.set_content(output.str(), "text/plain");
        }
    });
    if (_otel) {
        _otel->OnInterval([&](metrics::v1::ResourceMetrics &resource) {
            for (const auto &p_mname : _registry->policy_manager()->module_get_keys()) {
                try {
                    auto [policy, lock] = _registry->policy_manager()->module_get_locked(p_mname);
                    auto scope = resource.add_scope_metrics();
                    scope->mutable_scope()->set_name("pktvisor/" + p_mname);
                    auto attr = scope->mutable_scope()->add_attributes();
                    attr->set_key("policy_name");
                    attr->mutable_value()->set_string_value(p_mname);
                    policy->opentelemetry_metrics(*scope);
                } catch (const std::exception &) {
                    return false;
                }
            }
            return true;
        });
    }
}
}
