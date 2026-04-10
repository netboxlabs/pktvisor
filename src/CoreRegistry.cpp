/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "CoreRegistry.h"
#include "GeoDB.h"
#include "HandlerManager.h"
#include "InputStreamManager.h"
#include "Policies.h"
#include "Taps.h"
#include "CorradeCompat.h"
#include <Corrade/Utility/ConfigurationGroup.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

namespace visor {

CoreRegistry::CoreRegistry()
{

    _logger = spdlog::get("visor");
    if (!_logger) {
        _logger = spdlog::stderr_color_mt("visor");
    }

    // inputs
    _input_manager = std::make_unique<InputStreamManager>();

    // handlers
    _handler_manager = std::make_unique<HandlerManager>(this);

    // taps
    _tap_manager = std::make_unique<TapManager>(this);

    // policies policies
    _policy_manager = std::make_unique<PolicyManager>(this);
}

void CoreRegistry::start(HttpServer *svr)
{
    if (!svr) {
        _logger->warn("initializing modules with no HttpServer");
    }

    // initialize input plugins
    {
        auto plugin_list = _input_registry.pluginList();
        for (auto &s : plugin_list) {
            auto meta = _input_registry.metadata(s);
            if (!meta) {
                _logger->error("failed to load plugin metadata: {}", s);
                continue;
            }
            if (meta->data().hasValue("type") && meta->data().value("type") == "input") {
                if (!meta->data().hasValue("version")) {
                    _logger->error("version field is mandatory and was not provided by '{}'", s);
                }
                auto version = meta->data().value("version");
                if (_input_registry.loadState(s) == Corrade::PluginManager::LoadState::NotLoaded) {
                    _input_registry.load(s);
                }
                for (const auto &alias : meta->provides()) {
                    InputPluginPtr mod = _input_registry.instantiate(alias);
                    _logger->info("Load input stream plugin: {} version {} interface {}", alias, version, mod->pluginInterface());
                    mod->init_plugin(this, svr, &geo::GeoIP(), &geo::GeoASN());
                    auto result = _input_plugins.insert({std::make_pair(corrade_to_std_string(alias), version), std::move(mod)});
                    if (!result.second) {
                        throw std::runtime_error(fmt::format("Input alias '{}' with version '{}' was already loaded.", alias, version));
                    }
                }
            }
        }
    }

    // initialize handler plugins
    {
        auto plugin_list = _handler_registry.pluginList();
        for (auto &s : plugin_list) {
            auto meta = _handler_registry.metadata(s);
            if (!meta) {
                _logger->error("failed to load plugin metadata: {}", s);
                continue;
            }
            if (meta->data().hasValue("type") && meta->data().value("type") == "handler") {
                if (_handler_registry.loadState(s) == Corrade::PluginManager::LoadState::NotLoaded) {
                    _handler_registry.load(s);
                }
                if (!meta->data().hasValue("version")) {
                    _logger->error("version field is mandatory and was not provided by '{}'", s);
                }
                auto version = meta->data().value("version");
                for (const auto &alias : meta->provides()) {
                    HandlerPluginPtr mod = _handler_registry.instantiate(s);
                    _logger->info("Load stream handler plugin: {} version {} interface {}", alias, version, mod->pluginInterface());
                    mod->init_plugin(this, svr, &geo::GeoIP(), &geo::GeoASN());
                    auto result = _handler_plugins.insert({std::make_pair(corrade_to_std_string(alias), version), std::move(mod)});
                    if (!result.second) {
                        throw std::runtime_error(fmt::format("Handler alias '{}' with version '{}' was already loaded.", alias, version));
                    }
                }
            }
        }
    }
}

void CoreRegistry::stop()
{
    // gracefully stop all policies
    auto [policies, lock] = _policy_manager->module_get_all_locked();
    for (auto &[name, policy] : policies) {
        policy->stop();
    }
}

CoreRegistry::~CoreRegistry()
{
    stop();
}

void CoreRegistry::configure_from_yaml(YAML::Node &node)
{

    if (!node.IsMap() || !node["visor"]) {
        throw ConfigException("invalid schema");
    }

    if (!node["version"]) {
        _logger->info("missing version, using version \"1.0\"");
    } else if (!node["version"].IsScalar() || node["version"].as<std::string>() != "1.0") {
        throw ConfigException("unsupported version");
    }

    // taps
    if (node["visor"]["taps"] && node["visor"]["taps"].IsMap()) {
        _tap_manager->load(node["visor"]["taps"], true);
    }

    // global handlers config
    if (node["visor"]["global_handler_config"] && node["visor"]["global_handler_config"].IsMap()) {
        _handler_manager->set_default_handler_config(node["visor"]["global_handler_config"]);
    }

    // policies
    if (node["visor"]["policies"] && node["visor"]["policies"].IsMap()) {
        auto policies = _policy_manager->load(node["visor"]["policies"]);
    }
}

void CoreRegistry::configure_from_file(const std::string &filename)
{
    YAML::Node config = YAML::LoadFile(filename);
    configure_from_yaml(config);
}
void CoreRegistry::configure_from_str(const std::string &str)
{
    YAML::Node config = YAML::Load(str);
    configure_from_yaml(config);
}

}