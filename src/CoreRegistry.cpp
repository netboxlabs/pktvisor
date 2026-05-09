/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "CoreRegistry.h"
#include "GeoDB.h"
#include "HandlerManager.h"
#include "InputStreamManager.h"
#include "Policies.h"
#include "Taps.h"

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

void CoreRegistry::add_input_plugin(std::string alias, std::string version, std::unique_ptr<InputModulePlugin> mod)
{
    if (alias.empty() || version.empty() || !mod) {
        throw std::invalid_argument(fmt::format("add_input_plugin: alias='{}' version='{}' mod={}", alias, version, mod ? "<set>" : "<null>"));
    }
    _pending_inputs.push_back({std::move(alias), std::move(version), std::move(mod)});
}

void CoreRegistry::add_handler_plugin(std::string alias, std::string version, std::unique_ptr<HandlerModulePlugin> mod)
{
    if (alias.empty() || version.empty() || !mod) {
        throw std::invalid_argument(fmt::format("add_handler_plugin: alias='{}' version='{}' mod={}", alias, version, mod ? "<set>" : "<null>"));
    }
    _pending_handlers.push_back({std::move(alias), std::move(version), std::move(mod)});
}

std::vector<CoreRegistry::PluginInfo> CoreRegistry::pending_input_plugins() const
{
    std::vector<PluginInfo> result;
    result.reserve(_pending_inputs.size());
    for (const auto &p : _pending_inputs) {
        result.push_back({p.alias, p.version});
    }
    return result;
}

std::vector<CoreRegistry::PluginInfo> CoreRegistry::pending_handler_plugins() const
{
    std::vector<PluginInfo> result;
    result.reserve(_pending_handlers.size());
    for (const auto &p : _pending_handlers) {
        result.push_back({p.alias, p.version});
    }
    return result;
}

void CoreRegistry::start(HttpServer *svr)
{
    if (!svr) {
        _logger->warn("initializing modules with no HttpServer");
    }

    for (auto &p : _pending_inputs) {
        _logger->info("Load input stream plugin: {} version {} interface {}", p.alias, p.version, p.mod->pluginInterface());
        p.mod->init_plugin(this, svr, &geo::GeoIP(), &geo::GeoASN());
        auto result = _input_plugins.insert({std::make_pair(p.alias, p.version), std::move(p.mod)});
        if (!result.second) {
            throw std::runtime_error(fmt::format("Input alias '{}' with version '{}' was already loaded.", p.alias, p.version));
        }
    }
    _pending_inputs.clear();

    for (auto &p : _pending_handlers) {
        _logger->info("Load stream handler plugin: {} version {} interface {}", p.alias, p.version, p.mod->pluginInterface());
        p.mod->init_plugin(this, svr, &geo::GeoIP(), &geo::GeoASN());
        auto result = _handler_plugins.insert({std::make_pair(p.alias, p.version), std::move(p.mod)});
        if (!result.second) {
            throw std::runtime_error(fmt::format("Handler alias '{}' with version '{}' was already loaded.", p.alias, p.version));
        }
    }
    _pending_handlers.clear();
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