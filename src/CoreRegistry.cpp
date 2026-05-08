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

// Forward-declared factory functions, one per plugin TU. Defined alongside
// each plugin's class. Referencing them here forces the linker to pull each
// plugin .o out of its static archive — no anchor / force-link symbol needed.
// We use forward declarations rather than including the plugin headers because
// the plugin headers transitively pull in heavy implementation details (e.g.
// netflow.h, pcap headers) that visor-core itself does not need.
namespace visor {
std::unique_ptr<InputModulePlugin> make_input_mock(std::string);
std::unique_ptr<InputModulePlugin> make_input_pcap(std::string);
std::unique_ptr<InputModulePlugin> make_input_dnstap(std::string);
std::unique_ptr<InputModulePlugin> make_input_flow(std::string);
std::unique_ptr<InputModulePlugin> make_input_netprobe(std::string);

std::unique_ptr<HandlerModulePlugin> make_handler_net_v1(std::string);
std::unique_ptr<HandlerModulePlugin> make_handler_net_v2(std::string);
std::unique_ptr<HandlerModulePlugin> make_handler_dns_v1(std::string);
std::unique_ptr<HandlerModulePlugin> make_handler_dns_v2(std::string);
std::unique_ptr<HandlerModulePlugin> make_handler_bgp(std::string);
std::unique_ptr<HandlerModulePlugin> make_handler_flow(std::string);
std::unique_ptr<HandlerModulePlugin> make_handler_dhcp(std::string);
std::unique_ptr<HandlerModulePlugin> make_handler_pcap(std::string);
std::unique_ptr<HandlerModulePlugin> make_handler_netprobe(std::string);
std::unique_ptr<HandlerModulePlugin> make_handler_input_resources(std::string);
std::unique_ptr<HandlerModulePlugin> make_handler_mock(std::string);
}

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

namespace {

template <typename Plugin>
struct BuiltinPlugin {
    std::string_view alias;
    std::string_view version;
    std::unique_ptr<Plugin> (*factory)(std::string);
};

// Single source of truth for built-in plugins. The factory function pointers
// reference symbols defined in each plugin's TU, which forces the linker to
// pull each plugin .o out of its static archive at executable link time.
const BuiltinPlugin<InputModulePlugin> g_builtin_inputs[] = {
    {"mock", "1.0", &visor::make_input_mock},
    {"pcap", "1.0", &visor::make_input_pcap},
    {"dnstap", "1.0", &visor::make_input_dnstap},
    {"flow", "1.0", &visor::make_input_flow},
    {"sflow", "1.0", &visor::make_input_flow},
    {"netprobe", "1.0", &visor::make_input_netprobe},
};

const BuiltinPlugin<HandlerModulePlugin> g_builtin_handlers[] = {
    {"net", "1.0", &visor::make_handler_net_v1},
    {"net", "2.0", &visor::make_handler_net_v2},
    {"dns", "1.0", &visor::make_handler_dns_v1},
    {"dns", "2.0", &visor::make_handler_dns_v2},
    {"bgp", "1.0", &visor::make_handler_bgp},
    {"flow", "1.0", &visor::make_handler_flow},
    {"dhcp", "1.0", &visor::make_handler_dhcp},
    {"pcap", "1.0", &visor::make_handler_pcap},
    {"netprobe", "1.0", &visor::make_handler_netprobe},
    {"input_resources", "1.0", &visor::make_handler_input_resources},
    {"mock_dyn", "1.0", &visor::make_handler_mock},
};

}

std::vector<CoreRegistry::PluginInfo> CoreRegistry::builtin_input_plugins()
{
    std::vector<PluginInfo> result;
    result.reserve(std::size(g_builtin_inputs));
    for (const auto &p : g_builtin_inputs) {
        result.push_back({std::string(p.alias), std::string(p.version)});
    }
    return result;
}

std::vector<CoreRegistry::PluginInfo> CoreRegistry::builtin_handler_plugins()
{
    std::vector<PluginInfo> result;
    result.reserve(std::size(g_builtin_handlers));
    for (const auto &p : g_builtin_handlers) {
        result.push_back({std::string(p.alias), std::string(p.version)});
    }
    return result;
}

void CoreRegistry::start(HttpServer *svr)
{
    if (!svr) {
        _logger->warn("initializing modules with no HttpServer");
    }

    for (const auto &p : g_builtin_inputs) {
        auto mod = p.factory(std::string(p.alias));
        _logger->info("Load input stream plugin: {} version {} interface {}", p.alias, p.version, mod->pluginInterface());
        mod->init_plugin(this, svr, &geo::GeoIP(), &geo::GeoASN());
        auto result = _input_plugins.insert({std::make_pair(std::string(p.alias), std::string(p.version)), std::move(mod)});
        if (!result.second) {
            throw std::runtime_error(fmt::format("Input alias '{}' with version '{}' was already loaded.", p.alias, p.version));
        }
    }

    for (const auto &p : g_builtin_handlers) {
        auto mod = p.factory(std::string(p.alias));
        _logger->info("Load stream handler plugin: {} version {} interface {}", p.alias, p.version, mod->pluginInterface());
        mod->init_plugin(this, svr, &geo::GeoIP(), &geo::GeoASN());
        auto result = _handler_plugins.insert({std::make_pair(std::string(p.alias), std::string(p.version)), std::move(mod)});
        if (!result.second) {
            throw std::runtime_error(fmt::format("Handler alias '{}' with version '{}' was already loaded.", p.alias, p.version));
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