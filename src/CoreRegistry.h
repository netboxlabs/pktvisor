/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "HandlerModulePlugin.h"
#include "InputModulePlugin.h"
#include <map>
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#endif
#include <yaml-cpp/yaml.h>
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif
namespace spdlog {
class logger;
}

namespace visor {

class InputStreamManager;
class HandlerManager;
class TapManager;
class PolicyManager;

/**
 * The "registry" of core data structures such as plugins, modules, taps and policies
 */
class CoreRegistry
{
public:
    static constexpr const char *DEFAULT_HANDLER_PLUGIN_VERSION{"1.0"};
    static constexpr const char *DEFAULT_INPUT_PLUGIN_VERSION{"1.0"};
    typedef std::map<std::pair<std::string, std::string>, std::unique_ptr<InputModulePlugin>> InputPluginMap;
    typedef std::map<std::pair<std::string, std::string>, std::unique_ptr<HandlerModulePlugin>> HandlerPluginMap;

private:
    // these hold instantiated visor::AbstractPlugin instances built from
    // PluginRegistry<T>::entries() at start() time. They act as factories for
    // visor::AbstractModule instances (held in the managers below) via the HTTP
    // admin API (through setup_routes) or Tap instantiation. Keyed by (alias, version).
    InputPluginMap _input_plugins;
    HandlerPluginMap _handler_plugins;

    // these hold instances of active visor::AbstractModule derived modules (the main event processors) which are created from the plugins above
    // any number can exist per plugin type at a time, each with their own life cycle
    std::unique_ptr<InputStreamManager> _input_manager;
    std::unique_ptr<HandlerManager> _handler_manager;

    // taps and policies
    std::unique_ptr<TapManager> _tap_manager;
    std::unique_ptr<PolicyManager> _policy_manager;

    std::shared_ptr<spdlog::logger> _logger;

public:
    CoreRegistry();
    ~CoreRegistry();

    void start(HttpServer *svr);
    void stop();

    // yaml based configuration
    void configure_from_file(const std::string &filename);
    void configure_from_str(const std::string &str);
    void configure_from_yaml(YAML::Node &node);

    [[nodiscard]] const InputPluginMap &input_plugins() const
    {
        return _input_plugins;
    }
    [[nodiscard]] const HandlerPluginMap &handler_plugins() const
    {
        return _handler_plugins;
    }
    [[nodiscard]] const InputStreamManager *input_manager() const
    {
        return _input_manager.get();
    }
    [[nodiscard]] const HandlerManager *handler_manager() const
    {
        return _handler_manager.get();
    }
    [[nodiscard]] const TapManager *tap_manager() const
    {
        return _tap_manager.get();
    }
    [[nodiscard]] const PolicyManager *policy_manager() const
    {
        return _policy_manager.get();
    }
    [[nodiscard]] InputPluginMap &input_plugins()
    {
        return _input_plugins;
    }
    [[nodiscard]] HandlerPluginMap &handler_plugins()
    {
        return _handler_plugins;
    }

    [[nodiscard]] InputStreamManager *input_manager()
    {
        return _input_manager.get();
    }

    [[nodiscard]] HandlerManager *handler_manager()
    {
        return _handler_manager.get();
    }

    [[nodiscard]] TapManager *tap_manager()
    {
        return _tap_manager.get();
    }
    [[nodiscard]] PolicyManager *policy_manager()
    {
        return _policy_manager.get();
    }
};

}