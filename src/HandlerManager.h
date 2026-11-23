/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "AbstractManager.h"
#include "StreamHandler.h"
#include <spdlog/spdlog.h>

namespace visor {

// a handler configuration that pktvisord refuses as written: an invalid_argument, which the admin API answers 422
class HandlerException : public std::invalid_argument
{
public:
    HandlerException(const char *msg)
        : std::invalid_argument(msg)
    {
    }
    HandlerException(const std::string &msg)
        : std::invalid_argument(msg)
    {
    }
};

/**
 * called from HTTP threads so must be thread safe
 */
class HandlerManager : public AbstractManager<StreamHandler>
{
    CoreRegistry *_registry;
    std::map<std::string, std::unique_ptr<Configurable>> _global_handler_config;
    /**
     * the default number of periods we will maintain in the window for handlers
     */
    unsigned int _default_num_periods{5};
    uint32_t _default_deep_sample_rate{100};

public:
    HandlerManager(CoreRegistry *registry)
        : AbstractManager<StreamHandler>()
        , _registry(registry)
    {
    }

    virtual ~HandlerManager()
    {
    }

    // override to atomically ensure we don't remove if there are active consumers
    void module_remove(const std::string &name) override
    {
        std::unique_lock lock(_map_mutex);
        if (_map.count(name) == 0) {
            throw std::runtime_error("module name does not exist");
        }
        if (_map[name]->consumer_count()) {
            throw std::runtime_error("unable to remove, handler has consumers");
        }
        _map[name]->stop();
        _map.erase(name);
    }

    void set_default_num_periods(unsigned int n)
    {
        _default_num_periods = n;
    }
    void set_default_deep_sample_rate(uint32_t r)
    {
        _default_deep_sample_rate = r;
    }

    unsigned int default_num_periods() const
    {
        return _default_num_periods;
    }

    uint32_t default_deep_sample_rate() const
    {
        return _default_deep_sample_rate;
    }

    void set_default_handler_config(const YAML::Node &config_yaml)
    {
        for (YAML::const_iterator it = config_yaml.begin(); it != config_yaml.end(); ++it) {

            auto handler_module_type = it->first.as<std::string>();
            if (!it->second.IsMap()) {
                throw ConfigException("expecting global_handler_config configuration map");
            }

            auto handler_plugin = _registry->handler_plugins().find(std::make_pair(handler_module_type, CoreRegistry::DEFAULT_HANDLER_PLUGIN_VERSION));
            if (handler_plugin == _registry->handler_plugins().end()) {
                spdlog::get("visor")->warn(fmt::format("global_handler_config configures stream handler type '{}' which is not available, ignoring", handler_module_type));
                return;
            }

            if (_global_handler_config.count(handler_module_type) > 0) {
                throw ConfigException(fmt::format("stream handler type '{}' already exists in global_handler_config configuration", handler_module_type));
            }

            auto pair = _global_handler_config.emplace(handler_module_type, std::make_unique<Configurable>());
            pair.first->second->config_set_yaml(it->second);
        }
    }

    auto get_default_configuration(const YAML::Node &handler_node)
    {
        if (!handler_node || !handler_node.IsMap()) {
            throw HandlerException("missing or invalid handler configuration at key 'handlers'");
        }

        bool handler_sequence = false;
        if (!handler_node["modules"] || (!handler_node["modules"].IsMap() && !handler_node["modules"].IsSequence())) {
            throw HandlerException("missing or invalid handler modules at key 'modules'");
        } else if (handler_node["modules"].IsSequence()) {
            handler_sequence = true;
        }

        Config window_config;
        if (handler_node["window_config"] && handler_node["window_config"].IsMap()) {
            try {
                window_config.config_set_yaml(handler_node["window_config"]);
            } catch (ConfigException &e) {
                throw HandlerException(fmt::format("invalid stream handler window config: {}", e.what()));
            }
        } else {
            window_config.config_set<uint64_t>("num_periods", _default_num_periods);
            window_config.config_set<uint64_t>("deep_sample_rate", _default_deep_sample_rate);
        }

        return std::make_pair(window_config, handler_sequence);
    }

    struct HandlerData {
        std::string name;
        std::string type;
        std::string version;
        Config config;
        Config filter;
    };

    HandlerData validate_handler(const YAML::const_iterator &hander_iterator, const std::string &policy_name, Config &window_config, bool sequence)
    {
        // Per handler
        const auto it_module = [&]() -> const YAML::Node {
            return sequence ? *hander_iterator : hander_iterator->second;
        }();

        HandlerData handler;
        if (sequence) {
            // each item names its handler, as its first key: read nothing from an item without one
            if (!it_module.IsMap() || it_module.size() == 0 || !it_module.begin()->first.IsScalar()) {
                throw HandlerException("expecting handler module identifier");
            }
            handler.name = it_module.begin()->first.as<std::string>();
        } else {
            if (!hander_iterator->first.IsScalar()) {
                throw HandlerException("expecting handler module identifier");
            }
            handler.name = hander_iterator->first.as<std::string>();
        }

        if (!it_module.IsMap()) {
            throw HandlerException("expecting Handler configuration map");
        }

        auto module = YAML::Clone(it_module);
        if (!module["type"] || !module["type"].IsScalar()) {
            module = module[handler.name];
            if (!module["type"] || !module["type"].IsScalar()) {
                throw HandlerException("missing or invalid stream handler type at key 'type'");
            }
        }

        handler.version = CoreRegistry::DEFAULT_HANDLER_PLUGIN_VERSION;
        if (module["require_version"]) {
            if (!module["require_version"].IsScalar()) {
                throw HandlerException("Invalid stream handler version at key 'require_version'");
            }
            handler.version = module["require_version"].as<std::string>();
        }

        handler.type = module["type"].as<std::string>();
        auto handler_plugin = _registry->handler_plugins().find(std::make_pair(handler.type, handler.version));
        if (handler_plugin == _registry->handler_plugins().end()) {
            throw HandlerException(fmt::format("Policy '{}' requires stream handler type '{}' and version '{}' which is not available", policy_name, handler.type, handler.version));
        }

        if (module["filter"]) {
            if (!module["filter"].IsMap()) {
                throw HandlerException("stream handler filter configuration is not a map");
            }
            try {
                handler.filter.config_set_yaml(module["filter"]);
            } catch (ConfigException &e) {
                throw HandlerException(fmt::format("invalid stream handler filter config for handler '{}': {}", handler.name, e.what()));
            }
        }

        if (auto it_global = _global_handler_config.find(handler.type); it_global != _global_handler_config.end()) {
            handler.config.config_merge(*it_global->second);
        }
        if (module["config"]) {
            if (!module["config"].IsMap()) {
                throw HandlerException("stream handler configuration is not a map");
            }
            try {
                handler.config.config_set_yaml(module["config"]);
            } catch (ConfigException &e) {
                throw HandlerException(fmt::format("invalid stream handler config for handler '{}': {}", handler.name, e.what()));
            }
        }
        Config handler_metrics;
        if (module["metric_groups"]) {
            if (!module["metric_groups"].IsMap()) {
                throw HandlerException("stream handler metric groups is not a map");
            }

            if (!module["metric_groups"]["enable"] && !module["metric_groups"]["disable"]) {
                throw HandlerException("stream handler metric groups should contain enable and/or disable tags");
            }

            try {
                handler_metrics.config_set_yaml(module["metric_groups"]);
            } catch (ConfigException &e) {
                throw HandlerException(fmt::format("invalid stream handler metrics for handler '{}': {}", handler.name, e.what()));
            }
        }
        spdlog::get("visor")->info("policy [{}]: instantiating Handler {} of type {}", policy_name, handler.name, handler.type);
        // note, currently merging the handler config with the window config. do they need to be separate?
        handler.config.config_merge(window_config);
        handler.filter.config_merge(handler_metrics);

        return handler;
    }
};

}
