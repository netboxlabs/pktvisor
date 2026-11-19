/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "AbstractManager.h"
#include "InputStream.h"

namespace visor {

// an input configuration that pktvisord refuses as written: an invalid_argument, which the admin API answers 422
class InputStreamException : public std::invalid_argument
{
public:
    InputStreamException(const char *msg)
        : std::invalid_argument(msg)
    {
    }
    InputStreamException(const std::string &msg)
        : std::invalid_argument(msg)
    {
    }
};

/**
 * called from HTTP threads so must be thread safe
 */
class InputStreamManager : public AbstractManager<InputStream>
{

public:
    InputStreamManager()
        : AbstractManager<InputStream>()
    {
    }

    virtual ~InputStreamManager()
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
            throw std::runtime_error("unable to remove, stream has consumers");
        }
        _map[name]->stop();
        _map.erase(name);
    }

    auto get_config_and_filter(const YAML::Node &input_node)
    {
        if (!input_node || !input_node.IsMap()) {
            throw InputStreamException("missing or invalid policy input stream configuration at key 'input'");
        }
        if (!input_node["input_type"] || !input_node["input_type"].IsScalar()) {
            throw InputStreamException("missing or invalid input_type at key 'input.input_type'");
        }
        Config input_config;
        if (input_node["config"]) {
            if (!input_node["config"].IsMap()) {
                throw InputStreamException("input configuration is not a map");
            }
            try {
                input_config.config_set_yaml(input_node["config"]);
            } catch (ConfigException &e) {
                throw InputStreamException(fmt::format("invalid input config: {}", e.what()));
            }
        }
        Config input_filter;
        if (input_node["filter"]) {
            if (!input_node["filter"].IsMap()) {
                throw InputStreamException("input filter configuration is not a map");
            }
            try {
                input_filter.config_set_yaml(input_node["filter"]);
            } catch (ConfigException &e) {
                throw InputStreamException(fmt::format("invalid input filter: {}", e.what()));
            }
        }
        return std::make_pair(input_config, input_filter);
    }
};

}
