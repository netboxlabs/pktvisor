/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "AbstractManager.h"
#include "AbstractModule.h"
#include "Configurable.h"
#include "InputModulePlugin.h"
#include <Corrade/Containers/StringStl.h>
#include <yaml-cpp/yaml.h>

namespace visor {

class InputStream;
class Policy;

class TapException : public std::runtime_error
{
public:
    TapException(const char *msg)
        : std::runtime_error(msg)
    {
    }
    TapException(const std::string &msg)
        : std::runtime_error(msg)
    {
    }
};

class Tap : public AbstractModule
{

    InputModulePlugin *_input_plugin;
    std::unique_ptr<Configurable> _tags;

public:
    Tap(const std::string &name, InputModulePlugin *input_plugin)
        : AbstractModule(name)
        , _input_plugin(input_plugin)
        , _tags(std::make_unique<Configurable>())
    {
        assert(input_plugin);
    }

    std::string get_input_name(const Configurable &config, const Configurable &filter);

    std::unique_ptr<InputStream> instantiate(const Configurable *config, const Configurable *filter, std::string input_name);

    bool tags_match_selector_yaml(const YAML::Node &tag_yaml, bool all);

    const InputModulePlugin *input_plugin() const
    {
        return _input_plugin;
    }

    void info_json(json &j) const override
    {
        j["input_type"] = _input_plugin->plugin();
        j["interface"] = _input_plugin->pluginInterface();
        config_json(j["config"]);
        _tags->config_json(j["tags"]);
    }

    void tags_set_yaml(const YAML::Node &tag_yaml)
    {
        _tags->config_set_yaml(tag_yaml);
    }
};

class TapManager : public AbstractManager<Tap>
{

    const CoreRegistry *_registry;

public:
    TapManager(const CoreRegistry *registry)
        : _registry(registry)
    {
    }

    virtual ~TapManager()
    {
    }

    std::vector<Tap *> load_from_str(const std::string &str);
    std::vector<Tap *> load(const YAML::Node &tap_yaml, bool strict = true, bool single = false);
    std::vector<std::string> get_input_taps_name(const YAML::Node &input_node);
};

}