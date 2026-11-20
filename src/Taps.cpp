/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "Taps.h"
#include "CoreRegistry.h"
#include "InputStream.h"
#include "Policies.h"
#include <algorithm>
#include <fmt/core.h>
#include <spdlog/spdlog.h>

namespace visor {

std::vector<Tap *> TapManager::load_from_str(const std::string &str, json *info)
{
    if (str.empty()) {
        throw TapException("empty data");
    }

    YAML::Node node = YAML::Load(str);

    if (!node.IsMap() || !node["visor"]) {
        throw TapException("invalid schema");
    }
    if (!node["version"]) {
        spdlog::get("visor")->info("missing version, using version \"1.0\"");
    } else if (!node["version"].IsScalar() || node["version"].as<std::string>() != "1.0") {
        throw PolicyException("unsupported version");
    }
    if (node["visor"]["taps"] && node["visor"]["taps"].IsMap()) {
        return load(node["visor"]["taps"], true, true, info);
    } else {
        throw TapException("no taps found in schema");
    }
}

// needs to be thread safe and transactional: any errors mean resources get cleaned up with no side effects
std::vector<Tap *> TapManager::load(const YAML::Node &tap_yaml, bool strict, bool single, json *info)
{
    assert(tap_yaml.IsMap());
    assert(spdlog::get("visor"));

    if (single && tap_yaml.size() > 1) {
        throw TapException(fmt::format("only a single tap expected but got {}", tap_yaml.size()));
    }

    std::vector<Tap *> result;
    for (YAML::const_iterator it = tap_yaml.begin(); it != tap_yaml.end(); ++it) {
        if (!it->first.IsScalar()) {
            throw TapException("expecting tap identifier");
        }
        auto tap_name = it->first.as<std::string>();
        spdlog::get("visor")->info("tap [{}]: parsing", tap_name);
        if (!it->second.IsMap()) {
            throw TapException("expecting tap configuration map");
        }
        if (!it->second["input_type"] || !it->second["input_type"].IsScalar()) {
            throw TapException("missing or invalid tap type key 'input_type'");
        }
        auto input_type = it->second["input_type"].as<std::string>();

        auto input_plugin = _registry->input_plugins().find(std::make_pair(input_type, CoreRegistry::DEFAULT_INPUT_PLUGIN_VERSION));
        if (input_plugin == _registry->input_plugins().end()) {
            if (strict) {
                throw TapException(fmt::format("Tap '{}' requires input stream type '{}' which is not available", tap_name, input_type));
            } else {
                spdlog::get("visor")->warn("Tap '{}' requires input stream type '{}' which is not available; skipping", tap_name, input_type);
                continue;
            }
        }

        auto tap_module = std::make_unique<Tap>(tap_name, input_plugin->second.get());

        if (it->second["config"]) {
            if (!it->second["config"].IsMap()) {
                throw TapException("tap configuration is not a map");
            }
            try {
                tap_module->config_set_yaml(it->second["config"]);
            } catch (const ConfigException &e) {
                throw TapException(fmt::format("invalid tap config: {}", e.what()));
            }
        }

        if (it->second["tags"]) {
            if (!it->second["tags"].IsMap()) {
                throw TapException("tap tags is not a map");
            }
            try {
                tap_module->tags_set_yaml(it->second["tags"]);
            } catch (const ConfigException &e) {
                throw TapException(fmt::format("invalid tap tags: {}", e.what()));
            }
        }

        if (info) {
            tap_module->info_json((*info)[tap_name]);
        }
        // will throw if it already exists. nothing else to clean up
        result.push_back(tap_module.get());
        module_add(std::move(tap_module));
        spdlog::get("visor")->info("tap [{}]: loaded, type {}", tap_name, input_type);
    }
    return result;
}

std::vector<std::string> TapManager::get_input_taps_name(const YAML::Node &input_node)
{
    if (input_node["tap"] && input_node["tap_selector"]) {
        throw TapException("input can have only key 'input.tap' or key 'input.tap_selector'");
    } else if (!input_node["tap"] && !input_node["tap_selector"]) {
        throw TapException("missing key 'input.tap' or key 'input.tap_selector'");
    }

    std::vector<std::string> taps_name;

    if (input_node["tap"]) {
        if (!input_node["tap"].IsScalar()) {
            throw PolicyException("invalid tap at key 'input.tap'");
        }
        auto tap_name = input_node["tap"].as<std::string>();
        if (!_registry->tap_manager()->module_exists(tap_name)) {
            // like a selector that matches no tap: the policy names taps that do not exist, which the API answers 422
            throw std::invalid_argument(fmt::format("tap '{}' does not exist", tap_name));
        }
        taps_name.push_back(tap_name);
    } else if (input_node["tap_selector"]) {

        auto tap_selector = input_node["tap_selector"];
        if (!tap_selector.IsMap()) {
            throw TapException("'input.tap_selector' is not a map");
        }
        if (tap_selector["all"] && tap_selector["any"]) {
            throw TapException("input can have only key 'input.tap_selector.all' or key 'input.tap_selector.any'");
        } else if (!tap_selector["all"] && !tap_selector["any"]) {
            throw TapException("missing key 'input.tap_selector.all' or key 'input.tap_selector.any'");
        }

        std::string binary_op{"all"};
        if (tap_selector["all"]) {
            if (!tap_selector["all"].IsSequence()) {
                throw TapException("'input.tap_selector.all' is not a sequence");
            }
        } else if (tap_selector["any"]) {
            if (!tap_selector["any"].IsSequence()) {
                throw TapException("'input.tap_selector.any' is not a sequence");
            }
            binary_op = "any";
        }

        auto [tap_modules, hm_lock] = module_get_all_locked();
        bool match{false};
        for (auto &[name, mod] : tap_modules) {
            auto tmod = dynamic_cast<Tap *>(mod.get());
            if (tmod && tmod->tags_match_selector_yaml(tap_selector[binary_op], (binary_op == "all"))) {
                taps_name.push_back(tmod->name());
                match = true;
            }
        }

        if (!match) {
            spdlog::get("visor")->info("no tap match found for specified 'input.tap_selector' tags");
            throw std::invalid_argument("no tap match found for specified 'input.tap_selector' tags");
        }
    }
    return taps_name;
}

std::string Tap::get_input_name(const Configurable &config, const Configurable &filter)
{
    Config c;
    c.config_merge(dynamic_cast<const Configurable &>(*this));
    c.config_merge(config);
    return _input_plugin->generate_input_name(name(), c, filter);
}

std::unique_ptr<InputStream> Tap::instantiate(const Configurable *config, const Configurable *filter, std::string input_name)
{
    Config c;
    c.config_merge(dynamic_cast<const Configurable &>(*this));
    c.config_merge(*config);
    auto module = _input_plugin->instantiate(input_name, &c, filter);

    return module;
}

bool Tap::tags_match_selector_yaml(const YAML::Node &tag_yaml, bool all)
{
    bool any_match = false;
    for (YAML::const_iterator it = tag_yaml.begin(); it != tag_yaml.end(); ++it) {
        // sequence: read nothing from an item that is not one key and value
        if (!it->IsMap() || it->size() != 1) {
            throw TapException("selector tag must contain only one key/value pair per sequence index");
        }

        const auto it_module = it->begin();
        // before the key is read as a string, which a key that is not a scalar cannot be
        if (!it_module->first.IsScalar()) {
            throw TapException("selector tag key must be a scalar");
        }
        const auto &key = it_module->first.as<std::string>();
        if (!it_module->second.IsScalar()) {
            throw TapException(fmt::format("tag key '{}' must have scalar value", key));
        }

        if (!_tags->config_exists(key)) {
            if (all) {
                return false;
            } else {
                continue;
            }
        }

        // the yaml library doesn't discriminate between scalar types, so we have to do that ourselves
        auto value = it_module->second.as<std::string>();
        if (std::regex_match(value, std::regex("[0-9]+"))) {
            uint64_t tag_value;
            try {
                tag_value = _tags->config_get<uint64_t>(key);
            } catch (ConfigException &e) {
                throw TapException(fmt::format("Tap [{}]: tag and selector value types are different for key '{}'", name(), key));
            }
            if (tag_value == it_module->second.as<uint64_t>()) {
                any_match = true;
            } else if (all) {
                return false;
            }

        } else if (std::regex_match(value, std::regex("true|false", std::regex_constants::icase))) {
            bool tag_value;
            try {
                tag_value = _tags->config_get<bool>(key);
            } catch (ConfigException &e) {
                throw TapException(fmt::format("Tap [{}]: tag and selector value types are different for key '{}'", name(), key));
            }
            if (tag_value == it_module->second.as<bool>()) {
                any_match = true;
            } else if (all) {
                return false;
            }
        } else {
            std::string tag_value;
            try {
                tag_value = _tags->config_get<std::string>(key);
            } catch (ConfigException &e) {
                throw TapException(fmt::format("Tap [{}]: tag and selector value types are different for key '{}'", name(), key));
            }
            if (tag_value == value) {
                any_match = true;
            } else if (all) {
                return false;
            }
        }
    }

    return any_match;
}
}
