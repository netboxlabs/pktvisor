/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "Configurable.h"
#include <atomic>
#include <exception>
#include <nlohmann/json.hpp>
#include <regex>
#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <variant>

namespace visor {

class Policy;
using json = nlohmann::json;

class AbstractModule : public Configurable
{

protected:
    /**
     * the module instance identifier: unique name associated with this instance
     */
    std::string _name;

    void common_info_json(json &j) const
    {
        j["module"]["name"] = _name;
        config_json(j["module"]["config"]);
    }

public:
    inline static const std::string MODULE_ID_REGEX = "[a-zA-Z_][a-zA-Z0-9_-]*";

    AbstractModule(const std::string &name)
        : _name(name)
    {
        if (!std::regex_match(name, std::regex(MODULE_ID_REGEX))) {
            // every name the admin API loads comes from the request: an invalid_argument, which it answers 422
            throw std::invalid_argument("invalid module name: " + name);
        }
    }

    virtual ~AbstractModule(){};

    virtual void info_json(json &j) const = 0;

    const std::string &name() const
    {
        return _name;
    }
};

class AbstractRunnableModule : public AbstractModule
{

protected:
    std::atomic_bool _running = false;

    void common_info_json(json &j) const;

public:
    AbstractRunnableModule(const std::string &name)
        : AbstractModule(name)
    {
    }

    virtual ~AbstractRunnableModule(){};

    virtual void start() = 0;
    virtual void stop() = 0;

    void info_json(json &j) const override;

    /**
     * the module schema key: the same for all instances of this module
     * used in schemas such as json
     */
    virtual std::string schema_key() const = 0;

    bool running() const
    {
        return _running;
    }
};

}
