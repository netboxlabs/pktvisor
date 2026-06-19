/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "AbstractModule.h"
#include "InputEventProxy.h"
#include "StreamHandler.h"
#include <fmt/ranges.h>

namespace visor {

class InputStream : public AbstractRunnableModule
{

    std::vector<const Policy *> _policies;

protected:
    typedef std::vector<std::string> ConfigsDefType;
    static constexpr uint8_t HEARTBEAT_INTERVAL = 30; // in seconds
    mutable std::shared_mutex _input_mutex;
    std::vector<std::unique_ptr<InputEventProxy>> _event_proxies;

    void validate_configs(const ConfigsDefType &config_defs)
    {
        auto all_configs = get_all_keys();
        for (const auto &config : all_configs) {
            if (std::any_of(config_defs.begin(), config_defs.end(), [config](const auto &def) { return config == def; })) {
                continue;
            }
            throw ConfigException(fmt::format("{} is an invalid/unsupported config or filter. The valid configs/filters are: {}", config, fmt::join(config_defs, ", ")));
        }
    }

public:
    InputStream(const std::string &name)
        : AbstractRunnableModule(name)
    {
    }

    virtual ~InputStream(){};

    void add_policy(const Policy *policy)
    {
        std::unique_lock lock(_input_mutex);
        _policies.push_back(policy);
        for (auto const &proxy : _event_proxies) {
            proxy->policy_cb(policy, Action::AddPolicy);
        }
    }

    void remove_policy(const Policy *policy)
    {
        std::unique_lock lock(_input_mutex);
        _policies.erase(std::remove(_policies.begin(), _policies.end(), policy), _policies.end());
        for (auto const &proxy : _event_proxies) {
            proxy->policy_cb(policy, Action::RemovePolicy);
        }
    }

    size_t policies_count() const
    {
        std::shared_lock lock(_input_mutex);
        return _policies.size();
    }

    size_t consumer_count() const
    {
        std::shared_lock lock(_input_mutex);
        size_t count = 0;
        for (auto const &proxy : _event_proxies) {
            count = proxy->consumer_count();
        }
        return count;
    }

    InputEventProxy *add_event_proxy(const Configurable &filter)
    {
        std::unique_lock lock(_input_mutex);
        auto hash = filter.config_hash();
        for (auto const &proxy : _event_proxies) {
            if (proxy->hash() == hash) {
                return proxy.get();
            }
        }
        try {
            _event_proxies.push_back(create_event_proxy(filter));
        } catch (ConfigException &e) {
            throw ConfigException(fmt::format("unable to create event proxy due to invalid input filter config: {}", e.what()));
        }
        return _event_proxies.back().get();
    }

    virtual std::unique_ptr<InputEventProxy> create_event_proxy(const Configurable &filter) = 0;

    void common_info_json(json &j) const
    {
        AbstractModule::common_info_json(j);
        j["input"]["running"] = running();
        j["input"]["consumers"] = consumer_count();
    }
};

}
