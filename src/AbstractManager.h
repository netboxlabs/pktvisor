/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "AbstractModule.h"
#include <assert.h>
#include <fmt/format.h>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <unordered_map>

namespace visor {

class ModuleException : public std::runtime_error
{
    std::string _name;

public:
    explicit ModuleException(const std::string &name, const std::string &msg)
        : std::runtime_error(msg)
        , _name(name)
    {
    }

    const std::string &name() const
    {
        return _name;
    }
};

// a name in use: the admin API answers 409
class ModuleExistsException : public ModuleException
{
public:
    using ModuleException::ModuleException;
};

/**
 * called from HTTP threads so must be thread safe
 */
template <typename ModuleType>
class AbstractManager
{
    static_assert(std::is_base_of<AbstractModule, ModuleType>::value, "ModuleType must inherit from AbstractModule");

protected:
    typedef std::unordered_map<std::string, std::unique_ptr<ModuleType>> ModuleMap;
    ModuleMap _map;
    mutable std::shared_mutex _map_mutex;

public:
    AbstractManager()
        : _map()
    {
    }

    virtual ~AbstractManager()
    {
    }

    std::vector<std::string> module_get_keys() const {
        std::shared_lock lock(_map_mutex);
        std::vector<std::string> result;
        for (auto &kv : _map) {
            result.emplace_back(kv.first);
        }
        return result;
    }

    auto module_get_all_locked()
    {
        struct retVals {
            ModuleMap &map;
            std::unique_lock<std::shared_mutex> lock;
        };
        std::unique_lock lock(_map_mutex);
        return retVals{_map, std::move(lock)};
    }

    virtual void module_add(std::unique_ptr<ModuleType> &&m)
    {
        std::unique_lock lock(_map_mutex);
        if (_map.count(m->name())) {
            throw ModuleExistsException(m->name(), fmt::format("module name '{}' already exists", m->name()));
        }
        _map.emplace(m->name(), std::move(m));
    }

    // note the module returned has separate thread safety, but the returned lock ensures
    // the module will not be removed before the caller has a chance to initialize
    auto module_get_locked(const std::string &name)
    {
        std::unique_lock lock(_map_mutex);
        if (_map.count(name) == 0) {
            throw ModuleException(name, fmt::format("module name '{}' does not exist", name));
        }
        struct retVals {
            ModuleType *module;
            std::unique_lock<std::shared_mutex> lock;
        };
        return retVals{_map[name].get(), std::move(lock)};
    }

    // like module_get_locked, but a missing module comes back as nullptr. Checking and getting in one step leaves
    // no room for a concurrent removal in between, which module_exists followed by module_get_locked leaves
    auto module_find_locked(const std::string &name)
    {
        std::unique_lock lock(_map_mutex);
        struct retVals {
            ModuleType *module;
            std::unique_lock<std::shared_mutex> lock;
        };
        auto found = _map.find(name);
        return retVals{found == _map.end() ? nullptr : found->second.get(), std::move(lock)};
    }

    virtual void module_remove(const std::string &name)
    {
        std::unique_lock lock(_map_mutex);
        if (_map.count(name) == 0) {
            throw ModuleException(name, fmt::format("module name '{}' does not exist", name));
        }
        _map.erase(name);
    }

    // note, this only guarantees the name existed at the time of call, watch for race conditions! To use the module
    // too, look it up with module_find_locked instead
    bool module_exists(const std::string &name) const
    {
        std::shared_lock lock(_map_mutex);
        return _map.count(name) == 1;
    }
};

}

