/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include <Corrade/Containers/Array.h>
#include <Corrade/Containers/String.h>
#include <Corrade/PluginManager/AbstractPlugin.h>
#include <exception>
#include <nlohmann/json.hpp>
#include <string>
#include <unordered_map>

namespace visor {

using json = nlohmann::json;

class CoreRegistry;
class HttpServer;

namespace geo {
class MaxmindDB;
}

class SchemaException : public std::runtime_error
{
public:
    explicit SchemaException(const std::string &msg)
        : std::runtime_error(msg)
    {
    }
};

/**
 * These are loadable plugins (static or dynamic libraries)
 * Their job is to enable life cycle maintenance of AbstractModule instances
 * This means they provide an interface to do so over the Admin API and through Policies
 */
class AbstractPlugin : public Corrade::PluginManager::AbstractPlugin
{
public:
    typedef const std::unordered_map<std::string, std::string> SchemaMap;

private:
    CoreRegistry *_registry;

    /**
     * Utility functions for checking json schema
     */
    void check_schema(json obj, SchemaMap &required, SchemaMap &optional);

    /**
     * Configure Admin API routes for life cycle maintenance of AbstractModule instances
     * @param svr
     */
    virtual void setup_routes(HttpServer *svr) = 0;

    virtual void on_init_plugin([[maybe_unused]] geo::MaxmindDB *city_db, [[maybe_unused]] geo::MaxmindDB *asn_db)
    {
    }

    const CoreRegistry *registry() const
    {
        return _registry;
    }

    CoreRegistry *registry()
    {
        return _registry;
    }

public:
    static Corrade::Containers::Array<Corrade::Containers::String> pluginSearchPaths()
    {
        return {Corrade::InPlaceInit, {""}};
    }

    explicit AbstractPlugin(Corrade::PluginManager::AbstractManager &manager, const Corrade::Containers::StringView plugin)
        : Corrade::PluginManager::AbstractPlugin{manager, plugin}
    {
    }

    void init_plugin(CoreRegistry *mgrs, HttpServer *svr, geo::MaxmindDB *city_db, geo::MaxmindDB *asn_db)
    {
        _registry = mgrs;
        if (svr) {
            setup_routes(svr);
        }
        on_init_plugin(city_db, asn_db);
    }
};

}
