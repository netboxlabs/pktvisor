/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include <nlohmann/json.hpp>
#include <stdexcept>
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
 * Plugin instances managed in-process by CoreRegistry. They expose admin API
 * routes (setup_routes) and act as factories for AbstractModule instances
 * via subclass-specific instantiate() methods.
 */
class AbstractPlugin
{
public:
    typedef const std::unordered_map<std::string, std::string> SchemaMap;

private:
    std::string _alias;
    CoreRegistry *_registry{nullptr};

    /**
     * Utility functions for checking json schema
     */
    void check_schema(json obj, SchemaMap &required, SchemaMap &optional);

    /**
     * Configure Admin API routes for life cycle maintenance of AbstractModule instances
     */
    virtual void setup_routes(HttpServer *svr) = 0;

    virtual void on_init_plugin([[maybe_unused]] geo::MaxmindDB *city_db, [[maybe_unused]] geo::MaxmindDB *asn_db)
    {
    }

protected:
    [[nodiscard]] const CoreRegistry *registry() const
    {
        return _registry;
    }

    [[nodiscard]] CoreRegistry *registry()
    {
        return _registry;
    }

    [[nodiscard]] const std::string &plugin_name() const
    {
        return _alias;
    }

public:
    explicit AbstractPlugin(std::string alias)
        : _alias(std::move(alias))
    {
    }

    virtual ~AbstractPlugin() = default;

    [[nodiscard]] const std::string &plugin() const
    {
        return _alias;
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
