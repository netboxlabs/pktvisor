/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "AbstractPlugin.h"
#include <Corrade/Containers/Array.h>
#include <Corrade/Containers/String.h>
#include <Corrade/PluginManager/Manager.h>
#include <Corrade/PluginManager/PluginMetadata.h>
#include <string>

namespace visor {

class Configurable;
class StreamHandler;
class InputEventProxy;

class HandlerModulePlugin : public AbstractPlugin
{
public:
    static geo::MaxmindDB *asn;
    static geo::MaxmindDB *city;

    static Corrade::Containers::StringView pluginInterface()
    {
        return "visor.module.handler/1.0";
    }

    static Corrade::Containers::Array<Corrade::Containers::String> pluginSearchPaths()
    {
        return {Corrade::Containers::InPlaceInit, {""}};
    }

    explicit HandlerModulePlugin(Corrade::PluginManager::AbstractManager &manager, const Corrade::Containers::StringView plugin)
        : AbstractPlugin{manager, plugin}
    {
    }

    void on_init_plugin(geo::MaxmindDB *city_db, geo::MaxmindDB *asn_db) override
    {
        city = city_db;
        asn = asn_db;
    }

    /**
     * Instantiate a new StreamHandler
     */
    virtual std::unique_ptr<StreamHandler> instantiate(const std::string &name, InputEventProxy *proxy, const Configurable *config, const Configurable *filter) = 0;
};

typedef Corrade::PluginManager::Manager<HandlerModulePlugin> HandlerPluginRegistry;
typedef Corrade::Containers::Pointer<HandlerModulePlugin> HandlerPluginPtr;

}
