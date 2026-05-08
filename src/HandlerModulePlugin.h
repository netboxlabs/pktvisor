/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "AbstractPlugin.h"
#include "PluginRegistry.h"
#include <memory>
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

    static std::string pluginInterface()
    {
        return "visor.module.handler/1.0";
    }

    explicit HandlerModulePlugin(std::string alias)
        : AbstractPlugin{std::move(alias)}
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

using HandlerPluginRegistry = PluginRegistry<HandlerModulePlugin>;
using HandlerPluginPtr = std::unique_ptr<HandlerModulePlugin>;

}
