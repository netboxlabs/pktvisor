/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "AbstractPlugin.h"
#include <Corrade/PluginManager/Manager.h>
#include <Corrade/PluginManager/PluginMetadata.h>
#include <string>

namespace visor {

class InputStream;
class Configurable;

class InputModulePlugin : public AbstractPlugin
{

public:
    static Corrade::Containers::StringView pluginInterface()
    {
        using namespace Corrade::Containers::Literals;
        return "visor.module.input/1.0"_s;
    }

    static Corrade::Containers::Array<Corrade::Containers::String> pluginSearchPaths()
    {
        return {};
    }

    explicit InputModulePlugin(Corrade::PluginManager::AbstractManager &manager, const std::string &plugin)
        : AbstractPlugin{manager, plugin}
    {
    }

    /**
     * Instantiate a new InputStream
     */
    virtual std::unique_ptr<InputStream> instantiate(const std::string name, const Configurable *config, const Configurable *filter) = 0;

    virtual std::string generate_input_name(std::string prefix, const Configurable &config, const Configurable &filter) = 0;
};

typedef Corrade::PluginManager::Manager<InputModulePlugin> InputPluginRegistry;
typedef Corrade::Containers::Pointer<InputModulePlugin> InputPluginPtr;

}
