/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "InputModulePlugin.h"
#include "FlowInputStream.h"

namespace visor::input::flow {

class FlowInputModulePlugin : public visor::InputModulePlugin
{

protected:
    void setup_routes(HttpServer *svr) override;

public:
    explicit FlowInputModulePlugin(Corrade::PluginManager::AbstractManager &manager, const Corrade::Containers::StringView plugin)
        : visor::InputModulePlugin{manager, plugin}
    {
    }
    std::unique_ptr<InputStream> instantiate(const std::string name, const Configurable *config, const Configurable *filter) override;

    std::string generate_input_name(std::string prefix, const Configurable &config, const Configurable &filter) override;
};

}

