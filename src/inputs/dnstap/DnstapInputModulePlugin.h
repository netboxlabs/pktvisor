/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "InputModulePlugin.h"

namespace visor::input::dnstap {

class DnstapInputModulePlugin : public visor::InputModulePlugin
{

protected:
    void setup_routes(HttpServer *svr) override;

public:
    explicit DnstapInputModulePlugin(std::string alias)
        : visor::InputModulePlugin{std::move(alias)}
    {
    }
    std::unique_ptr<InputStream> instantiate(const std::string name, const Configurable *config, const Configurable *filter) override;

    std::string generate_input_name(std::string prefix, const Configurable &config, const Configurable &filter) override;
};

}
