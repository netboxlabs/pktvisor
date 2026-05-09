/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "AbstractPlugin.h"
#include <memory>
#include <string>

namespace visor {

class InputStream;
class Configurable;

class InputModulePlugin : public AbstractPlugin
{
public:
    static std::string pluginInterface()
    {
        return "visor.module.input/1.0";
    }

    explicit InputModulePlugin(std::string alias)
        : AbstractPlugin{std::move(alias)}
    {
    }

    /**
     * Instantiate a new InputStream
     */
    virtual std::unique_ptr<InputStream> instantiate(const std::string name, const Configurable *config, const Configurable *filter) = 0;

    virtual std::string generate_input_name(std::string prefix, const Configurable &config, const Configurable &filter) = 0;
};

using InputPluginPtr = std::unique_ptr<InputModulePlugin>;

}
