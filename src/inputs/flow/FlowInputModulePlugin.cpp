/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "FlowInputModulePlugin.h"
#include "CoreRegistry.h"
#include "InputStreamManager.h"
#include "PluginRegistry.h"

VISOR_REGISTER_INPUT_PLUGIN(VisorInputFlow, visor::input::flow::FlowInputModulePlugin, "flow", "1.0")
VISOR_REGISTER_INPUT_PLUGIN_ALIAS(VisorInputSflow, visor::input::flow::FlowInputModulePlugin, "sflow", "1.0")

namespace visor::input::flow {

void FlowInputModulePlugin::setup_routes([[maybe_unused]] HttpServer *svr)
{
}

std::unique_ptr<InputStream> FlowInputModulePlugin::instantiate(const std::string name, const Configurable *config, const Configurable *filter)
{
    auto input_stream = std::make_unique<FlowInputStream>(name);
    input_stream->config_merge(*config);
    input_stream->config_merge(*filter);
    return input_stream;
}

std::string FlowInputModulePlugin::generate_input_name(std::string prefix, const Configurable &config, [[maybe_unused]] const Configurable &filter)
{
    return prefix + "-" + config.config_hash();
}
}
