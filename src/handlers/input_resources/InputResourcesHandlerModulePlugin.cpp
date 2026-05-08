/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "InputResourcesHandlerModulePlugin.h"
#include "CoreRegistry.h"
#include "HandlerManager.h"
#include "InputResourcesStreamHandler.h"
#include "InputStreamManager.h"
#include <nlohmann/json.hpp>
namespace visor::handler::resources {

using json = nlohmann::json;

void InputResourcesHandlerModulePlugin::setup_routes(HttpServer *)
{
}

std::unique_ptr<StreamHandler> InputResourcesHandlerModulePlugin::instantiate(const std::string &name, InputEventProxy *proxy, const Configurable *config, [[maybe_unused]] const Configurable *filter)
{
    // TODO using config as both window config and module config
    auto handler_module = std::make_unique<InputResourcesStreamHandler>(name, proxy, config);
    handler_module->config_merge(*config);
    return handler_module;
}

}

namespace visor {
std::unique_ptr<HandlerModulePlugin> make_handler_input_resources(std::string alias)
{
    return std::make_unique<visor::handler::resources::InputResourcesHandlerModulePlugin>(std::move(alias));
}
}
