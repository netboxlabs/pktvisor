/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "MockHandlerModulePlugin.h"
#include "CoreRegistry.h"
#include "HandlerManager.h"
#include "InputStreamManager.h"
#include "MockInputStream.h"
#include "MockStreamHandler.h"
#include <nlohmann/json.hpp>

#include "PluginRegistry.h"

VISOR_REGISTER_HANDLER_PLUGIN(VisorHandlerMock, visor::handler::mock::MockHandlerModulePlugin, "mock_dyn", "1.0")

namespace visor::handler::mock {

using namespace visor::input::mock;
using json = nlohmann::json;

void MockHandlerModulePlugin::setup_routes(HttpServer *)
{
}

std::unique_ptr<StreamHandler> MockHandlerModulePlugin::instantiate(const std::string &name, InputEventProxy *proxy, const Configurable *config, const Configurable *filter)
{
    // TODO using config as both window config and module config
    auto handler_module = std::make_unique<MockStreamHandler>(name, proxy, config);
    handler_module->config_merge(*config);
    handler_module->config_merge(*filter);
    return handler_module;
}

}