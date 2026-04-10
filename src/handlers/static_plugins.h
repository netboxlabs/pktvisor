#pragma once

#include <Corrade/PluginManager/AbstractManager.h>
#include <Corrade/Utility/Macros.h>

static int import_handler_plugins()
{
    CORRADE_PLUGIN_IMPORT(VisorHandlerNet);
    CORRADE_PLUGIN_IMPORT(VisorHandlerNetV2);
    CORRADE_PLUGIN_IMPORT(VisorHandlerDns);
    CORRADE_PLUGIN_IMPORT(VisorHandlerDnsV2);
    CORRADE_PLUGIN_IMPORT(VisorHandlerBgp);
    CORRADE_PLUGIN_IMPORT(VisorHandlerFlow);
    CORRADE_PLUGIN_IMPORT(VisorHandlerDhcp);
    CORRADE_PLUGIN_IMPORT(VisorHandlerPcap);
    CORRADE_PLUGIN_IMPORT(VisorHandlerNetProbe);
    CORRADE_PLUGIN_IMPORT(VisorHandlerInputResources);
    return 0;
}

CORRADE_AUTOMATIC_INITIALIZER(import_handler_plugins)
