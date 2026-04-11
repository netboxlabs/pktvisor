#pragma once

#include <Corrade/PluginManager/AbstractManager.h>
#include <Corrade/Utility/Macros.h>

static int import_input_plugins()
{
    CORRADE_PLUGIN_IMPORT(VisorInputMock);
    CORRADE_PLUGIN_IMPORT(VisorInputPcap);
    CORRADE_PLUGIN_IMPORT(VisorInputDnstap);
    CORRADE_PLUGIN_IMPORT(VisorInputFlow);
    CORRADE_PLUGIN_IMPORT(VisorInputNetProbe);
    return 0;
}

CORRADE_AUTOMATIC_INITIALIZER(import_input_plugins)
