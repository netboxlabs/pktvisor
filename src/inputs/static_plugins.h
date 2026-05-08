#pragma once

/* See handlers/static_plugins.h for the force-link mechanism. */

extern "C" int visor_force_link_VisorInputMock;
extern "C" int visor_force_link_VisorInputPcap;
extern "C" int visor_force_link_VisorInputDnstap;
extern "C" int visor_force_link_VisorInputFlow;
extern "C" int visor_force_link_VisorInputNetProbe;

namespace visor::detail {

inline int force_link_input_plugins()
{
    return visor_force_link_VisorInputMock
        + visor_force_link_VisorInputPcap
        + visor_force_link_VisorInputDnstap
        + visor_force_link_VisorInputFlow
        + visor_force_link_VisorInputNetProbe;
}

[[maybe_unused]] static const int _visor_input_plugin_anchor = force_link_input_plugins();

}
