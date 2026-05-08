#pragma once

/* Force the linker to keep handler plugin .o files when statically linking
 * the handler archives into the final binary. Each VISOR_REGISTER_HANDLER_PLUGIN
 * call exports an extern int symbol named visor_force_link_<SYMBOL>; referencing
 * those symbols here resolves them at link time and pulls in the .o that holds
 * the corresponding static-init registrar. */

extern "C" int visor_force_link_VisorHandlerNet;
extern "C" int visor_force_link_VisorHandlerNetV2;
extern "C" int visor_force_link_VisorHandlerDns;
extern "C" int visor_force_link_VisorHandlerDnsV2;
extern "C" int visor_force_link_VisorHandlerBgp;
extern "C" int visor_force_link_VisorHandlerFlow;
extern "C" int visor_force_link_VisorHandlerDhcp;
extern "C" int visor_force_link_VisorHandlerPcap;
extern "C" int visor_force_link_VisorHandlerNetProbe;
extern "C" int visor_force_link_VisorHandlerInputResources;

namespace visor::detail {

inline int force_link_handler_plugins()
{
    return visor_force_link_VisorHandlerNet
        + visor_force_link_VisorHandlerNetV2
        + visor_force_link_VisorHandlerDns
        + visor_force_link_VisorHandlerDnsV2
        + visor_force_link_VisorHandlerBgp
        + visor_force_link_VisorHandlerFlow
        + visor_force_link_VisorHandlerDhcp
        + visor_force_link_VisorHandlerPcap
        + visor_force_link_VisorHandlerNetProbe
        + visor_force_link_VisorHandlerInputResources;
}

[[maybe_unused]] static const int _visor_handler_plugin_anchor = force_link_handler_plugins();

}
