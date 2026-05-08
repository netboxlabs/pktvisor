#pragma once

/* See handlers/static_plugins.h for the force-link mechanism. */

extern "C" int visor_force_link_VisorInputMock;
extern "C" int visor_force_link_VisorInputPcap;
extern "C" int visor_force_link_VisorInputDnstap;
extern "C" int visor_force_link_VisorInputFlow;
extern "C" int visor_force_link_VisorInputNetProbe;

namespace visor::detail {

#if defined(__GNUC__) || defined(__clang__)
[[gnu::used]]
#endif
inline int *const _visor_input_plugin_anchors[] = {
    &visor_force_link_VisorInputMock,
    &visor_force_link_VisorInputPcap,
    &visor_force_link_VisorInputDnstap,
    &visor_force_link_VisorInputFlow,
    &visor_force_link_VisorInputNetProbe,
};

}
