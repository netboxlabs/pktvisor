#pragma once

/* See handlers/static_plugins.h for the force-link mechanism, including the
 * MSVC /OPT:REF mitigation via #pragma comment(linker, "/INCLUDE:..."). */

/* Note: VisorInputSflow is a secondary alias registered alongside VisorInputFlow
 * in the same TU; pulling in VisorInputFlow's .o is enough to run both registrars,
 * so no separate force-link symbol is needed (and none is emitted by the
 * VISOR_REGISTER_INPUT_PLUGIN_ALIAS macro). */
extern "C" int visor_force_link_VisorInputMock;
extern "C" int visor_force_link_VisorInputPcap;
extern "C" int visor_force_link_VisorInputDnstap;
extern "C" int visor_force_link_VisorInputFlow;
extern "C" int visor_force_link_VisorInputNetProbe;

#if defined(_MSC_VER)
#pragma comment(linker, "/INCLUDE:visor_force_link_VisorInputMock")
#pragma comment(linker, "/INCLUDE:visor_force_link_VisorInputPcap")
#pragma comment(linker, "/INCLUDE:visor_force_link_VisorInputDnstap")
#pragma comment(linker, "/INCLUDE:visor_force_link_VisorInputFlow")
#pragma comment(linker, "/INCLUDE:visor_force_link_VisorInputNetProbe")
#endif

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
