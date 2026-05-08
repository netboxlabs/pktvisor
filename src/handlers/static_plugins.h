#pragma once

/* Force the linker to keep handler plugin .o files when statically linking
 * the handler archives into the final binary. Each VISOR_REGISTER_HANDLER_PLUGIN
 * call exports an extern int symbol named visor_force_link_<SYMBOL>; an array
 * of pointers to those symbols below references each one, forcing the linker to
 * resolve them and pull in the .o that holds the corresponding static-init
 * registrar.
 *
 * The array MUST NOT be elidable by the optimizer (GCC at -O2 will drop unused
 * static initializers whose side effects it can prove are absent), or the
 * registrar never runs and the runtime registry is empty. We pin it with
 * __attribute__((used)) on GCC/Clang and rely on inline-variable external
 * linkage to keep MSVC honest. */

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

#if defined(__GNUC__) || defined(__clang__)
[[gnu::used]]
#endif
inline int *const _visor_handler_plugin_anchors[] = {
    &visor_force_link_VisorHandlerNet,
    &visor_force_link_VisorHandlerNetV2,
    &visor_force_link_VisorHandlerDns,
    &visor_force_link_VisorHandlerDnsV2,
    &visor_force_link_VisorHandlerBgp,
    &visor_force_link_VisorHandlerFlow,
    &visor_force_link_VisorHandlerDhcp,
    &visor_force_link_VisorHandlerPcap,
    &visor_force_link_VisorHandlerNetProbe,
    &visor_force_link_VisorHandlerInputResources,
};

}
