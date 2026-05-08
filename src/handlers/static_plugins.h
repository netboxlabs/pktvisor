#pragma once

/* Force the linker to keep handler plugin .o files when statically linking
 * the handler archives into the final binary. Each VISOR_REGISTER_HANDLER_PLUGIN
 * call exports an extern int symbol named visor_force_link_<SYMBOL>. We then
 * have to keep references to those symbols alive across both the compiler's
 * dead-code elimination (GCC/Clang at -O2) and the linker's COMDAT/dead-strip
 * (MSVC's /OPT:REF), or the registrars never run and the runtime registry is
 * empty.
 *
 * GCC/Clang: an inline pointer array marked [[gnu::used]] forces the compiler
 * to emit it; the pointer initializers reference the externs which forces the
 * linker to resolve them and pull in the .o files.
 *
 * MSVC: /OPT:REF strips unreferenced data even with the array present, so we
 * additionally emit per-symbol /INCLUDE: linker directives via #pragma comment.
 * Those directives are processed by link.exe regardless of optimization. */

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
extern "C" int visor_force_link_VisorHandlerMock;

#if defined(_MSC_VER)
#pragma comment(linker, "/INCLUDE:visor_force_link_VisorHandlerNet")
#pragma comment(linker, "/INCLUDE:visor_force_link_VisorHandlerNetV2")
#pragma comment(linker, "/INCLUDE:visor_force_link_VisorHandlerDns")
#pragma comment(linker, "/INCLUDE:visor_force_link_VisorHandlerDnsV2")
#pragma comment(linker, "/INCLUDE:visor_force_link_VisorHandlerBgp")
#pragma comment(linker, "/INCLUDE:visor_force_link_VisorHandlerFlow")
#pragma comment(linker, "/INCLUDE:visor_force_link_VisorHandlerDhcp")
#pragma comment(linker, "/INCLUDE:visor_force_link_VisorHandlerPcap")
#pragma comment(linker, "/INCLUDE:visor_force_link_VisorHandlerNetProbe")
#pragma comment(linker, "/INCLUDE:visor_force_link_VisorHandlerInputResources")
#pragma comment(linker, "/INCLUDE:visor_force_link_VisorHandlerMock")
#endif

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
    &visor_force_link_VisorHandlerMock,
};

}
