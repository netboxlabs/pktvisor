/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "BuiltinPlugins.h"
#include "CoreRegistry.h"

#include "handlers/bgp/BgpHandlerModulePlugin.h"
#include "handlers/dhcp/DhcpHandlerModulePlugin.h"
#include "handlers/dns/v1/DnsHandlerModulePlugin.h"
#include "handlers/dns/v2/DnsHandlerModulePlugin.h"
#include "handlers/flow/FlowHandlerModulePlugin.h"
#include "handlers/input_resources/InputResourcesHandlerModulePlugin.h"
#include "handlers/mock/MockHandlerModulePlugin.h"
#include "handlers/net/v1/NetHandlerModulePlugin.h"
#include "handlers/net/v2/NetHandlerModulePlugin.h"
#include "handlers/netprobe/NetProbeHandlerModulePlugin.h"
#include "handlers/pcap/PcapHandlerModulePlugin.h"
#include "inputs/dnstap/DnstapInputModulePlugin.h"
#include "inputs/flow/FlowInputModulePlugin.h"
#include "inputs/mock/MockInputModulePlugin.h"
#include "inputs/netprobe/NetProbeInputModulePlugin.h"
#include "inputs/pcap/PcapInputModulePlugin.h"

#include <memory>

namespace visor {

namespace {

template <typename Plugin>
std::unique_ptr<Plugin> make(std::string alias)
{
    return std::make_unique<Plugin>(std::move(alias));
}

}

void load_builtin_plugins(CoreRegistry &reg)
{
    // Inputs
    reg.add_input_plugin("mock", "1.0", make<input::mock::MockInputModulePlugin>("mock"));
    reg.add_input_plugin("pcap", "1.0", make<input::pcap::PcapInputModulePlugin>("pcap"));
    reg.add_input_plugin("dnstap", "1.0", make<input::dnstap::DnstapInputModulePlugin>("dnstap"));
    reg.add_input_plugin("flow", "1.0", make<input::flow::FlowInputModulePlugin>("flow"));
    reg.add_input_plugin("sflow", "1.0", make<input::flow::FlowInputModulePlugin>("sflow"));
    reg.add_input_plugin("netprobe", "1.0", make<input::netprobe::NetProbeInputModulePlugin>("netprobe"));

    // Handlers
    reg.add_handler_plugin("net", "1.0", make<handler::net::NetHandlerModulePlugin>("net"));
    reg.add_handler_plugin("net", "2.0", make<handler::net::v2::NetHandlerModulePlugin>("net"));
    reg.add_handler_plugin("dns", "1.0", make<handler::dns::DnsHandlerModulePlugin>("dns"));
    reg.add_handler_plugin("dns", "2.0", make<handler::dns::v2::DnsHandlerModulePlugin>("dns"));
    reg.add_handler_plugin("bgp", "1.0", make<handler::bgp::BgpHandlerModulePlugin>("bgp"));
    reg.add_handler_plugin("flow", "1.0", make<handler::flow::FlowHandlerModulePlugin>("flow"));
    reg.add_handler_plugin("dhcp", "1.0", make<handler::dhcp::DhcpHandlerModulePlugin>("dhcp"));
    reg.add_handler_plugin("pcap", "1.0", make<handler::pcap::PcapHandlerModulePlugin>("pcap"));
    reg.add_handler_plugin("netprobe", "1.0", make<handler::netprobe::NetProbeHandlerModulePlugin>("netprobe"));
    reg.add_handler_plugin("input_resources", "1.0", make<handler::resources::InputResourcesHandlerModulePlugin>("input_resources"));
    reg.add_handler_plugin("mock_dyn", "1.0", make<handler::mock::MockHandlerModulePlugin>("mock_dyn"));
}

}
