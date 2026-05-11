/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include <catch2/catch_test_macros.hpp>

#include <algorithm>

#include "BuiltinPlugins.h"
#include "Configurable.h"
#include "CoreRegistry.h"
#include "HandlerModulePlugin.h"
#include "HttpServer.h"
#include "InputModulePlugin.h"
#include "InputStream.h"

#include "inputs/dnstap/DnstapInputStream.h"
#include "inputs/flow/FlowInputStream.h"
#include "inputs/mock/MockInputStream.h"
#include "inputs/netprobe/NetProbeInputStream.h"
#include "inputs/pcap/PcapInputStream.h"

namespace {

// Maps each handler alias to an alias of an input it accepts as a proxy.
// Determined from each handler's dynamic_cast<*InputEventProxy*>(proxy)
// calls — see e.g. NetStreamHandler.cpp / DnsStreamHandler.cpp.
const std::unordered_map<std::string, std::string> kHandlerProxy = {
    {"net", "pcap"},
    {"dns", "pcap"},
    {"bgp", "pcap"},
    {"dhcp", "pcap"},
    {"pcap", "pcap"},
    {"input_resources", "pcap"},
    {"flow", "flow"},
    {"netprobe", "netprobe"},
};

}

TEST_CASE("CoreRegistry::start invokes setup_routes for every builtin plugin", "[plugins][unit]")
{
    visor::CoreRegistry registry;
    visor::load_builtin_plugins(registry);

    visor::HttpConfig http_config;
    visor::HttpServer http_server(http_config);

    // Passing a non-null server makes init_plugin() call setup_routes() on each
    // builtin plugin, which is otherwise unreachable from tests that pass nullptr.
    REQUIRE_NOTHROW(registry.start(&http_server));

    CHECK(!registry.input_plugins().empty());
    CHECK(!registry.handler_plugins().empty());
}

TEST_CASE("Input plugins: instantiate + generate_input_name", "[plugins][unit]")
{
    visor::CoreRegistry registry;
    visor::load_builtin_plugins(registry);
    registry.start(nullptr);

    visor::Configurable empty_cfg;

    for (const auto &[key, plugin] : registry.input_plugins()) {
        const auto &alias = key.first;
        const auto &version = key.second;
        INFO("input plugin: " << alias << "/" << version);

        auto stream = plugin->instantiate("test-" + alias, &empty_cfg, &empty_cfg);
        CHECK(stream != nullptr);
        CHECK(plugin->plugin() == alias);

        auto generated = plugin->generate_input_name("prefix", empty_cfg, empty_cfg);
        CHECK(generated.rfind("prefix-", 0) == 0);
    }
}

TEST_CASE("Handler plugins: instantiate produces a StreamHandler", "[plugins][unit]")
{
    visor::CoreRegistry registry;
    visor::load_builtin_plugins(registry);
    registry.start(nullptr);

    visor::Configurable empty_cfg;

    // Build one InputStream per alias we'll need a proxy from. Instantiating
    // through the registry keeps the test agnostic to ctor changes.
    std::unordered_map<std::string, std::unique_ptr<visor::InputStream>> inputs;
    std::unordered_map<std::string, visor::InputEventProxy *> proxies;
    for (const auto &needed_alias : {"pcap", "flow", "netprobe"}) {
        auto it = std::find_if(registry.input_plugins().begin(), registry.input_plugins().end(),
            [&](const auto &kv) { return kv.first.first == needed_alias; });
        REQUIRE(it != registry.input_plugins().end());
        auto stream = it->second->instantiate(std::string("proxy-src-") + needed_alias, &empty_cfg, &empty_cfg);
        proxies[needed_alias] = stream->add_event_proxy(empty_cfg);
        inputs[needed_alias] = std::move(stream);
    }

    for (const auto &[key, plugin] : registry.handler_plugins()) {
        const auto &alias = key.first;
        const auto &version = key.second;
        INFO("handler plugin: " << alias << "/" << version);

        auto proxy_it = kHandlerProxy.find(alias);
        REQUIRE(proxy_it != kHandlerProxy.end());
        auto *proxy = proxies.at(proxy_it->second);

        // AbstractModule rejects dots in names; flatten the version into a hyphen.
        std::string version_id = version;
        std::replace(version_id.begin(), version_id.end(), '.', '-');
        auto handler = plugin->instantiate("test-" + alias + "-v" + version_id, proxy, &empty_cfg, &empty_cfg);
        CHECK(handler != nullptr);
        CHECK(plugin->plugin() == alias);
    }
}
