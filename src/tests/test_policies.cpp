#include "BuiltinPlugins.h"
#include "CoreRegistry.h"
#include "CoreServer.h"
#include "HandlerManager.h"
#include "HandlerModulePlugin.h"
#include "InputStream.h"
#include "InputStreamManager.h"
#include "Policies.h"
#include "PrometheusSerializer.h"
#include "handlers/dns/v1/DnsStreamHandler.h"
#include "handlers/input_resources/InputResourcesStreamHandler.h"
#include "handlers/net/v1/NetStreamHandler.h"
#include "inputs/mock/MockInputModulePlugin.h"

#include <atomic>
#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers.hpp>
#include <catch2/matchers/catch_matchers_exception.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <fmt/format.h>
#include <functional>
#include <future>
#include <map>
#include <set>
#include <spdlog/details/null_mutex.h>
#include <spdlog/sinks/base_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>
#include <string_view>
#include <yaml-cpp/yaml.h>

using namespace visor;

auto policies_config = R"(
version: "1.0"

visor:
  taps:
    anycast:
      input_type: mock
      config:
        iface: eth0
  global_handler_config:
    dns:
        only_rcode: 2
  policies:
    # policy name and description
    default_view:
      kind: collection
#      description: "a mock view of anycast traffic"
      # input stream to create based on the given tap and optional filter config
      input:
        # this must reference a tap name, or application of the policy will fail
        tap: anycast
        input_type: mock
        config:
          sample: value
          bpf: "tcp or udp"
      # stream handlers to attach to this input stream
      # these decide exactly which data to summarize and expose for collection
      handlers:
        # default configuration for the stream handlers
        window_config:
          num_periods: 5
          deep_sample_rate: 100
        modules:
          # the keys at this level are unique identifiers
          default_net:
            type: net
          default_dns:
            type: dns
#            window_config:
#              max_deep_sample: 75
          special_domain:
            type: dns
            metric_groups:
              disable:
                - "top_qnames"
            filter:
              only_qname_suffix:
                - ".google.com"
                - ".ns1.com"
                - "slack.com"
)";

auto policies_config_merge = R"(
visor:
  taps:
    anycast_merge:
      input_type: mock
      config:
        iface: eth0
  policies:
   default_merge:
     config:
        merge_like_handlers: true
     kind: collection
     input:
       tap: anycast_merge
       input_type: mock
       config:
         sample: value
     handlers:
        window_config:
          num_periods: 5
          deep_sample_rate: 100
        modules:
          default_dns_1:
            type: dns
          default_dns_2:
            type: dns
          default_net_1:
            type: net
          default_net_2:
            type: net
)";

auto policies_config_hseq = R"(
visor:
  taps:
    anycast:
      input_type: mock
      config:
        iface: eth0
  policies:
   default_view:
     kind: collection
     input:
       tap: anycast
       input_type: mock
       config:
         sample: value
     handlers:
        window_config:
          num_periods: 5
          deep_sample_rate: 100
        modules:
          - default_dns:
            type: dns
            config:
              exclude_noerror: true
          - default_net:
            type: net
)";

auto policies_config_tap_selector_all = R"(
version: "1.0"

visor:
  taps:
    anycast1:
      input_type: mock
      config:
        iface: eth0
      tags:
        virtual: true
        vhost: 1
        key: value
    anycast2:
      input_type: mock
      config:
        iface: eth0
      tags:
        virtual: true
        vhost: 2
        key: value
  policies:
   default_view:
     kind: collection
     input:
       tap_selector:
         all: [virtual: true, vhost: 1, key: value]
       input_type: mock
       config:
         sample: value
     handlers:
        window_config:
          num_periods: 5
          deep_sample_rate: 100
        modules:
          default_dns:
            type: dns
          default_net:
            type: net
)";

auto policies_config_tap_selector_any = R"(
version: "1.0"

visor:
  taps:
    anycast1:
      input_type: mock
      config:
        iface: eth0
      tags:
        virtual: true
        vhost: 1
        key: value
    anycast2:
      input_type: mock
      config:
        iface: eth0
      tags:
        virtual: true
        vhost: 2
        key: value
  policies:
   default_view:
     kind: collection
     input:
       tap_selector:
         any:
           - virtual: true
           - virtual: false
           - vhost: 1
           - key: value
       input_type: mock
       config:
         sample: value
     handlers:
        window_config:
          num_periods: 5
          deep_sample_rate: 100
        modules:
          default_dns:
            type: dns
          default_net:
            type: net
)";

auto policies_config_same_input = R"(
version: "1.0"

visor:
  policies:
    # policy name and description
    same_input:
      kind: collection
      input:
        # this must reference a tap name, or application of the policy will fail
        tap: anycast
        input_type: mock
        config:
          sample: value
          bpf: "tcp or udp"
      handlers:
        window_config:
          num_periods: 5
          deep_sample_rate: 100
        modules:
          net:
            type: net
)";

auto policies_config_bad0 = R"(
version: "1.0"

visor:
  no_policies:
)";

auto policies_config_bad1 = R"(
version: "2.0"

visor:
  policies:
    missing:
)";

auto policies_config_bad2 = R"(
version: "1.0"

visor:
  taps:
    anycast:
      input_type: mock
      config:
        iface: eth0
  policies:
    default_view:
      kind: collection
      input:
        tap: nonexist
        input_type: mock
      handlers:
        modules:
          net:
            type: net
)";

auto policies_config_bad3 = R"(
version: "1.0"

visor:
  taps:
    anycast:
      input_type: mock
      config:
        iface: eth0
  policies:
    default_view:
      kind: collection
      input:
        tap: anycast
        input_type: mock
        filter:
          bpf:
            badmap: "bad value"
)";

auto policies_config_bad4 = R"(
visor:
  taps:
    anycast:
      input_type: mock
      config:
        iface: eth0
  policies:
    default_view:
      kind: collection
      input:
        tap: anycast
        input_type: mock
        config:
          except_on_start: true
      handlers:
        modules:
          default_net:
            type: net
)";
auto policies_config_bad5 = R"(
version: "1.0"

visor:
  taps:
    anycast:
      input_type: mock
      config:
        iface: eth0
  policies:
    default_view:
      kind: collection
      handlers:
        modules:
          default_dns:
            type: dns
      input:
        tap: anycast
        input_type: wrong_type
)";
auto policies_config_bad6 = R"(
version: "1.0"

visor:
  taps:
    anycast:
      input_type: mock
      config:
        iface: eth0
  policies:
    default_view:
      kind: unknown_kind
      input:
        tap: anycast
        input_type: mock
)";

auto policies_config_bad7 = R"(
version: "1.0"

visor:
  taps:
    anycast:
      input_type: mock
      config:
        iface: eth0
  policies:
    default_view:
      kind: collection
      input:
        tap: anycast
        input_type: mock
      handlers:
        window_config:
          num_periods: 5
          deep_sample_rate: 100
        modules:
           default_net:
            type: net2
)";

auto policies_config_bad8 = R"(
version: "1.0"

visor:
  taps:
    anycast:
      input_type: mock
      config:
        iface: eth0
  policies:
    default_view:
      kind: collection
      input:
        tap: anycast
        input_type: mock
      handlers:
        window_config:
          num_periods: 5
          deep_sample_rate: 100
        modules:
          default_net:
             type: net
          default_dns:
             config: dns
)";

auto policies_config_bad9 = R"(
version: "1.0"

visor:
  taps:
    anycast:
      input_type: mock
      config:
        iface: eth0
  policies:
    default_view:
      kind: collection
      input:
        tap: anycast
        input_type: mock
      handlers:
        window_config:
          num_periods: 5
          deep_sample_rate: 100
        modules:
          default_net:
             type: net
          default_dns:
             type: dns
             config: not_a_map
)";

auto policies_config_bad10 = R"(
version: "1.0"

visor:
  taps:
    anycast:
      input_type: mock
      config:
        iface: eth0
  policies:
    default_view:
      kind: collection
      input:
        tap: anycast
        input_type: mock
      handlers:
        window_config:
          num_periods: 5
          deep_sample_rate: 100
        modules:
          default_net:
             type: net
          default_dns:
             type: dns
             metric_groups:
               - top_qnames
               - counters
)";

auto policies_config_bad11 = R"(
version: "1.0"

visor:
  taps:
    anycast:
      input_type: mock
      config:
        iface: eth0
  policies:
    default_view:
      kind: collection
      input:
        tap: anycast
        input_type: mock
      handlers:
        window_config:
          num_periods: 5
          deep_sample_rate: 100
        modules:
          default_net:
             type: net
          default_dns:
             type: dns
             metric_groups:
               allow:
                 - top_qnames
                 - counters
)";

auto policies_config_bad12 = R"(
version: "1.0"

visor:
  taps:
    anycast:
      input_type: mock
      config:
        iface: eth0
  global_handler_config:
    dns2:
      only_rcode: 2
  policies:
    default_view:
      kind: collection
      input:
        tap: anycast
        input_type: mock
      handlers:
        modules:
           default_net:
            type: net
)";

auto policies_config_bad13 = R"(
version: "1.0"

visor:
  taps:
    anycast:
      input_type: mock
      config:
        iface: eth0
  global_handler_config:
      only_rcode: 2
  policies:
    default_view:
      kind: collection
      input:
        tap: anycast
        input_type: mock
      handlers:
        modules:
           default_net:
            type: net
)";

auto policies_config_bad14 = R"(
version: "1.0"

visor:
  taps:
    anycast:
      input_type: mock
      config:
        iface: eth0
  policies:
    default_view:
      config: not_a_map
      kind: collection
      input:
        tap: anycast
        input_type: mock
      handlers:
        modules:
           default_net:
            type: net
)";

auto policies_config_hseq_bad2 = R"(
version: "1.0"

visor:
  taps:
    anycast:
      input_type: mock
      config:
        iface: eth0
  policies:
    default_view:
      kind: collection
      input:
        tap: anycast
        input_type: mock
      handlers:
        window_config:
          num_periods: 5
          deep_sample_rate: 100
        modules:
           default_dns:
            type: dns
          - default_net:
            type: net
)";

auto policies_config_tap_selector_bad1 = R"(
version: "1.0"

visor:
  taps:
    anycast1:
      input_type: mock
      config:
        iface: eth0
      tags:
        virtual: true
        vhost: "1"
        key: value
    anycast2:
      input_type: mock
      config:
        iface: eth0
      tags:
        virtual: true
        vhost: "2"
        key: value
  policies:
   default_view:
     kind: collection
     handlers:
       modules:
        default_dns:
          type: dns
     input:
       tap_selector:
         all: [virtual: true, vhost: "1", non_existent_key: value]
       input_type: mock
)";

auto policies_config_tap_selector_bad2 = R"(
version: "1.0"

visor:
  taps:
    anycast1:
      input_type: mock
      config:
        iface: eth0
      tags:
        virtual: true
        vhost: 1
        key: value
    anycast2:
      input_type: mock
      config:
        iface: eth0
      tags:
        virtual: true
        vhost: 2
        key: value
  policies:
   default_view:
     kind: collection
     handlers:
       modules:
         default_dns:
           type: dns
     input:
       tap_selector:
         any:
            - virtual:
                vhost: 1
                non_existent_key: value
       input_type: mock
)";

auto policies_config_tap_selector_bad3 = R"(
version: "1.0"

visor:
  taps:
    anycast1:
      input_type: mock
      config:
        iface: eth0
      tags:
        virtual: true
        vhost: 1
        key: value
    anycast2:
      input_type: mock
      config:
        iface: eth0
      tags:
        virtual: true
        vhost: 2
        key: value
  policies:
   default_view:
     kind: collection
     handlers:
       modules:
         default_dns:
           type: dns
     input:
       tap: anycast1
       tap_selector:
         any:
           virtual: true
       input_type: mock
)";

auto policies_config_tap_selector_bad4 = R"(
version: "1.0"

visor:
  taps:
    anycast1:
      input_type: mock
      config:
        iface: eth0
      tags:
        virtual: true
        vhost: 1
        key: value
    anycast2:
      input_type: mock
      config:
        iface: eth0
      tags:
        virtual: true
        vhost: 2
        key: value
  policies:
   default_view:
     kind: collection
     handlers:
       modules:
         default_dns:
           type: dns
     input:
       tap_selector:
         any:
           virtual: true
       input_type: mock
)";

auto policies_config_tap_selector_bad5 = R"(
version: "1.0"

visor:
  taps:
    anycast1:
      input_type: mock
      config:
        iface: eth0
      tags:
        virtual: true
        vhost: 1
        key: value
    anycast2:
      input_type: mock
      config:
        iface: eth0
      tags:
        virtual: true
        vhost: 2a
        key: value
  policies:
   default_view:
     kind: collection
     handlers:
       modules:
         default_dns:
           type: dns
     input:
       tap_selector:
         any:
           - vhost: 1
       input_type: mock
)";

auto policies_config_tap_selector_bad6 = R"(
version: "1.0"

visor:
  taps:
    anycast1:
      input_type: mock
      config:
        iface: eth0
      tags:
        virtual: true
        vhost: 1
        key: value
    anycast2:
      input_type: mock
      config:
        iface: eth0
      tags:
        virtual: true
        vhost: 2
        key: value
  policies:
   default_view:
     kind: collection
     handlers:
       modules:
         default_dns:
           type: dns
     input:
       tap_selector:
         any:
           - vhost: 1
             key: value
       input_type: mock
)";

auto policies_config_pcap_file = R"(
version: "1.0"

visor:
  taps:
    recorded:
      input_type: pcap
      config:
        pcap_file: tests/fixtures/dns_ipv4_udp.pcap
  policies:
    recorded_view:
      kind: collection
      input:
        tap: recorded
        input_type: pcap
      handlers:
        modules:
          recorded_net:
            type: net
)";

auto policies_config_pcap_file_missing_hseq = R"(
version: "1.0"

visor:
  taps:
    broken:
      input_type: pcap
      config:
        pcap_file: tests/fixtures/does_not_exist.pcap
  policies:
    broken_view:
      kind: collection
      input:
        tap: broken
        input_type: pcap
      handlers:
        modules:
          - broken_dns:
            type: dns
          - broken_net:
            type: net
)";

auto policies_config_shared_input = R"(
version: "1.0"

visor:
  taps:
    live_a:
      input_type: pcap
      config:
        pcap_source: mock
      tags:
        group: g1
    broken_b:
      input_type: pcap
      config:
        pcap_file: tests/fixtures/does_not_exist.pcap
      tags:
        group: g1
  policies:
    first_view:
      kind: collection
      input:
        tap: live_a
        input_type: pcap
      handlers:
        modules:
          first_net:
            type: net
)";

auto policies_config_shared_input_failing = R"(
version: "1.0"

visor:
  policies:
    second_view:
      kind: collection
      input:
        tap_selector:
          any:
            - group: g1
        input_type: pcap
      handlers:
        modules:
          second_net:
            type: net
)";

auto policies_config_logic_error_on_start = R"(
visor:
  taps:
    anycast:
      input_type: mock
      config:
        iface: eth0
  policies:
    default_view:
      kind: collection
      input:
        tap: anycast
        input_type: mock
        config:
          except_on_start_logic: true
      handlers:
        modules:
          default_net:
            type: net
)";

auto policies_config_flow_port_in_use = R"(
visor:
  taps:
    flow_tap:
      input_type: flow
  policies:
    sflow_view:
      kind: collection
      input:
        tap: flow_tap
        input_type: flow
        config:
          flow_type: sflow
          bind: 127.0.0.1
          port: 6346
      handlers:
        modules:
          sflow_flow:
            type: flow
)";

auto policies_config_flow_port_in_use_second = R"(
visor:
  policies:
    netflow_view:
      kind: collection
      input:
        tap: flow_tap
        input_type: flow
        config:
          flow_type: netflow
          bind: 127.0.0.1
          port: 6346
      handlers:
        modules:
          netflow_flow:
            type: flow
)";

TEST_CASE("Policies", "[policies]")
{

    SECTION("Good Config happy path")
    {
        CoreRegistry registry;
        visor::load_builtin_plugins(registry);
        registry.start(nullptr);
        YAML::Node config_file = YAML::Load(policies_config);

        CHECK(config_file["visor"]["policies"]);
        CHECK(config_file["visor"]["policies"].IsMap());

        REQUIRE_NOTHROW(registry.tap_manager()->load(config_file["visor"]["taps"]));
        REQUIRE_NOTHROW(registry.handler_manager()->set_default_handler_config(config_file["visor"]["global_handler_config"]));
        REQUIRE_NOTHROW(registry.policy_manager()->load(config_file["visor"]["policies"]));

        REQUIRE(registry.policy_manager()->module_exists("default_view"));
        auto [policy, lock] = registry.policy_manager()->module_get_locked("default_view");
        CHECK(policy->name() == "default_view");
        CHECK(policy->input_stream().back()->name().find("anycast-") != std::string::npos);
        CHECK(policy->input_stream().back()->config_get<std::string>("bpf") == "tcp or udp"); // TODO this will move to filter member variable
        CHECK(policy->input_stream().back()->config_get<std::string>("sample") == "value");
        CHECK(policy->modules()[0]->name() == "default_view-anycast-default_net");
        CHECK(dynamic_cast<StreamHandler *>(policy->modules()[0])->version() == "1.0");
        CHECK(policy->modules()[1]->name() == "default_view-anycast-default_dns");
        CHECK(dynamic_cast<StreamHandler *>(policy->modules()[1])->version() == "1.0");
        CHECK(policy->modules()[1]->config_get<uint64_t>("only_rcode") == 2);
        CHECK(policy->modules()[2]->name() == "default_view-anycast-special_domain");
        CHECK(dynamic_cast<StreamHandler *>(policy->modules()[2])->version() == "1.0");
        CHECK(policy->modules()[2]->config_get<Configurable::StringList>("only_qname_suffix")[0] == ".google.com");
        CHECK(policy->modules()[2]->config_get<uint64_t>("only_rcode") == 2);
        // TODO check window config settings made it through
        CHECK(policy->input_stream().back()->running());
        CHECK(policy->modules()[0]->running());
        CHECK(policy->modules()[1]->running());
        CHECK(policy->modules()[2]->running());

        json j;
        REQUIRE_NOTHROW(policy->info_json(j));
        CHECK(j["input"] != nullptr);
        CHECK(j["modules"]["default_view-anycast-default_net"] != nullptr);
        CHECK(j["taps"]["anycast"]["config"]["iface"] == "eth0");
    }

    SECTION("Good Config merge like handlers")
    {
        CoreRegistry registry;
        visor::load_builtin_plugins(registry);
        registry.start(nullptr);
        YAML::Node config_file = YAML::Load(policies_config_merge);
        CHECK(config_file["visor"]["policies"]);
        CHECK(config_file["visor"]["policies"].IsMap());
        REQUIRE_NOTHROW(registry.tap_manager()->load(config_file["visor"]["taps"]));
        REQUIRE_NOTHROW(registry.policy_manager()->load(config_file["visor"]["policies"]));

        REQUIRE(registry.policy_manager()->module_exists("default_merge"));
        auto [policy, lock] = registry.policy_manager()->module_get_locked("default_merge");
        CHECK(policy->name() == "default_merge");
        CHECK(policy->input_stream().back()->name().find("anycast_merge-") != std::string::npos);
        CHECK(policy->modules()[0]->name() == "default_merge-anycast_merge-default_dns_1");
        CHECK(policy->modules()[1]->name() == "default_merge-anycast_merge-default_dns_2");
        CHECK(policy->modules()[2]->name() == "default_merge-anycast_merge-default_net_1");
        CHECK(policy->modules()[3]->name() == "default_merge-anycast_merge-default_net_2");
        CHECK(policy->input_stream().back()->running());
        CHECK(policy->modules()[0]->running());
        CHECK(policy->modules()[1]->running());
    }

    SECTION("Good Config sequence modules")
    {
        CoreRegistry registry;
        visor::load_builtin_plugins(registry);
        registry.start(nullptr);
        YAML::Node config_file = YAML::Load(policies_config_hseq);
        CHECK(config_file["visor"]["policies"]);
        CHECK(config_file["visor"]["policies"].IsMap());
        REQUIRE_NOTHROW(registry.tap_manager()->load(config_file["visor"]["taps"]));
        REQUIRE_NOTHROW(registry.policy_manager()->load(config_file["visor"]["policies"]));

        REQUIRE(registry.policy_manager()->module_exists("default_view"));
        auto [policy, lock] = registry.policy_manager()->module_get_locked("default_view");
        CHECK(policy->name() == "default_view");
        CHECK(policy->input_stream().back()->name().find("anycast-") != std::string::npos);
        CHECK(policy->modules()[0]->name() == "default_view-anycast-default_dns");
        CHECK(policy->modules()[1]->name() == "default_view-anycast-default_net");
        CHECK(policy->input_stream().back()->running());
        CHECK(policy->modules()[0]->running());
        CHECK(policy->modules()[1]->running());
    }

    SECTION("Good Config pcap_file input feeds the policy's handlers")
    {
        CoreRegistry registry;
        visor::load_builtin_plugins(registry);
        registry.start(nullptr);
        YAML::Node config_file = YAML::Load(policies_config_pcap_file);
        REQUIRE_NOTHROW(registry.tap_manager()->load(config_file["visor"]["taps"]));
        REQUIRE_NOTHROW(registry.policy_manager()->load(config_file["visor"]["policies"]));

        // The file is read while the policy loads, so the policy's handlers and
        // the input's resources handler must both be running before it starts.
        std::string resources_name;
        {
            auto [policy, lock] = registry.policy_manager()->module_get_locked("recorded_view");
            auto net_handler = dynamic_cast<handler::net::NetStreamHandler *>(policy->modules()[0]);
            REQUIRE(net_handler);
            auto event_data = net_handler->metrics()->bucket(0)->event_data_locked();
            CHECK(event_data.num_events->value() == 140);
            CHECK(net_handler->metrics()->start_tstamp().tv_sec == 1567706414);
            resources_name = policy->input_stream().back()->name() + "-resources";
        }

        REQUIRE(registry.policy_manager()->module_exists(resources_name));
        auto [resources, lock] = registry.policy_manager()->module_get_locked(resources_name);
        CHECK(resources->running());
        auto resources_handler = dynamic_cast<handler::resources::InputResourcesStreamHandler *>(resources->modules()[0]);
        REQUIRE(resources_handler);
        json j;
        resources_handler->metrics()->bucket(0)->to_json(j);
        CHECK(j["cpu_usage"]["p50"] != nullptr);
        CHECK(j["memory_bytes"]["p50"] != nullptr);
    }

    // TODO multiple collection policies in the same yaml

    SECTION("Duplicate")
    {
        CoreRegistry registry;
        visor::load_builtin_plugins(registry);
        registry.start(nullptr);
        YAML::Node config_file = YAML::Load(policies_config);

        REQUIRE_NOTHROW(registry.tap_manager()->load(config_file["visor"]["taps"]));
        REQUIRE_NOTHROW(registry.policy_manager()->load(config_file["visor"]["policies"]));
        REQUIRE_THROWS_WITH(registry.policy_manager()->load(config_file["visor"]["policies"]), "policy with name 'default_view' already defined");

        REQUIRE(registry.policy_manager()->module_exists("default_view"));
        auto [policy, lock] = registry.policy_manager()->module_get_locked("default_view");
        CHECK(policy->name() == "default_view");
    }

    SECTION("Good Config tap selector all")
    {
        CoreRegistry registry;
        visor::load_builtin_plugins(registry);
        registry.start(nullptr);
        YAML::Node config_file = YAML::Load(policies_config_tap_selector_all);
        CHECK(config_file["visor"]["policies"]);
        CHECK(config_file["visor"]["policies"].IsMap());
        REQUIRE_NOTHROW(registry.tap_manager()->load(config_file["visor"]["taps"]));
        REQUIRE_NOTHROW(registry.policy_manager()->load(config_file["visor"]["policies"]));

        REQUIRE(registry.policy_manager()->module_exists("default_view"));
        REQUIRE_FALSE(registry.policy_manager()->module_exists("default_view_anycast2"));
    }

    SECTION("Good Config tap selector any")
    {
        CoreRegistry registry;
        visor::load_builtin_plugins(registry);
        registry.start(nullptr);
        YAML::Node config_file = YAML::Load(policies_config_tap_selector_any);
        CHECK(config_file["visor"]["policies"]);
        CHECK(config_file["visor"]["policies"].IsMap());
        REQUIRE_NOTHROW(registry.tap_manager()->load(config_file["visor"]["taps"]));
        REQUIRE_NOTHROW(registry.policy_manager()->load(config_file["visor"]["policies"]));

        REQUIRE(registry.policy_manager()->module_exists("default_view"));
    }

    SECTION("Bad Config: no policies schema")
    {
        CoreRegistry registry;
        visor::load_builtin_plugins(registry);
        REQUIRE_THROWS_WITH(registry.policy_manager()->load_from_str(policies_config_bad0), "no policies found in schema");
    }

    SECTION("Bad Config: no policies map config")
    {
        CoreRegistry registry;
        visor::load_builtin_plugins(registry);
        YAML::Node config_file = YAML::Load(policies_config_bad1);

        REQUIRE_THROWS_WITH(registry.policy_manager()->load(config_file["visor"]["policies"]), "expecting policy configuration map");
    }

    SECTION("Bad Config: empty data")
    {
        CoreRegistry registry;
        visor::load_builtin_plugins(registry);
        REQUIRE_THROWS_WITH(registry.policy_manager()->load_from_str(""), "empty data");
    }

    SECTION("Bad Config: invalid schema")
    {
        CoreRegistry registry;
        visor::load_builtin_plugins(registry);
        REQUIRE_THROWS_WITH(registry.policy_manager()->load_from_str("invalid: schema"), "invalid schema");
    }

    SECTION("Bad Config: unsupported version")
    {
        CoreRegistry registry;
        visor::load_builtin_plugins(registry);
        REQUIRE_THROWS_WITH(registry.policy_manager()->load_from_str(policies_config_bad1), "unsupported version");
    }

    SECTION("Bad Config: invalid tap")
    {
        CoreRegistry registry;
        visor::load_builtin_plugins(registry);
        YAML::Node config_file = YAML::Load(policies_config_bad2);

        REQUIRE_THROWS_WITH(registry.policy_manager()->load(config_file["visor"]["policies"]), "tap 'nonexist' does not exist");
    }

    SECTION("Bad Config: invalid tap config")
    {
        CoreRegistry registry;
        visor::load_builtin_plugins(registry);
        registry.start(nullptr);
        YAML::Node config_file = YAML::Load(policies_config_bad3);

        REQUIRE_NOTHROW(registry.tap_manager()->load(config_file["visor"]["taps"]));
        REQUIRE_THROWS_WITH(registry.policy_manager()->load(config_file["visor"]["policies"]), "missing or invalid handler configuration at key 'handlers'");
    }

    SECTION("Bad Config: exception on input start")
    {
        CoreRegistry registry;
        visor::load_builtin_plugins(registry);
        registry.start(nullptr);

        REQUIRE_NOTHROW(registry.tap_manager()->load_from_str(policies_config_bad4));
        REQUIRE_THROWS_WITH(registry.policy_manager()->load_from_str(policies_config_bad4), "policy [default_view] failed to start: mock error on start");
        CHECK_FALSE(registry.policy_manager()->module_exists("default_view"));
        REQUIRE_THROWS_WITH(registry.policy_manager()->load_from_str(policies_config_bad4), "policy [default_view] failed to start: mock error on start");
    }

    SECTION("Bad Config: exception on input start with sequence modules")
    {
        CoreRegistry registry;
        visor::load_builtin_plugins(registry);
        registry.start(nullptr);
        YAML::Node config_file = YAML::Load(policies_config_pcap_file_missing_hseq);
        REQUIRE_NOTHROW(registry.tap_manager()->load(config_file["visor"]["taps"]));

        // the handlers started before the input failed, and each one consumes the one before it, so they must
        // be stopped before they can be removed; a retry must fail the same way, not as a name clash
        for (int attempt = 0; attempt < 2; ++attempt) {
            REQUIRE_THROWS_WITH(registry.policy_manager()->load(config_file["visor"]["policies"]), "policy [broken_view] failed to start: Cannot open pcap/pcapng file");
        }
        CHECK_FALSE(registry.policy_manager()->module_exists("broken_view"));
        CHECK_FALSE(registry.handler_manager()->module_exists("broken_view-broken-broken_dns"));
        CHECK_FALSE(registry.handler_manager()->module_exists("broken_view-broken-broken_net"));
    }

    SECTION("Bad Config: a failed load leaves no reference on a shared input")
    {
        CoreRegistry registry;
        visor::load_builtin_plugins(registry);
        registry.start(nullptr);
        YAML::Node config_file = YAML::Load(policies_config_shared_input);
        REQUIRE_NOTHROW(registry.tap_manager()->load(config_file["visor"]["taps"]));
        REQUIRE_NOTHROW(registry.policy_manager()->load(config_file["visor"]["policies"]));

        std::string input_name;
        size_t policies_before;
        {
            auto [policy, lock] = registry.policy_manager()->module_get_locked("first_view");
            input_name = policy->input_stream().back()->name();
            policies_before = policy->input_stream().back()->policies_count();
        }

        // second_view reuses first_view's input and adds one that fails to start, so it fails before it has
        // started; it must still be detached from the input it shares
        YAML::Node failing = YAML::Load(policies_config_shared_input_failing);
        REQUIRE_THROWS_WITH(registry.policy_manager()->load(failing["visor"]["policies"]), "policy [second_view] failed to start: Cannot open pcap/pcapng file");
        {
            auto [input, lock] = registry.input_manager()->module_get_locked(input_name);
            CHECK(input->policies_count() == policies_before);
        }
        CHECK_FALSE(registry.handler_manager()->module_exists("second_view-live_a-second_net"));
        CHECK_FALSE(registry.handler_manager()->module_exists("second_view-broken_b-second_net"));
        {
            auto [inputs, lock] = registry.input_manager()->module_get_all_locked();
            CHECK(inputs.size() == 1);
        }

        // so removing the last policy on that input still tears it down
        REQUIRE_NOTHROW(registry.policy_manager()->remove_policy("first_view"));
        CHECK_FALSE(registry.input_manager()->module_exists(input_name));
    }

    SECTION("Bad Config: an exception that is not a runtime_error is rolled back too")
    {
        CoreRegistry registry;
        visor::load_builtin_plugins(registry);
        registry.start(nullptr);

        REQUIRE_NOTHROW(registry.tap_manager()->load_from_str(policies_config_logic_error_on_start));
        // rethrown as it was, so the API still answers it as before; and rolled back, so a retry fails the
        // same way rather than as a name clash
        for (int attempt = 0; attempt < 2; ++attempt) {
            REQUIRE_THROWS_AS(registry.policy_manager()->load_from_str(policies_config_logic_error_on_start), std::logic_error);
        }
        CHECK_FALSE(registry.policy_manager()->module_exists("default_view"));
        CHECK_FALSE(registry.handler_manager()->module_exists("default_view-anycast-default_net"));
        auto [inputs, lock] = registry.input_manager()->module_get_all_locked();
        CHECK(inputs.empty());
    }

    SECTION("Bad Config: a flow policy on a port another flow input listens on is refused")
    {
        CoreRegistry registry;
        visor::load_builtin_plugins(registry);
        registry.start(nullptr);
        YAML::Node config_file = YAML::Load(policies_config_flow_port_in_use);
        REQUIRE_NOTHROW(registry.tap_manager()->load(config_file["visor"]["taps"]));
        REQUIRE_NOTHROW(registry.policy_manager()->load(config_file["visor"]["policies"]));

        // a different config on the same port gives a second input stream, whose listener cannot bind
        YAML::Node second = YAML::Load(policies_config_flow_port_in_use_second);
        CHECK_THROWS_WITH(registry.policy_manager()->load(second["visor"]["policies"]), Catch::Matchers::StartsWith("policy [netflow_view] failed to start: unable to bind flow UDP server on 127.0.0.1:6346: "));
        CHECK_FALSE(registry.policy_manager()->module_exists("netflow_view"));
        CHECK_FALSE(registry.handler_manager()->module_exists("netflow_view-flow_tap-netflow_flow"));

        // the first policy keeps its listener
        REQUIRE(registry.policy_manager()->module_exists("sflow_view"));
        {
            auto [policy, lock] = registry.policy_manager()->module_get_locked("sflow_view");
            CHECK(policy->running());
            CHECK(policy->input_stream().back()->running());
        }
        auto [inputs, lock] = registry.input_manager()->module_get_all_locked();
        CHECK(inputs.size() == 1);
    }

    SECTION("Bad Config: a resources policy that cannot be registered is rolled back")
    {
        CoreRegistry registry;
        visor::load_builtin_plugins(registry);
        registry.start(nullptr);
        REQUIRE_NOTHROW(registry.tap_manager()->load_from_str(policies_config_logic_error_on_start));
        auto policy_on = [](const std::string &name, const std::string &sample) {
            return fmt::format(R"(
visor:
  policies:
    {0}:
      kind: collection
      input:
        tap: anycast
        input_type: mock
        config:
          sample: {1}
      handlers:
        modules:
          {0}_net:
            type: net
)",
                name, sample);
        };

        // learn the input clash_view will get, then free it
        REQUIRE_NOTHROW(registry.policy_manager()->load_from_str(policy_on("clash_view", "one")));
        std::string input_name;
        {
            auto [policy, lock] = registry.policy_manager()->module_get_locked("clash_view");
            input_name = policy->input_stream().back()->name();
        }
        REQUIRE_NOTHROW(registry.policy_manager()->remove_policy("clash_view"));

        // a policy on another input takes the name clash_view's resources policy needs, so its registration
        // fails after the policy and its input have started
        auto taken = input_name + "-resources";
        REQUIRE_NOTHROW(registry.policy_manager()->load_from_str(policy_on(taken, "two")));
        // a name in use, so the admin API answers 409
        REQUIRE_THROWS_MATCHES(registry.policy_manager()->load_from_str(policy_on("clash_view", "one")), ModuleExistsException,
            Catch::Matchers::Message(fmt::format("policy [clash_view] failed to start: module name '{}' already exists", taken)));

        // the rollback removes what the load made, and leaves the policy that owns the name alone
        CHECK_FALSE(registry.policy_manager()->module_exists("clash_view"));
        CHECK_FALSE(registry.input_manager()->module_exists(input_name));
        CHECK_FALSE(registry.handler_manager()->module_exists("clash_view-anycast-clash_view_net"));
        CHECK_FALSE(registry.handler_manager()->module_exists(taken));
        REQUIRE(registry.policy_manager()->module_exists(taken));
        auto [owner, lock] = registry.policy_manager()->module_get_locked(taken);
        CHECK(owner->running());
    }

    SECTION("Bad Config: mis-matched input_type on tap")
    {
        CoreRegistry registry;
        visor::load_builtin_plugins(registry);
        registry.start(nullptr);
        YAML::Node config_file = YAML::Load(policies_config_bad5);

        REQUIRE_NOTHROW(registry.tap_manager()->load(config_file["visor"]["taps"]));
        REQUIRE_THROWS_WITH(registry.policy_manager()->load(config_file["visor"]["policies"]), "input_type for policy specified tap 'anycast' doesn't match tap's defined input type: wrong_type/mock");
    }

    SECTION("Bad Config: bad policy kind")
    {
        CoreRegistry registry;
        visor::load_builtin_plugins(registry);
        registry.start(nullptr);
        YAML::Node config_file = YAML::Load(policies_config_bad6);

        REQUIRE_NOTHROW(registry.tap_manager()->load(config_file["visor"]["taps"]));
        REQUIRE_THROWS_WITH(registry.policy_manager()->load(config_file["visor"]["policies"]), "unknown policy kind: unknown_kind");
    }

    SECTION("Bad Config: invalid handler")
    {
        CoreRegistry registry;
        visor::load_builtin_plugins(registry);
        registry.start(nullptr);
        YAML::Node config_file = YAML::Load(policies_config_bad7);

        REQUIRE_NOTHROW(registry.tap_manager()->load(config_file["visor"]["taps"]));
        REQUIRE_THROWS_WITH(registry.policy_manager()->load(config_file["visor"]["policies"]), "Policy 'default_view' requires stream handler type 'net2' and version '1.0' which is not available");
    }

    SECTION("Bad Config: invalid handler module")
    {
        CoreRegistry registry;
        visor::load_builtin_plugins(registry);
        registry.start(nullptr);
        YAML::Node config_file = YAML::Load(policies_config_bad7);

        REQUIRE_NOTHROW(registry.tap_manager()->load(config_file["visor"]["taps"], true));
        REQUIRE_THROWS_WITH(registry.policy_manager()->load(config_file["visor"]["policies"]), "Policy 'default_view' requires stream handler type 'net2' and version '1.0' which is not available");
    }

    SECTION("Bad Config: handler module without a type")
    {
        CoreRegistry registry;
        visor::load_builtin_plugins(registry);
        registry.start(nullptr);
        YAML::Node config_file = YAML::Load(policies_config_bad8);

        REQUIRE_NOTHROW(registry.tap_manager()->load(config_file["visor"]["taps"], true));
        REQUIRE_THROWS_WITH(registry.policy_manager()->load(config_file["visor"]["policies"]), "missing or invalid stream handler type at key 'type'");
    }

    SECTION("Bad Config: handler module not map config")
    {
        CoreRegistry registry;
        visor::load_builtin_plugins(registry);
        registry.start(nullptr);
        YAML::Node config_file = YAML::Load(policies_config_bad9);

        REQUIRE_NOTHROW(registry.tap_manager()->load(config_file["visor"]["taps"], true));
        REQUIRE_THROWS_WITH(registry.policy_manager()->load(config_file["visor"]["policies"]), "stream handler configuration is not a map");
    }

    SECTION("Bad Config: handler module not map metric groups")
    {
        CoreRegistry registry;
        visor::load_builtin_plugins(registry);
        registry.start(nullptr);
        YAML::Node config_file = YAML::Load(policies_config_bad10);

        REQUIRE_NOTHROW(registry.tap_manager()->load(config_file["visor"]["taps"], true));
        REQUIRE_THROWS_WITH(registry.policy_manager()->load(config_file["visor"]["policies"]), "stream handler metric groups is not a map");
    }

    SECTION("Bad Config: handler module metric groups not valid")
    {
        CoreRegistry registry;
        visor::load_builtin_plugins(registry);
        registry.start(nullptr);
        YAML::Node config_file = YAML::Load(policies_config_bad11);

        REQUIRE_NOTHROW(registry.tap_manager()->load(config_file["visor"]["taps"], true));
        REQUIRE_THROWS_WITH(registry.policy_manager()->load(config_file["visor"]["policies"]), "stream handler metric groups should contain enable and/or disable tags");
    }

    SECTION("Bad Config: global_handler_config with not valid format")
    {
        CoreRegistry registry;
        visor::load_builtin_plugins(registry);
        registry.start(nullptr);
        YAML::Node config_file = YAML::Load(policies_config_bad13);

        REQUIRE_NOTHROW(registry.tap_manager()->load(config_file["visor"]["taps"], true));
        REQUIRE_THROWS_WITH(registry.handler_manager()->set_default_handler_config(config_file["visor"]["global_handler_config"]), "expecting global_handler_config configuration map");
    }

    SECTION("Bad Config: policy config not a map")
    {
        CoreRegistry registry;
        visor::load_builtin_plugins(registry);
        registry.start(nullptr);
        YAML::Node config_file = YAML::Load(policies_config_bad14);

        REQUIRE_NOTHROW(registry.tap_manager()->load(config_file["visor"]["taps"], true));
        REQUIRE_THROWS_WITH(registry.policy_manager()->load(config_file["visor"]["policies"]), "policy configuration is not a map");
    }

    SECTION("Bad Config: invalid handler modules YAML type")
    {
        CoreRegistry registry;
        visor::load_builtin_plugins(registry);
        registry.start(nullptr);
        REQUIRE_THROWS_WITH(YAML::Load(policies_config_hseq_bad2), "yaml-cpp: error at line 23, column 11: end of map not found");
    }

    SECTION("Bad Config: invalid matching tags for tap selector")
    {
        CoreRegistry registry;
        visor::load_builtin_plugins(registry);
        registry.start(nullptr);
        YAML::Node config_file = YAML::Load(policies_config_tap_selector_bad1);

        REQUIRE_NOTHROW(registry.tap_manager()->load(config_file["visor"]["taps"], true));
        REQUIRE_THROWS_WITH(registry.policy_manager()->load(config_file["visor"]["policies"]), "no tap match found for specified 'input.tap_selector' tags");
    }

    SECTION("Bad Config: invalid matching tags for tap selector")
    {
        CoreRegistry registry;
        visor::load_builtin_plugins(registry);
        registry.start(nullptr);
        YAML::Node config_file = YAML::Load(policies_config_tap_selector_bad2);

        REQUIRE_NOTHROW(registry.tap_manager()->load(config_file["visor"]["taps"], true));
        REQUIRE_THROWS_WITH(registry.policy_manager()->load(config_file["visor"]["policies"]), "tag key 'virtual' must have scalar value");
    }

    SECTION("Bad Config: both tap and tap selector")
    {
        CoreRegistry registry;
        visor::load_builtin_plugins(registry);
        registry.start(nullptr);
        YAML::Node config_file = YAML::Load(policies_config_tap_selector_bad3);

        REQUIRE_NOTHROW(registry.tap_manager()->load(config_file["visor"]["taps"], true));
        REQUIRE_THROWS_WITH(registry.policy_manager()->load(config_file["visor"]["policies"]), "input can have only key 'input.tap' or key 'input.tap_selector'");
    }

    SECTION("Bad Config: tap selector any must be sequence")
    {
        CoreRegistry registry;
        visor::load_builtin_plugins(registry);
        registry.start(nullptr);
        YAML::Node config_file = YAML::Load(policies_config_tap_selector_bad4);

        REQUIRE_NOTHROW(registry.tap_manager()->load(config_file["visor"]["taps"], true));
        REQUIRE_THROWS_WITH(registry.policy_manager()->load(config_file["visor"]["policies"]), "'input.tap_selector.any' is not a sequence");
    }

    SECTION("Bad Config: tap selector tag and selector must have same value type")
    {
        CoreRegistry registry;
        visor::load_builtin_plugins(registry);
        registry.start(nullptr);
        YAML::Node config_file = YAML::Load(policies_config_tap_selector_bad5);

        REQUIRE_NOTHROW(registry.tap_manager()->load(config_file["visor"]["taps"], true));
        REQUIRE_THROWS_WITH(registry.policy_manager()->load(config_file["visor"]["policies"]), "Tap [anycast2]: tag and selector value types are different for key 'vhost'");
    }

    SECTION("Bad Config: tap selector must have only one key and value")
    {
        CoreRegistry registry;
        visor::load_builtin_plugins(registry);
        registry.start(nullptr);
        YAML::Node config_file = YAML::Load(policies_config_tap_selector_bad6);

        REQUIRE_NOTHROW(registry.tap_manager()->load(config_file["visor"]["taps"], true));
        REQUIRE_THROWS_WITH(registry.policy_manager()->load(config_file["visor"]["policies"]), "selector tag must contain only one key/value pair per sequence index");
    }

    SECTION("Roll Back")
    {
        CoreRegistry registry;
        visor::load_builtin_plugins(registry);
        registry.start(nullptr);
        YAML::Node config_file = YAML::Load(policies_config);

        CHECK(config_file["visor"]["policies"]);
        CHECK(config_file["visor"]["policies"].IsMap());

        REQUIRE_NOTHROW(registry.tap_manager()->load(config_file["visor"]["taps"], true));

        // force a roll back by creating a conflict with a handler module name that already exists
        Config config;
        Config filter;
        auto input_stream = registry.input_plugins()[std::make_pair("mock", "1.0")]->instantiate("mymock", &config, &filter);
        auto stream_proxy = input_stream->add_event_proxy(filter);
        auto mod = registry.handler_plugins()[std::make_pair("net", "1.0")]->instantiate("default_view-anycast-default_net", stream_proxy, &config, &filter);
        registry.handler_manager()->module_add(std::move(mod));
        REQUIRE_THROWS_WITH(registry.policy_manager()->load(config_file["visor"]["policies"]), "module name 'default_view-anycast-default_net' already exists");

        auto input_node = config_file["visor"]["policies"]["default_view"]["input"];
        Config input_config;
        input_config.config_set_yaml(input_node["config"]);
        auto hash = input_config.config_hash();

        // ensure the modules were rolled back
        REQUIRE(!registry.policy_manager()->module_exists("default_view"));
        REQUIRE(!registry.input_manager()->module_exists("anycast-" + hash));
    }
    SECTION("Good Config, test stop()")
    {
        CoreRegistry registry;
        visor::load_builtin_plugins(registry);
        registry.start(nullptr);
        YAML::Node config_file = YAML::Load(policies_config);

        CHECK(config_file["visor"]["policies"]);
        CHECK(config_file["visor"]["policies"].IsMap());

        REQUIRE_NOTHROW(registry.tap_manager()->load(config_file["visor"]["taps"], true));
        REQUIRE_NOTHROW(registry.policy_manager()->load(config_file["visor"]["policies"]));

        REQUIRE(registry.policy_manager()->module_exists("default_view"));
        auto [policy, lock] = registry.policy_manager()->module_get_locked("default_view");
        CHECK(policy->name() == "default_view");
        CHECK(policy->input_stream().back()->running());
        CHECK(policy->modules()[0]->running());
        CHECK(policy->modules()[1]->running());
        CHECK(policy->modules()[2]->running());
        policy->stop();
        CHECK(policy->input_stream().back()->running());
        CHECK(!policy->modules()[0]->running());
        CHECK(!policy->modules()[1]->running());
        CHECK(!policy->modules()[2]->running());
        lock.unlock();
        REQUIRE_NOTHROW(registry.policy_manager()->module_remove("default_view"));
    }

    SECTION("Good Config, test remove policy and add again")
    {
        CoreRegistry registry;
        visor::load_builtin_plugins(registry);
        registry.start(nullptr);
        YAML::Node config_file = YAML::Load(policies_config);

        CHECK(config_file["visor"]["policies"]);
        CHECK(config_file["visor"]["policies"].IsMap());

        REQUIRE_NOTHROW(registry.tap_manager()->load(config_file["visor"]["taps"], true));
        REQUIRE_NOTHROW(registry.policy_manager()->load(config_file["visor"]["policies"]));

        REQUIRE(registry.policy_manager()->module_exists("default_view"));
        auto [policy, lock] = registry.policy_manager()->module_get_locked("default_view");
        CHECK(policy->name() == "default_view");
        CHECK(policy->input_stream().back()->running());
        CHECK(policy->modules()[0]->running());
        CHECK(policy->modules()[1]->running());
        CHECK(policy->modules()[2]->running());
        lock.unlock();

        REQUIRE_NOTHROW(registry.policy_manager()->remove_policy("default_view"));

        REQUIRE_NOTHROW(registry.policy_manager()->load(config_file["visor"]["policies"]));
        REQUIRE(registry.policy_manager()->module_exists("default_view"));
        auto [new_policy, new_lock] = registry.policy_manager()->module_get_locked("default_view");
        CHECK(new_policy->name() == "default_view");
        CHECK(new_policy->input_stream().back()->running());
        CHECK(new_policy->modules()[0]->running());
        CHECK(new_policy->modules()[1]->running());
        CHECK(new_policy->modules()[2]->running());
        new_lock.unlock();
        REQUIRE_NOTHROW(registry.policy_manager()->remove_policy("default_view"));
    }

    SECTION("Good Config, test remove sequence handler policy and add again")
    {
        CoreRegistry registry;
        visor::load_builtin_plugins(registry);
        registry.start(nullptr);
        YAML::Node config_file = YAML::Load(policies_config_hseq);

        CHECK(config_file["visor"]["policies"]);
        CHECK(config_file["visor"]["policies"].IsMap());

        REQUIRE_NOTHROW(registry.tap_manager()->load(config_file["visor"]["taps"], true));
        REQUIRE_NOTHROW(registry.policy_manager()->load(config_file["visor"]["policies"]));

        REQUIRE(registry.policy_manager()->module_exists("default_view"));
        auto [policy, lock] = registry.policy_manager()->module_get_locked("default_view");
        CHECK(policy->name() == "default_view");
        CHECK(policy->input_stream().back()->running());
        CHECK(policy->modules()[0]->running());
        CHECK(policy->modules()[1]->running());
        lock.unlock();

        REQUIRE_NOTHROW(registry.policy_manager()->remove_policy("default_view"));

        REQUIRE_NOTHROW(registry.policy_manager()->load(config_file["visor"]["policies"]));
        REQUIRE(registry.policy_manager()->module_exists("default_view"));
        auto [new_policy, new_lock] = registry.policy_manager()->module_get_locked("default_view");
        CHECK(new_policy->name() == "default_view");
        CHECK(new_policy->input_stream().back()->running());
        CHECK(new_policy->modules()[0]->running());
        CHECK(new_policy->modules()[1]->running());
        new_lock.unlock();
        REQUIRE_NOTHROW(registry.policy_manager()->remove_policy("default_view"));
    }

    SECTION("Good Config, policies with same tap and input")
    {
        CoreRegistry registry;
        visor::load_builtin_plugins(registry);
        registry.start(nullptr);
        YAML::Node config_file = YAML::Load(policies_config);

        CHECK(config_file["visor"]["policies"]);
        CHECK(config_file["visor"]["policies"].IsMap());

        REQUIRE_NOTHROW(registry.tap_manager()->load(config_file["visor"]["taps"], true));
        REQUIRE_NOTHROW(registry.policy_manager()->load(config_file["visor"]["policies"]));

        REQUIRE(registry.policy_manager()->module_exists("default_view"));
        auto [policy, lock] = registry.policy_manager()->module_get_locked("default_view");
        CHECK(policy->name() == "default_view");
        CHECK(policy->input_stream().back()->name().find("anycast-") != std::string::npos);
        lock.unlock();

        YAML::Node config_file2 = YAML::Load(policies_config_same_input);
        CHECK(config_file2["visor"]["policies"]);
        CHECK(config_file2["visor"]["policies"].IsMap());

        REQUIRE_NOTHROW(registry.policy_manager()->load(config_file2["visor"]["policies"]));

        REQUIRE(registry.policy_manager()->module_exists("same_input"));
        auto [policy2, lock2] = registry.policy_manager()->module_get_locked("same_input");
        CHECK(policy2->name() == "same_input");
        CHECK(policy2->input_stream().back()->name() == policy->input_stream().back()->name());
        lock2.unlock();
    }
}

TEST_CASE("Policies and Metrics", "[policies][metrics]")
{
    CoreRegistry registry;
    visor::load_builtin_plugins(registry);
    registry.start(nullptr);
    YAML::Node config_file = YAML::Load(policies_config);
    CHECK(config_file["visor"]["policies"]);
    CHECK(config_file["visor"]["policies"].IsMap());
    REQUIRE_NOTHROW(registry.tap_manager()->load(config_file["visor"]["taps"]));
    REQUIRE_NOTHROW(registry.policy_manager()->load(config_file["visor"]["policies"]));
    REQUIRE(registry.policy_manager()->module_exists("default_view"));

    SECTION("JSON")
    {
        auto [policy, lock] = registry.policy_manager()->module_get_locked("default_view");
        json j;
        policy->json_metrics(j, 0, false);
        CHECK(j["default_view"]["default_view-anycast-default_dns"] != nullptr);
        CHECK(j["default_view"]["default_view-anycast-default_net"] != nullptr);
    }

    SECTION("Prometheus")
    {
        auto [policy, lock] = registry.policy_manager()->module_get_locked("default_view");
        std::stringstream out;
        REQUIRE_NOTHROW(policy->prometheus_metrics(out));
    }

    SECTION("Opentelemetry")
    {
        auto [policy, lock] = registry.policy_manager()->module_get_locked("default_view");
        metrics::v1::ScopeMetrics scope;
        REQUIRE_NOTHROW(policy->opentelemetry_metrics(scope));
    }

    SECTION("Opentelemetry push carries only policies with a window")
    {
        metrics::v1::ResourceMetrics resource;
        registry.policy_manager()->opentelemetry_metrics(resource);
        // Whatever the first push held, nothing is new right after it.
        resource.Clear();
        CHECK_FALSE(registry.policy_manager()->opentelemetry_metrics(resource));
        CHECK(resource.scope_metrics_size() == 0);
    }

    config_file = YAML::Load(policies_config_merge);
    CHECK(config_file["visor"]["policies"]);
    CHECK(config_file["visor"]["policies"].IsMap());
    REQUIRE_NOTHROW(registry.tap_manager()->load(config_file["visor"]["taps"]));
    REQUIRE_NOTHROW(registry.policy_manager()->load(config_file["visor"]["policies"]));
    REQUIRE(registry.policy_manager()->module_exists("default_merge"));

    SECTION("JSON merge_like_handlers")
    {
        auto [policy, lock] = registry.policy_manager()->module_get_locked("default_merge");
        json j;
        policy->json_metrics(j, 0, false);
        std::cout << j.dump();
        CHECK(j["default_merge"]["dns_merged"] != nullptr);
        CHECK(j["default_merge"]["packets_merged"] != nullptr);
    }

    SECTION("Prometheus merge_like_handlers")
    {
        auto [policy, lock] = registry.policy_manager()->module_get_locked("default_merge");
        std::stringstream out;
        REQUIRE_NOTHROW(policy->prometheus_metrics(out));
    }

    SECTION("Opentelemetry merge_like_handlers")
    {
        auto [policy, lock] = registry.policy_manager()->module_get_locked("default_merge");
        metrics::v1::ScopeMetrics scope;
        REQUIRE_NOTHROW(policy->opentelemetry_metrics(scope));
    }

    SECTION("Opentelemetry merge_like_handlers pushes each window once")
    {
        auto [policy, lock] = registry.policy_manager()->module_get_locked("default_merge");
        auto mods = policy->modules();
        REQUIRE(mods.size() == 4);
        // Closes a window on the handlers given at stamp, as an input event would.
        auto close_window = [](const std::vector<AbstractRunnableModule *> &handlers, timespec stamp) {
            for (auto mod : handlers) {
                if (auto dns = dynamic_cast<handler::dns::DnsStreamHandler *>(mod)) {
                    dns->check_period_shift(stamp);
                } else if (auto net = dynamic_cast<handler::net::NetStreamHandler *>(mod)) {
                    net->check_period_shift(stamp);
                }
            }
        };
        // When each window in the push ended, which names the window.
        auto window_ends = [](const metrics::v1::ScopeMetrics &scope) {
            std::set<uint64_t> ends;
            for (const auto &metric : scope.metrics()) {
                for (const auto &point : metric.gauge().data_points()) {
                    ends.insert(point.time_unix_nano());
                }
                for (const auto &point : metric.sum().data_points()) {
                    ends.insert(point.time_unix_nano());
                }
                for (const auto &point : metric.summary().data_points()) {
                    ends.insert(point.time_unix_nano());
                }
                for (const auto &point : metric.histogram().data_points()) {
                    ends.insert(point.time_unix_nano());
                }
            }
            return ends;
        };
        auto ns = [](timespec t) { return static_cast<uint64_t>(t.tv_sec) * 1000000000ULL; };
        timespec t1;
        timespec_get(&t1, TIME_UTC);
        t1.tv_sec += 61;
        auto t2 = t1;
        t2.tv_sec += 60;
        auto t3 = t2;
        t3.tv_sec += 60;

        metrics::v1::ScopeMetrics scope;
        policy->opentelemetry_metrics(scope);
        CHECK(scope.metrics_size() == 0);

        close_window(mods, t1);
        policy->opentelemetry_metrics(scope);
        CHECK(window_ends(scope) == std::set<uint64_t>{ns(t1)});
        scope.Clear();
        policy->opentelemetry_metrics(scope);
        CHECK(scope.metrics_size() == 0);

        // One handler closes two windows while the others close one, and each
        // push still merges the same window from every handler.
        close_window({mods[0]}, t2);
        policy->opentelemetry_metrics(scope);
        CHECK(scope.metrics_size() == 0);
        close_window({mods[0]}, t3);
        close_window({mods[1], mods[2], mods[3]}, t2);
        policy->opentelemetry_metrics(scope);
        CHECK(window_ends(scope) == std::set<uint64_t>{ns(t2)});
        scope.Clear();
        policy->opentelemetry_metrics(scope);
        CHECK(scope.metrics_size() == 0);
        close_window({mods[1], mods[2], mods[3]}, t3);
        policy->opentelemetry_metrics(scope);
        CHECK(window_ends(scope) == std::set<uint64_t>{ns(t3)});
    }
}

static auto policies_config_two_policies = R"(
version: "1.0"

visor:
  taps:
    tap_multi:
      input_type: mock
      config:
        iface: eth0
  policies:
    policy_alpha:
      kind: collection
      input:
        tap: tap_multi
        input_type: mock
      handlers:
        window_config:
          num_periods: 5
          deep_sample_rate: 100
        modules:
          net:
            type: net
    policy_beta:
      kind: collection
      input:
        tap: tap_multi
        input_type: mock
      handlers:
        window_config:
          num_periods: 5
          deep_sample_rate: 100
        modules:
          net:
            type: net
)";

// Count non-overlapping occurrences of needle in haystack.
static int count_occurrences(const std::string &haystack, const std::string &needle)
{
    int count = 0;
    std::string::size_type pos = 0;
    while ((pos = haystack.find(needle, pos)) != std::string::npos) {
        ++count;
        pos += needle.size();
    }
    return count;
}

TEST_CASE("Multi-policy Prometheus shared serializer", "[policies][prometheus][multi-policy]")
{
    // Regression test for #716: rendering two policies through a shared PrometheusSerializer
    // must produce exactly one # HELP / # TYPE line per metric family, not one per policy.
    CoreRegistry registry;
    visor::load_builtin_plugins(registry);
    registry.start(nullptr);

    YAML::Node config_file = YAML::Load(policies_config_two_policies);
    REQUIRE_NOTHROW(registry.tap_manager()->load(config_file["visor"]["taps"]));
    REQUIRE_NOTHROW(registry.policy_manager()->load(config_file["visor"]["policies"]));
    REQUIRE(registry.policy_manager()->module_exists("policy_alpha"));
    REQUIRE(registry.policy_manager()->module_exists("policy_beta"));

    SECTION("Shared serializer produces unique # HELP and # TYPE headers")
    {
        PrometheusSerializer ser;

        {
            auto [policy, lock] = registry.policy_manager()->module_get_locked("policy_alpha");
            REQUIRE_NOTHROW(policy->prometheus_metrics(ser));
        }
        {
            auto [policy, lock] = registry.policy_manager()->module_get_locked("policy_beta");
            REQUIRE_NOTHROW(policy->prometheus_metrics(ser));
        }

        std::string output = ser.finalize();
        REQUIRE(!output.empty());

        // Every metric family must have its # HELP and # TYPE header emitted exactly once,
        // even when two policies contribute series to the same family.
        CHECK(count_occurrences(output, "# HELP packets_udp ") == 1);
        CHECK(count_occurrences(output, "# TYPE packets_udp ") == 1);
        CHECK(count_occurrences(output, "# HELP packets_tcp ") == 1);
        CHECK(count_occurrences(output, "# TYPE packets_tcp ") == 1);
        // Each policy must still contribute its own series (two distinct policy= label values).
        CHECK(count_occurrences(output, "policy=\"policy_alpha\"") >= 1);
        CHECK(count_occurrences(output, "policy=\"policy_beta\"") >= 1);
    }
}

TEST_CASE("OpenTelemetry push tags each policy's scope with pktvisor.policy.name", "[policies][metrics][multi-policy]")
{
    CoreRegistry registry;
    visor::load_builtin_plugins(registry);
    registry.start(nullptr);

    YAML::Node config_file = YAML::Load(policies_config_two_policies);
    REQUIRE_NOTHROW(registry.tap_manager()->load(config_file["visor"]["taps"]));
    REQUIRE_NOTHROW(registry.policy_manager()->load(config_file["visor"]["policies"]));
    const std::vector<std::string> names{"policy_alpha", "policy_beta"};

    // Closes a window on every handler so each policy has a scope to push.
    timespec stamp;
    timespec_get(&stamp, TIME_UTC);
    stamp.tv_sec += 61;
    for (const auto &name : names) {
        auto [policy, lock] = registry.policy_manager()->module_get_locked(name);
        for (auto mod : policy->modules()) {
            auto net = dynamic_cast<handler::net::NetStreamHandler *>(mod);
            REQUIRE(net);
            net->check_period_shift(stamp);
        }
    }

    metrics::v1::ResourceMetrics resource;
    REQUIRE(registry.policy_manager()->opentelemetry_metrics(resource));

    std::map<std::string, const metrics::v1::ScopeMetrics *> by_scope_name;
    for (const auto &scope : resource.scope_metrics()) {
        by_scope_name[scope.scope().name()] = &scope;
    }
    for (const auto &name : names) {
        CAPTURE(name);
        auto it = by_scope_name.find("pktvisor/" + name);
        REQUIRE(it != by_scope_name.end());
        const auto &attributes = it->second->scope().attributes();
        REQUIRE(attributes.size() == 1);
        CHECK(attributes[0].key() == "pktvisor.policy.name");
        CHECK(attributes[0].value().string_value() == name);
        for (const auto &attribute : attributes) {
            CHECK(attribute.key() != "policy_name");
        }
    }
}

// keeps the visor logger to warnings while in scope, for tests that log several lines per iteration
struct QuietLogger {
    std::shared_ptr<spdlog::logger> logger = spdlog::get("visor");
    spdlog::level::level_enum level = logger->level();
    QuietLogger()
    {
        logger->set_level(spdlog::level::warn);
    }
    ~QuietLogger()
    {
        logger->set_level(level);
    }
};

TEST_CASE("Loading and removing policies concurrently does not deadlock", "[policies][concurrency]")
{
    CoreRegistry registry;
    visor::load_builtin_plugins(registry);
    registry.start(nullptr);
    REQUIRE_NOTHROW(registry.tap_manager()->load_from_str(R"(
visor:
  taps:
    anycast:
      input_type: mock
      config:
        iface: eth0
)"));

    QuietLogger quiet;

    // every policy gets an input of its own, so each load creates an input and its resources policy and each
    // removal tears both down: load and remove_policy then take the input and policy maps on every iteration,
    // and a load runs while the other thread removes. A slow build stops early; the deadlock this guards
    // against showed up within 2000 iterations.
    auto stop_at = std::chrono::steady_clock::now() + std::chrono::seconds(15);
    auto churn = [&registry, stop_at](const std::string &prefix) {
        for (int i = 0; i < 5000 && std::chrono::steady_clock::now() < stop_at; ++i) {
            auto name = fmt::format("{}_{}", prefix, i);
            registry.policy_manager()->load_from_str(fmt::format(R"(
visor:
  policies:
    {0}:
      kind: collection
      input:
        tap: anycast
        input_type: mock
        config:
          sample: {0}
      handlers:
        modules:
          {0}_net:
            type: net
)",
                name));
            registry.policy_manager()->remove_policy(name);
        }
    };

    auto a = std::async(std::launch::async, churn, std::string("a"));
    auto b = std::async(std::launch::async, churn, std::string("b"));
    // well past the time box, so it only fires on a hang
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(180);
    if (a.wait_until(deadline) == std::future_status::timeout || b.wait_until(deadline) == std::future_status::timeout) {
        // the stuck threads can never be joined, so fail loudly instead of hanging the suite
        std::fprintf(stderr, "load and remove_policy did not finish within 180 s, most likely a deadlock\n");
        std::abort();
    }
    REQUIRE_NOTHROW(a.get());
    REQUIRE_NOTHROW(b.get());
    {
        auto [policies, lock] = registry.policy_manager()->module_get_all_locked();
        CHECK(policies.empty());
    }
    {
        auto [handlers, lock] = registry.handler_manager()->module_get_all_locked();
        CHECK(handlers.empty());
    }
    auto [inputs, lock] = registry.input_manager()->module_get_all_locked();
    CHECK(inputs.empty());
}

TEST_CASE("Removing a tap detaches it from every policy", "[policies][taps]")
{
    CoreRegistry registry;
    visor::load_builtin_plugins(registry);
    registry.start(nullptr);
    REQUIRE_NOTHROW(registry.tap_manager()->load_from_str(R"(
visor:
  taps:
    anycast:
      input_type: mock
      config:
        iface: eth0
)"));
    for (auto name : {"view_a", "view_b"}) {
        REQUIRE_NOTHROW(registry.policy_manager()->load_from_str(fmt::format(R"(
visor:
  policies:
    {0}:
      kind: collection
      input:
        tap: anycast
        input_type: mock
      handlers:
        modules:
          {0}_net:
            type: net
)",
            name)));
    }

    registry.policy_manager()->remove_tap("anycast");

    CHECK_FALSE(registry.tap_manager()->module_exists("anycast"));
    for (auto name : {"view_a", "view_b"}) {
        auto [policy, lock] = registry.policy_manager()->module_get_locked(name);
        CHECK(policy->taps().empty());
    }
    REQUIRE_THROWS_WITH(registry.policy_manager()->remove_tap("anycast"), "module name 'anycast' does not exist");
}

TEST_CASE("Removing taps concurrently does not deadlock", "[policies][taps][concurrency]")
{
    CoreRegistry registry;
    visor::load_builtin_plugins(registry);
    registry.start(nullptr);
    REQUIRE_NOTHROW(registry.tap_manager()->load_from_str(R"(
visor:
  taps:
    anycast:
      input_type: mock
      config:
        iface: eth0
)"));

    QuietLogger quiet;

    // two threads load and remove taps of their own while a third loads and removes policies, each with its own
    // input, so every lock a tap removal takes is also taken in the other orders the managers use
    auto stop_at = std::chrono::steady_clock::now() + std::chrono::seconds(15);
    std::atomic<bool> taps_done{false};
    auto policies = std::async(std::launch::async, [&registry, &taps_done, stop_at] {
        for (int i = 0; !taps_done && std::chrono::steady_clock::now() < stop_at; ++i) {
            auto name = fmt::format("view_{}", i);
            registry.policy_manager()->load_from_str(fmt::format(R"(
visor:
  policies:
    {0}:
      kind: collection
      input:
        tap: anycast
        input_type: mock
        config:
          sample: {0}
      handlers:
        modules:
          {0}_net:
            type: net
)",
                name));
            registry.policy_manager()->remove_policy(name);
        }
    });
    auto churn = [&registry, stop_at](const std::string &prefix) {
        for (int i = 0; i < 5000 && std::chrono::steady_clock::now() < stop_at; ++i) {
            auto name = fmt::format("{}_{}", prefix, i);
            registry.tap_manager()->load_from_str(fmt::format(R"(
visor:
  taps:
    {}:
      input_type: mock
)",
                name));
            registry.policy_manager()->remove_tap(name);
        }
    };

    auto a = std::async(std::launch::async, churn, std::string("a"));
    auto b = std::async(std::launch::async, churn, std::string("b"));
    // well past the time box, so it only fires on a hang
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(180);
    auto hung = a.wait_until(deadline) == std::future_status::timeout || b.wait_until(deadline) == std::future_status::timeout;
    taps_done = true;
    if (hung || policies.wait_until(deadline) == std::future_status::timeout) {
        // the stuck threads can never be joined, so fail loudly instead of hanging the suite
        std::fprintf(stderr, "concurrent tap removals did not finish within 180 s, most likely a deadlock\n");
        std::abort();
    }
    REQUIRE_NOTHROW(a.get());
    REQUIRE_NOTHROW(b.get());
    REQUIRE_NOTHROW(policies.get());
    {
        auto [policy_modules, lock] = registry.policy_manager()->module_get_all_locked();
        CHECK(policy_modules.empty());
    }
    auto [taps, lock] = registry.tap_manager()->module_get_all_locked();
    CHECK(taps.size() == 1);
}

// once armed, holds the next policy load at its first registration, after it has added its taps to the policy, or
// with hold_after set, just after it registers the policy of that name
class GatedPolicyManager : public PolicyManager
{
    void hold()
    {
        armed = false;
        reached.set_value();
        release.wait();
    }

public:
    using PolicyManager::PolicyManager;

    bool armed{false};
    std::string hold_after;
    std::promise<void> reached;
    std::shared_future<void> release;

    void module_add(std::unique_ptr<Policy> &&m) override
    {
        auto name = m->name();
        if (armed && hold_after.empty()) {
            hold();
        }
        PolicyManager::module_add(std::move(m));
        if (armed && name == hold_after) {
            hold();
        }
    }
};

// opens once, by release() or on destruction, so a failed REQUIRE does not leave a load held for good
struct Gate {
    std::promise<void> promise;
    bool open{false};
    void release()
    {
        if (!open) {
            open = true;
            promise.set_value();
        }
    }
    ~Gate()
    {
        release();
    }
};

static const char *DEFAULT_VIEW_POLICY = R"(
visor:
  policies:
    default_view:
      kind: collection
      input:
        tap: anycast
        input_type: mock
      handlers:
        modules:
          default_net:
            type: net
)";

// returns once the load is held at its gate, failing if it finishes first
static void wait_held(std::future<void> &reached, std::future<void> &load)
{
    // a load that fails before the gate finishes without reaching it
    auto reach_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(180);
    while (reached.wait_for(std::chrono::milliseconds(10)) == std::future_status::timeout) {
        if (load.wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
            REQUIRE_NOTHROW(load.get());
            FAIL("the policy load finished without reaching the gate");
        }
        if (std::chrono::steady_clock::now() > reach_deadline) {
            std::fprintf(stderr, "the policy load neither reached the gate nor finished within 180 s\n");
            std::abort();
        }
    }
}

// starts loading default_view on the tap anycast, or runs load, and returns once the load is held at the gate
static std::future<void> hold_load_at_gate(GatedPolicyManager &policies, Gate &gate, std::function<void()> load = {})
{
    policies.release = gate.promise.get_future().share();
    policies.armed = true;
    auto reached = policies.reached.get_future();

    if (!load) {
        load = [&policies] { policies.load_from_str(DEFAULT_VIEW_POLICY); };
    }
    auto loading = std::async(std::launch::async, std::move(load));
    wait_held(reached, loading);
    return loading;
}

TEST_CASE("Removing a tap waits for a policy load that holds it", "[policies][taps][concurrency]")
{
    CoreRegistry registry;
    visor::load_builtin_plugins(registry);
    registry.start(nullptr);
    REQUIRE_NOTHROW(registry.tap_manager()->load_from_str(R"(
visor:
  taps:
    anycast:
      input_type: mock
      config:
        iface: eth0
)"));

    GatedPolicyManager policies(&registry);
    std::future<void> load;
    std::future<void> remove;
    // declared after the futures so it is destroyed first: a failed REQUIRE releases the load before the futures
    // wait for their threads
    Gate gate;
    load = hold_load_at_gate(policies, gate);

    // the policy holds the tap but is not registered yet, so a removal now would leave it holding a freed tap
    remove = std::async(std::launch::async, [&policies] { policies.remove_tap("anycast"); });
    CHECK(remove.wait_for(std::chrono::milliseconds(200)) == std::future_status::timeout);
    gate.release();
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(180);
    if (load.wait_until(deadline) == std::future_status::timeout || remove.wait_until(deadline) == std::future_status::timeout) {
        // the stuck threads can never be joined, so fail loudly instead of hanging the suite
        std::fprintf(stderr, "the policy load and the tap removal did not finish within 180 s, most likely a deadlock\n");
        std::abort();
    }
    REQUIRE_NOTHROW(load.get());
    REQUIRE_NOTHROW(remove.get());

    CHECK_FALSE(registry.tap_manager()->module_exists("anycast"));
    {
        auto [policy, lock] = policies.module_get_locked("default_view");
        CHECK(policy->taps().empty());
    }
    policies.remove_policy("default_view");
}

TEST_CASE("Deleting a tap that does not exist answers 404 without waiting for a policy load", "[policies][taps][concurrency]")
{
    CoreRegistry registry;
    visor::load_builtin_plugins(registry);
    registry.start(nullptr);
    REQUIRE_NOTHROW(registry.tap_manager()->load_from_str(R"(
visor:
  taps:
    anycast:
      input_type: mock
      config:
        iface: eth0
)"));

    GatedPolicyManager policies(&registry);
    std::future<void> load;
    std::future<httplib::Response> remove;
    // declared after the futures so it is destroyed first: a failed REQUIRE releases the load before the futures
    // wait for their threads
    Gate gate;
    load = hold_load_at_gate(policies, gate);

    // the held load keeps the lock that removing a tap waits for, as a load starting a long pcap_file input does
    remove = std::async(std::launch::async, [&policies] {
        httplib::Response res;
        api::delete_tap(policies, "missing", res);
        return res;
    });
    CHECK(remove.wait_for(std::chrono::seconds(5)) == std::future_status::ready);
    gate.release();
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(180);
    if (load.wait_until(deadline) == std::future_status::timeout || remove.wait_until(deadline) == std::future_status::timeout) {
        // the stuck threads can never be joined, so fail loudly instead of hanging the suite
        std::fprintf(stderr, "the policy load and the tap delete did not finish within 180 s, most likely a deadlock\n");
        std::abort();
    }
    REQUIRE_NOTHROW(load.get());
    auto res = remove.get();
    CHECK(res.status == 404);
    CHECK(json::parse(res.body) == json{{"error", "tap does not exists"}});
    CHECK(registry.tap_manager()->module_exists("anycast"));
    policies.remove_policy("default_view");
}

TEST_CASE("Two deletes of a tap that both found it remove it once and answer 404 to the other", "[policies][taps][concurrency]")
{
    CoreRegistry registry;
    visor::load_builtin_plugins(registry);
    registry.start(nullptr);
    REQUIRE_NOTHROW(registry.tap_manager()->load_from_str(R"(
visor:
  taps:
    anycast:
      input_type: mock
      config:
        iface: eth0
)"));

    GatedPolicyManager policies(&registry);
    std::future<void> load;
    std::future<httplib::Response> first;
    std::future<httplib::Response> second;
    // declared after the futures so it is destroyed first: a failed REQUIRE releases the load before the futures
    // wait for their threads
    Gate gate;
    load = hold_load_at_gate(policies, gate);

    // only remove_tap removes taps, and it waits for the held load, so both deletes find the tap before they wait.
    // Once the load ends, one removes the tap and the other must find it gone under the locks
    auto remove = [&policies] {
        httplib::Response res;
        api::delete_tap(policies, "anycast", res);
        return res;
    };
    first = std::async(std::launch::async, remove);
    second = std::async(std::launch::async, remove);
    CHECK(first.wait_for(std::chrono::milliseconds(200)) == std::future_status::timeout);
    CHECK(second.wait_for(std::chrono::seconds(0)) == std::future_status::timeout);
    gate.release();
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(180);
    if (load.wait_until(deadline) == std::future_status::timeout || first.wait_until(deadline) == std::future_status::timeout || second.wait_until(deadline) == std::future_status::timeout) {
        // the stuck threads can never be joined, so fail loudly instead of hanging the suite
        std::fprintf(stderr, "the policy load and the tap deletes did not finish within 180 s, most likely a deadlock\n");
        std::abort();
    }
    REQUIRE_NOTHROW(load.get());
    auto a = first.get();
    auto b = second.get();
    auto &missing = (a.status == 404) ? a : b;
    CHECK(std::set<int>{a.status, b.status} == std::set<int>{200, 404});
    CHECK(json::parse(missing.body) == json{{"error", "tap does not exists"}});
    CHECK_FALSE(registry.tap_manager()->module_exists("anycast"));
    {
        auto [policy, lock] = policies.module_get_locked("default_view");
        CHECK(policy->taps().empty());
    }
    policies.remove_policy("default_view");
}

TEST_CASE("Concurrent removals of a policy remove it once and find it missing otherwise", "[policies][concurrency]")
{
    CoreRegistry registry;
    visor::load_builtin_plugins(registry);
    registry.start(nullptr);
    REQUIRE_NOTHROW(registry.tap_manager()->load_from_str(R"(
visor:
  taps:
    anycast:
      input_type: mock
      config:
        iface: eth0
)"));

    QuietLogger quiet;

    // each round starts four removals together: one removes the policy, and the others throw ModuleException, which
    // DELETE /api/v1/policies/{name} answers with 404
    int removed{0};
    int missing{0};
    std::vector<std::string> failures;
    for (int round = 0; round < 100; ++round) {
        REQUIRE_NOTHROW(registry.policy_manager()->load_from_str(R"(
visor:
  policies:
    default_view:
      kind: collection
      input:
        tap: anycast
        input_type: mock
      handlers:
        modules:
          default_net:
            type: net
)"));
        std::promise<void> go;
        std::shared_future<void> start = go.get_future().share();
        std::vector<std::future<bool>> removals;
        for (int i = 0; i < 4; ++i) {
            removals.push_back(std::async(std::launch::async, [&registry, start] {
                start.wait();
                try {
                    registry.policy_manager()->remove_policy("default_view");
                    return true;
                } catch (const ModuleException &) {
                    return false;
                }
            }));
        }
        go.set_value();
        // well past what a round takes, so it only fires on a hang
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(180);
        for (auto &removal : removals) {
            if (removal.wait_until(deadline) == std::future_status::timeout) {
                // the stuck threads can never be joined, so fail loudly instead of hanging the suite
                std::fprintf(stderr, "concurrent policy removals did not finish within 180 s, most likely a deadlock\n");
                std::abort();
            }
            try {
                if (removal.get()) {
                    ++removed;
                } else {
                    ++missing;
                }
            } catch (const std::exception &e) {
                failures.emplace_back(e.what());
            }
        }
    }

    CHECK(removed == 100);
    CHECK(missing == 300);
    CHECK(failures == std::vector<std::string>{});
    auto [inputs, lock] = registry.input_manager()->module_get_all_locked();
    CHECK(inputs.empty());
}

static const char *ANYCAST_TAP = R"(
visor:
  taps:
    anycast:
      input_type: mock
      config:
        iface: eth0
)";

// on the tap anycast, with the same input whatever the name, so the policies loaded from it share one input
static std::string policy_on_shared_input(const std::string &name)
{
    return fmt::format(R"(
visor:
  policies:
    {0}:
      kind: collection
      input:
        tap: anycast
        input_type: mock
      handlers:
        modules:
          {0}_net:
            type: net
)",
        name);
}

// waits for every thread until 180 s from now, well past any test's time box, so it only fires on a hang
template <typename... Futures>
static void wait_or_abort(const char *what, Futures &...threads)
{
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(180);
    if (((threads.wait_until(deadline) == std::future_status::timeout) || ...)) {
        // the stuck threads can never be joined, so fail loudly instead of hanging the suite
        std::fprintf(stderr, "%s did not finish within 180 s, most likely a deadlock\n", what);
        std::abort();
    }
}

static void check_no_modules(CoreRegistry &registry)
{
    {
        auto [policies, lock] = registry.policy_manager()->module_get_all_locked();
        CHECK(policies.empty());
    }
    {
        auto [handlers, lock] = registry.handler_manager()->module_get_all_locked();
        CHECK(handlers.empty());
    }
    auto [inputs, lock] = registry.input_manager()->module_get_all_locked();
    CHECK(inputs.empty());
}

TEST_CASE("POST and DELETE of one tap at once", "[policies][taps][api][concurrency]")
{
    CoreRegistry registry;
    visor::load_builtin_plugins(registry);
    registry.start(nullptr);

    QuietLogger quiet;

    auto stop_at = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    std::map<int, int> post_statuses;
    std::map<int, int> delete_statuses;
    int bad_bodies{0};
    auto post = std::async(std::launch::async, [&registry, &post_statuses, &bad_bodies, stop_at] {
        while (std::chrono::steady_clock::now() < stop_at) {
            httplib::Response res;
            api::post_taps(*registry.tap_manager(), ANYCAST_TAP, res);
            ++post_statuses[res.status];
            if (res.status == 201) {
                auto j = json::parse(res.body);
                if (j["anycast"]["input_type"] != "mock" || j["anycast"]["config"]["iface"] != "eth0") {
                    ++bad_bodies;
                }
            }
        }
    });
    auto remove = std::async(std::launch::async, [&registry, &delete_statuses, stop_at] {
        while (std::chrono::steady_clock::now() < stop_at) {
            httplib::Response res;
            api::delete_tap(*registry.policy_manager(), "anycast", res);
            ++delete_statuses[res.status];
        }
    });
    wait_or_abort("racing tap POST and DELETE", post, remove);
    REQUIRE_NOTHROW(post.get());
    REQUIRE_NOTHROW(remove.get());

    // a POST that loads the tap answers with it as loaded, even if a DELETE has removed it since; one that finds the
    // tap still there is refused
    INFO("POST: " << json(post_statuses).dump() << " DELETE: " << json(delete_statuses).dump());
    for (auto &[code, count] : post_statuses) {
        CHECK((code == 201 || code == 409));
    }
    for (auto &[code, count] : delete_statuses) {
        CHECK((code == 200 || code == 404));
    }
    CHECK(post_statuses[201] > 0);
    CHECK(delete_statuses[200] > 0);
    CHECK(bad_bodies == 0);
}

// the mock input, counting how often a tap of its type is rendered
class RenderCountingMock : public input::mock::MockInputModulePlugin
{
public:
    using MockInputModulePlugin::MockInputModulePlugin;

    mutable std::atomic<int> renders{0};

    void redact_config_json(nlohmann::json &j) const override
    {
        ++renders;
        MockInputModulePlugin::redact_config_json(j);
    }
};

// once armed, holds the next tap load just after it registers a tap
class GatedTapManager : public TapManager
{
public:
    using TapManager::TapManager;

    bool armed{false};
    std::promise<void> reached;
    std::shared_future<void> release;

    void module_add(std::unique_ptr<Tap> &&m) override
    {
        TapManager::module_add(std::move(m));
        if (armed) {
            armed = false;
            reached.set_value();
            release.wait();
        }
    }
};

TEST_CASE("A tap POST answers with the tap as loaded when it is removed before the POST answers", "[policies][taps][api][concurrency]")
{
    CoreRegistry registry;
    visor::load_builtin_plugins(registry);
    auto plugin = std::make_unique<RenderCountingMock>("counted_mock");
    auto counted = plugin.get();
    registry.add_input_plugin("counted_mock", "1.0", std::move(plugin));
    registry.start(nullptr);

    GatedTapManager taps(&registry);
    httplib::Response posted;
    std::future<void> post;
    // declared after the future so it is destroyed first: a failed REQUIRE releases the load before the future waits
    // for its thread
    Gate gate;
    taps.release = gate.promise.get_future().share();
    taps.armed = true;
    auto reached = taps.reached.get_future();
    post = std::async(std::launch::async, [&taps, &posted] {
        api::post_taps(taps, R"(
visor:
  taps:
    anycast:
      input_type: counted_mock
      config:
        iface: eth0
)",
            posted);
    });
    wait_held(reached, post);

    // registered, and the POST has not answered yet: a removal now frees the tap, so the POST must have rendered it
    // already. module_remove frees it as DELETE /api/v1/taps/{name} does, which goes through the registry's own tap
    // manager instead of this one
    REQUIRE(counted->renders == 1);
    taps.module_remove("anycast");
    gate.release();
    wait_or_abort("the tap POST", post);
    REQUIRE_NOTHROW(post.get());

    INFO(posted.body);
    CHECK(posted.status == 201);
    auto j = json::parse(posted.body);
    CHECK(j["anycast"]["input_type"] == "counted_mock");
    CHECK(j["anycast"]["config"] == json{{"iface", "eth0"}});
    CHECK(counted->renders == 1);
    CHECK_FALSE(taps.module_exists("anycast"));
}

TEST_CASE("POST and DELETE of one policy at once", "[policies][api][concurrency]")
{
    CoreRegistry registry;
    visor::load_builtin_plugins(registry);
    registry.start(nullptr);
    REQUIRE_NOTHROW(registry.tap_manager()->load_from_str(ANYCAST_TAP));

    QuietLogger quiet;

    auto stop_at = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    std::map<int, int> post_statuses;
    std::map<int, int> delete_statuses;
    int bad_bodies{0};
    auto post = std::async(std::launch::async, [&registry, &post_statuses, &bad_bodies, stop_at] {
        while (std::chrono::steady_clock::now() < stop_at) {
            httplib::Response res;
            api::post_policies(*registry.policy_manager(), policy_on_shared_input("view"), res);
            ++post_statuses[res.status];
            if (res.status == 201) {
                auto j = json::parse(res.body);
                if (!j["view"]["taps"].contains("anycast") || j["view"]["input"].size() != 1 || !j["view"]["modules"].contains("view-anycast-view_net")) {
                    ++bad_bodies;
                }
            }
        }
    });
    auto remove = std::async(std::launch::async, [&registry, &delete_statuses, stop_at] {
        while (std::chrono::steady_clock::now() < stop_at) {
            httplib::Response res;
            api::delete_policy(*registry.policy_manager(), "view", res);
            ++delete_statuses[res.status];
        }
    });
    wait_or_abort("racing policy POST and DELETE", post, remove);
    REQUIRE_NOTHROW(post.get());
    REQUIRE_NOTHROW(remove.get());

    INFO("POST: " << json(post_statuses).dump() << " DELETE: " << json(delete_statuses).dump());
    for (auto &[code, count] : post_statuses) {
        CHECK((code == 201 || code == 409));
    }
    for (auto &[code, count] : delete_statuses) {
        CHECK((code == 200 || code == 404));
    }
    CHECK(post_statuses[201] > 0);
    CHECK(delete_statuses[200] > 0);
    CHECK(bad_bodies == 0);
    if (registry.policy_manager()->module_exists("view")) {
        registry.policy_manager()->remove_policy("view");
    }
    check_no_modules(registry);
}

TEST_CASE("Deleting a policy waits for the POST loading it to answer with the policy as loaded", "[policies][api][concurrency]")
{
    CoreRegistry registry;
    visor::load_builtin_plugins(registry);
    registry.start(nullptr);
    REQUIRE_NOTHROW(registry.tap_manager()->load_from_str(ANYCAST_TAP));

    GatedPolicyManager policies(&registry);
    policies.hold_after = "default_view";
    httplib::Response posted;
    std::future<void> post;
    std::future<httplib::Response> remove;
    // declared after the futures so it is destroyed first: a failed REQUIRE releases the load before the futures
    // wait for their threads
    Gate gate;
    post = hold_load_at_gate(policies, gate, [&policies, &posted] { api::post_policies(policies, DEFAULT_VIEW_POLICY, posted); });

    // registered, and the POST has not answered yet: a removal now would free the policy under the POST
    remove = std::async(std::launch::async, [&policies] {
        httplib::Response res;
        api::delete_policy(policies, "default_view", res);
        return res;
    });
    CHECK(remove.wait_for(std::chrono::milliseconds(200)) == std::future_status::timeout);
    gate.release();
    wait_or_abort("the policy POST and DELETE", post, remove);
    REQUIRE_NOTHROW(post.get());
    auto removed = remove.get();

    INFO(posted.body);
    REQUIRE(posted.status == 201);
    auto j = json::parse(posted.body);
    CHECK(j["default_view"]["taps"].contains("anycast"));
    CHECK(j["default_view"]["input"].size() == 1);
    CHECK(j["default_view"]["modules"].contains("default_view-anycast-default_net"));
    CHECK(removed.status == 200);
    CHECK(policies.module_get_keys().empty());
    check_no_modules(registry);
}

TEST_CASE("Deleting a policy that does not exist answers 404 without waiting for a policy load", "[policies][api][concurrency]")
{
    CoreRegistry registry;
    visor::load_builtin_plugins(registry);
    registry.start(nullptr);
    REQUIRE_NOTHROW(registry.tap_manager()->load_from_str(ANYCAST_TAP));

    GatedPolicyManager policies(&registry);
    std::future<void> load;
    std::future<httplib::Response> remove;
    // declared after the futures so it is destroyed first: a failed REQUIRE releases the load before the futures
    // wait for their threads
    Gate gate;
    load = hold_load_at_gate(policies, gate);

    // the held load keeps the lock that removing a policy waits for, as a load starting a long pcap_file input does
    remove = std::async(std::launch::async, [&policies] {
        httplib::Response res;
        api::delete_policy(policies, "missing", res);
        return res;
    });
    CHECK(remove.wait_for(std::chrono::seconds(5)) == std::future_status::ready);
    gate.release();
    wait_or_abort("the policy load and the policy delete", load, remove);
    REQUIRE_NOTHROW(load.get());
    auto res = remove.get();
    CHECK(res.status == 404);
    CHECK(json::parse(res.body) == json{{"error", "policy does not exists"}});
    policies.remove_policy("default_view");
}

TEST_CASE("Two deletes of a policy that both found it remove it once and answer 404 to the other", "[policies][api][concurrency]")
{
    CoreRegistry registry;
    visor::load_builtin_plugins(registry);
    registry.start(nullptr);
    REQUIRE_NOTHROW(registry.tap_manager()->load_from_str(ANYCAST_TAP));

    GatedPolicyManager policies(&registry);
    REQUIRE_NOTHROW(policies.load_from_str(policy_on_shared_input("edge")));
    std::future<void> load;
    std::future<httplib::Response> first;
    std::future<httplib::Response> second;
    // declared after the futures so it is destroyed first: a failed REQUIRE releases the load before the futures
    // wait for their threads
    Gate gate;
    load = hold_load_at_gate(policies, gate);

    // both deletes find edge before they wait for the held load. Once it ends, one removes edge and the other must
    // find it gone under the locks
    auto remove = [&policies] {
        httplib::Response res;
        api::delete_policy(policies, "edge", res);
        return res;
    };
    first = std::async(std::launch::async, remove);
    second = std::async(std::launch::async, remove);
    CHECK(first.wait_for(std::chrono::milliseconds(200)) == std::future_status::timeout);
    CHECK(second.wait_for(std::chrono::seconds(0)) == std::future_status::timeout);
    gate.release();
    wait_or_abort("the policy load and the policy deletes", load, first, second);
    REQUIRE_NOTHROW(load.get());
    auto a = first.get();
    auto b = second.get();
    auto &missing = (a.status == 404) ? a : b;
    CHECK(std::set<int>{a.status, b.status} == std::set<int>{200, 404});
    CHECK(json::parse(missing.body) == json{{"error", "policy does not exists"}});
    CHECK_FALSE(policies.module_exists("edge"));
    policies.remove_policy("default_view");
    CHECK(policies.module_get_keys().empty());
    check_no_modules(registry);
}

// holds the first thread that logs a message containing pattern, without holding a lock other threads log under
class LogGate : public spdlog::sinks::base_sink<spdlog::details::null_mutex>
{
    std::string _pattern;
    std::atomic<bool> _fired{false};

public:
    std::promise<void> reached;
    std::shared_future<void> release;

    explicit LogGate(std::string pattern)
        : _pattern(std::move(pattern))
    {
    }

protected:
    void sink_it_(const spdlog::details::log_msg &msg) override
    {
        if (std::string_view(msg.payload.data(), msg.payload.size()).find(_pattern) == std::string_view::npos || _fired.exchange(true)) {
            return;
        }
        reached.set_value();
        release.wait();
    }

    void flush_() override
    {
    }
};

// sends the visor logger's debug messages to a sink while in scope, and nothing below warnings to the others. Set up
// and torn down while no input runs, since running inputs log from their own threads
struct ScopedDebugSink {
    std::shared_ptr<spdlog::logger> logger = spdlog::get("visor");
    spdlog::level::level_enum level = logger->level();
    std::vector<spdlog::level::level_enum> sink_levels;

    explicit ScopedDebugSink(std::shared_ptr<spdlog::sinks::sink> sink)
    {
        for (auto &s : logger->sinks()) {
            sink_levels.push_back(s->level());
            s->set_level(spdlog::level::warn);
        }
        logger->sinks().push_back(std::move(sink));
        logger->set_level(spdlog::level::debug);
    }
    ~ScopedDebugSink()
    {
        logger->set_level(level);
        logger->sinks().pop_back();
        for (size_t i = 0; i < sink_levels.size(); ++i) {
            logger->sinks()[i]->set_level(sink_levels[i]);
        }
    }
};

// removes the policies still loaded on scope exit, stopping their inputs. Declared after a ScopedDebugSink, it runs
// first, so a test that fails midway leaves no input logging while the sink is torn down
struct RemovePoliciesOnExit {
    PolicyManager &policies;
    std::vector<std::string> names;
    ~RemovePoliciesOnExit()
    {
        for (auto &name : names) {
            try {
                policies.remove_policy(name);
            } catch (const std::exception &) {
                // not loaded, or already removed by the test
            }
        }
    }
};

TEST_CASE("A policy POST reusing an input outlasts the DELETE of the input's last policy", "[policies][api][concurrency]")
{
    CoreRegistry registry;
    visor::load_builtin_plugins(registry);
    registry.start(nullptr);
    REQUIRE_NOTHROW(registry.tap_manager()->load_from_str(ANYCAST_TAP));

    // holds the load of view_b once it has found the input view_a runs on, before it takes it
    auto log_gate = std::make_shared<LogGate>("policy [view_b]: input stream already exists. reusing");
    ScopedDebugSink debug_sink(log_gate);
    RemovePoliciesOnExit cleanup{*registry.policy_manager(), {"view_a", "view_b"}};

    REQUIRE_NOTHROW(registry.policy_manager()->load_from_str(policy_on_shared_input("view_a")));
    std::string input_name;
    {
        auto [view_a, lock] = registry.policy_manager()->module_get_locked("view_a");
        input_name = view_a->input_stream().front()->name();
    }

    httplib::Response posted;
    std::future<void> post;
    std::future<httplib::Response> remove;
    // declared after the futures so it is destroyed first: a failed REQUIRE releases the load before the futures
    // wait for their threads
    Gate gate;
    log_gate->release = gate.promise.get_future().share();
    auto reached = log_gate->reached.get_future();
    post = std::async(std::launch::async, [&registry, &posted] { api::post_policies(*registry.policy_manager(), policy_on_shared_input("view_b"), posted); });
    wait_held(reached, post);

    // view_a is the last policy on the input, so removing it now removes the input too
    remove = std::async(std::launch::async, [&registry] {
        httplib::Response res;
        api::delete_policy(*registry.policy_manager(), "view_a", res);
        return res;
    });
    CHECK(remove.wait_for(std::chrono::milliseconds(200)) == std::future_status::timeout);
    gate.release();
    wait_or_abort("the view_b POST and the view_a DELETE", post, remove);
    REQUIRE_NOTHROW(post.get());
    auto removed = remove.get();

    INFO(posted.body);
    CHECK(posted.status == 201);
    CHECK(removed.status == 200);
    REQUIRE(registry.policy_manager()->module_exists("view_b"));
    {
        auto [view_b, lock] = registry.policy_manager()->module_get_locked("view_b");
        REQUIRE(view_b->input_stream().size() == 1);
        CHECK(view_b->input_stream().front()->name() == input_name);
        CHECK(view_b->input_stream().front()->running());
        CHECK(view_b->running());
    }
    registry.policy_manager()->remove_policy("view_b");
    check_no_modules(registry);
}

TEST_CASE("POSTs and DELETEs of policies sharing one input", "[policies][api][concurrency]")
{
    CoreRegistry registry;
    visor::load_builtin_plugins(registry);
    registry.start(nullptr);
    REQUIRE_NOTHROW(registry.tap_manager()->load_from_str(ANYCAST_TAP));

    QuietLogger quiet;

    // two policies on one input, each posted and deleted in turn, so a POST often reuses the input while the other
    // policy, its last one, is being deleted
    auto stop_at = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    struct Answers {
        std::map<int, int> statuses;
        std::string error;
    };
    auto churn = [&registry, stop_at](const std::string &name, Answers &answers) {
        while (std::chrono::steady_clock::now() < stop_at) {
            httplib::Response res;
            api::post_policies(*registry.policy_manager(), policy_on_shared_input(name), res);
            ++answers.statuses[res.status];
            if (res.status != 201) {
                answers.error = res.body;
                continue;
            }
            httplib::Response removed;
            api::delete_policy(*registry.policy_manager(), name, removed);
            ++answers.statuses[removed.status];
            if (removed.status != 200) {
                answers.error = removed.body;
            }
        }
    };
    Answers a_answers;
    Answers b_answers;
    auto a = std::async(std::launch::async, churn, std::string("view_a"), std::ref(a_answers));
    auto b = std::async(std::launch::async, churn, std::string("view_b"), std::ref(b_answers));
    wait_or_abort("policy POSTs and DELETEs on one input", a, b);
    REQUIRE_NOTHROW(a.get());
    REQUIRE_NOTHROW(b.get());

    // each POST either reuses the input or, once the other policy's DELETE has removed it, creates it again
    for (auto answers : {a_answers, b_answers}) {
        INFO(json(answers.statuses).dump() << " " << answers.error);
        for (auto &[code, count] : answers.statuses) {
            CHECK((code == 201 || code == 200));
        }
        CHECK(answers.statuses[201] > 0);
    }
    check_no_modules(registry);
}

TEST_CASE("An input's consumers are those of every filter it serves", "[policies][input]")
{
    CoreRegistry registry;
    visor::load_builtin_plugins(registry);
    registry.start(nullptr);
    Config config;
    Config no_filter;
    Config filter;
    filter.config_set<std::string>("only", "core");
    auto input = registry.input_plugins()[std::make_pair("mock", "1.0")]->instantiate("mymock", &config, &no_filter);
    auto unfiltered = input->add_event_proxy(no_filter);
    auto filtered = input->add_event_proxy(filter);
    REQUIRE(unfiltered != filtered);
    CHECK(input->consumer_count() == 0);

    auto heartbeat = unfiltered->heartbeat_signal.connect([](const timespec) {});
    auto policies = unfiltered->policy_signal.connect([](const Policy *, Action) {});
    CHECK(input->consumer_count() == 2);

    auto filtered_heartbeat = filtered->heartbeat_signal.connect([](const timespec) {});
    CHECK(input->consumer_count() == 3);
}
