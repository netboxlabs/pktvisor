#include "BuiltinPlugins.h"
#include "CoreRegistry.h"
#include "HandlerManager.h"
#include "InputStreamManager.h"
#include "Policies.h"
#include "PrometheusSerializer.h"
#include "handlers/flow/FlowStreamHandler.h"
#include "handlers/net/v1/NetStreamHandler.h"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>
#include <fmt/format.h>
#include <map>
#include <sstream>
#include <string>
#include <vector>
#include <yaml-cpp/yaml.h>

using namespace visor;
using Catch::Matchers::ContainsSubstring;

namespace {

using Attrs = std::map<std::string, std::string>;

Attrs attributes_of(const google::protobuf::RepeatedPtrField<common::v1::KeyValue> &kvs)
{
    Attrs attrs;
    for (const auto &kv : kvs) {
        attrs[kv.key()] = kv.value().string_value();
    }
    return attrs;
}

// The attributes of every datapoint of every metric in the scope.
std::vector<Attrs> datapoint_attributes(const metrics::v1::ScopeMetrics &scope)
{
    std::vector<Attrs> all;
    for (const auto &metric : scope.metrics()) {
        for (const auto &point : metric.gauge().data_points()) {
            all.push_back(attributes_of(point.attributes()));
        }
        for (const auto &point : metric.sum().data_points()) {
            all.push_back(attributes_of(point.attributes()));
        }
        for (const auto &point : metric.summary().data_points()) {
            all.push_back(attributes_of(point.attributes()));
        }
        for (const auto &point : metric.histogram().data_points()) {
            all.push_back(attributes_of(point.attributes()));
        }
    }
    return all;
}

timespec after_now()
{
    timespec t;
    timespec_get(&t, TIME_UTC);
    t.tv_sec += 61;
    return t;
}

void close_windows(Policy *policy)
{
    auto stamp = after_now();
    for (auto mod : policy->modules()) {
        if (auto net = dynamic_cast<handler::net::NetStreamHandler *>(mod)) {
            net->check_period_shift(stamp);
        } else if (auto flow = dynamic_cast<handler::flow::FlowStreamHandler *>(mod)) {
            flow->check_period_shift(stamp);
        }
    }
}

std::vector<std::string> sample_lines(const std::string &text)
{
    std::vector<std::string> lines;
    std::istringstream in(text);
    for (std::string line; std::getline(in, line);) {
        if (!line.empty() && line[0] != '#') {
            lines.push_back(line);
        }
    }
    return lines;
}

constexpr auto pcap_tap = R"(
visor:
  taps:
    recorded:
      input_type: pcap
      config:
        pcap_file: tests/fixtures/dns_ipv4_udp.pcap
)";

std::string pcap_policy(const std::string &name, const std::string &attributes, const std::string &config = "")
{
    return fmt::format(R"(
visor:
  policies:
    {}:
      kind: collection
{}
{}
      input:
        tap: recorded
        input_type: pcap
      handlers:
        modules:
          recorded_net:
            type: net
)",
        name, config, attributes);
}

constexpr auto attributes_yaml = R"(      attributes:
        netbox.site.name: "dc-west"
        netbox_id: "netbox-device-12"
        zero: "007"
        flag: "True"
)";

void load(CoreRegistry &registry, const std::string &tap_yaml, const std::string &policy_yaml)
{
    auto taps = YAML::Load(tap_yaml);
    auto policies = YAML::Load(policy_yaml);
    registry.tap_manager()->load(taps["visor"]["taps"]);
    registry.policy_manager()->load(policies["visor"]["policies"]);
}

}

TEST_CASE("Policy attributes reach every OpenTelemetry datapoint", "[policies][attributes]")
{
    CoreRegistry registry;
    visor::load_builtin_plugins(registry);
    registry.start(nullptr);
    REQUIRE_NOTHROW(load(registry, pcap_tap, pcap_policy("attr_view", attributes_yaml)));

    auto [policy, lock] = registry.policy_manager()->module_get_locked("attr_view");
    CHECK(policy->attributes().at("zero") == "007");
    close_windows(policy);
    metrics::v1::ScopeMetrics scope;
    policy->opentelemetry_metrics(scope);
    auto points = datapoint_attributes(scope);
    REQUIRE_FALSE(points.empty());
    for (const auto &attrs : points) {
        CHECK(attrs.at("netbox.site.name") == "dc-west");
        CHECK(attrs.at("netbox_id") == "netbox-device-12");
        CHECK(attrs.at("zero") == "007");
        CHECK(attrs.at("flag") == "True");
        CHECK(attrs.at("policy") == "attr_view");
        CHECK(attrs.at("handler") == "attr_view-recorded-recorded_net");
    }
}

TEST_CASE("Policy attributes reach Prometheus output under converted names", "[policies][attributes][prometheus]")
{
    CoreRegistry registry;
    visor::load_builtin_plugins(registry);
    registry.start(nullptr);
    REQUIRE_NOTHROW(load(registry, pcap_tap, pcap_policy("attr_view", attributes_yaml)));

    auto [policy, lock] = registry.policy_manager()->module_get_locked("attr_view");
    close_windows(policy);
    std::stringstream out;
    policy->prometheus_metrics(out);
    auto lines = sample_lines(out.str());
    REQUIRE_FALSE(lines.empty());
    for (const auto &line : lines) {
        CHECK_THAT(line, ContainsSubstring("netbox_site_name=\"dc-west\""));
        CHECK_THAT(line, ContainsSubstring("zero=\"007\""));
        CHECK_THAT(line, ContainsSubstring("flag=\"True\""));
        CHECK_THAT(line, ContainsSubstring("policy=\"attr_view\""));
    }
}

TEST_CASE("Policy attributes reach the merged-handlers path", "[policies][attributes]")
{
    CoreRegistry registry;
    visor::load_builtin_plugins(registry);
    registry.start(nullptr);
    auto policy_yaml = fmt::format(R"(
visor:
  policies:
    merged_view:
      kind: collection
      config:
        merge_like_handlers: true
{}
      input:
        tap: recorded
        input_type: pcap
      handlers:
        modules:
          net_1:
            type: net
          net_2:
            type: net
)",
        attributes_yaml);
    REQUIRE_NOTHROW(load(registry, pcap_tap, policy_yaml));

    auto [policy, lock] = registry.policy_manager()->module_get_locked("merged_view");
    close_windows(policy);

    metrics::v1::ScopeMetrics scope;
    policy->opentelemetry_metrics(scope);
    auto points = datapoint_attributes(scope);
    REQUIRE_FALSE(points.empty());
    for (const auto &attrs : points) {
        CHECK(attrs.at("netbox.site.name") == "dc-west");
        CHECK(attrs.at("handler") == "packets_merged");
    }

    std::stringstream out;
    policy->prometheus_metrics(out);
    auto lines = sample_lines(out.str());
    REQUIRE_FALSE(lines.empty());
    for (const auto &line : lines) {
        CHECK_THAT(line, ContainsSubstring("netbox_site_name=\"dc-west\""));
    }
}

TEST_CASE("Policy attributes reach a flow policy's series", "[policies][attributes][flow]")
{
    CoreRegistry registry;
    visor::load_builtin_plugins(registry);
    registry.start(nullptr);
    auto taps = R"(
visor:
  taps:
    flows:
      input_type: flow
)";
    auto policy_yaml = R"(
visor:
  policies:
    flow_view:
      kind: collection
      attributes:
        netbox.tenant.name: "acme"
      input:
        tap: flows
        input_type: flow
        config:
          flow_type: sflow
          pcap_file: tests/fixtures/ecmp.pcap
      handlers:
        modules:
          sflow_flow:
            type: flow
            config:
              device_map:
                192.168.0.13:
                  name: router13
                  interfaces:
                    52:
                      name: eth52
)";
    REQUIRE_NOTHROW(load(registry, taps, policy_yaml));

    auto [policy, lock] = registry.policy_manager()->module_get_locked("flow_view");
    close_windows(policy);
    metrics::v1::ScopeMetrics scope;
    policy->opentelemetry_metrics(scope);
    auto points = datapoint_attributes(scope);
    REQUIRE_FALSE(points.empty());
    bool named_device = false;
    for (const auto &attrs : points) {
        CHECK(attrs.at("netbox.tenant.name") == "acme");
        CHECK(attrs.count("device") == 1);
        named_device = named_device || attrs.at("device") == "router13";
    }
    CHECK(named_device);
}

TEST_CASE("Two policies on one input carry only their own attributes", "[policies][attributes]")
{
    CoreRegistry registry;
    visor::load_builtin_plugins(registry);
    registry.start(nullptr);
    auto tap = R"(
visor:
  taps:
    shared:
      input_type: mock
      config:
        iface: eth0
)";
    auto policy_yaml = [](const std::string &name, const std::string &site) {
        return fmt::format(R"(
visor:
  policies:
    {0}:
      kind: collection
      attributes:
        site: {1}
      input:
        tap: shared
        input_type: mock
        config:
          sample: value
      handlers:
        modules:
          {0}_net:
            type: net
)",
            name, site);
    };
    REQUIRE_NOTHROW(load(registry, tap, policy_yaml("p1", "a")));
    auto second = YAML::Load(policy_yaml("p2", "b"));
    REQUIRE_NOTHROW(registry.policy_manager()->load(second["visor"]["policies"]));

    for (const auto &name : {"p1", "p2"}) {
        auto [policy, lock] = registry.policy_manager()->module_get_locked(name);
        close_windows(policy);
    }
    metrics::v1::ResourceMetrics resource;
    REQUIRE(registry.policy_manager()->opentelemetry_metrics(resource));
    std::map<std::string, std::string> seen;
    for (const auto &scope : resource.scope_metrics()) {
        auto points = datapoint_attributes(scope);
        REQUIRE_FALSE(points.empty());
        for (const auto &attrs : points) {
            CHECK(attrs.at("site") == (scope.scope().name() == "pktvisor/p1" ? "a" : "b"));
        }
        seen[scope.scope().name()] = points.front().at("site");
    }
    CHECK(seen == std::map<std::string, std::string>{{"pktvisor/p1", "a"}, {"pktvisor/p2", "b"}});
}

TEST_CASE("Attribute values with quotes, backslashes and non-ASCII are escaped like any label value", "[policies][attributes][prometheus]")
{
    const std::string value = "S\xc3\xa3o \"Paulo\" \\ 1";
    CoreRegistry registry;
    visor::load_builtin_plugins(registry);
    registry.start(nullptr);
    auto attributes = std::string("      attributes:\n        city: 'S\xc3\xa3o \"Paulo\" \\ 1'\n");
    REQUIRE_NOTHROW(load(registry, pcap_tap, pcap_policy("esc_view", attributes)));

    // how the serializer renders a label of the same text
    PrometheusSerializer ser;
    ser.write("m", PrometheusSerializer::Type::Gauge, "h", {}, {{"city", value}}, 1);
    auto rendered = sample_lines(ser.finalize()).at(0);
    auto expected = rendered.substr(rendered.find("city=\""));
    expected = expected.substr(0, expected.find("\",") == std::string::npos ? expected.find("\"}") + 1 : expected.find("\",") + 1);

    auto [policy, lock] = registry.policy_manager()->module_get_locked("esc_view");
    close_windows(policy);
    std::stringstream out;
    policy->prometheus_metrics(out);
    auto lines = sample_lines(out.str());
    REQUIRE_FALSE(lines.empty());
    for (const auto &line : lines) {
        CHECK_THAT(line, ContainsSubstring(expected));
    }

    metrics::v1::ScopeMetrics scope;
    policy->opentelemetry_metrics(scope);
    auto points = datapoint_attributes(scope);
    REQUIRE_FALSE(points.empty());
    for (const auto &attrs : points) {
        CHECK(attrs.at("city") == value);
    }
}

TEST_CASE("Malformed attributes are refused at load", "[policies][attributes]")
{
    struct Case {
        std::string attributes;
        std::string key;
    };
    const std::vector<Case> cases = {
        {"      attributes: [a, b]\n", "attributes"},
        {"      attributes: {k: {x: 1}}\n", "'k'"},
        {"      attributes: {k: [1]}\n", "'k'"},
        {"      attributes: {k: ~}\n", "'k'"},
        {"      attributes: {k: \"\"}\n", "'k'"},
        {"      attributes: {netbox.site.name: a, netbox_site_name: b}\n", "'netbox.site.name'"},
        {"      attributes: {netbox.site.name: a, netbox_site_name: b}\n", "'netbox_site_name'"},
    };
    for (const auto &c : cases) {
        DYNAMIC_SECTION(c.attributes << c.key)
        {
            CoreRegistry registry;
            visor::load_builtin_plugins(registry);
            registry.start(nullptr);
            std::string message;
            try {
                load(registry, pcap_tap, pcap_policy("bad_view", c.attributes));
            } catch (const PolicyException &e) {
                message = e.what();
            }
            CHECK_THAT(message, ContainsSubstring(c.key));
            CHECK_THAT(message, ContainsSubstring("bad_view"));
            CHECK_FALSE(registry.policy_manager()->module_exists("bad_view"));
        }
    }
}
