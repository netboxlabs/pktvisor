#include "BuiltinPlugins.h"
#include "CoreRegistry.h"
#include "HandlerManager.h"
#include "InputStreamManager.h"
#include "Policies.h"
#include "PrometheusSerializer.h"
#include "handlers/flow/FlowStreamHandler.h"
#include "handlers/net/v1/NetStreamHandler.h"
#include "handlers/netprobe/NetProbeStreamHandler.h"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>
#include <fmt/format.h>
#include <algorithm>
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
        } else if (auto probe = dynamic_cast<handler::netprobe::NetProbeStreamHandler *>(mod)) {
            probe->check_period_shift(stamp);
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
        {"      attributes: {\"\": a}\n", "attributes of policy 'bad_view'"},
        {"      attributes: {1st_floor: a}\n", "'1st_floor'"},
        {"      attributes: {_x: a}\n", "'_x'"},
        {"      attributes: {__name__: a}\n", "'__name__'"},
        {"      attributes: {\"a\xff\": a}\n", "UTF-8"},
        {"      attributes: {sit\xc3\xa9: a, sit_: b}\n", "'sit_'"},
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

namespace {

constexpr auto flow_tap = R"(
visor:
  taps:
    flows:
      input_type: flow
)";

constexpr auto netprobe_tap = R"(
visor:
  taps:
    probes:
      input_type: netprobe
)";

std::string handler_policy(const std::string &name, const std::string &tap, const std::string &input_type, const std::string &input_config, const std::string &handler_type, const std::string &attributes)
{
    return fmt::format(R"(
visor:
  policies:
    {}:
      kind: collection
      attributes:
        {}
      input:
        tap: {}
        input_type: {}
        config:
{}
      handlers:
        modules:
          the_handler:
            type: {}
)",
        name, attributes, tap, input_type, input_config, handler_type);
}

constexpr auto flow_input = R"(          flow_type: sflow
          pcap_file: tests/fixtures/ecmp.pcap)";

constexpr auto netprobe_input = R"(          test_type: http
          targets:
            one:
              target: http://localhost:1/)";

constexpr auto pcap_input = R"(          pcap_file: tests/fixtures/dns_ipv4_udp.pcap)";

}

TEST_CASE("An attribute named after a label pktvisor sets is refused", "[policies][attributes]")
{
    struct Case {
        std::string key;
        std::string tap_yaml;
        std::string tap;
        std::string input_type;
        std::string input_config;
        std::string handler;
    };
    const std::string pcap = "pcap";
    std::vector<Case> cases;
    for (const std::string key : {"policy", "handler", "tap", "le", "quantile"}) {
        cases.push_back({key, pcap_tap, "recorded", pcap, pcap_input, "net"});
    }
    // direction is a label of the 2.0 handlers only
    const std::string v2 = "\n            require_version: \"2.0\"";
    cases.push_back({"direction", pcap_tap, "recorded", pcap, pcap_input, "net" + v2});
    cases.push_back({"direction", pcap_tap, "recorded", pcap, pcap_input, "dns" + v2});
    cases.push_back({"lat", pcap_tap, "recorded", pcap, pcap_input, "dns"});
    cases.push_back({"device", flow_tap, "flows", "flow", flow_input, "flow"});
    cases.push_back({"device.interface", flow_tap, "flows", "flow", flow_input, "flow"});
    cases.push_back({"target", netprobe_tap, "probes", "netprobe", netprobe_input, "netprobe"});
    cases.push_back({"status_code", netprobe_tap, "probes", "netprobe", netprobe_input, "netprobe"});
    for (const auto &c : cases) {
        DYNAMIC_SECTION(c.handler << " handler: " << c.key)
        {
            CoreRegistry registry;
            visor::load_builtin_plugins(registry);
            registry.start(nullptr);
            std::string message;
            try {
                load(registry, c.tap_yaml, handler_policy("reserved_view", c.tap, c.input_type, c.input_config, c.handler, c.key + ": v"));
            } catch (const PolicyException &e) {
                message = e.what();
            }
            CHECK_THAT(message, ContainsSubstring("'" + c.key + "'"));
            CHECK_THAT(message, ContainsSubstring("reserved_view"));
            CHECK_FALSE(registry.policy_manager()->module_exists("reserved_view"));
        }
    }
}

TEST_CASE("Attributes that no label pktvisor sets are accepted", "[policies][attributes]")
{
    CoreRegistry registry;
    visor::load_builtin_plugins(registry);
    registry.start(nullptr);
    REQUIRE_NOTHROW(load(registry, flow_tap, handler_policy("free_view", "flows", "flow", flow_input, "flow", R"(netbox.site.name: dc
        netbox_id: "12"
        device_ip: 10.0.0.1)")));
    CHECK(registry.policy_manager()->module_exists("free_view"));
}

TEST_CASE("An attribute named after a static label is refused", "[policies][attributes]")
{
    Metric::reset_static_labels();
    Metric::add_static_label("instance_id", "x");
    CoreRegistry registry;
    visor::load_builtin_plugins(registry);
    registry.start(nullptr);
    std::string message;
    try {
        load(registry, pcap_tap, pcap_policy("static_view", "      attributes: {instance.id: v}\n"));
    } catch (const PolicyException &e) {
        message = e.what();
    }
    Metric::reset_static_labels();
    CHECK_THAT(message, ContainsSubstring("'instance.id'"));
    CHECK_FALSE(registry.policy_manager()->module_exists("static_view"));
}

TEST_CASE("A refused policy leaves nothing behind", "[policies][attributes]")
{
    CoreRegistry registry;
    visor::load_builtin_plugins(registry);
    registry.start(nullptr);
    CHECK_THROWS_AS(load(registry, flow_tap, handler_policy("refused_view", "flows", "flow", flow_input, "flow", "device: v")), PolicyException);
    CHECK_FALSE(registry.policy_manager()->module_exists("refused_view"));
    CHECK_FALSE(registry.handler_manager()->module_exists("refused_view-flows-the_handler"));
    CHECK(registry.input_manager()->module_get_keys().empty());
}

namespace {

// A netprobe policy probing gw1 and gw2. Either attributes argument is a YAML flow map, or empty for none.
std::string netprobe_policy(const std::string &name, const std::string &policy_attributes, const std::string &gw1_attributes)
{
    return fmt::format(R"(
visor:
  policies:
    {}:
      kind: collection
      {}
      input:
        tap: probes
        input_type: netprobe
        config:
          test_type: http
          interval_msec: 60000
          targets:
            gw1:
              target: http://localhost:1/
              {}
            gw2:
              target: http://localhost:1/
      handlers:
        modules:
          probe:
            type: netprobe
)",
        name,
        policy_attributes.empty() ? "" : "attributes: " + policy_attributes,
        gw1_attributes.empty() ? "" : "attributes: " + gw1_attributes);
}

// Loads a policy that must be refused, and returns the refusal. Nothing the load made may be left behind.
std::string refusal(const std::string &policy_name, const std::string &policy_yaml)
{
    CoreRegistry registry;
    visor::load_builtin_plugins(registry);
    registry.start(nullptr);
    std::string message;
    try {
        load(registry, netprobe_tap, policy_yaml);
    } catch (const PolicyException &e) {
        message = e.what();
    }
    CHECK_FALSE(registry.policy_manager()->module_exists(policy_name));
    CHECK_FALSE(registry.handler_manager()->module_exists(policy_name + "-probes-probe"));
    CHECK(registry.input_manager()->module_get_keys().empty());
    return message;
}

// Records a timeout for gw1 and gw2 on the policy's netprobe handler, as a probe would. False if it has none.
bool feed_targets(Policy *policy)
{
    bool fed = false;
    for (auto mod : policy->modules()) {
        if (auto probe = dynamic_cast<handler::netprobe::NetProbeStreamHandler *>(mod)) {
            auto metrics = const_cast<handler::netprobe::NetProbeMetricsManager *>(probe->metrics());
            metrics->process_failure(input::netprobe::ErrorType::Timeout, "gw1");
            metrics->process_failure(input::netprobe::ErrorType::Timeout, "gw2");
            fed = true;
        }
    }
    return fed;
}

}

TEST_CASE("Netprobe target attributes are parsed from the raw policy YAML", "[policies][attributes]")
{
    auto input = YAML::Load(R"(
input_type: netprobe
config:
  test_type: ping
  targets:
    gw1:
      target: 192.0.2.1
      attributes:
        zero: "007"
        flag: True
    gw2:
      target: 192.0.2.2
)");
    CHECK(parse_target_attributes(input, "probe_view") == TargetAttributes{{"gw1", {{"zero", "007"}, {"flag", "True"}}}});

    CHECK(parse_target_attributes(YAML::Load("input_type: netprobe"), "probe_view").empty());
    CHECK(parse_target_attributes(YAML::Load("{input_type: pcap, config: {pcap_file: x.pcap}}"), "probe_view").empty());

    std::string message;
    try {
        parse_target_attributes(YAML::Load("{config: {targets: {gw1: {target: 192.0.2.1, attributes: [a, b]}}}}"), "probe_view");
    } catch (const PolicyException &e) {
        message = e.what();
    }
    CHECK_THAT(message, ContainsSubstring("probe_view"));
    CHECK_THAT(message, ContainsSubstring("gw1"));
}

TEST_CASE("A target attribute named after a pktvisor label is refused", "[policies][attributes]")
{
    for (const std::string key : {"target", "policy", "rcode", "status_code", "le"}) {
        DYNAMIC_SECTION(key)
        {
            auto message = refusal("target_view", netprobe_policy("target_view", "", "{" + key + ": v}"));
            CHECK_THAT(message, ContainsSubstring("'" + key + "'"));
            CHECK_THAT(message, ContainsSubstring("gw1"));
            CHECK_THAT(message, ContainsSubstring("target_view"));
        }
    }
}

TEST_CASE("A target attribute written as the Prometheus label of another policy attribute is refused", "[policies][attributes]")
{
    for (const auto &[policy_key, target_key] : std::vector<std::pair<std::string, std::string>>{
             {"netbox.site.name", "netbox_site_name"},
             {"netbox_site_name", "netbox.site.name"}}) {
        DYNAMIC_SECTION(policy_key << " / " << target_key)
        {
            auto message = refusal("clash_view", netprobe_policy("clash_view", "{" + policy_key + ": dc-west}", "{" + target_key + ": dc-east}"));
            CHECK_THAT(message, ContainsSubstring("'" + policy_key + "'"));
            CHECK_THAT(message, ContainsSubstring("'" + target_key + "'"));
            CHECK_THAT(message, ContainsSubstring("gw1"));
            CHECK_THAT(message, ContainsSubstring("clash_view"));
        }
    }
}

TEST_CASE("A netprobe policy's target attributes reach that target's series", "[policies][attributes][prometheus]")
{
    CoreRegistry registry;
    visor::load_builtin_plugins(registry);
    registry.start(nullptr);
    REQUIRE_NOTHROW(load(registry, netprobe_tap, netprobe_policy("probe_view", "{netbox.site.name: dc-west}", R"({netbox.site.name: dc-east, netbox_id: netbox-device-1, device_ip: 192.0.2.1, zero: "007"})")));

    auto [policy, lock] = registry.policy_manager()->module_get_locked("probe_view");
    REQUIRE(feed_targets(policy));

    std::stringstream out;
    policy->prometheus_metrics(out);
    size_t gw1 = 0;
    size_t gw2 = 0;
    for (const auto &line : sample_lines(out.str())) {
        CHECK_THAT(line, ContainsSubstring("policy=\"probe_view\""));
        if (line.find("target=\"gw1\"") != std::string::npos) {
            ++gw1;
            CHECK_THAT(line, ContainsSubstring("netbox_site_name=\"dc-east\""));
            CHECK_THAT(line, ContainsSubstring("netbox_id=\"netbox-device-1\""));
            CHECK_THAT(line, ContainsSubstring("device_ip=\"192.0.2.1\""));
            CHECK_THAT(line, ContainsSubstring("zero=\"007\""));
        } else if (line.find("target=\"gw2\"") != std::string::npos) {
            ++gw2;
            CHECK_THAT(line, ContainsSubstring("netbox_site_name=\"dc-west\""));
            CHECK(line.find("netbox_id=") == std::string::npos);
        }
    }
    CHECK(gw1 > 0);
    CHECK(gw2 > 0);
}

TEST_CASE("A target attribute too long to be a number reaches its series as written", "[policies][attributes]")
{
    constexpr auto serial = "1234567890123456789012345";
    CoreRegistry registry;
    visor::load_builtin_plugins(registry);
    registry.start(nullptr);
    REQUIRE_NOTHROW(load(registry, netprobe_tap, netprobe_policy("serial_view", "", fmt::format(R"({{serial: "{}"}})", serial))));

    auto [policy, lock] = registry.policy_manager()->module_get_locked("serial_view");
    REQUIRE(feed_targets(policy));
    close_windows(policy);
    metrics::v1::ScopeMetrics scope;
    policy->opentelemetry_metrics(scope);
    size_t gw1 = 0;
    size_t gw2 = 0;
    for (const auto &attrs : datapoint_attributes(scope)) {
        auto target = attrs.find("target");
        REQUIRE(target != attrs.end());
        if (target->second == "gw1") {
            ++gw1;
            CHECK(attrs.at("serial") == serial);
        } else if (target->second == "gw2") {
            ++gw2;
            CHECK(attrs.count("serial") == 0);
        }
    }
    CHECK(gw1 > 0);
    CHECK(gw2 > 0);
}

TEST_CASE("Policies that differ only in their target attributes share one input", "[policies][attributes]")
{
    CoreRegistry registry;
    visor::load_builtin_plugins(registry);
    registry.start(nullptr);
    REQUIRE_NOTHROW(load(registry, netprobe_tap, netprobe_policy("east_view", "", "{netbox.site.name: dc-east}")));
    REQUIRE_NOTHROW(registry.policy_manager()->load(YAML::Load(netprobe_policy("west_view", "", "{netbox.site.name: dc-west}"))["visor"]["policies"]));

    CHECK(registry.input_manager()->module_get_keys().size() == 1);
    for (const auto &[name, site] : std::vector<std::pair<std::string, std::string>>{{"east_view", "dc-east"}, {"west_view", "dc-west"}}) {
        auto [policy, lock] = registry.policy_manager()->module_get_locked(name);
        REQUIRE(feed_targets(policy));
        std::stringstream out;
        policy->prometheus_metrics(out);
        size_t gw1 = 0;
        for (const auto &line : sample_lines(out.str())) {
            if (line.find("target=\"gw1\"") != std::string::npos) {
                ++gw1;
                CHECK_THAT(line, ContainsSubstring("netbox_site_name=\"" + site + "\""));
                CHECK_THAT(line, ContainsSubstring("policy=\"" + name + "\""));
            }
        }
        CHECK(gw1 > 0);
    }
}

TEST_CASE("A malformed target attribute is refused, naming the target and the key", "[policies][attributes]")
{
    for (const std::string value : {"[{x: 1}]", "{x: 1}", "~", "\"\""}) {
        DYNAMIC_SECTION(value)
        {
            auto message = refusal("malformed_view", netprobe_policy("malformed_view", "", "{k: " + value + "}"));
            CHECK_THAT(message, ContainsSubstring("'k'"));
            CHECK_THAT(message, ContainsSubstring("gw1"));
            CHECK_THAT(message, ContainsSubstring("malformed_view"));
        }
    }
}

TEST_CASE("The input node a policy builds its input from has no target attributes", "[policies][attributes]")
{
    const auto raw = YAML::Load(R"(
tap: probes
input_type: netprobe
config:
  test_type: http
  targets:
    gw1:
      target: http://localhost:1/
      attributes: {serial: "1234567890123456789012345"}
    gw2:
      target: http://localhost:1/
)");
    const auto cleaned = without_target_attributes(raw);
    CHECK_FALSE(cleaned["config"]["targets"]["gw1"]["attributes"].IsDefined());
    CHECK(cleaned["config"]["targets"]["gw1"]["target"].Scalar() == "http://localhost:1/");
    CHECK(cleaned["config"]["targets"]["gw2"]["target"].Scalar() == "http://localhost:1/");
    CHECK(cleaned["config"]["test_type"].Scalar() == "http");
    CHECK(cleaned["input_type"].Scalar() == "netprobe");
    CHECK(cleaned["tap"].Scalar() == "probes");
    // a clone: the node as read keeps them
    CHECK(raw["config"]["targets"]["gw1"]["attributes"]["serial"].Scalar() == "1234567890123456789012345");

    // nothing to remove: the same node back
    for (const std::string yaml : {"{input_type: pcap, config: {pcap_file: x.pcap}}", "{input_type: netprobe}", "[a, b]"}) {
        CHECK(YAML::Dump(without_target_attributes(YAML::Load(yaml))) == YAML::Dump(YAML::Load(yaml)));
    }
}

TEST_CASE("A malformed key of a target attribute is refused, naming the target", "[policies][attributes]")
{
    for (const std::string key : {"\"\"", "1st_floor", "_x", "__name__", "\"a\xff\""}) {
        DYNAMIC_SECTION(key)
        {
            auto message = refusal("keyed_view", netprobe_policy("keyed_view", "", "{" + key + ": v}"));
            CHECK_THAT(message, ContainsSubstring("gw1"));
            CHECK_THAT(message, ContainsSubstring("keyed_view"));
            CHECK(is_utf8(message));
        }
    }
}

TEST_CASE("A non-ASCII attribute key is written as a Prometheus label one underscore per character", "[policies][attributes]")
{
    CHECK(prometheus_label_name("sit\xc3\xa9") == "sit_");
    CHECK(prometheus_label_name("a\xe2\x82\xac.b") == "a__b");
    CHECK(prometheus_label_name("netbox.site") == "netbox_site");
}

TEST_CASE("A null attributes means none", "[policies][attributes]")
{
    for (const std::string attributes : {"      attributes:\n", "      attributes: ~\n"}) {
        DYNAMIC_SECTION("policy " << attributes)
        {
            CoreRegistry registry;
            visor::load_builtin_plugins(registry);
            registry.start(nullptr);
            REQUIRE_NOTHROW(load(registry, pcap_tap, pcap_policy("null_view", attributes)));
            auto [policy, lock] = registry.policy_manager()->module_get_locked("null_view");
            CHECK(policy->attributes().empty());
        }
    }
    for (const std::string attributes : {"attributes:", "attributes: ~"}) {
        DYNAMIC_SECTION("target " << attributes)
        {
            CoreRegistry registry;
            visor::load_builtin_plugins(registry);
            registry.start(nullptr);
            REQUIRE_NOTHROW(load(registry, netprobe_tap, netprobe_policy("null_view", "", "")));
            auto yaml = netprobe_policy("null_target_view", "", "");
            yaml.replace(yaml.find("              target: http://localhost:1/"), 0, "              " + attributes + "\n");
            REQUIRE_NOTHROW(registry.policy_manager()->load(YAML::Load(yaml)["visor"]["policies"]));
            auto [policy, lock] = registry.policy_manager()->module_get_locked("null_target_view");
            REQUIRE(feed_targets(policy));
            std::stringstream out;
            policy->prometheus_metrics(out);
            CHECK_FALSE(sample_lines(out.str()).empty());
            for (const auto &line : sample_lines(out.str())) {
                CHECK_THAT(line, ContainsSubstring("policy=\"null_target_view\""));
            }
        }
    }
    CHECK(parse_target_attributes(YAML::Load("{config: {targets: {gw1: {target: x, attributes: ~}}}}"), "p").empty());
}

TEST_CASE("A bad input config value of a policy without target attributes reports its own position", "[policies][attributes]")
{
    auto yaml = netprobe_policy("pos_view", "", "");
    const auto at = yaml.find("interval_msec: 60000");
    yaml.replace(at, 20, "interval_msec: 99999999999999999999999");
    const auto line = 1 + std::count(yaml.begin(), yaml.begin() + at, '\n');
    CoreRegistry registry;
    visor::load_builtin_plugins(registry);
    registry.start(nullptr);
    std::string message;
    try {
        load(registry, netprobe_tap, yaml);
    } catch (const std::exception &e) {
        message = e.what();
    }
    INFO(message);
    CHECK_THAT(message, ContainsSubstring(fmt::format("line {}", line)));
    CHECK_THAT(message, !ContainsSubstring("line 1, column 1"));
}

TEST_CASE("An input node without target attributes is returned as it is", "[policies][attributes]")
{
    const auto raw = YAML::Load("input_type: netprobe\nconfig:\n  targets:\n    gw1:\n      target: x\n");
    const auto same = without_target_attributes(raw);
    CHECK(same["config"]["targets"]["gw1"].Mark().line == raw["config"]["targets"]["gw1"].Mark().line);
    CHECK(same["config"]["targets"]["gw1"].Mark().line == 4);
    CHECK(same.is(raw));
}
