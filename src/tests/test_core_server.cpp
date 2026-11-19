#include "BuiltinPlugins.h"
#include "CoreRegistry.h"
#include "CoreServer.h"
#include "HandlerManager.h"
#include "InputStreamManager.h"
#include "Policies.h"
#include "Taps.h"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>
#include <fmt/format.h>

using namespace visor;

namespace {

// the server answers 200 for a route that sets no status
int status(const httplib::Response &res)
{
    return res.status == -1 ? 200 : res.status;
}

auto constexpr TAP = R"(
visor:
  taps:
    anycast:
      input_type: mock
      config:
        iface: eth0
)";

void load_tap(CoreRegistry &registry)
{
    registry.tap_manager()->load_from_str(TAP);
}

// on the tap from load_tap, with an input of its own and a net handler
std::string policy(const std::string &name)
{
    return fmt::format(R"(
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
        name);
}

void load_policy(CoreRegistry &registry, const std::string &name)
{
    registry.policy_manager()->load_from_str(policy(name));
}

}

// Each test removes a module, then calls a route as a request that a concurrent DELETE beat to it would.

TEST_CASE("Tap routes answer 404 for a tap a concurrent request removed", "[api][taps]")
{
    CoreRegistry registry;
    visor::load_builtin_plugins(registry);
    registry.start(nullptr);
    REQUIRE_NOTHROW(load_tap(registry));

    SECTION("GET /api/v1/taps/{name}")
    {
        httplib::Response before;
        api::get_tap(*registry.tap_manager(), "anycast", before);
        CHECK(status(before) == 200);
        CHECK(json::parse(before.body).contains("anycast"));

        registry.policy_manager()->remove_tap("anycast");
        httplib::Response res;
        api::get_tap(*registry.tap_manager(), "anycast", res);
        CHECK(res.status == 404);
        CHECK(json::parse(res.body) == json{{"error", "tap does not exists"}});
    }

    SECTION("DELETE /api/v1/taps/{name}")
    {
        registry.policy_manager()->remove_tap("anycast");
        httplib::Response res;
        api::delete_tap(*registry.policy_manager(), "anycast", res);
        CHECK(res.status == 404);
        CHECK(json::parse(res.body) == json{{"error", "tap does not exists"}});

        REQUIRE_NOTHROW(load_tap(registry));
        httplib::Response removed;
        api::delete_tap(*registry.policy_manager(), "anycast", removed);
        CHECK(removed.status == 200);
        CHECK_FALSE(registry.tap_manager()->module_exists("anycast"));
    }
}

TEST_CASE("Policy routes answer 404 for a policy a concurrent request removed", "[api][policies]")
{
    CoreRegistry registry;
    visor::load_builtin_plugins(registry);
    registry.start(nullptr);
    REQUIRE_NOTHROW(load_tap(registry));
    REQUIRE_NOTHROW(load_policy(registry, "edge"));

    SECTION("GET /api/v1/policies/{name}")
    {
        httplib::Response before;
        api::get_policy(*registry.policy_manager(), "edge", before);
        CHECK(status(before) == 200);
        CHECK(json::parse(before.body).contains("edge"));

        registry.policy_manager()->remove_policy("edge");
        httplib::Response res;
        api::get_policy(*registry.policy_manager(), "edge", res);
        CHECK(res.status == 404);
        CHECK(json::parse(res.body) == json{{"error", "policy does not exists"}});
    }

    SECTION("DELETE /api/v1/policies/{name}")
    {
        httplib::Response removed;
        api::delete_policy(*registry.policy_manager(), "edge", removed);
        CHECK(removed.status == 200);
        CHECK_FALSE(registry.policy_manager()->module_exists("edge"));

        httplib::Response res;
        api::delete_policy(*registry.policy_manager(), "edge", res);
        CHECK(res.status == 404);
        CHECK(json::parse(res.body) == json{{"error", "policy does not exists"}});
    }
}

TEST_CASE("Default policy routes answer 404 for a default policy a concurrent request removed", "[api][policies]")
{
    CoreRegistry registry;
    visor::load_builtin_plugins(registry);
    registry.start(nullptr);
    REQUIRE_NOTHROW(load_tap(registry));
    REQUIRE_NOTHROW(load_policy(registry, "default"));

    SECTION("GET /api/v1/metrics/bucket/{period}")
    {
        httplib::Response before;
        api::get_default_bucket(*registry.policy_manager(), "0", before);
        CHECK(status(before) == 200);
        CHECK(json::parse(before.body).contains("1m"));

        registry.policy_manager()->remove_policy("default");
        httplib::Response res;
        api::get_default_bucket(*registry.policy_manager(), "0", res);
        CHECK(res.status == 404);
        CHECK(json::parse(res.body) == json{{"error", "no \"default\" policy exists"}});
    }

    SECTION("GET /api/v1/metrics/window/{period}")
    {
        httplib::Response before;
        api::get_default_window(*registry.policy_manager(), "2", before);
        CHECK(status(before) == 200);
        CHECK(json::parse(before.body).contains("2m"));

        registry.policy_manager()->remove_policy("default");
        httplib::Response res;
        api::get_default_window(*registry.policy_manager(), "2", res);
        CHECK(res.status == 404);
        CHECK(json::parse(res.body) == json{{"error", "no \"default\" policy exists"}});
    }

    SECTION("GET on the default policy's Prometheus path")
    {
        httplib::Response before;
        api::get_default_prometheus(*registry.policy_manager(), before);
        CHECK(status(before) == 200);
        CHECK_THAT(before.body, Catch::Matchers::ContainsSubstring(R"(policy="default")"));

        registry.policy_manager()->remove_policy("default");
        httplib::Response res;
        api::get_default_prometheus(*registry.policy_manager(), res);
        CHECK(res.status == 404);
        CHECK(res.body.empty());
    }
}

TEST_CASE("The default policy's Prometheus path carries its attributes, with policy on top and no handler label", "[api][policies]")
{
    CoreRegistry registry;
    visor::load_builtin_plugins(registry);
    registry.start(nullptr);
    REQUIRE_NOTHROW(load_tap(registry));
    auto yaml = policy("default");
    yaml.replace(yaml.find("      input:"), 0, "      attributes: {site: dc-west}\n");
    REQUIRE_NOTHROW(registry.policy_manager()->load_from_str(yaml));

    httplib::Response res;
    api::get_default_prometheus(*registry.policy_manager(), res);
    CHECK(status(res) == 200);
    CHECK_THAT(res.body, Catch::Matchers::ContainsSubstring(R"(policy="default")"));
    CHECK_THAT(res.body, Catch::Matchers::ContainsSubstring(R"(site="dc-west")"));
    CHECK_THAT(res.body, !Catch::Matchers::ContainsSubstring("handler="));
}

TEST_CASE("Policy metrics answer 404 for a removed policy and __all skips one removed after it was listed", "[api][policies]")
{
    CoreRegistry registry;
    visor::load_builtin_plugins(registry);
    registry.start(nullptr);
    REQUIRE_NOTHROW(load_tap(registry));
    REQUIRE_NOTHROW(load_policy(registry, "edge"));
    REQUIRE_NOTHROW(load_policy(registry, "core"));

    // __all lists every policy before it looks any up
    auto names = registry.policy_manager()->module_get_keys();
    registry.policy_manager()->remove_policy("core");

    SECTION("GET /api/v1/policies/{name}/metrics/(window|bucket)/{period}")
    {
        httplib::Response all;
        api::get_policies_metrics(*registry.policy_manager(), names, true, "0", false, all);
        CHECK(status(all) == 200);
        auto j = json::parse(all.body);
        CHECK(j.contains("edge"));
        CHECK_FALSE(j.contains("core"));

        httplib::Response res;
        api::get_policies_metrics(*registry.policy_manager(), {"core"}, false, "0", false, res);
        CHECK(res.status == 404);
        CHECK(json::parse(res.body) == json{{"error", "policy does not exist"}});

        // a missing policy answers 404 before its period is parsed, even one too large to parse
        httplib::Response unparsed;
        api::get_policies_metrics(*registry.policy_manager(), {"core"}, false, "99999999999999999999", false, unparsed);
        CHECK(unparsed.status == 404);
        CHECK(json::parse(unparsed.body) == json{{"error", "policy does not exist"}});
    }

    SECTION("GET /api/v1/policies/{name}/metrics/prometheus")
    {
        httplib::Response all;
        api::get_policies_prometheus(*registry.policy_manager(), names, true, all);
        CHECK(status(all) == 200);
        CHECK_THAT(all.body, Catch::Matchers::ContainsSubstring(R"(policy="edge")"));
        CHECK_THAT(all.body, !Catch::Matchers::ContainsSubstring(R"(policy="core")"));

        httplib::Response res;
        api::get_policies_prometheus(*registry.policy_manager(), {"core"}, false, res);
        CHECK(res.status == 404);
        CHECK(res.body == "policy does not exists");
    }
}

TEST_CASE("Policy metrics skip a policy without the period under __all and answer 425 for it alone", "[api][policies]")
{
    CoreRegistry registry;
    visor::load_builtin_plugins(registry);
    registry.start(nullptr);
    REQUIRE_NOTHROW(load_tap(registry));
    REQUIRE_NOTHROW(load_policy(registry, "edge"));
    REQUIRE_NOTHROW(load_policy(registry, "core"));

    // a policy just created holds only period 0
    httplib::Response all;
    api::get_policies_metrics(*registry.policy_manager(), registry.policy_manager()->module_get_keys(), true, "1", false, all);
    CHECK(status(all) == 200);
    auto j = json::parse(all.body);
    CHECK_FALSE(j.contains("edge"));
    CHECK_FALSE(j.contains("core"));

    httplib::Response res;
    api::get_policies_metrics(*registry.policy_manager(), {"edge"}, false, "1", false, res);
    CHECK(res.status == 425);
    CHECK_THAT(json::parse(res.body).value("error", ""), Catch::Matchers::ContainsSubstring("has not yet accumulated"));
}

// the largest period that fits in a signed 64-bit number, the next one, and one past every 64-bit number
auto constexpr INT64_MAX_PERIOD = "9223372036854775807";
auto constexpr PAST_INT64 = "9223372036854775808";
auto constexpr PAST_UINT64 = "99999999999999999999";

TEST_CASE("Policy metrics answer a period too large for 64 bits as they answer any period past the range", "[api][policies]")
{
    CoreRegistry registry;
    visor::load_builtin_plugins(registry);
    registry.start(nullptr);
    REQUIRE_NOTHROW(load_tap(registry));
    REQUIRE_NOTHROW(load_policy(registry, "edge"));

    for (auto period : {"99", INT64_MAX_PERIOD, PAST_INT64, PAST_UINT64}) {
        INFO("period " << period);
        httplib::Response bucket;
        api::get_policies_metrics(*registry.policy_manager(), {"edge"}, false, period, false, bucket);
        CHECK(bucket.status == 425);
        CHECK(json::parse(bucket.body) == json{{"error", "invalid metrics period, specify [0, 4]"}});

        httplib::Response window;
        api::get_policies_metrics(*registry.policy_manager(), {"edge"}, false, period, true, window);
        CHECK(window.status == 425);
        CHECK(json::parse(window.body) == json{{"error", "invalid metrics period, specify [2, 5]"}});
    }

    // the routes pass only digits, but a direct caller can pass anything
    httplib::Response text;
    api::get_policies_metrics(*registry.policy_manager(), {"edge"}, false, "1x", false, text);
    CHECK(text.status == 425);
    CHECK(json::parse(text.body) == json{{"error", "invalid metrics period '1x'"}});
}

TEST_CASE("Policy metrics under __all answer 425 for a period no policy keeps, and leave out one that has not reached it", "[api][policies]")
{
    CoreRegistry registry;
    visor::load_builtin_plugins(registry);
    registry.start(nullptr);
    REQUIRE_NOTHROW(load_tap(registry));
    // edge keeps 5 periods, wide keeps 10; both have accumulated only period 0
    REQUIRE_NOTHROW(load_policy(registry, "edge"));
    auto wide = policy("wide");
    wide.replace(wide.find("      handlers:\n") + std::string("      handlers:\n").size(), 0, "        window_config:\n          num_periods: 10\n");
    REQUIRE_NOTHROW(registry.policy_manager()->load_from_str(wide));
    auto names = registry.policy_manager()->module_get_keys();

    SECTION("a period past every policy's range")
    {
        // the widest range any policy keeps, whichever policy is looked up last: a client reads the range from it
        for (auto order : {names, std::vector<std::string>(names.rbegin(), names.rend())}) {
            for (auto period : {"10", "99", PAST_INT64, PAST_UINT64}) {
                INFO("period " << period);
                httplib::Response bucket;
                api::get_policies_metrics(*registry.policy_manager(), order, true, period, false, bucket);
                CHECK(bucket.status == 425);
                CHECK(json::parse(bucket.body) == json{{"error", "invalid metrics period, specify [0, 9]"}});
            }
            for (auto period : {"0", "1", "11", PAST_INT64}) {
                INFO("window " << period);
                httplib::Response window;
                api::get_policies_metrics(*registry.policy_manager(), order, true, period, true, window);
                CHECK(window.status == 425);
                CHECK(json::parse(window.body) == json{{"error", "invalid metrics period, specify [2, 10]"}});
            }
        }
    }

    SECTION("a policy without handlers holds no period")
    {
        auto bare = policy("bare");
        auto modules = bare.find("        modules:\n");
        bare.replace(modules, std::string::npos, "        modules: {}\n");
        REQUIRE_NOTHROW(registry.policy_manager()->load_from_str(bare));
        registry.policy_manager()->remove_policy("wide");

        httplib::Response res;
        api::get_policies_metrics(*registry.policy_manager(), registry.policy_manager()->module_get_keys(), true, "99", false, res);
        CHECK(res.status == 425);
        CHECK(json::parse(res.body) == json{{"error", "invalid metrics period, specify [0, 4]"}});

        // alone, it refuses nothing either
        httplib::Response alone;
        api::get_policies_metrics(*registry.policy_manager(), {"bare"}, true, "99", false, alone);
        CHECK(status(alone) == 200);
        CHECK(json::parse(alone.body) == json::object());
    }

    SECTION("a period inside one policy's range")
    {
        // past edge's range, kept by wide but not reached yet: wide may still have it, so nothing is refused
        httplib::Response bucket;
        api::get_policies_metrics(*registry.policy_manager(), names, true, "7", false, bucket);
        CHECK(status(bucket) == 200);
        CHECK(json::parse(bucket.body) == json::object());

        // a window merges what wide holds so far
        httplib::Response window;
        api::get_policies_metrics(*registry.policy_manager(), names, true, "7", true, window);
        CHECK(status(window) == 200);
        auto j = json::parse(window.body);
        CHECK(j.contains("wide"));
        CHECK_FALSE(j.contains("edge"));
    }

    SECTION("no policy at all")
    {
        httplib::Response res;
        api::get_policies_metrics(*registry.policy_manager(), {}, true, "99", false, res);
        CHECK(status(res) == 200);
        CHECK(json::parse(res.body) == json::object());
    }
}

TEST_CASE("Default policy routes answer a period the default policy does not keep as the per-policy route does", "[api][policies]")
{
    CoreRegistry registry;
    visor::load_builtin_plugins(registry);
    registry.start(nullptr);
    REQUIRE_NOTHROW(load_tap(registry));
    REQUIRE_NOTHROW(load_policy(registry, "default"));

    for (auto period : {"1", "99", PAST_INT64, PAST_UINT64}) {
        INFO("bucket " << period);
        httplib::Response per_policy;
        api::get_policies_metrics(*registry.policy_manager(), {"default"}, false, period, false, per_policy);
        httplib::Response res;
        api::get_default_bucket(*registry.policy_manager(), period, res);
        CHECK(res.status == 425);
        CHECK(res.status == per_policy.status);
        CHECK(json::parse(res.body) == json::parse(per_policy.body));
    }
    httplib::Response past;
    api::get_default_bucket(*registry.policy_manager(), "99", past);
    CHECK(json::parse(past.body) == json{{"error", "invalid metrics period, specify [0, 4]"}});

    for (auto period : {"1", "99", PAST_INT64, PAST_UINT64}) {
        INFO("window " << period);
        httplib::Response per_policy;
        api::get_policies_metrics(*registry.policy_manager(), {"default"}, false, period, true, per_policy);
        httplib::Response res;
        api::get_default_window(*registry.policy_manager(), period, res);
        CHECK(res.status == 425);
        CHECK(res.status == per_policy.status);
        CHECK(json::parse(res.body) == json{{"error", "invalid metrics period, specify [2, 5]"}});
    }
}

TEST_CASE("POST routes answer 201 with what they loaded and refuse a name already taken", "[api][taps][policies]")
{
    CoreRegistry registry;
    visor::load_builtin_plugins(registry);
    registry.start(nullptr);

    SECTION("POST /api/v1/taps")
    {
        httplib::Response res;
        api::post_taps(*registry.tap_manager(), TAP, res);
        CHECK(res.status == 201);
        auto j = json::parse(res.body);
        CHECK(j["anycast"]["input_type"] == "mock");
        CHECK(j["anycast"]["config"]["iface"] == "eth0");

        httplib::Response again;
        api::post_taps(*registry.tap_manager(), TAP, again);
        CHECK(again.status == 409);
        CHECK(json::parse(again.body) == json{{"error", "module name 'anycast' already exists"}});
    }

    SECTION("POST /api/v1/policies")
    {
        REQUIRE_NOTHROW(load_tap(registry));
        httplib::Response res;
        api::post_policies(*registry.policy_manager(), policy("edge"), res);
        CHECK(res.status == 201);
        auto j = json::parse(res.body);
        CHECK(j["edge"]["taps"].contains("anycast"));
        CHECK(j["edge"]["input"].size() == 1);
        CHECK(j["edge"]["modules"].contains("edge-anycast-edge_net"));

        httplib::Response again;
        api::post_policies(*registry.policy_manager(), policy("edge"), again);
        CHECK(again.status == 409);
        CHECK(json::parse(again.body) == json{{"error", "policy with name 'edge' already defined"}});

        // a tap selector that matches no tap
        httplib::Response unmatched;
        api::post_policies(*registry.policy_manager(), R"(
visor:
  policies:
    core:
      kind: collection
      input:
        tap_selector:
          any:
            - site: nowhere
        input_type: mock
      handlers:
        modules:
          core_net:
            type: net
)",
            unmatched);
        CHECK(unmatched.status == 422);
        CHECK_FALSE(registry.policy_manager()->module_exists("core"));
    }
}

TEST_CASE("A policy POST naming a tap that does not exist answers 422 and creates nothing", "[api][policies]")
{
    CoreRegistry registry;
    visor::load_builtin_plugins(registry);
    registry.start(nullptr);
    auto yaml = policy("core");
    yaml.replace(yaml.find("tap: anycast"), std::string("tap: anycast").size(), "tap: nowhere");

    httplib::Response res;
    api::post_policies(*registry.policy_manager(), yaml, res);
    CHECK(res.status == 422);
    CHECK(json::parse(res.body) == json{{"error", "tap 'nowhere' does not exist"}});
    CHECK_FALSE(registry.policy_manager()->module_exists("core"));

    // nothing was left behind: the same body is refused the same way, not as a name in use
    httplib::Response again;
    api::post_policies(*registry.policy_manager(), yaml, again);
    CHECK(again.status == 422);
}

namespace {

// a policy named core with the input lines given, at the indentation of the keys under input, and the net handler
// unless the handlers are given; extra is added after the handlers, at the indentation of the policy's keys
std::string core_policy(const std::string &input, const std::string &handlers = "handlers:\n        modules:\n          core_net:\n            type: net\n", const std::string &extra = "")
{
    return "visor:\n  policies:\n    core:\n      kind: collection\n      input:\n" + input + "      " + handlers + extra;
}

auto constexpr ON_ANYCAST = "        tap: anycast\n        input_type: mock\n";

}

TEST_CASE("POST routes answer 422 for a body they refuse as written, and create nothing", "[api][taps][policies]")
{
    CoreRegistry registry;
    visor::load_builtin_plugins(registry);
    registry.start(nullptr);

    SECTION("POST /api/v1/taps")
    {
        const std::vector<std::pair<std::string, std::string>> refused{
            {"", "empty data"},
            {"visor:\n  policies: {}\n", "no taps found in schema"},
            {"version: \"2.0\"\nvisor:\n  taps:\n    x:\n      input_type: mock\n", "unsupported version"},
            {"visor:\n  taps:\n    x:\n      config: {}\n", "missing or invalid tap type key 'input_type'"},
            {"visor:\n  taps:\n    x:\n      input_type: nope\n", "Tap 'x' requires input stream type 'nope' which is not available"},
            {"visor:\n  taps:\n    x:\n      input_type: mock\n      config: 3\n", "tap configuration is not a map"},
            {"visor:\n  taps:\n    x:\n      input_type: mock\n      config:\n        list:\n          - a: b\n", "invalid tap config: invalid value for sequence in key: list"},
            {"visor:\n  taps:\n    x:\n      input_type: mock\n      tags:\n        list:\n          - a: b\n", "invalid tap tags: invalid value for sequence in key: list"},
            {"visor:\n  taps:\n    x:\n      input_type: mock\n    y:\n      input_type: mock\n", "only a single tap expected but got 2"},
            {"visor:\n  taps:\n    my tap:\n      input_type: mock\n", "invalid module name: my tap"},
        };
        for (const auto &[body, error] : refused) {
            CAPTURE(body);
            httplib::Response res;
            api::post_taps(*registry.tap_manager(), body, res);
            CHECK(res.status == 422);
            CHECK(json::parse(res.body) == json{{"error", error}});
        }

        // a key yaml-cpp cannot read as the string the tap's config expects
        httplib::Response shape;
        api::post_taps(*registry.tap_manager(), "visor:\n  taps:\n    x:\n      input_type: mock\n      config:\n        ? [a, b]\n        : 1\n", shape);
        CHECK(shape.status == 422);
        CHECK_THAT(json::parse(shape.body)["error"].get<std::string>(), Catch::Matchers::ContainsSubstring("bad conversion"));

        CHECK(registry.tap_manager()->module_get_keys().empty());
    }

    SECTION("POST /api/v1/policies")
    {
        REQUIRE_NOTHROW(load_tap(registry));
        REQUIRE_NOTHROW(registry.tap_manager()->load_from_str("visor:\n  taps:\n    flows:\n      input_type: flow\n"));
        REQUIRE_NOTHROW(registry.tap_manager()->load_from_str("visor:\n  taps:\n    numbered:\n      input_type: mock\n      tags:\n        site: 5\n"));
        auto renamed = core_policy(ON_ANYCAST);
        renamed.replace(renamed.find("    core:"), std::string("    core:").size(), "    1core:");
        const std::vector<std::pair<std::string, std::string>> refused{
            {"", "empty data"},
            {"visor:\n  taps: {}\n", "no policies found in schema"},
            {"version: \"2.0\"\n" + core_policy(ON_ANYCAST), "unsupported version"},
            {"visor:\n  policies:\n    a:\n      kind: collection\n    b:\n      kind: collection\n", "only a single policy expected but got 2"},
            {"visor:\n  policies:\n    core:\n      input: {}\n", "missing or invalid policy kind at key 'kind'"},
            {"visor:\n  policies:\n    core:\n      kind: other\n", "unknown policy kind: other"},
            {core_policy("        input_type: mock\n        config: 3\n        tap: anycast\n"), "input configuration is not a map"},
            {core_policy(ON_ANYCAST + std::string("        tap_selector:\n          any:\n            - site: dc\n")), "input can have only key 'input.tap' or key 'input.tap_selector'"},
            {core_policy("        input_type: mock\n"), "missing key 'input.tap' or key 'input.tap_selector'"},
            {core_policy("        tap: [anycast]\n        input_type: mock\n"), "invalid tap at key 'input.tap'"},
            {core_policy("        tap: flows\n        input_type: mock\n"), "input_type for policy specified tap 'flows' doesn't match tap's defined input type: mock/flow"},
            {core_policy(ON_ANYCAST, "kind_of_handlers: {}\n"), "missing or invalid handler configuration at key 'handlers'"},
            {core_policy(ON_ANYCAST, "handlers:\n        modules:\n          core_x:\n            type: nope\n"), "Policy 'core' requires stream handler type 'nope' and version '1.0' which is not available"},
            {core_policy(ON_ANYCAST, "handlers:\n        modules:\n          core_net:\n            type: net\n", "      config: 3\n"), "policy configuration is not a map"},
            {core_policy(ON_ANYCAST, "handlers:\n        modules:\n          core_net:\n            type: net\n", "      attributes: 3\n"), "attributes of policy 'core' is not a map"},
            {renamed, "invalid module name: 1core"},
            {core_policy(ON_ANYCAST, "handlers:\n        modules:\n          core.net:\n            type: net\n"), "invalid module name: core-anycast-core.net"},
            // a sequence item that names no handler, and one that is not a map
            {core_policy(ON_ANYCAST, "handlers:\n        modules:\n          - {}\n"), "expecting handler module identifier"},
            {core_policy(ON_ANYCAST, "handlers:\n        modules:\n          - core_net\n"), "expecting handler module identifier"},
            // a selector item that is not one key and value
            {core_policy("        input_type: mock\n        tap_selector:\n          any:\n            - {}\n"), "selector tag must contain only one key/value pair per sequence index"},
            {core_policy("        input_type: mock\n        tap_selector:\n          any:\n            - site\n"), "selector tag must contain only one key/value pair per sequence index"},
            {core_policy("        input_type: mock\n        tap_selector:\n          any:\n            - site: dc\n"), "Tap [numbered]: tag and selector value types are different for key 'site'"},
            // a config value of the wrong type, which the handler reads as it is built
            {core_policy(ON_ANYCAST, "handlers:\n        window_config:\n          num_periods: abc\n        modules:\n          core_net:\n            type: net\n"), "wrong type for key: num_periods"},
            {core_policy(ON_ANYCAST, "handlers:\n        window_config:\n          num_periods: 3\n        modules:\n          core_net:\n            type: net\n            config:\n              deep_sample_rate: abc\n"), "wrong type for key: deep_sample_rate"},
        };
        for (const auto &[body, error] : refused) {
            CAPTURE(body);
            httplib::Response res;
            api::post_policies(*registry.policy_manager(), body, res);
            CHECK(res.status == 422);
            CHECK(json::parse(res.body) == json{{"error", error}});
        }
        // a handler that cannot read the tap's input refuses it as it is built
        httplib::Response unreadable;
        api::post_policies(*registry.policy_manager(), core_policy("        tap: flows\n        input_type: flow\n"), unreadable);
        CHECK(unreadable.status == 422);
        CHECK_THAT(json::parse(unreadable.body)["error"].get<std::string>(), Catch::Matchers::StartsWith("NetStreamHandler: unsupported input event proxy"));

        CHECK(registry.policy_manager()->module_get_keys().empty());
        CHECK(registry.input_manager()->module_get_keys().empty());
        CHECK(registry.handler_manager()->module_get_keys().empty());

        // nothing was left behind: a valid policy with the same name loads
        httplib::Response valid;
        api::post_policies(*registry.policy_manager(), core_policy(ON_ANYCAST), valid);
        CHECK(valid.status == 201);
    }
}

TEST_CASE("POST routes answer 400 for a body that is not YAML", "[api][taps][policies]")
{
    CoreRegistry registry;
    visor::load_builtin_plugins(registry);
    registry.start(nullptr);

    for (const std::string body : {"visor: [unclosed", R"({"visor": {"taps": )"}) {
        CAPTURE(body);
        httplib::Response tap;
        api::post_taps(*registry.tap_manager(), body, tap);
        CHECK(tap.status == 400);
        CHECK_THAT(json::parse(tap.body)["error"].get<std::string>(), Catch::Matchers::StartsWith("yaml-cpp: error at line"));

        httplib::Response policy;
        api::post_policies(*registry.policy_manager(), body, policy);
        CHECK(policy.status == 400);
        CHECK_THAT(json::parse(policy.body)["error"].get<std::string>(), Catch::Matchers::StartsWith("yaml-cpp: error at line"));
    }
    CHECK(registry.tap_manager()->module_get_keys().empty());
    CHECK(registry.policy_manager()->module_get_keys().empty());
}

TEST_CASE("A policy POST that passes the checks and fails to start still answers 500", "[api][policies]")
{
    CoreRegistry registry;
    visor::load_builtin_plugins(registry);
    registry.start(nullptr);
    // only the input checks its test_type, as it starts: the API cannot tell this from a failure of the host
    REQUIRE_NOTHROW(registry.tap_manager()->load_from_str(
        "visor:\n  taps:\n    probes:\n      input_type: netprobe\n      config:\n        test_type: nope\n        targets:\n          a:\n            target: 127.0.0.1\n"));

    httplib::Response res;
    api::post_policies(*registry.policy_manager(), core_policy("        tap: probes\n        input_type: netprobe\n", "handlers:\n        modules:\n          core_probe:\n            type: netprobe\n"), res);
    CHECK(res.status == 500);
    CHECK_THAT(json::parse(res.body)["error"].get<std::string>(), Catch::Matchers::StartsWith("policy [core] failed to start: nope is an invalid/unsupported test type"));
    CHECK_FALSE(registry.policy_manager()->module_exists("core"));
}
