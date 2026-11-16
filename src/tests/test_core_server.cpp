#include "BuiltinPlugins.h"
#include "CoreRegistry.h"
#include "CoreServer.h"
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

void load_tap(CoreRegistry &registry)
{
    registry.tap_manager()->load_from_str(R"(
visor:
  taps:
    anycast:
      input_type: mock
      config:
        iface: eth0
)");
}

// on the tap from load_tap, with an input of its own and a net handler
void load_policy(CoreRegistry &registry, const std::string &name)
{
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
