#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-declarations"
#endif
#include "inputs/static_plugins.h"
#include "handlers/static_plugins.h"
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

#include "CoreRegistry.h"
#include "Taps.h"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers.hpp>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>
#include <yaml-cpp/yaml.h>

using namespace visor;

auto tap_config = R"(
version: "1.0"

visor:
  config:
    verbose: true
  taps:
    wired:
      input_type: pcap
      config:
        iface: en7
        number: 123
        boolean: true
      tags:
        number: 123
        boolean: true
        string: "value"
    wireless:
      input_type: pcap
      config:
        iface: en0
      tags:
        string: "value"
)";

auto tap_config_bad = R"(
visor:
  config:
    verbose: true
  taps:
    wired:
      input_type: nonexistent
      config:
        iface: en7
)";

auto tap_config_bad_version = R"(
version: "2.0"

visor:
  taps:
    wired:
      input_type: nonexistent
      config:
        iface: en7
)";

auto tap_config_bad_no_tap = R"(
version: "1.0"

visor:
  policies:
    default:
      input_type: nonexistent
)";

TEST_CASE("Taps", "[taps]")
{

    SECTION("Good Config")
    {
        CoreRegistry registry;
        registry.start(nullptr);
        YAML::Node config_file = YAML::Load(tap_config);

        CHECK(config_file["visor"]["taps"]);
        CHECK(config_file["visor"]["taps"].IsMap());
        CHECK_NOTHROW(registry.tap_manager()->load(config_file["visor"]["taps"], true));

        auto [tap, lock] = registry.tap_manager()->module_get_locked("wired");
        CHECK(tap->name() == "wired");
        CHECK(tap->config_get<std::string>("iface") == "en7");
        CHECK(tap->config_get<uint64_t>("number") == 123);
        CHECK(tap->config_get<bool>("boolean") == true);
    }

    SECTION("Good config, test remove tap and add again")
    {
        CoreRegistry registry;
        registry.start(nullptr);
        YAML::Node config_file = YAML::Load(tap_config);

        CHECK(config_file["visor"]["taps"]);
        CHECK(config_file["visor"]["taps"].IsMap());
        CHECK_NOTHROW(registry.tap_manager()->load(config_file["visor"]["taps"], true));

        auto [tap, lock] = registry.tap_manager()->module_get_locked("wired");
        CHECK(tap->name() == "wired");
        CHECK(tap->config_get<std::string>("iface") == "en7");
        CHECK(tap->config_get<uint64_t>("number") == 123);
        CHECK(tap->config_get<bool>("boolean") == true);
        lock.unlock();

        REQUIRE_NOTHROW(registry.tap_manager()->module_remove("wired"));
        REQUIRE_NOTHROW(registry.tap_manager()->module_remove("wireless"));

        CHECK_NOTHROW(registry.tap_manager()->load(config_file["visor"]["taps"], true));
        auto [new_tap, new_lock] = registry.tap_manager()->module_get_locked("wired");
        CHECK(new_tap->name() == "wired");
        CHECK(new_tap->config_get<std::string>("iface") == "en7");
        CHECK(new_tap->config_get<uint64_t>("number") == 123);
        CHECK(new_tap->config_get<bool>("boolean") == true);
    }

    SECTION("Duplicate")
    {
        CoreRegistry registry;
        registry.start(nullptr);
        YAML::Node config_file = YAML::Load(tap_config);

        CHECK_NOTHROW(registry.tap_manager()->load(config_file["visor"]["taps"], true));
        CHECK_THROWS(registry.tap_manager()->load(config_file["visor"]["taps"], true));
    }

    SECTION("Bad Config")
    {
        CoreRegistry registry;
        registry.start(nullptr);
        YAML::Node config_file = YAML::Load(tap_config_bad);

        CHECK(config_file["visor"]["taps"]);
        CHECK(config_file["visor"]["taps"].IsMap());
        CHECK_THROWS(registry.tap_manager()->load(config_file["visor"]["taps"], true));
    }

    SECTION("Bad Config: empty data")
    {
        CoreRegistry registry;
        registry.start(nullptr);
        REQUIRE_THROWS_WITH(registry.tap_manager()->load_from_str(""), "empty data");
    }

    SECTION("Bad Config: invalid schema")
    {
        CoreRegistry registry;
        registry.start(nullptr);
        REQUIRE_THROWS_WITH(registry.tap_manager()->load_from_str("invalid: schema"), "invalid schema");
    }

    SECTION("Bad Config: invalid version")
    {
        CoreRegistry registry;
        registry.start(nullptr);
        REQUIRE_THROWS_WITH(registry.tap_manager()->load_from_str(tap_config_bad_version), "unsupported version");
    }

    SECTION("Bad Config: no taps")
    {
        CoreRegistry registry;
        registry.start(nullptr);
        REQUIRE_THROWS_WITH(registry.tap_manager()->load_from_str(tap_config_bad_no_tap), "no taps found in schema");
    }

    SECTION("Json validation")
    {
        CoreRegistry registry;
        registry.start(nullptr);
        YAML::Node config_file = YAML::Load(tap_config);

        CHECK(config_file["visor"]["taps"]);
        CHECK(config_file["visor"]["taps"].IsMap());
        CHECK_NOTHROW(registry.tap_manager()->load(config_file["visor"]["taps"], true));
        auto [tap, lock] = registry.tap_manager()->module_get_locked("wired");
        CHECK(tap->name() == "wired");

        json j;
        tap->info_json(j);

        CHECK(j["input_type"] == "pcap");
        CHECK(j["config"]["boolean"] == true);
        CHECK(j["config"]["number"] == 123);
        CHECK(j["config"]["iface"] == "en7");
        CHECK(j["tags"]["boolean"] == true);
        CHECK(j["tags"]["number"] == 123);
        CHECK(j["tags"]["string"] == "value");
    }
}
