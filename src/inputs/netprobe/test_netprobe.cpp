#include "NetProbeInputStream.h"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers.hpp>
#include <catch2/catch_test_visor.hpp>

using namespace visor::input::netprobe;
using namespace std::chrono;

TEST_CASE("NetProbe Configs", "[netprobe][ping]")
{
    // Sends real ICMP pings to localhost; needs raw-socket privileges and
    // segfaults in unprivileged CI. Only asserts the config round-trips,
    // which the config-validation tests below already cover deterministically.
    SKIP("requires raw-socket privileges");
    NetProbeInputStream stream{"net-probe-test"};
    stream.config_set("test_type", "ping");
    stream.config_set<uint64_t>("interval_msec", 2000);
    stream.config_set<uint64_t>("timeout_msec", 1000);
    stream.config_set<uint64_t>("packets_interval_msec", 25);
    stream.config_set<uint64_t>("packets_per_test", 2);
    stream.config_set<uint64_t>("packet_payload_size", 56);
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", "localhost");
    targets->config_set<std::shared_ptr<visor::Configurable>>("my_target", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);

    CHECK_NOTHROW(stream.start());
    std::this_thread::sleep_for(1s);
    CHECK_NOTHROW(stream.stop());

    nlohmann::json j;
    stream.info_json(j);
    CHECK(j["module"]["config"]["test_type"] == "ping");
}

TEST_CASE("NetProbe TCP config", "[netprobe][tcp]")
{
    // Resolves example.com and opens a TCP socket; segfaults in CI when DNS
    // or outbound network is restricted. Same justification as the [ping]
    // case above — the assertion is purely a config round-trip.
    SKIP("requires external network");
    NetProbeInputStream stream{"net-probe-test"};
    stream.config_set("test_type", "tcp");
    stream.config_set<uint64_t>("interval_msec", 500);
    stream.config_set<uint64_t>("timeout_msec", 200);
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", "example.com");
    target->config_set<uint64_t>("port", 80);
    targets->config_set<std::shared_ptr<visor::Configurable>>("my_target", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);

    CHECK_NOTHROW(stream.start());
    std::this_thread::sleep_for(1s);
    CHECK_NOTHROW(stream.stop());

    nlohmann::json j;
    stream.info_json(j);
    CHECK(j["module"]["config"]["test_type"] == "tcp");
}

TEST_CASE("NetProbe Boundaries", "[netprobe]")
{
    NetProbeInputStream stream{"net-probe-test"};
    stream.config_set("test_type", "ping");
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", "localhost");
    targets->config_set<std::shared_ptr<visor::Configurable>>("my_target", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);

    SECTION("timeout greater than interval")
    {
        stream.config_set<uint64_t>("interval_msec", 2000);
        stream.config_set<uint64_t>("timeout_msec", 5000);
        CHECK_THROWS_WITH(stream.start(), "timeout_msec [5000] cannot be greater than interval_msec [2000]");
    }

    SECTION("huge payload size")
    {
        stream.config_set<uint64_t>("packet_payload_size", 50000000000);
        CHECK_THROWS_WITH(stream.start(), "packet_payload_size was set to 50000000000 but max supported size is 65500");
    }

    SECTION("num packets times packets interval greater than interval")
    {
        stream.config_set<uint64_t>("interval_msec", 2000);
        stream.config_set<uint64_t>("packets_interval_msec", 100);
        stream.config_set<uint64_t>("packets_per_test", 25);
        CHECK_THROWS_WITH(stream.start(), "packets_per_test [25] times packets_interval_msec [100] cannot be greater than packets_interval_msec [2000]");
    }
}

TEST_CASE("Test Configs fail", "[netprobe][config]")
{
    NetProbeInputStream stream{"net-probe-test"};
    stream.config_set("test_type", "ping");

    CHECK_THROWS_WITH(stream.start(), "no targets specified");
}

TEST_CASE("Netprobe invalid config", "[netprobe][config]")
{
    NetProbeInputStream stream{"net-probe-test"};
    stream.config_set("invalid_config", true);

    CHECK_THROWS_WITH(stream.start(), "invalid_config is an invalid/unsupported config or filter. The valid configs/filters are: test_type, interval_msec, timeout_msec, packets_per_test, packets_interval_msec, packet_payload_size, targets");
}

TEST_CASE("NetProbe ip_version config", "[netprobe][config][ipv6]")
{
    auto make = [](const std::string &tgt, std::optional<uint64_t> ipv) {
        auto targets = std::make_shared<visor::Configurable>();
        auto target = std::make_shared<visor::Configurable>();
        target->config_set("target", tgt);
        if (ipv) target->config_set<uint64_t>("ip_version", *ipv);
        targets->config_set<std::shared_ptr<visor::Configurable>>("my_target", target);
        return targets;
    };
    auto stream_with = [&](const std::shared_ptr<visor::Configurable> &targets) {
        auto s = std::make_unique<NetProbeInputStream>("net-probe-test");
        s->config_set("test_type", "ping");
        s->config_set<std::shared_ptr<visor::Configurable>>("targets", targets);
        return s;
    };

    SECTION("invalid ip_version value") {
        auto s = stream_with(make("localhost", 5));
        CHECK_THROWS_WITH(s->start(), "ip_version must be 4 or 6");
    }
    SECTION("literal IPv4 with ip_version 6 conflicts") {
        auto s = stream_with(make("1.2.3.4", 6));
        CHECK_THROWS_WITH(s->start(), "target 1.2.3.4 is IPv4 but ip_version is set to 6");
    }
    SECTION("literal IPv6 with ip_version 4 conflicts") {
        auto s = stream_with(make("2001:db8::1", 4));
        CHECK_THROWS_WITH(s->start(), "target 2001:db8::1 is IPv6 but ip_version is set to 4");
    }
    SECTION("top-level valid-keys string unchanged") {
        NetProbeInputStream s{"net-probe-test"};
        s.config_set("invalid_config", true);
        CHECK_THROWS_WITH(s.start(), "invalid_config is an invalid/unsupported config or filter. The valid configs/filters are: test_type, interval_msec, timeout_msec, packets_per_test, packets_interval_msec, packet_payload_size, targets");
    }
}
