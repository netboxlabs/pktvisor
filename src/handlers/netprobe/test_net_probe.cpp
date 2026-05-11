#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_test_visor.hpp>

#include <sstream>

#include "NetProbeInputStream.h"
#include "NetProbeStreamHandler.h"

using namespace visor::handler::netprobe;
using namespace visor::input::netprobe;
using namespace std::chrono;
using namespace nlohmann;

namespace {

// Holds the boilerplate needed to construct a NetProbeStreamHandler so that the
// metrics manager's `_groups` bitset is initialized. `start()` is what calls
// process_groups() which in turn calls _metrics->configure_groups(&_groups);
// without it, `group_enabled()` dereferences a null pointer and segfaults.
struct UnitFixture {
    visor::Config c;
    NetProbeInputStream stream{"netprobe-unit"};
    visor::InputEventProxy *proxy;
    std::unique_ptr<NetProbeStreamHandler> handler;

    explicit UnitFixture(uint64_t num_periods = 1)
    {
        c.config_set<uint64_t>("num_periods", num_periods);
        proxy = stream.add_event_proxy(c);
        handler = std::make_unique<NetProbeStreamHandler>("netprobe-unit", proxy, &c);
        handler->start();
    }

    ~UnitFixture()
    {
        handler->stop();
    }

    NetProbeMetricsManager *manager() { return const_cast<NetProbeMetricsManager *>(handler->metrics()); }
};

}

TEST_CASE("Net Probe ping tests", "[netprobe][ping]")
{
    // Requires raw-socket privileges + external network and only asserts
    // attempts >= 0 (always true). Bus-errors in CI; the unit tests below
    // cover the same code paths deterministically.
    SKIP("requires raw-socket privileges and external network");
    NetProbeInputStream stream{"net-probe-test"};
    stream.config_set("test_type", "ping");
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", "localhost");
    targets->config_set<std::shared_ptr<visor::Configurable>>("my_target", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);

    visor::Config c;
    c.config_set<uint64_t>("num_periods", 1);
    auto stream_proxy = stream.add_event_proxy(c);
    NetProbeStreamHandler netprobe_handler{"net-probe-test", stream_proxy, &c};

    netprobe_handler.start();
    stream.start();
    std::this_thread::sleep_for(1s);
    netprobe_handler.stop();
    stream.stop();

    auto event_data = netprobe_handler.metrics()->bucket(0)->event_data_locked();

    CHECK(netprobe_handler.metrics()->current_periods() == 1);
    CHECK(netprobe_handler.metrics()->bucket(0)->period_length() >= 1);

    json j;
    netprobe_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["targets"]["my_target"]["attempts"] >= 0);
}

TEST_CASE("NetProbe metrics process_failure each ErrorType", "[netprobe][unit]")
{
    UnitFixture fx;

    fx.manager()->process_failure(ErrorType::DnsLookupFailure, "host-dns");
    fx.manager()->process_failure(ErrorType::Timeout, "host-timeout");
    fx.manager()->process_failure(ErrorType::SocketError, "host-socket");
    fx.manager()->process_failure(ErrorType::InvalidIp, "host-invalid");
    fx.manager()->process_failure(ErrorType::ConnectFailure, "host-connect");

    json j;
    fx.manager()->bucket(0)->to_json(j);

    CHECK(j["targets"]["host-dns"]["dns_lookup_failures"] == 1);
    CHECK(j["targets"]["host-timeout"]["packets_timeout"] == 1);
    // SocketError, InvalidIp, ConnectFailure all map to connect_failures
    CHECK(j["targets"]["host-socket"]["connect_failures"] == 1);
    CHECK(j["targets"]["host-invalid"]["connect_failures"] == 1);
    CHECK(j["targets"]["host-connect"]["connect_failures"] == 1);
}

TEST_CASE("NetProbe TCP send/recv transaction", "[netprobe][unit]")
{
    UnitFixture fx;

    timespec ts_send{100, 0};
    timespec ts_recv{100, 50'000'000}; // 50ms later

    fx.manager()->process_netprobe_tcp(true, "tcp-target", ts_send);
    fx.manager()->process_netprobe_tcp(false, "tcp-target", ts_recv);

    json j;
    fx.manager()->bucket(0)->to_json(j);

    CHECK(j["targets"]["tcp-target"]["attempts"] == 1);
    CHECK(j["targets"]["tcp-target"]["successes"] == 1);
}

TEST_CASE("NetProbe TCP transaction timeout", "[netprobe][unit]")
{
    UnitFixture fx;
    // Default ttl is 5000ms. Use a recv timestamp 6s after send so the
    // transaction is detected as TimedOut by maybe_end_transaction.
    timespec ts_send{100, 0};
    timespec ts_recv_late{106, 0};

    fx.manager()->process_netprobe_tcp(true, "tcp-late", ts_send);
    fx.manager()->process_netprobe_tcp(false, "tcp-late", ts_recv_late);

    json j;
    fx.manager()->bucket(0)->to_json(j);

    CHECK(j["targets"]["tcp-late"]["attempts"] == 1);
    CHECK(j["targets"]["tcp-late"]["packets_timeout"] == 1);
}

TEST_CASE("NetProbe process_filtered increments event count", "[netprobe][unit]")
{
    UnitFixture fx;

    timespec stamp{200, 0};
    fx.manager()->process_filtered(stamp);
    fx.manager()->process_filtered(stamp);

    auto event_data = fx.manager()->bucket(0)->event_data_locked();
    CHECK(event_data.num_events->value() == 2);
}

TEST_CASE("NetProbe to_prometheus emits configured metrics", "[netprobe][unit]")
{
    UnitFixture fx;

    fx.manager()->process_failure(ErrorType::Timeout, "tprom");

    std::stringstream out;
    fx.manager()->bucket(0)->to_prometheus(out, {});
    auto s = out.str();

    // Counter name is registered in Target ctor as "packets_timeout".
    CHECK(s.find("packets_timeout") != std::string::npos);
    CHECK(s.find("tprom") != std::string::npos);
}

TEST_CASE("NetProbe specialized_merge aggregates targets across buckets", "[netprobe][unit]")
{
    UnitFixture fx_a(2);
    UnitFixture fx_b(2);

    fx_a.manager()->process_failure(ErrorType::Timeout, "shared");
    fx_a.manager()->process_failure(ErrorType::Timeout, "shared");
    fx_b.manager()->process_failure(ErrorType::Timeout, "shared");
    fx_b.manager()->process_failure(ErrorType::DnsLookupFailure, "only-in-b");

    UnitFixture fx_merged(2);
    auto *merged = const_cast<NetProbeMetricsBucket *>(fx_merged.manager()->bucket(0));
    merged->specialized_merge(*fx_a.manager()->bucket(0), visor::Metric::Aggregate::DEFAULT);
    merged->specialized_merge(*fx_b.manager()->bucket(0), visor::Metric::Aggregate::DEFAULT);

    json j;
    merged->to_json(j);
    CHECK(j["targets"]["shared"]["packets_timeout"] == 3);
    CHECK(j["targets"]["only-in-b"]["dns_lookup_failures"] == 1);
}

TEST_CASE("Net Probe TCP tests", "[netprobe][tcp]")
{
    // Requires external network (www.google.com:80) and only asserts
    // attempts >= 0 (always true). The unit tests above cover TCP send/recv
    // and timeout deterministically.
    SKIP("requires external network");
    NetProbeInputStream stream{"net-probe-test"};
    stream.config_set("test_type", "tcp");
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", "www.google.com");
    target->config_set<uint64_t>("port", 80);
    targets->config_set<std::shared_ptr<visor::Configurable>>("my_target", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);

    visor::Config c;
    c.config_set<uint64_t>("num_periods", 1);
    auto stream_proxy = stream.add_event_proxy(c);
    NetProbeStreamHandler netprobe_handler{"net-probe-test", stream_proxy, &c};

    netprobe_handler.start();
    stream.start();
    std::this_thread::sleep_for(1s);
    netprobe_handler.stop();
    stream.stop();

    auto event_data = netprobe_handler.metrics()->bucket(0)->event_data_locked();

    CHECK(netprobe_handler.metrics()->current_periods() == 1);
    CHECK(netprobe_handler.metrics()->bucket(0)->period_length() >= 1);

    json j;
    netprobe_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["targets"]["my_target"]["attempts"] >= 0);
}
