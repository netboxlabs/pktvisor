#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_test_visor.hpp>

#include <opentelemetry/proto/metrics/v1/metrics.pb.h>
#include <sstream>

#include "PcapInputStream.h"
#include "BgpStreamHandler.h"

using namespace visor::handler::bgp;
using namespace visor::input::pcap;
using namespace nlohmann;

TEST_CASE("Parse BGP tests", "[pcap][bgp]")
{
    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "tests/fixtures/bgp.pcap");
    stream.config_set("bpf", "");

    visor::Config c;
    c.config_set<uint64_t>("num_periods", 1);
    auto stream_proxy = stream.add_event_proxy(c);
    BgpStreamHandler bgp_handler{"bgp-test", stream_proxy, &c};

    bgp_handler.start();
    stream.start();
    bgp_handler.stop();
    stream.stop();

    auto counters = bgp_handler.metrics()->bucket(0)->counters();
    auto event_data = bgp_handler.metrics()->bucket(0)->event_data_locked();

    CHECK(bgp_handler.metrics()->current_periods() == 1);
    CHECK(bgp_handler.metrics()->start_tstamp().tv_sec == 1453594491);
    CHECK(bgp_handler.metrics()->start_tstamp().tv_nsec == 508326000);

    CHECK(bgp_handler.metrics()->end_tstamp().tv_sec == 1453594495);
    CHECK(bgp_handler.metrics()->end_tstamp().tv_nsec == 971400000);

    CHECK(bgp_handler.metrics()->bucket(0)->period_length() == 4);

    json j;
    bgp_handler.metrics()->bucket(0)->to_json(j);

    CHECK(event_data.num_events->value() == 9);

    CHECK(counters.OPEN.value() == 2);
    CHECK(counters.UPDATE.value() == 4);
    CHECK(counters.NOTIFICATION.value() == 0);
    CHECK(counters.KEEPALIVE.value() == 3);
    CHECK(counters.ROUTEREFRESH.value() == 0);
    CHECK(counters.filtered.value() == 0);
    CHECK(counters.total.value() == 9);

}

TEST_CASE("BGP to_prometheus and to_opentelemetry backends", "[pcap][bgp][backends]")
{
    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "tests/fixtures/bgp.pcap");
    stream.config_set("bpf", "");

    visor::Config c;
    c.config_set<uint64_t>("num_periods", 1);
    auto stream_proxy = stream.add_event_proxy(c);
    BgpStreamHandler bgp_handler{"bgp-test", stream_proxy, &c};

    bgp_handler.start();
    stream.start();
    bgp_handler.stop();
    stream.stop();

    std::stringstream prom;
    bgp_handler.metrics()->bucket(0)->to_prometheus(prom, {});
    auto prom_text = prom.str();
    CHECK(prom_text.find("bgp_") != std::string::npos);

    opentelemetry::proto::metrics::v1::ScopeMetrics scope;
    timespec start_ts{}, end_ts{};
    bgp_handler.metrics()->bucket(0)->to_opentelemetry(scope, start_ts, end_ts, {});
    CHECK(scope.metrics_size() > 0);
}
