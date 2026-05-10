#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_test_visor.hpp>

#include <opentelemetry/proto/metrics/v1/metrics.pb.h>
#include <sstream>

#include "DhcpStreamHandler.h"
#include "PcapInputStream.h"

using namespace visor::handler::dhcp;
using namespace visor::input::pcap;
using namespace nlohmann;

TEST_CASE("Parse DHCP tests", "[pcap][dhcp]")
{
    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "tests/fixtures/dhcp-flow.pcap");
    stream.config_set("bpf", "");

    visor::Config c;
    c.config_set<uint64_t>("num_periods", 1);
    auto stream_proxy = stream.add_event_proxy(c);
    DhcpStreamHandler dhcp_handler{"dhcp-test", stream_proxy, &c};

    dhcp_handler.start();
    stream.start();
    dhcp_handler.stop();
    stream.stop();

    auto counters = dhcp_handler.metrics()->bucket(0)->counters();
    auto event_data = dhcp_handler.metrics()->bucket(0)->event_data_locked();

    CHECK(dhcp_handler.metrics()->current_periods() == 1);
    CHECK(dhcp_handler.metrics()->start_tstamp().tv_sec == 1634851620);
    CHECK(dhcp_handler.metrics()->start_tstamp().tv_nsec == 703423000);

    CHECK(dhcp_handler.metrics()->end_tstamp().tv_sec == 1634851650);
    CHECK(dhcp_handler.metrics()->end_tstamp().tv_nsec == 401994000);

    CHECK(dhcp_handler.metrics()->bucket(0)->period_length() == 30);

    json j;
    dhcp_handler.metrics()->bucket(0)->to_json(j);

    CHECK(event_data.num_events->value() == 8);
    CHECK(counters.filtered.value() == 0);
    CHECK(counters.DISCOVER.value() == 1);
    CHECK(counters.OFFER.value() == 1);
    CHECK(counters.REQUEST.value() == 3);
    CHECK(counters.ACK.value() == 3);

    CHECK(j["top_clients"][0]["name"] == "78:4f:43:78:19:bc/Shannons-MBP/192.168.2.205");
    CHECK(j["top_clients"][1]["name"] == "32:47:73:53:0e:3d/Zenfone-8/192.168.2.248");
    CHECK(j["top_servers"][0]["name"] == "b8:27:eb:0c:b3:e2/192.168.2.1");
}

TEST_CASE("Parse DHCP V6 tests", "[pcap][dhcp]")
{
    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "tests/fixtures/dhcpv6.pcap");
    stream.config_set("bpf", "");

    visor::Config c;
    c.config_set<uint64_t>("num_periods", 1);
    auto stream_proxy = stream.add_event_proxy(c);
    DhcpStreamHandler dhcp_handler{"dhcp-test", stream_proxy, &c};

    dhcp_handler.start();
    stream.start();
    dhcp_handler.stop();
    stream.stop();

    auto counters = dhcp_handler.metrics()->bucket(0)->counters();
    auto event_data = dhcp_handler.metrics()->bucket(0)->event_data_locked();

    CHECK(dhcp_handler.metrics()->current_periods() == 1);
    CHECK(dhcp_handler.metrics()->start_tstamp().tv_sec == 1420235556);
    CHECK(dhcp_handler.metrics()->start_tstamp().tv_nsec == 799722000);

    CHECK(dhcp_handler.metrics()->end_tstamp().tv_sec == 1420235569);
    CHECK(dhcp_handler.metrics()->end_tstamp().tv_nsec == 893300000);

    CHECK(dhcp_handler.metrics()->bucket(0)->period_length() == 13);

    json j;
    dhcp_handler.metrics()->bucket(0)->to_json(j);

    CHECK(event_data.num_events->value() == 6);
    CHECK(counters.filtered.value() == 0);
    CHECK(counters.SOLICIT.value() == 1);
    CHECK(counters.ADVERTISE.value() == 1);
    CHECK(counters.REQUESTV6.value() == 1);
    CHECK(counters.REPLY.value() == 2);

    CHECK(j["top_clients"][0]["name"] == nullptr);
    CHECK(j["top_servers"][0]["name"] == "08:00:27:d4:10:bb/fe80::a00:27ff:fed4:10bb");
}

TEST_CASE("DHCP to_prometheus and to_opentelemetry backends", "[pcap][dhcp][backends]")
{
    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "tests/fixtures/dhcp-flow.pcap");
    stream.config_set("bpf", "");

    visor::Config c;
    c.config_set<uint64_t>("num_periods", 1);
    auto stream_proxy = stream.add_event_proxy(c);
    DhcpStreamHandler dhcp_handler{"dhcp-test", stream_proxy, &c};

    dhcp_handler.start();
    stream.start();
    dhcp_handler.stop();
    stream.stop();

    std::stringstream prom;
    dhcp_handler.metrics()->bucket(0)->to_prometheus(prom, {});
    CHECK(prom.str().find("dhcp_") != std::string::npos);

    opentelemetry::proto::metrics::v1::ScopeMetrics scope;
    timespec start_ts{}, end_ts{};
    dhcp_handler.metrics()->bucket(0)->to_opentelemetry(scope, start_ts, end_ts, {});
    CHECK(scope.metrics_size() > 0);
}
