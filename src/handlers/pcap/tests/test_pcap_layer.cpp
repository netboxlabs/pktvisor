#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_test_visor.hpp>

#include <opentelemetry/proto/metrics/v1/metrics.pb.h>
#include <sstream>

#include "GeoDB.h"
#include "PcapInputStream.h"
#include "PcapStreamHandler.h"

using namespace visor::handler::pcap;
using namespace visor::input::pcap;

TEST_CASE("Parse net (dns) random UDP/TCP tests", "[pcap][net]")
{

    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "tests/fixtures/dns_udp_tcp_random.pcap");
    stream.config_set("bpf", "");
    stream.config_set("host_spec", "192.168.0.0/24");
    stream.parse_host_spec();

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    PcapStreamHandler pcap_handler{"pcap-handler-test", stream_proxy, &c};

    pcap_handler.start();
    stream.start();
    stream.stop();
    pcap_handler.stop();

    auto counters = pcap_handler.metrics()->bucket(0)->counters();

    CHECK(pcap_handler.metrics()->start_tstamp().tv_sec == 1614874231);
    CHECK(pcap_handler.metrics()->start_tstamp().tv_nsec == 565771000);

    // confirmed with wireshark
    CHECK(counters.pcap_TCP_reassembly_errors.value() == 0);
    CHECK(counters.pcap_os_drop.value() == 0);
    CHECK(counters.pcap_if_drop.value() == 0);
}

TEST_CASE("pcap to_prometheus and to_opentelemetry backends", "[pcap][pcap][backends]")
{
    visor::input::pcap::PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "tests/fixtures/dns_udp_tcp_random.pcap");
    stream.config_set("bpf", "");

    visor::Config c;
    c.config_set<uint64_t>("num_periods", 1);
    auto stream_proxy = stream.add_event_proxy(c);
    visor::handler::pcap::PcapStreamHandler handler{"pcap-test", stream_proxy, &c};

    handler.start();
    stream.start();
    handler.stop();
    stream.stop();

    std::stringstream prom;
    handler.metrics()->bucket(0)->to_prometheus(prom, {});
    CHECK(prom.str().find("pcap_") != std::string::npos);

    opentelemetry::proto::metrics::v1::ScopeMetrics scope;
    timespec start_ts{}, end_ts{};
    handler.metrics()->bucket(0)->to_opentelemetry(scope, start_ts, end_ts, {});
    CHECK(scope.metrics_size() > 0);
}
