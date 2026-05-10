#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers.hpp>
#include <catch2/catch_test_visor.hpp>

#include <opentelemetry/proto/metrics/v1/metrics.pb.h>
#include <sstream>

#include "DnsStreamHandler.h"
#include "DnstapInputStream.h"
#include "GeoDB.h"
#include "PcapInputStream.h"
#include "NetStreamHandler.h"

using namespace visor::handler::net::v2;
using namespace visor::handler::dns::v2;
using namespace visor::input::pcap;

TEST_CASE("Parse net (dns) UDP IPv4 tests", "[pcap][ipv4][udp][net]")
{

    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "tests/fixtures/dns_ipv4_udp.pcap");
    stream.config_set("bpf", std::string());

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    NetStreamHandler net_handler{"net-test", stream_proxy, &c};

    net_handler.start();
    stream.start();
    net_handler.stop();
    stream.stop();

    auto counters = net_handler.metrics()->bucket(0)->counters(NetworkPacketDirection::unknown);
    auto event_data = net_handler.metrics()->bucket(0)->event_data_locked();

    CHECK(net_handler.metrics()->current_periods() == 1);
    CHECK(net_handler.metrics()->start_tstamp().tv_sec == 1567706414);
    CHECK(net_handler.metrics()->start_tstamp().tv_nsec == 599964000);

    CHECK(net_handler.metrics()->end_tstamp().tv_sec == 1567706420);
    CHECK(net_handler.metrics()->end_tstamp().tv_nsec == 602866000);

    CHECK(net_handler.metrics()->bucket(0)->period_length() == 6);

    CHECK(event_data.num_events->value() == 140);
    CHECK(counters.UDP.value() == 140);
    CHECK(counters.IPv4.value() == 140);
    CHECK(counters.IPv6.value() == 0);
}

TEST_CASE("Parse net (dns) TCP IPv4 tests", "[pcap][ipv4][tcp][net]")
{
    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "tests/fixtures/dns_ipv4_tcp.pcap");
    stream.config_set("bpf", "");

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    NetStreamHandler net_handler{"net-test", stream_proxy, &c};

    net_handler.start();
    stream.start();
    net_handler.stop();
    stream.stop();

    auto counters = net_handler.metrics()->bucket(0)->counters(NetworkPacketDirection::unknown);
    auto event_data = net_handler.metrics()->bucket(0)->event_data_locked();

    CHECK(net_handler.metrics()->start_tstamp().tv_sec == 1567706433);
    CHECK(net_handler.metrics()->start_tstamp().tv_nsec == 56403000);
    CHECK(event_data.num_events->value() == 2100);
    CHECK(counters.TCP.value() == 2100);
    CHECK(counters.TCP_SYN.value() == 420);
    CHECK(counters.IPv4.value() == 2100);
    CHECK(counters.IPv6.value() == 0);
}

TEST_CASE("Parse net (dns) UDP IPv6 tests", "[pcap][ipv6][udp][net]")
{

    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "tests/fixtures/dns_ipv6_udp.pcap");
    stream.config_set("bpf", "");

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    NetStreamHandler net_handler{"net-test", stream_proxy, &c};

    net_handler.start();
    stream.start();
    stream.stop();
    net_handler.stop();

    auto counters = net_handler.metrics()->bucket(0)->counters(NetworkPacketDirection::unknown);
    auto event_data = net_handler.metrics()->bucket(0)->event_data_locked();

    CHECK(net_handler.metrics()->start_tstamp().tv_sec == 1567706365);
    CHECK(net_handler.metrics()->start_tstamp().tv_nsec == 513271000);
    CHECK(event_data.num_events->value() == 140);
    CHECK(counters.UDP.value() == 140);
    CHECK(counters.IPv4.value() == 0);
    CHECK(counters.IPv6.value() == 140);
}

TEST_CASE("Parse net (dns) TCP IPv6 tests", "[pcap][ipv6][tcp][net]")
{

    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "tests/fixtures/dns_ipv6_tcp.pcap");
    stream.config_set("bpf", "");

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    NetStreamHandler net_handler{"net-test", stream_proxy, &c};

    net_handler.start();
    stream.start();
    stream.stop();
    net_handler.stop();

    auto counters = net_handler.metrics()->bucket(0)->counters(NetworkPacketDirection::unknown);
    auto event_data = net_handler.metrics()->bucket(0)->event_data_locked();

    CHECK(net_handler.metrics()->start_tstamp().tv_sec == 1567706308);
    CHECK(net_handler.metrics()->start_tstamp().tv_nsec == 958184000);
    CHECK(event_data.num_events->value() == 1800);
    CHECK(counters.TCP.value() == 1800);
    CHECK(counters.TCP_SYN.value() == 360);
    CHECK(counters.IPv4.value() == 0);
    CHECK(counters.IPv6.value() == 1800);
}

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
    NetStreamHandler net_handler{"net-test", stream_proxy, &c};

    net_handler.start();
    stream.start();
    stream.stop();
    net_handler.stop();

    auto counters = net_handler.metrics()->bucket(0)->counters(NetworkPacketDirection::in);
    counters += net_handler.metrics()->bucket(0)->counters(NetworkPacketDirection::out);
    auto event_data = net_handler.metrics()->bucket(0)->event_data_locked();

    CHECK(net_handler.metrics()->start_tstamp().tv_sec == 1614874231);
    CHECK(net_handler.metrics()->start_tstamp().tv_nsec == 565771000);

    // confirmed with wireshark
    CHECK(event_data.num_events->value() == 16147);
    CHECK(event_data.num_samples->value() == 16147);
    CHECK(counters.TCP.value() == 13176);
    CHECK(counters.TCP_SYN.value() == 2846);
    CHECK(counters.UDP.value() == 2971);
    CHECK(counters.IPv4.value() == 16147);
    CHECK(counters.IPv6.value() == 0);
    CHECK(counters.OtherL4.value() == 0);
    CHECK(counters.total.value() == 16147);


    nlohmann::json j;
    net_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["out"]["cardinality"]["ips"] == 1);
    CHECK(j["out"]["cardinality"]["ips"] == 1);
    CHECK(j["out"]["top_ipv4_packets"][0]["estimate"] == 9499);
    CHECK(j["out"]["top_ipv4_packets"][0]["name"] == "8.8.8.8");
    CHECK(j["in"]["payload_size_bytes"]["p50"] >= 66);
}

TEST_CASE("Parse net (dns) with DNS filter only_qname_suffix", "[pcap][dns][net]")
{

    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "tests/fixtures/dns_udp_mixed_rcode.pcap");
    stream.config_set("bpf", "");
    stream.config_set("host_spec", "192.168.0.0/24");
    stream.parse_host_spec();

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    DnsStreamHandler dns_handler{"dns-test", stream_proxy, &c};
    dns_handler.set_event_proxy(stream.create_event_proxy(c));
    NetStreamHandler net_handler{"net-test", dns_handler.get_event_proxy(), &c};

    dns_handler.config_set<visor::Configurable::StringList>("only_qname_suffix", {"google.com"});

    net_handler.start();
    dns_handler.start();
    stream.start();
    stream.stop();
    dns_handler.stop();
    net_handler.stop();

    auto dns_counters = dns_handler.metrics()->bucket(0)->counters(TransactionDirection::out);
    CHECK(dns_counters.UDP.value() == 4);
    CHECK(dns_counters.IPv4.value() == 4);

    auto net_counters = net_handler.metrics()->bucket(0)->counters(NetworkPacketDirection::in);
    auto event_data = net_handler.metrics()->bucket(0)->event_data_locked();

    CHECK(event_data.num_events->value() == 17);
    CHECK(net_counters.TCP.value() == 0);
    CHECK(net_counters.UDP.value() == 13);
    CHECK(net_counters.IPv4.value() == 13);

    nlohmann::json j;
    net_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["in"]["cardinality"]["ips"] == 8);
    CHECK(j["in"]["top_ipv4_packets"][0]["estimate"] == 3);
    CHECK(j["in"]["top_ipv4_packets"][0]["name"] == "192.168.0.54");
}

TEST_CASE("Parse DNS with NET filter geo", "[pcap][dns][net]")
{
    CHECK_NOTHROW(visor::geo::GeoIP().enable("tests/fixtures/GeoIP2-City-Test.mmdb"));
    CHECK_NOTHROW(visor::geo::GeoASN().enable("tests/fixtures/GeoIP2-ISP-Test.mmdb"));

    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "tests/fixtures/dns_udp_mixed_rcode.pcap");
    stream.config_set("bpf", "");
    stream.config_set("host_spec", "192.168.0.0/24");
    stream.parse_host_spec();

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    NetStreamHandler net_handler{"net-test", stream_proxy, &c};
    net_handler.set_event_proxy(stream.create_event_proxy(c));
    DnsStreamHandler dns_handler{"dns-test", net_handler.get_event_proxy(), &c};

    net_handler.config_set<bool>("geoloc_notfound", true);

    dns_handler.start();
    net_handler.start();
    stream.start();
    stream.stop();
    net_handler.stop();
    dns_handler.stop();

    auto net_counters = net_handler.metrics()->bucket(0)->counters(NetworkPacketDirection::in);
    auto event_data = net_handler.metrics()->bucket(0)->event_data_locked();

    CHECK(event_data.num_events->value() == 24);
    CHECK(net_counters.TCP.value() == 0);
    CHECK(net_counters.UDP.value() == 15);
    CHECK(net_counters.IPv4.value() == 15);

    auto dns_counters = dns_handler.metrics()->bucket(0)->counters(TransactionDirection::out);
    CHECK(dns_counters.UDP.value() == 9);
    CHECK(dns_counters.IPv4.value() == 9);
}

TEST_CASE("Parse DNS TCP data with NET filter geo", "[pcap][dns][net]")
{
    CHECK_NOTHROW(visor::geo::GeoIP().enable("tests/fixtures/GeoIP2-City-Test.mmdb"));
    CHECK_NOTHROW(visor::geo::GeoASN().enable("tests/fixtures/GeoIP2-ISP-Test.mmdb"));

    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "tests/fixtures/dns_ipv4_tcp.pcap");
    stream.config_set("bpf", "");
    stream.parse_host_spec();

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    NetStreamHandler net_handler{"net-test", stream_proxy, &c};
    net_handler.set_event_proxy(stream.create_event_proxy(c));
    DnsStreamHandler dns_handler{"dns-test", net_handler.get_event_proxy(), &c};
    dns_handler.set_event_proxy(stream.create_event_proxy(c));
    NetStreamHandler net_handler_2{"net-test-2", dns_handler.get_event_proxy(), &c};
    net_handler_2.set_event_proxy(stream.create_event_proxy(c));
    DnsStreamHandler dns_handler_2{"dns-test-2", net_handler_2.get_event_proxy(), &c};

    dns_handler_2.start();
    net_handler_2.start();
    dns_handler.start();
    net_handler.start();
    stream.start();
    stream.stop();
    net_handler.stop();
    dns_handler.stop();
    net_handler_2.stop();
    dns_handler_2.stop();

    auto net_counters = net_handler.metrics()->bucket(0)->counters(NetworkPacketDirection::unknown);
    auto event_data = net_handler.metrics()->bucket(0)->event_data_locked();

    CHECK(event_data.num_events->value() == 2100);
    CHECK(net_counters.TCP.value() == 2100);
    CHECK(net_counters.IPv4.value() == 2100);

    auto dns_counters = dns_handler.metrics()->bucket(0)->counters(TransactionDirection::unknown);
    CHECK(dns_counters.TCP.value() == 210);
    CHECK(dns_counters.IPv4.value() == 210);

    auto net_counters_2 = net_handler_2.metrics()->bucket(0)->counters(NetworkPacketDirection::unknown);
    CHECK(net_counters_2.TCP.value() == 420);
    CHECK(net_counters_2.IPv4.value() == 420);

    auto dns_counters_2 = dns_handler_2.metrics()->bucket(0)->counters(TransactionDirection::unknown);
    CHECK(dns_counters_2.TCP.value() == 210);
    CHECK(dns_counters_2.IPv4.value() == 210);
}

TEST_CASE("Parse net dnstap stream", "[dnstap][net][!mayfail]")
{

    DnstapInputStream stream{"dnstap-test"};
    stream.config_set("dnstap_file", "inputs/dnstap/tests/fixtures/fixture.dnstap");
    stream.config_set<visor::Configurable::StringList>("only_hosts", {"192.168.0.0/24", "2001:db8::/48"});
    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    NetStreamHandler net_handler{"dns-test", stream_proxy, &c};

    net_handler.start();
    stream.start();
    stream.stop();
    net_handler.stop();

    auto counters = net_handler.metrics()->bucket(0)->counters(NetworkPacketDirection::in);
    auto event_data = net_handler.metrics()->bucket(0)->event_data_locked();

    // confirmed with wireshark
    CHECK(event_data.num_events->value() == 153);
    CHECK(event_data.num_samples->value() == 153);
    CHECK(counters.TCP.value() == 0);
    CHECK(counters.TCP_SYN.value() == 0);
    CHECK(counters.UDP.value() == 79);
    CHECK(counters.IPv4.value() == 79);
    CHECK(counters.IPv6.value() == 0);
    CHECK(counters.total.value() == 79);

    nlohmann::json j;
    net_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["in"]["cardinality"]["ips"] == 2);
    CHECK(j["in"]["top_ipv4_packets"][0]["estimate"] == 79);
    CHECK(j["in"]["top_ipv4_packets"][0]["name"] == "192.168.0.54");
    CHECK(j["in"]["payload_size_bytes"]["p50"] == 89);
}

TEST_CASE("Net groups", "[pcap][net]")
{

    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "tests/fixtures/dns_udp_tcp_random.pcap");
    stream.config_set("bpf", "");
    stream.config_set("host_spec", "192.168.0.0/24");
    stream.parse_host_spec();

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    NetStreamHandler net_handler{"net-test", stream_proxy, &c};

    SECTION("disable cardinality and counters")
    {
        net_handler.config_set<visor::Configurable::StringList>("disable", {"cardinality", "counters"});

        net_handler.start();
        stream.start();
        stream.stop();
        net_handler.stop();

        auto counters = net_handler.metrics()->bucket(0)->counters(NetworkPacketDirection::in);
        auto event_data = net_handler.metrics()->bucket(0)->event_data_locked();

        CHECK(net_handler.metrics()->start_tstamp().tv_sec == 1614874231);
        CHECK(net_handler.metrics()->start_tstamp().tv_nsec == 565771000);

        CHECK(event_data.num_events->value() == 16147);
        CHECK(event_data.num_samples->value() == 16147);
        CHECK(counters.TCP.value() == 0);
        CHECK(counters.TCP_SYN.value() == 0);
        CHECK(counters.UDP.value() == 0);
        CHECK(counters.IPv4.value() == 0);
        CHECK(counters.IPv6.value() == 0);
        CHECK(counters.OtherL4.value() == 0);
        CHECK(counters.total.value() == 0);

        nlohmann::json j;
        net_handler.metrics()->bucket(0)->to_json(j);

        CHECK(j["in"]["cardinality"]["dst_ips_out"] == nullptr);
        CHECK(j["in"]["cardinality"]["src_ips_in"] == nullptr);
        CHECK(j["in"]["top_ipv4_packets"][0]["estimate"] == 6648);
        CHECK(j["in"]["top_ipv4_packets"][0]["name"] == "8.8.8.8");
    }

    SECTION("disable Top ips and Top geo")
    {
        net_handler.config_set<visor::Configurable::StringList>("disable", {"top_ips", "top_geo"});

        net_handler.start();
        stream.start();
        stream.stop();
        net_handler.stop();

        auto counters = net_handler.metrics()->bucket(0)->counters(NetworkPacketDirection::in);
        counters += net_handler.metrics()->bucket(0)->counters(NetworkPacketDirection::out);
        auto event_data = net_handler.metrics()->bucket(0)->event_data_locked();

        CHECK(net_handler.metrics()->start_tstamp().tv_sec == 1614874231);
        CHECK(net_handler.metrics()->start_tstamp().tv_nsec == 565771000);

        // confirmed with wireshark
        CHECK(event_data.num_events->value() == 16147);
        CHECK(event_data.num_samples->value() == 16147);
        CHECK(counters.TCP.value() == 13176);
        CHECK(counters.UDP.value() == 2971);
        CHECK(counters.IPv4.value() == 16147);
        CHECK(counters.IPv6.value() == 0);
        CHECK(counters.OtherL4.value() == 0);
        CHECK(counters.total.value() == 16147);

        nlohmann::json j;
        net_handler.metrics()->bucket(0)->to_json(j);

        CHECK(j["in"]["cardinality"]["ips"] == 1);
        CHECK(j["in"]["top_ipv4"][0]["estimate"] == nullptr);
        CHECK(j["in"]["top_ipv4"][0]["name"] == nullptr);
    }

    SECTION("disable invalid dns group")
    {
        net_handler.config_set<visor::Configurable::StringList>("disable", {"top_ips", "rates"});
        REQUIRE_THROWS_WITH(net_handler.start(), "rates is an invalid/unsupported metric group. The valid groups are: all, cardinality, counters, quantiles, top_geo, top_ips");
    }

    SECTION("enable invalid dns group")
    {
        net_handler.config_set<visor::Configurable::StringList>("enable", {"top_ips", "rates"});
        REQUIRE_THROWS_WITH(net_handler.start(), "rates is an invalid/unsupported metric group. The valid groups are: all, cardinality, counters, quantiles, top_geo, top_ips");
    }
}

TEST_CASE("Net geolocation filtering", "[pcap][net][geo]")
{
    CHECK_NOTHROW(visor::geo::GeoIP().enable("tests/fixtures/GeoIP2-City-Test.mmdb"));
    CHECK_NOTHROW(visor::geo::GeoASN().enable("tests/fixtures/GeoIP2-ISP-Test.mmdb"));

    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "tests/fixtures/dns_udp_mixed_rcode.pcap");
    stream.config_set("bpf", "");
    stream.config_set("host_spec", "192.168.0.0/24");
    stream.parse_host_spec();

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    NetStreamHandler net_handler{"net-test", stream_proxy, &c};

    SECTION("Enable geoloc not found")
    {
        net_handler.config_set<bool>("geoloc_notfound", true);

        net_handler.start();
        stream.start();
        stream.stop();
        net_handler.stop();

        nlohmann::json j;
        net_handler.metrics()->bucket(0)->to_json(j);
        CHECK(j["in"]["top_ipv4_packets"][0]["estimate"] == 3);
        CHECK(j["in"]["top_ipv4_packets"][0]["name"] == "192.168.0.54");
        CHECK(j["in"]["top_geo_loc_packets"][0]["estimate"] == 15);
        CHECK(j["in"]["top_geo_loc_packets"][0]["name"] == "Unknown");
    }

    SECTION("Enable asn not found")
    {
        net_handler.config_set<bool>("asn_notfound", true);

        net_handler.start();
        stream.start();
        stream.stop();
        net_handler.stop();

        nlohmann::json j;
        net_handler.metrics()->bucket(0)->to_json(j);
        CHECK(j["in"]["top_ipv4_packets"][0]["estimate"] == 3);
        CHECK(j["in"]["top_ipv4_packets"][0]["name"] == "192.168.0.54");
        CHECK(j["in"]["top_asn_packets"][0]["estimate"] == 15);
        CHECK(j["in"]["top_asn_packets"][0]["name"] == "Unknown");
    }

    SECTION("Enable geoloc and asn not found")
    {
        net_handler.config_set<bool>("geoloc_notfound", true);
        net_handler.config_set<bool>("asn_notfound", true);

        net_handler.start();
        stream.start();
        stream.stop();
        net_handler.stop();

        nlohmann::json j;
        net_handler.metrics()->bucket(0)->to_json(j);
        CHECK(j["in"]["top_ipv4_packets"][0]["estimate"] == 3);
        CHECK(j["in"]["top_ipv4_packets"][0]["name"] == "192.168.0.54");
        CHECK(j["in"]["top_geo_loc_packets"][0]["estimate"] == 15);
        CHECK(j["in"]["top_geo_loc_packets"][0]["name"] == "Unknown");
        CHECK(j["in"]["top_asn_packets"][0]["estimate"] == 15);
        CHECK(j["in"]["top_asn_packets"][0]["name"] == "Unknown");
    }

    SECTION("Enable geoloc prefix")
    {
        net_handler.config_set<visor::Configurable::StringList>("only_geoloc_prefix", {"NA/United States"});

        net_handler.start();
        stream.start();
        stream.stop();
        net_handler.stop();

        nlohmann::json j;
        net_handler.metrics()->bucket(0)->to_json(j);
        CHECK(j["filtered_packets"] == 24);
        CHECK(j["top_geo_loc_packets"][0]["name"] == nullptr);
    }

    SECTION("Enable asn number")
    {
        net_handler.config_set<visor::Configurable::StringList>("only_asn_number", {"16509", "22131"});

        net_handler.start();
        stream.start();
        stream.stop();
        net_handler.stop();

        nlohmann::json j;
        net_handler.metrics()->bucket(0)->to_json(j);
        CHECK(j["filtered_packets"] == 24);
        CHECK(j["top_asn_packets"][0]["name"] == nullptr);
    }

    SECTION("Invalid asn number")
    {
        net_handler.config_set<visor::Configurable::StringList>("only_asn_number", {"16509/Amazon"});
        REQUIRE_THROWS_WITH(net_handler.start(), "NetStreamHandler: only_asn_number filter contained an invalid/unsupported value: 16509/Amazon");
    }
}

TEST_CASE("Net invalid config", "[net][filter][config]")
{
    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "tests/fixtures/dns_udp_mixed_rcode.pcap");

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    NetStreamHandler net_handler{"net-test", stream_proxy, &c};
    net_handler.config_set<bool>("invalid_config", true);
    REQUIRE_THROWS_WITH(net_handler.start(), "invalid_config is an invalid/unsupported config or filter. The valid configs/filters are: geoloc_notfound, asn_notfound, only_geoloc_prefix, only_asn_number, recorded_stream, deep_sample_rate, num_periods, topn_count, topn_percentile_threshold");
}

TEST_CASE("netv2 to_prometheus and to_opentelemetry backends", "[pcap][netv2][backends]")
{
    visor::input::pcap::PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "tests/fixtures/dns_ipv4_udp.pcap");
    stream.config_set("bpf", "");

    visor::Config c;
    c.config_set<uint64_t>("num_periods", 1);
    auto stream_proxy = stream.add_event_proxy(c);
    visor::handler::net::v2::NetStreamHandler handler{"netv2-test", stream_proxy, &c};

    handler.start();
    stream.start();
    handler.stop();
    stream.stop();

    std::stringstream prom;
    handler.metrics()->bucket(0)->to_prometheus(prom, {});
    CHECK(prom.str().find("net_") != std::string::npos);

    opentelemetry::proto::metrics::v1::ScopeMetrics scope;
    timespec start_ts{}, end_ts{};
    handler.metrics()->bucket(0)->to_opentelemetry(scope, start_ts, end_ts, {});
    CHECK(scope.metrics_size() > 0);
}
