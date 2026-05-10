#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers.hpp>
#include <catch2/catch_test_visor.hpp>

#include <opentelemetry/proto/metrics/v1/metrics.pb.h>
#include <sstream>

#include "DnsStreamHandler.h"
#include "GeoDB.h"
#include "PcapInputStream.h"
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wzero-as-null-pointer-constant"
#pragma clang diagnostic ignored "-Wc99-extensions"
#pragma clang diagnostic ignored "-Wrange-loop-analysis"
#endif
#include <pcapplusplus/DnsLayer.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/PcapFileDevice.h>
#include <pcapplusplus/ProtocolType.h>
#include <pcapplusplus/UdpLayer.h>
#ifdef __GNUC__
#pragma GCC diagnostic pop
#pragma GCC diagnostic ignored "-Wold-style-cast"
#endif

using namespace visor::handler::dns::v2;
using namespace visor::input::pcap;
using namespace nlohmann;

TEST_CASE("Ensure we use only pktvisor DnsLayer", "[pcap][ipv4][dns]")
{

    pcpp::IFileReaderDevice *reader = pcpp::IFileReaderDevice::getReader("tests/fixtures/dns_udp_tcp_random.pcap");

    CHECK(reader->open());

    pcpp::RawPacket rawPacket;

    while (reader->getNextPacket(rawPacket)) {
        pcpp::Packet dnsRequest(&rawPacket, pcpp::OsiModelTransportLayer);
        if (dnsRequest.isPacketOfType(pcpp::UDP)) {
            CHECK(dnsRequest.getLayerOfType<pcpp::UdpLayer>() != nullptr);
        } else {
            CHECK(dnsRequest.getLayerOfType<pcpp::TcpLayer>() != nullptr);
        }
        // we do NOT expect to see pcpp::DnsLayer or DNS protocol yet
        CHECK(dnsRequest.getLayerOfType<pcpp::DnsLayer>() == nullptr);
        CHECK(dnsRequest.getLayerOfType<pcpp::DnsOverTcpLayer>() == nullptr);
        CHECK(dnsRequest.isPacketOfType(pcpp::DNS) == false);
    }

    reader->close();
    delete reader;
}

TEST_CASE("Parse DNS UDP IPv4 tests", "[pcap][ipv4][udp][dns]")
{

    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "tests/fixtures/dns_ipv4_udp.pcap");
    stream.config_set("bpf", "");

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    DnsStreamHandler dns_handler{"dns-test", stream_proxy, &c};

    dns_handler.start();
    stream.start();
    dns_handler.stop();
    stream.stop();

    auto counters = dns_handler.metrics()->bucket(0)->counters(TransactionDirection::unknown);
    auto event_data = dns_handler.metrics()->bucket(0)->event_data_locked();

    CHECK(dns_handler.metrics()->current_periods() == 1);
    CHECK(dns_handler.metrics()->start_tstamp().tv_sec == 1567706414);
    CHECK(dns_handler.metrics()->start_tstamp().tv_nsec == 599964000);

    CHECK(dns_handler.metrics()->end_tstamp().tv_sec == 1567706420);
    CHECK(dns_handler.metrics()->end_tstamp().tv_nsec == 602866000);

    CHECK(dns_handler.metrics()->bucket(0)->period_length() == 6);

    json j;
    dns_handler.metrics()->bucket(0)->to_json(j);

    CHECK(dns_handler.metrics()->current_periods() == 1);
    CHECK(event_data.num_events->value() == 140);
    CHECK(counters.UDP.value() == 70);
    CHECK(counters.IPv4.value() == 70);
    CHECK(counters.IPv6.value() == 0);
    CHECK(counters.xacts.value() == 70);
    CHECK(j["unknown"]["top_qname2_xacts"][0]["name"] == ".test.com");
    CHECK(j["unknown"]["top_qname2_xacts"][0]["estimate"] == 70);
}

TEST_CASE("Parse DNS TCP IPv4 tests", "[pcap][ipv4][tcp][dns]")
{
    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "tests/fixtures/dns_ipv4_tcp.pcap");
    stream.config_set("bpf", "");

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    DnsStreamHandler dns_handler{"dns-test", stream_proxy, &c};

    dns_handler.start();
    stream.start();
    dns_handler.stop();
    stream.stop();

    auto counters = dns_handler.metrics()->bucket(0)->counters(TransactionDirection::unknown);
    auto event_data = dns_handler.metrics()->bucket(0)->event_data_locked();
    json j;
    dns_handler.metrics()->bucket(0)->to_json(j);

    CHECK(event_data.num_events->value() == 420);
    CHECK(counters.TCP.value() == 210);
    CHECK(counters.IPv4.value() == 210);
    CHECK(counters.IPv6.value() == 0);
    CHECK(counters.xacts.value() == 210);
    CHECK(counters.timeout.value() == 0);
    CHECK(counters.orphan.value() == 0);
    CHECK(j["unknown"]["top_qname2_xacts"][0]["name"] == ".test.com");
    CHECK(j["unknown"]["top_qname2_xacts"][0]["estimate"] == 210);
}

TEST_CASE("Parse DNS TCP tests with limit", "[pcap][ipv4][tcp][dns]")
{
    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "tests/fixtures/dns_ipv4_tcp.pcap");
    stream.config_set("bpf", "");
    stream.config_set<uint64_t>("tcp_packet_reassembly_cache_limit", 10);

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    DnsStreamHandler dns_handler{"dns-test", stream_proxy, &c};

    dns_handler.start();
    stream.start();
    dns_handler.stop();
    stream.stop();

    auto counters = dns_handler.metrics()->bucket(0)->counters(TransactionDirection::unknown);
    auto event_data = dns_handler.metrics()->bucket(0)->event_data_locked();
    json j;
    dns_handler.metrics()->bucket(0)->to_json(j);

    CHECK(event_data.num_events->value() == 140);
    CHECK(counters.TCP.value() == 70);
    CHECK(counters.IPv4.value() == 70);
    CHECK(counters.IPv6.value() == 0);
    CHECK(counters.xacts.value() == 70);
    CHECK(counters.timeout.value() == 0);
    CHECK(counters.orphan.value() == 0);
    CHECK(j["unknown"]["top_qname2_xacts"][0]["name"] == ".test.com");
    CHECK(j["unknown"]["top_qname2_xacts"][0]["estimate"] == 70);
}

TEST_CASE("Parse DNS UDP IPv6 tests", "[pcap][ipv6][udp][dns]")
{

    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "tests/fixtures/dns_ipv6_udp.pcap");
    stream.config_set("bpf", "");

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    DnsStreamHandler dns_handler{"dns-test", stream_proxy, &c};

    dns_handler.start();
    stream.start();
    stream.stop();
    dns_handler.stop();

    auto counters = dns_handler.metrics()->bucket(0)->counters(TransactionDirection::unknown);
    auto event_data = dns_handler.metrics()->bucket(0)->event_data_locked();
    json j;
    dns_handler.metrics()->bucket(0)->to_json(j);

    CHECK(event_data.num_events->value() == 140);
    CHECK(counters.UDP.value() == 70);
    CHECK(counters.IPv4.value() == 0);
    CHECK(counters.IPv6.value() == 70);
    CHECK(counters.xacts.value() == 70);
    CHECK(counters.timeout.value() == 0);
    CHECK(counters.orphan.value() == 0);
    CHECK(j["unknown"]["top_qname2_xacts"][0]["name"] == ".test.com");
    CHECK(j["unknown"]["top_qname2_xacts"][0]["estimate"] == 70);
}

TEST_CASE("Parse DNS TCP IPv6 tests", "[pcap][ipv6][tcp][dns]")
{

    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "tests/fixtures/dns_ipv6_tcp.pcap");
    stream.config_set("bpf", "");

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    DnsStreamHandler dns_handler{"dns-test", stream_proxy, &c};

    dns_handler.start();
    stream.start();
    stream.stop();
    dns_handler.stop();

    auto counters = dns_handler.metrics()->bucket(0)->counters(TransactionDirection::unknown);
    auto event_data = dns_handler.metrics()->bucket(0)->event_data_locked();
    json j;
    dns_handler.metrics()->bucket(0)->to_json(j);

    CHECK(event_data.num_events->value() == 360);
    CHECK(counters.TCP.value() == 180);
    CHECK(counters.IPv4.value() == 0);
    CHECK(counters.IPv6.value() == 180);
    CHECK(counters.xacts.value() == 180);
    CHECK(counters.timeout.value() == 0);
    CHECK(counters.orphan.value() == 0);
    CHECK(j["unknown"]["top_qname2_xacts"][0]["name"] == ".test.com");
    CHECK(j["unknown"]["top_qname2_xacts"][0]["estimate"] == 180);
}

TEST_CASE("Parse DNS random UDP/TCP tests", "[pcap][dns]")
{

    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "tests/fixtures/dns_udp_tcp_random.pcap");
    stream.config_set("bpf", "");
    stream.config_set("host_spec", "192.168.0.0/24");
    stream.parse_host_spec();

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    DnsStreamHandler dns_handler{"dns-test", stream_proxy, &c};
    dns_handler.config_set<visor::Configurable::StringList>("enable", {"top_size", "top_ports"});

    dns_handler.start();
    stream.start();
    stream.stop();
    dns_handler.stop();

    auto counters = dns_handler.metrics()->bucket(0)->counters(TransactionDirection::out);
    auto event_data = dns_handler.metrics()->bucket(0)->event_data_locked();

    // confirmed with wireshark. there are 14 TCP retransmissions which are counted differently in our state machine
    // and account for some minor differences in TCP based stats
    CHECK(event_data.num_events->value() == 5851); // wireshark: 5838
    CHECK(event_data.num_samples->value() == 5851);
    CHECK(counters.TCP.value() == 1440);
    CHECK(counters.UDP.value() == 1481);
    CHECK(counters.IPv4.value() == 2921);
    CHECK(counters.IPv6.value() == 0);
    CHECK(counters.xacts.value() == 2921);
    CHECK(counters.timeout.value() == 0);
    CHECK(counters.orphan.value() == 0);
    CHECK(counters.NODATA.value() == 2254);
    CHECK(counters.RNOERROR.value() == 2921);
    CHECK(counters.RNOERROR.value() == 2921);
    CHECK(counters.NX.value() == 0);
    CHECK(counters.REFUSED.value() == 0);
    CHECK(counters.SRVFAIL.value() == 0);

    nlohmann::json j;
    dns_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["out"]["cardinality"]["qname"] == 2036); // flame was run with 1000 randoms x2 (udp+tcp)

    CHECK(j["out"]["top_qname2_xacts"][0]["name"] == ".test.com");
    CHECK(j["out"]["top_qname2_xacts"][0]["estimate"] == counters.xacts.value());

    CHECK(j["out"]["top_rcode_xacts"][0]["name"] == "NOERROR");
    CHECK(j["out"]["top_rcode_xacts"][0]["estimate"] == counters.RNOERROR.value());

    CHECK(j["out"]["top_udp_ports_xacts"][0]["name"] == "57975");
    CHECK(j["out"]["top_udp_ports_xacts"][0]["estimate"] == 151);

    CHECK(j["out"]["top_response_bytes"][0]["name"] == "82gdxvz5vp.mmyv7ma0jn.rxst40swe.tcbgtnfa.test.com");
    CHECK(j["out"]["top_response_bytes"][0]["estimate"] == 290);

    CHECK(j["out"]["top_qtype_xacts"][0]["name"] == "AAAA");
    CHECK(j["out"]["top_qtype_xacts"][0]["estimate"] == 737);
    CHECK(j["out"]["top_qtype_xacts"][1]["name"] == "CNAME");
    CHECK(j["out"]["top_qtype_xacts"][1]["estimate"] == 412);
    CHECK(j["out"]["top_qtype_xacts"][2]["name"] == "SOA");
    CHECK(j["out"]["top_qtype_xacts"][2]["estimate"] == 397);
    CHECK(j["out"]["top_qtype_xacts"][3]["name"] == "MX");
    CHECK(j["out"]["top_qtype_xacts"][3]["estimate"] == 377);
    CHECK(j["out"]["top_qtype_xacts"][4]["name"] == "A");
    CHECK(j["out"]["top_qtype_xacts"][4]["estimate"] == 358);
    CHECK(j["out"]["top_qtype_xacts"][5]["name"] == "NS");
    CHECK(j["out"]["top_qtype_xacts"][5]["estimate"] == 331);
    CHECK(j["out"]["top_qtype_xacts"][6]["name"] == "TXT");
    CHECK(j["out"]["top_qtype_xacts"][6]["estimate"] == 309);
}

TEST_CASE("DNS Filters: exclude_noerror", "[pcap][dns]")
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

    dns_handler.config_set<bool>("exclude_noerror", true);

    dns_handler.start();
    stream.start();
    stream.stop();
    dns_handler.stop();

    auto counters = dns_handler.metrics()->bucket(0)->counters(TransactionDirection::out);
    REQUIRE(counters.RNOERROR.value() == 0);
    REQUIRE(counters.SRVFAIL.value() == 0);
    REQUIRE(counters.REFUSED.value() == 1);
    REQUIRE(counters.NX.value() == 1);
    REQUIRE(counters.NODATA.value() == 0);
    nlohmann::json j;
    dns_handler.metrics()->bucket(0)->to_json(j);
    REQUIRE(j["filtered_packets"] == 17);
}

TEST_CASE("DNS Filters: only_rcode nx", "[pcap][net]")
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

    dns_handler.config_set<uint64_t>("only_rcode", NXDomain);

    dns_handler.start();
    stream.start();
    stream.stop();
    dns_handler.stop();

    auto counters = dns_handler.metrics()->bucket(0)->counters(TransactionDirection::out);
    REQUIRE(counters.RNOERROR.value() == 0);
    REQUIRE(counters.SRVFAIL.value() == 0);
    REQUIRE(counters.REFUSED.value() == 0);
    REQUIRE(counters.NX.value() == 1);
    REQUIRE(counters.NODATA.value() == 0);
    nlohmann::json j;
    dns_handler.metrics()->bucket(0)->to_json(j);
    REQUIRE(j["filtered_packets"] == 19);
}

TEST_CASE("DNS Filters: only_rcode refused and nx", "[pcap][dns]")
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

    dns_handler.config_set<visor::Configurable::StringList>("only_rcode", {"nxdomain", "5"});

    dns_handler.start();
    stream.start();
    stream.stop();
    dns_handler.stop();

    auto counters = dns_handler.metrics()->bucket(0)->counters(TransactionDirection::out);
    REQUIRE(counters.RNOERROR.value() == 0);
    REQUIRE(counters.SRVFAIL.value() == 0);
    REQUIRE(counters.REFUSED.value() == 1);
    REQUIRE(counters.NX.value() == 1);
    REQUIRE(counters.NODATA.value() == 0);
    nlohmann::json j;
    dns_handler.metrics()->bucket(0)->to_json(j);
    REQUIRE(j["filtered_packets"] == 17);
}
TEST_CASE("DNS Filters: only_qtypes AAAA and TXT", "[pcap][dns]")
{

    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "tests/fixtures/dns_udp_tcp_random.pcap");
    stream.config_set("bpf", "");
    stream.config_set("host_spec", "192.168.0.0/24");
    stream.parse_host_spec();

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    DnsStreamHandler dns_handler{"dns-test", stream_proxy, &c};

    // notice case-insensitive
    dns_handler.config_set<visor::Configurable::StringList>("only_qtype", {"AAAA", "TxT"});
    dns_handler.start();
    stream.start();
    stream.stop();
    dns_handler.stop();

    auto counters = dns_handler.metrics()->bucket(0)->counters(TransactionDirection::out);
    auto event_data = dns_handler.metrics()->bucket(0)->event_data_locked();

    // confirmed with wireshark. there are 14 TCP retransmissions which are counted differently in our state machine
    // and account for some minor differences in TCP based stats
    CHECK(event_data.num_events->value() == 5851); // wireshark: 5838
    CHECK(event_data.num_samples->value() == 5851);
    CHECK(counters.IPv4.value() == 1046);
    CHECK(counters.IPv6.value() == 0);
    CHECK(counters.xacts.value() == 1046);
    CHECK(counters.timeout.value() == 0);
    CHECK(counters.orphan.value() == 0);
    CHECK(counters.NODATA.value() == 737);
    CHECK(counters.RNOERROR.value() == 1046);

    nlohmann::json j;
    dns_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["out"]["top_qtype_xacts"][0]["name"] == "AAAA");
    CHECK(j["out"]["top_qtype_xacts"][0]["estimate"] == 737);
    CHECK(j["out"]["top_qtype_xacts"][1]["name"] == "TXT");
    CHECK(j["out"]["top_qtype_xacts"][1]["estimate"] == 309);
    CHECK(j["out"]["top_qtype_xacts"][2] == nullptr);
}

TEST_CASE("DNS TopN custom size", "[pcap][dns]")
{

    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "tests/fixtures/dns_udp_tcp_random.pcap");
    stream.config_set("bpf", "");
    stream.config_set("host_spec", "192.168.0.0/24");
    stream.parse_host_spec();

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    c.config_set<uint64_t>("topn_count", 3);
    DnsStreamHandler dns_handler{"dns-test", stream_proxy, &c};

    dns_handler.start();
    stream.start();
    stream.stop();
    dns_handler.stop();

    nlohmann::json j;
    dns_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["out"]["cardinality"]["qname"] == 2036); // flame was run with 1000 randoms x2 (udp+tcp)

    CHECK(j["out"]["top_qtype_xacts"][0]["name"] == "AAAA");
    CHECK(j["out"]["top_qtype_xacts"][0]["estimate"] == 737);
    CHECK(j["out"]["top_qtype_xacts"][1]["name"] == "CNAME");
    CHECK(j["out"]["top_qtype_xacts"][1]["estimate"] == 412);
    CHECK(j["out"]["top_qtype_xacts"][2]["name"] == "SOA");
    CHECK(j["out"]["top_qtype_xacts"][2]["estimate"] == 397);
    CHECK(j["out"]["top_qtype_xacts"][3] == nullptr);
}

TEST_CASE("DNS Filters: only_qname", "[pcap][dns]")
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

    // notice, case-insensitive
    dns_handler.config_set<visor::Configurable::StringList>("only_qname", {"play.GooGle.com", "nonexistent.google.com"});
    dns_handler.start();
    stream.start();
    stream.stop();
    dns_handler.stop();

    auto counters = dns_handler.metrics()->bucket(0)->counters(TransactionDirection::out);

    CHECK(counters.UDP.value() == 2);
    CHECK(counters.RNOERROR.value() == 1);
    CHECK(counters.SRVFAIL.value() == 0);
    CHECK(counters.REFUSED.value() == 0);
    CHECK(counters.NX.value() == 1);
    CHECK(counters.NODATA.value() == 1);
    CHECK(counters.xacts.value() == 2);
    CHECK(counters.timeout.value() == 0);
    CHECK(counters.orphan.value() == 3);

    nlohmann::json j;
    dns_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["out"]["top_qname2_xacts"][0]["name"] == ".google.com");
    CHECK(j["out"]["top_qname3_xacts"][0]["name"] != nullptr);
}

TEST_CASE("DNS Filters: only_qname_suffix", "[pcap][dns]")
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

    // notice, case-insensitive
    dns_handler.config_set<visor::Configurable::StringList>("only_qname_suffix", {"GooGle.com"});
    dns_handler.start();
    stream.start();
    stream.stop();
    dns_handler.stop();

    auto counters = dns_handler.metrics()->bucket(0)->counters(TransactionDirection::out);

    CHECK(counters.UDP.value() == 4);
    CHECK(counters.RNOERROR.value() == 3);
    CHECK(counters.SRVFAIL.value() == 0);
    CHECK(counters.REFUSED.value() == 0);
    CHECK(counters.NX.value() == 1);
    CHECK(counters.NODATA.value() == 1);
    CHECK(counters.xacts.value() == 4);
    CHECK(counters.timeout.value() == 0);
    CHECK(counters.orphan.value() == 3);

    nlohmann::json j;
    dns_handler.metrics()->bucket(0)->to_json(j);

    REQUIRE(j["filtered_packets"] == 12);

    CHECK(j["out"]["top_qname2_xacts"][0]["name"].get<std::string>().find("google.com") != std::string::npos);
}

TEST_CASE("DNS Filters: answer_count", "[pcap][dns]")
{

    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "tests/fixtures/dns_udp_mixed_rcode.pcap");
    stream.config_set("bpf", "");
    stream.config_set("host_spec", "192.168.0.0/26");
    stream.parse_host_spec();

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    DnsStreamHandler dns_handler{"dns-test", stream_proxy, &c};
    dns_handler.config_set<uint64_t>("only_rcode", NoError);
    dns_handler.config_set<uint64_t>("answer_count", 0);
    dns_handler.start();
    stream.start();
    stream.stop();
    dns_handler.stop();

    auto counters = dns_handler.metrics()->bucket(0)->counters(TransactionDirection::out);

    CHECK(counters.UDP.value() == 2);
    CHECK(counters.RNOERROR.value() == 2);
    CHECK(counters.SRVFAIL.value() == 0);
    CHECK(counters.REFUSED.value() == 0);
    CHECK(counters.NX.value() == 0);
    CHECK(counters.NODATA.value() == 2);

    nlohmann::json j;
    dns_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["filtered_packets"] == 16);
    CHECK(j["out"]["top_qname2_xacts"][0]["estimate"] == 1);
}

TEST_CASE("DNS Filters: only_dnssec_response", "[pcap][dns]")
{

    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "tests/fixtures/dnssec.pcap");
    stream.config_set("bpf", "");
    stream.config_set("host_spec", "192.168.0.0/24");
    stream.parse_host_spec();

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    DnsStreamHandler dns_handler{"dns-test", stream_proxy, &c};
    dns_handler.config_set<bool>("only_dnssec_response", true);
    dns_handler.start();
    stream.start();
    stream.stop();
    dns_handler.stop();

    auto counters = dns_handler.metrics()->bucket(0)->counters(TransactionDirection::unknown);
    auto event_data = dns_handler.metrics()->bucket(0)->event_data_locked();

    CHECK(event_data.num_events->value() == 14);
    CHECK(event_data.num_samples->value() == 14);
    CHECK(counters.TCP.value() == 0);
    CHECK(counters.UDP.value() == 6);
    CHECK(counters.IPv4.value() == 6);
    CHECK(counters.IPv6.value() == 0);
    CHECK(counters.xacts.value() == 6);
    CHECK(counters.checkDisabled.value() == 0);
    CHECK(counters.authData.value() == 6);
    CHECK(counters.authAnswer.value() == 0);
    CHECK(counters.timeout.value() == 0);
    CHECK(counters.orphan.value() == 0);
    CHECK(counters.RNOERROR.value() == 6);

    nlohmann::json j;
    dns_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["unknown"]["cardinality"]["qname"] == 3);

    CHECK(j["unknown"]["top_qtype_xacts"][0]["name"] == "DNSKEY");
    CHECK(j["unknown"]["top_qtype_xacts"][0]["estimate"] == 3);
    CHECK(j["unknown"]["top_qtype_xacts"][1]["name"] == "DS");
    CHECK(j["unknown"]["top_qtype_xacts"][1]["estimate"] == 2);
    CHECK(j["unknown"]["top_qtype_xacts"][2]["name"] == "A");
    CHECK(j["unknown"]["top_qtype_xacts"][2]["estimate"] == 1);
}

TEST_CASE("DNS Configs: public_suffix_list", "[pcap][dns]")
{

    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "tests/fixtures/dns_udp_mixed_rcode.pcap");
    stream.config_set("bpf", "");
    stream.config_set("host_spec", "192.168.0.0/26");
    stream.parse_host_spec();

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    DnsStreamHandler dns_handler{"dns-test", stream_proxy, &c};

    // notice, case-insensitive
    dns_handler.config_set<bool>("public_suffix_list", true);
    dns_handler.start();
    stream.start();
    stream.stop();
    dns_handler.stop();

    auto counters = dns_handler.metrics()->bucket(0)->counters(TransactionDirection::out);

    CHECK(counters.UDP.value() == 9);
    CHECK(counters.RNOERROR.value() == 7);
    CHECK(counters.SRVFAIL.value() == 0);
    CHECK(counters.REFUSED.value() == 1);
    CHECK(counters.NX.value() == 1);

    nlohmann::json j;
    dns_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["filtered_packets"] == 0);

    CHECK(j["out"]["top_qname2_xacts"][0]["estimate"] == 2);
}

TEST_CASE("Parse DNS with ECS data", "[pcap][dns][ecs]")
{
    CHECK_NOTHROW(visor::geo::GeoIP().enable("tests/fixtures/GeoIP2-City-Test.mmdb"));
    CHECK_NOTHROW(visor::geo::GeoASN().enable("tests/fixtures/GeoIP2-ISP-Test.mmdb"));

    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "tests/fixtures/ecs.pcap");
    stream.config_set("bpf", "");
    stream.config_set("host_spec", "192.168.0.0/24");
    stream.parse_host_spec();

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    DnsStreamHandler dns_handler{"dns-test", stream_proxy, &c};
    dns_handler.config_set<visor::Configurable::StringList>("enable", visor::Configurable::StringList({"top_ecs"}));
    dns_handler.start();
    stream.start();
    stream.stop();
    dns_handler.stop();

    auto counters = dns_handler.metrics()->bucket(0)->counters(TransactionDirection::unknown);
    auto event_data = dns_handler.metrics()->bucket(0)->event_data_locked();

    CHECK(event_data.num_events->value() == 36);
    CHECK(event_data.num_samples->value() == 36);
    CHECK(counters.TCP.value() == 2);
    CHECK(counters.UDP.value() == 12);
    CHECK(counters.IPv4.value() == 1);
    CHECK(counters.IPv6.value() == 13);
    CHECK(counters.xacts.value() == 14);
    CHECK(counters.timeout.value() == 0);
    CHECK(counters.orphan.value() == 0);
    CHECK(counters.ECS.value() == 2);

    nlohmann::json j;
    dns_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["filtered_packets"] == 0);

    CHECK(j["unknown"]["cardinality"]["qname"] == 8);

    CHECK(j["unknown"]["top_ecs_xacts"][0]["name"] == "2001:470:1f0b:1600::"); // wireshark
    CHECK(j["unknown"]["top_ecs_xacts"][0]["estimate"] == 2);
    CHECK(j["unknown"]["top_ecs_xacts"][1] == nullptr);
    CHECK(j["unknown"]["top_geo_loc_ecs_xacts"][0]["name"] == "Unknown");
    CHECK(j["unknown"]["top_geo_loc_ecs_xacts"][0]["estimate"] == 2);
    CHECK(j["unknown"]["top_asn_ecs_xacts"][0]["name"] == "Unknown");
    CHECK(j["unknown"]["top_asn_ecs_xacts"][0]["estimate"] == 2);
}

TEST_CASE("DNS filter: GeoLoc not found", "[pcap][dns][ecs]")
{
    CHECK_NOTHROW(visor::geo::GeoIP().enable("tests/fixtures/GeoIP2-City-Test.mmdb"));
    CHECK_NOTHROW(visor::geo::GeoASN().enable("tests/fixtures/GeoIP2-ISP-Test.mmdb"));

    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "tests/fixtures/ecs.pcap");
    stream.config_set("bpf", "");
    stream.config_set("host_spec", "192.168.0.0/24");
    stream.parse_host_spec();

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    DnsStreamHandler dns_handler{"dns-test", stream_proxy, &c};
    dns_handler.config_set<visor::Configurable::StringList>("enable", visor::Configurable::StringList({"top_ecs"}));
    dns_handler.config_set<bool>("geoloc_notfound", true);
    dns_handler.start();
    stream.start();
    stream.stop();
    dns_handler.stop();

    auto counters = dns_handler.metrics()->bucket(0)->counters(TransactionDirection::unknown);
    auto event_data = dns_handler.metrics()->bucket(0)->event_data_locked();

    CHECK(event_data.num_events->value() == 36);
    CHECK(event_data.num_samples->value() == 36);
    CHECK(counters.TCP.value() == 0);
    CHECK(counters.UDP.value() == 2);
    CHECK(counters.IPv4.value() == 0);
    CHECK(counters.IPv6.value() == 2);
    CHECK(counters.xacts.value() == 2);
    CHECK(counters.timeout.value() == 0);
    CHECK(counters.orphan.value() == 2);
    CHECK(counters.ECS.value() == 2);

    nlohmann::json j;
    dns_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["filtered_packets"] == 27);

    CHECK(j["unknown"]["cardinality"]["qname"] == 1);

    CHECK(j["unknown"]["top_ecs_xacts"][0]["name"] == "2001:470:1f0b:1600::"); // wireshark
    CHECK(j["unknown"]["top_ecs_xacts"][0]["estimate"] == 2);
    CHECK(j["unknown"]["top_ecs_xacts"][1] == nullptr);
    CHECK(j["unknown"]["top_geo_loc_ecs_xacts"][0]["name"] == "Unknown");
    CHECK(j["unknown"]["top_geo_loc_ecs_xacts"][0]["estimate"] == 2);
}

TEST_CASE("DNS filter: ASN not found", "[pcap][dns][ecs]")
{
    CHECK_NOTHROW(visor::geo::GeoIP().enable("tests/fixtures/GeoIP2-City-Test.mmdb"));
    CHECK_NOTHROW(visor::geo::GeoASN().enable("tests/fixtures/GeoIP2-ISP-Test.mmdb"));

    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "tests/fixtures/ecs.pcap");
    stream.config_set("bpf", "");
    stream.config_set("host_spec", "192.168.0.0/24");
    stream.parse_host_spec();

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    DnsStreamHandler dns_handler{"dns-test", stream_proxy, &c};
    dns_handler.config_set<visor::Configurable::StringList>("enable", visor::Configurable::StringList({"top_ecs"}));
    dns_handler.config_set<bool>("asn_notfound", true);
    dns_handler.start();
    stream.start();
    stream.stop();
    dns_handler.stop();

    auto counters = dns_handler.metrics()->bucket(0)->counters(TransactionDirection::unknown);
    auto event_data = dns_handler.metrics()->bucket(0)->event_data_locked();

    CHECK(event_data.num_events->value() == 36);
    CHECK(event_data.num_samples->value() == 36);
    CHECK(counters.TCP.value() == 0);
    CHECK(counters.UDP.value() == 2);
    CHECK(counters.IPv4.value() == 0);
    CHECK(counters.IPv6.value() == 2);
    CHECK(counters.xacts.value() == 2);
    CHECK(counters.timeout.value() == 0);
    CHECK(counters.orphan.value() == 2);
    CHECK(counters.ECS.value() == 2);

    nlohmann::json j;
    dns_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["filtered_packets"] == 27);

    CHECK(j["unknown"]["cardinality"]["qname"] == 1);

    CHECK(j["unknown"]["top_ecs_xacts"][0]["name"] == "2001:470:1f0b:1600::"); // wireshark
    CHECK(j["unknown"]["top_ecs_xacts"][0]["estimate"] == 2);
    CHECK(j["unknown"]["top_ecs_xacts"][1] == nullptr);
    CHECK(j["unknown"]["top_asn_ecs_xacts"][0]["name"] == "Unknown");
    CHECK(j["unknown"]["top_asn_ecs_xacts"][0]["estimate"] == 2);
}

TEST_CASE("DNS filter exceptions", "[pcap][dns][filter]")
{
    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "tests/fixtures/dns_udp_tcp_random.pcap");
    stream.config_set("bpf", "");
    stream.config_set("host_spec", "192.168.0.0/24");
    stream.parse_host_spec();

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    DnsStreamHandler dns_handler{"dns-test", stream_proxy, &c};

    SECTION("only_rcode as string")
    {
        dns_handler.config_set<std::string>("only_rcode", "1");
        REQUIRE_THROWS_WITH(dns_handler.start(), "DnsStreamHandler: wrong value type for only_rcode filter. It should be an integer or an array");
    }

    SECTION("only_rcode invalid")
    {
        dns_handler.config_set<uint64_t>("only_rcode", 133);
        REQUIRE_THROWS_WITH(dns_handler.start(), "DnsStreamHandler: only_rcode filter contained an invalid/unsupported rcode");
    }

    SECTION("only_qtype invalid qtype string")
    {
        dns_handler.config_set<visor::Configurable::StringList>("only_qtype", {"AAAA", "TEXT"});
        REQUIRE_THROWS_WITH(dns_handler.start(), "DnsStreamHandler: only_qtype filter contained an invalid/unsupported qtype: TEXT");
    }

    SECTION("only_qtype invalid qtype number")
    {
        dns_handler.config_set<visor::Configurable::StringList>("only_qtype", {"AAAA", "270"});
        REQUIRE_THROWS_WITH(dns_handler.start(), "DnsStreamHandler: only_qtype filter contained an invalid/unsupported qtype: 270");
    }

    SECTION("answer_count as string")
    {
        dns_handler.config_set<std::string>("answer_count", "1");
        REQUIRE_THROWS_WITH(dns_handler.start(), "DnsStreamHandler: wrong value type for answer_count filter. It should be an integer");
    }
}

TEST_CASE("DNS groups", "[pcap][dns]")
{
    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "tests/fixtures/dns_udp_tcp_random.pcap");
    stream.config_set("bpf", "");
    stream.config_set("host_spec", "192.168.0.0/24");
    stream.parse_host_spec();

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    DnsStreamHandler dns_handler{"dns-test", stream_proxy, &c};

    SECTION("disable cardinality and counters")
    {
        dns_handler.config_set<visor::Configurable::StringList>("disable", {"cardinality", "counters"});
        dns_handler.config_set<visor::Configurable::StringList>("enable", {"top_size", "xact_times"});

        dns_handler.start();
        stream.start();
        stream.stop();
        dns_handler.stop();

        auto counters = dns_handler.metrics()->bucket(0)->counters(TransactionDirection::out);
        auto event_data = dns_handler.metrics()->bucket(0)->event_data_locked();

        CHECK(event_data.num_events->value() == 5851);
        CHECK(event_data.num_samples->value() == 5851);
        CHECK(counters.TCP.value() == 0);
        CHECK(counters.UDP.value() == 0);
        CHECK(counters.IPv4.value() == 0);
        CHECK(counters.IPv6.value() == 0);
        CHECK(counters.xacts.value() == 0);
        CHECK(counters.timeout.value() == 0);
        CHECK(counters.orphan.value() == 0);

        nlohmann::json j;
        dns_handler.metrics()->bucket(0)->to_json(j);

        CHECK(j["out"]["cardinality"]["qname"] == nullptr);
        CHECK(j["out"]["top_qname2_xacts"][0]["name"] == ".test.com");
        CHECK(j["out"]["response_query_size_ratio"]["p50"] != nullptr);
        CHECK(j["out"]["xact_time_us"]["p50"] != nullptr);
        CHECK(j["out"]["xact_histogram_us"]["buckets"] != nullptr);
    }

    SECTION("disable TopQname and Dns Transactions")
    {
        dns_handler.config_set<visor::Configurable::StringList>("disable", {"top_qnames"});

        dns_handler.start();
        stream.start();
        stream.stop();
        dns_handler.stop();

        auto counters = dns_handler.metrics()->bucket(0)->counters(TransactionDirection::out);
        auto event_data = dns_handler.metrics()->bucket(0)->event_data_locked();

        CHECK(event_data.num_events->value() == 5851);
        CHECK(event_data.num_samples->value() == 5851);
        CHECK(counters.TCP.value() == 1440);
        CHECK(counters.UDP.value() == 1481);
        CHECK(counters.IPv4.value() == 2921);
        CHECK(counters.IPv6.value() == 0);
        CHECK(counters.xacts.value() == 2921);
        CHECK(counters.timeout.value() == 0);
        CHECK(counters.orphan.value() == 0);

        nlohmann::json j;
        dns_handler.metrics()->bucket(0)->to_json(j);

        CHECK(j["out"]["cardinality"]["qname"] == 2036);
        CHECK(j["out"]["top_qname2_xacts"][0]["name"] == nullptr);
    }

    SECTION("disable invalid dns group")
    {
        dns_handler.config_set<visor::Configurable::StringList>("disable", {"top_qnames", "dns_top_wired"});
        REQUIRE_THROWS_WITH(dns_handler.start(), "dns_top_wired is an invalid/unsupported metric group. The valid groups are: all, cardinality, counters, quantiles, top_ecs, top_ports, top_qnames, top_qtypes, top_rcodes, top_size, xact_times");
    }

    SECTION("enable invalid dns group")
    {
        dns_handler.config_set<visor::Configurable::StringList>("enable", {"top_qnames", "dns_top_wired"});
        REQUIRE_THROWS_WITH(dns_handler.start(), "dns_top_wired is an invalid/unsupported metric group. The valid groups are: all, cardinality, counters, quantiles, top_ecs, top_ports, top_qnames, top_qtypes, top_rcodes, top_size, xact_times");
    }
}

TEST_CASE("DNS invalid config", "[dns][filter][config]")
{
    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "tests/fixtures/dns_udp_tcp_random.pcap");

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    DnsStreamHandler dns_handler{"dns-test", stream_proxy, &c};
    dns_handler.config_set<bool>("invalid_config", true);
    REQUIRE_THROWS_WITH(dns_handler.start(), "invalid_config is an invalid/unsupported config or filter. The valid configs/filters are: exclude_noerror, only_rcode, only_dnssec_response, answer_count, only_qtype, only_qname, only_qname_suffix, geoloc_notfound, asn_notfound, dnstap_msg_type, public_suffix_list, recorded_stream, xact_ttl_secs, xact_ttl_ms, deep_sample_rate, num_periods, topn_count, topn_percentile_threshold");
}

TEST_CASE("dnsv2 to_prometheus and to_opentelemetry backends", "[pcap][dnsv2][backends]")
{
    visor::input::pcap::PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "tests/fixtures/dns_udp_tcp_random.pcap");
    stream.config_set("bpf", "");

    visor::Config c;
    c.config_set<uint64_t>("num_periods", 1);
    auto stream_proxy = stream.add_event_proxy(c);
    visor::handler::dns::v2::DnsStreamHandler handler{"dnsv2-test", stream_proxy, &c};

    handler.start();
    stream.start();
    handler.stop();
    stream.stop();

    std::stringstream prom;
    handler.metrics()->bucket(0)->to_prometheus(prom, {});
    CHECK(prom.str().find("dns_") != std::string::npos);

    opentelemetry::proto::metrics::v1::ScopeMetrics scope;
    timespec start_ts{}, end_ts{};
    handler.metrics()->bucket(0)->to_opentelemetry(scope, start_ts, end_ts, {});
    CHECK(scope.metrics_size() > 0);
}

TEST_CASE("DNS v2 specialized_merge aggregates two buckets", "[dns][unit]")
{
    auto run = [](const std::string &name,
                  std::shared_ptr<visor::input::pcap::PcapInputStream> &stream,
                  std::shared_ptr<visor::Config> &c,
                  std::shared_ptr<visor::handler::dns::v2::DnsStreamHandler> &h) {
        stream = std::make_shared<visor::input::pcap::PcapInputStream>(name + "-stream");
        stream->config_set("pcap_file", std::string("tests/fixtures/dns_udp_tcp_random.pcap"));
        stream->config_set("bpf", std::string(""));
        c = std::make_shared<visor::Config>();
        c->config_set<uint64_t>("num_periods", 1);
        auto proxy = stream->add_event_proxy(*c);
        h = std::make_shared<visor::handler::dns::v2::DnsStreamHandler>(name, proxy, c.get());
        h->start();
        stream->start();
        h->stop();
        stream->stop();
    };

    std::shared_ptr<visor::input::pcap::PcapInputStream> s1, s2;
    std::shared_ptr<visor::Config> c1, c2;
    std::shared_ptr<visor::handler::dns::v2::DnsStreamHandler> h1, h2;
    run("dns-merge-1", s1, c1, h1);
    run("dns-merge-2", s2, c2, h2);

    auto *target = const_cast<visor::handler::dns::v2::DnsMetricsBucket *>(h1->metrics()->bucket(0));
    REQUIRE_NOTHROW(target->specialized_merge(*h2->metrics()->bucket(0), visor::Metric::Aggregate::DEFAULT));

    nlohmann::json j;
    target->to_json(j);
    CHECK(!j.empty());
}
