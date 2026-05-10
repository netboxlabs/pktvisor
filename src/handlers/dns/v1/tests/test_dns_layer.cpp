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
using namespace visor::handler::dns;
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

    auto counters = dns_handler.metrics()->bucket(0)->counters();
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
    CHECK(counters.UDP.value() == 140);
    CHECK(counters.IPv4.value() == 140);
    CHECK(counters.IPv6.value() == 0);
    CHECK(counters.queries.value() == 70);
    CHECK(counters.replies.value() == 70);
    CHECK(j["top_qname2"][0]["name"] == ".test.com");
    CHECK(j["top_qname2"][0]["estimate"] == 140);
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

    auto counters = dns_handler.metrics()->bucket(0)->counters();
    auto event_data = dns_handler.metrics()->bucket(0)->event_data_locked();
    json j;
    dns_handler.metrics()->bucket(0)->to_json(j);

    CHECK(event_data.num_events->value() == 420);
    CHECK(counters.TCP.value() == 420);
    CHECK(counters.IPv4.value() == 420);
    CHECK(counters.IPv6.value() == 0);
    CHECK(counters.queries.value() == 210);
    CHECK(counters.replies.value() == 210);
    CHECK(j["top_qname2"][0]["name"] == ".test.com");
    CHECK(j["top_qname2"][0]["estimate"] == 420);
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

    auto counters = dns_handler.metrics()->bucket(0)->counters();
    auto event_data = dns_handler.metrics()->bucket(0)->event_data_locked();
    json j;
    dns_handler.metrics()->bucket(0)->to_json(j);

    CHECK(event_data.num_events->value() == 140);
    CHECK(counters.UDP.value() == 140);
    CHECK(counters.IPv4.value() == 0);
    CHECK(counters.IPv6.value() == 140);
    CHECK(counters.queries.value() == 70);
    CHECK(counters.replies.value() == 70);
    CHECK(j["top_qname2"][0]["name"] == ".test.com");
    CHECK(j["top_qname2"][0]["estimate"] == 140);
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

    auto counters = dns_handler.metrics()->bucket(0)->counters();
    auto event_data = dns_handler.metrics()->bucket(0)->event_data_locked();
    json j;
    dns_handler.metrics()->bucket(0)->to_json(j);

    CHECK(event_data.num_events->value() == 360);
    CHECK(counters.TCP.value() == 360);
    CHECK(counters.IPv4.value() == 0);
    CHECK(counters.IPv6.value() == 360);
    CHECK(counters.queries.value() == 180);
    CHECK(counters.replies.value() == 180);
    CHECK(j["top_qname2"][0]["name"] == ".test.com");
    CHECK(j["top_qname2"][0]["estimate"] == 360);
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
    dns_handler.config_set<visor::Configurable::StringList>("enable", visor::Configurable::StringList({"top_qnames_details"}));

    dns_handler.start();
    stream.start();
    stream.stop();
    dns_handler.stop();

    auto counters = dns_handler.metrics()->bucket(0)->counters();
    auto event_data = dns_handler.metrics()->bucket(0)->event_data_locked();

    // confirmed with wireshark. there are 14 TCP retransmissions which are counted differently in our state machine
    // and account for some minor differences in TCP based stats
    CHECK(event_data.num_events->value() == 5851); // wireshark: 5838
    CHECK(event_data.num_samples->value() == 5851);
    CHECK(counters.TCP.value() == 2880); // wireshark: 2867
    CHECK(counters.UDP.value() == 2971);
    CHECK(counters.IPv4.value() == 5851); // wireshark: 5838
    CHECK(counters.IPv6.value() == 0);
    CHECK(counters.queries.value() == 2930);
    CHECK(counters.replies.value() == 2921);     // wireshark: 2908
    CHECK(counters.xacts_total.value() == 2921); // wireshark: 2894
    CHECK(counters.xacts_in.value() == 0);
    CHECK(counters.xacts_out.value() == 2921); // wireshark: 2894
    CHECK(counters.xacts_timed_out.value() == 0);
    CHECK(counters.NODATA.value() == 2254);
    CHECK(counters.RNOERROR.value() == 2921); // wireshark: 5838 (we only count reply result codes)
    CHECK(counters.RNOERROR.value() == 2921); // wireshark: 5838 (we only count reply result codes)
    CHECK(counters.NX.value() == 0);
    CHECK(counters.REFUSED.value() == 0);
    CHECK(counters.SRVFAIL.value() == 0);

    nlohmann::json j;
    dns_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["cardinality"]["qname"] == 2036); // flame was run with 1000 randoms x2 (udp+tcp)

    CHECK(j["top_qname2"][0]["name"] == ".test.com");
    CHECK(j["top_qname2"][0]["estimate"] == event_data.num_events->value());

    CHECK(j["top_rcode"][0]["name"] == "NOERROR");
    CHECK(j["top_rcode"][0]["estimate"] == counters.RNOERROR.value());

    CHECK(j["top_udp_ports"][0]["name"] == "57975");
    CHECK(j["top_udp_ports"][0]["estimate"] == 302);

    CHECK(j["top_qname_by_resp_bytes"][0]["name"] == "82gdxvz5vp.mmyv7ma0jn.rxst40swe.tcbgtnfa.test.com");
    CHECK(j["top_qname_by_resp_bytes"][0]["estimate"] == 290);

    CHECK(j["top_qtype"][0]["name"] == "AAAA");
    CHECK(j["top_qtype"][0]["estimate"] == 1476);
    CHECK(j["top_qtype"][1]["name"] == "CNAME");
    CHECK(j["top_qtype"][1]["estimate"] == 825);
    CHECK(j["top_qtype"][2]["name"] == "SOA");
    CHECK(j["top_qtype"][2]["estimate"] == 794);
    CHECK(j["top_qtype"][3]["name"] == "MX");
    CHECK(j["top_qtype"][3]["estimate"] == 757);
    CHECK(j["top_qtype"][4]["name"] == "A");
    CHECK(j["top_qtype"][4]["estimate"] == 717);
    CHECK(j["top_qtype"][5]["name"] == "NS");
    CHECK(j["top_qtype"][5]["estimate"] == 662);
    CHECK(j["top_qtype"][6]["name"] == "TXT");
    CHECK(j["top_qtype"][6]["estimate"] == 620);
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

    auto counters = dns_handler.metrics()->bucket(0)->counters();
    REQUIRE(counters.RNOERROR.value() == 0);
    REQUIRE(counters.SRVFAIL.value() == 0);
    REQUIRE(counters.REFUSED.value() == 1);
    REQUIRE(counters.NX.value() == 1);
    REQUIRE(counters.NODATA.value() == 0);
    REQUIRE(counters.filtered.value() == 22);
    nlohmann::json j;
    dns_handler.metrics()->bucket(0)->to_json(j);
    REQUIRE(j["wire_packets"]["filtered"] == 22);
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

    auto counters = dns_handler.metrics()->bucket(0)->counters();
    REQUIRE(counters.RNOERROR.value() == 0);
    REQUIRE(counters.SRVFAIL.value() == 0);
    REQUIRE(counters.REFUSED.value() == 0);
    REQUIRE(counters.NX.value() == 1);
    REQUIRE(counters.NODATA.value() == 0);
    nlohmann::json j;
    dns_handler.metrics()->bucket(0)->to_json(j);
    REQUIRE(j["wire_packets"]["filtered"] == 0);
}

TEST_CASE("DNS Filters: only_rcode nx and refused", "[pcap][dns]")
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

    auto counters = dns_handler.metrics()->bucket(0)->counters();
    REQUIRE(counters.RNOERROR.value() == 0);
    REQUIRE(counters.SRVFAIL.value() == 0);
    REQUIRE(counters.REFUSED.value() == 1);
    REQUIRE(counters.NX.value() == 1);
    REQUIRE(counters.NODATA.value() == 0);
    nlohmann::json j;
    dns_handler.metrics()->bucket(0)->to_json(j);
    REQUIRE(j["wire_packets"]["filtered"] == 0);
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

    auto counters = dns_handler.metrics()->bucket(0)->counters();
    auto event_data = dns_handler.metrics()->bucket(0)->event_data_locked();

    // confirmed with wireshark. there are 14 TCP retransmissions which are counted differently in our state machine
    // and account for some minor differences in TCP based stats
    CHECK(event_data.num_events->value() == 5851); // wireshark: 5838
    CHECK(event_data.num_samples->value() == 5851);
    CHECK(counters.IPv4.value() == 2096);
    CHECK(counters.IPv6.value() == 0);
    CHECK(counters.queries.value() == 1050);
    CHECK(counters.replies.value() == 1046);
    CHECK(counters.NODATA.value() == 737);
    CHECK(counters.RNOERROR.value() == 1046);

    nlohmann::json j;
    dns_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["top_qtype"][0]["name"] == "AAAA");
    CHECK(j["top_qtype"][0]["estimate"] == 1476);
    CHECK(j["top_qtype"][1]["name"] == "TXT");
    CHECK(j["top_qtype"][1]["estimate"] == 620);
    CHECK(j["top_qtype"][2] == nullptr);
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

    CHECK(j["cardinality"]["qname"] == 2036); // flame was run with 1000 randoms x2 (udp+tcp)

    CHECK(j["top_qtype"][0]["name"] == "AAAA");
    CHECK(j["top_qtype"][0]["estimate"] == 1476);
    CHECK(j["top_qtype"][1]["name"] == "CNAME");
    CHECK(j["top_qtype"][1]["estimate"] == 825);
    CHECK(j["top_qtype"][2]["name"] == "SOA");
    CHECK(j["top_qtype"][2]["estimate"] == 794);
    CHECK(j["top_qtype"][3] == nullptr);
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

    auto counters = dns_handler.metrics()->bucket(0)->counters();

    CHECK(counters.UDP.value() == 6);
    CHECK(counters.RNOERROR.value() == 2);
    CHECK(counters.SRVFAIL.value() == 0);
    CHECK(counters.REFUSED.value() == 0);
    CHECK(counters.NX.value() == 1);
    CHECK(counters.NODATA.value() == 2);
    CHECK(counters.total.value() == 6);
    CHECK(counters.filtered.value() == 0);

    nlohmann::json j;
    dns_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["top_qname2"][0]["name"] == ".google.com");
    CHECK(j["top_qname3"][0]["name"] == "play.google.com");
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

    auto counters = dns_handler.metrics()->bucket(0)->counters();

    CHECK(counters.UDP.value() == 10);
    CHECK(counters.RNOERROR.value() == 4);
    CHECK(counters.SRVFAIL.value() == 0);
    CHECK(counters.REFUSED.value() == 0);
    CHECK(counters.NX.value() == 1);
    CHECK(counters.NODATA.value() == 2);
    CHECK(counters.total.value() == 10);
    CHECK(counters.filtered.value() == 14);

    nlohmann::json j;
    dns_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["top_qname2"][0]["name"].get<std::string>().find("google.com") != std::string::npos);
    CHECK(j["top_qname3"][0]["name"] == nullptr);
}

TEST_CASE("DNS Filters: answer_count", "[pcap][dns]")
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
    dns_handler.config_set<uint64_t>("only_rcode", NoError);
    dns_handler.config_set<uint64_t>("answer_count", 0);
    dns_handler.start();
    stream.start();
    stream.stop();
    dns_handler.stop();

    auto counters = dns_handler.metrics()->bucket(0)->counters();

    CHECK(counters.UDP.value() == 4);
    CHECK(counters.RNOERROR.value() == 4);
    CHECK(counters.SRVFAIL.value() == 0);
    CHECK(counters.REFUSED.value() == 0);
    CHECK(counters.NX.value() == 0);
    CHECK(counters.NODATA.value() == 4);
    CHECK(counters.filtered.value() == 6);

    nlohmann::json j;
    dns_handler.metrics()->bucket(0)->to_json(j);
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

    auto counters = dns_handler.metrics()->bucket(0)->counters();
    auto event_data = dns_handler.metrics()->bucket(0)->event_data_locked();

    CHECK(event_data.num_events->value() == 14);
    CHECK(event_data.num_samples->value() == 14);
    CHECK(counters.TCP.value() == 0);
    CHECK(counters.UDP.value() == 6);
    CHECK(counters.IPv4.value() == 6);
    CHECK(counters.IPv6.value() == 0);
    CHECK(counters.queries.value() == 0);
    CHECK(counters.replies.value() == 6);
    CHECK(counters.RNOERROR.value() == 6);

    nlohmann::json j;
    dns_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["cardinality"]["qname"] == 3);

    CHECK(j["top_qtype"][0]["name"] == "DNSKEY");
    CHECK(j["top_qtype"][0]["estimate"] == 3);
    CHECK(j["top_qtype"][1]["name"] == "DS");
    CHECK(j["top_qtype"][1]["estimate"] == 2);
    CHECK(j["top_qtype"][2]["name"] == "A");
    CHECK(j["top_qtype"][2]["estimate"] == 1);
}

TEST_CASE("DNS Configs: public_suffix_list", "[pcap][dns]")
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

    dns_handler.config_set<bool>("public_suffix_list", true);
    dns_handler.start();
    stream.start();
    stream.stop();
    dns_handler.stop();

    auto counters = dns_handler.metrics()->bucket(0)->counters();

    CHECK(counters.UDP.value() == 24);
    CHECK(counters.RNOERROR.value() == 10);
    CHECK(counters.SRVFAIL.value() == 0);
    CHECK(counters.REFUSED.value() == 1);
    CHECK(counters.NX.value() == 1);
    CHECK(counters.filtered.value() == 0);

    nlohmann::json j;
    dns_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["top_qname2"][0]["name"] == ".mwbsys.com");
    CHECK(j["top_qname3"][0]["name"] == "sirius.mwbsys.com");
}

TEST_CASE("DNS Configs: only_queries", "[pcap][dns]")
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

    dns_handler.config_set<bool>("only_queries", true);
    dns_handler.start();
    stream.start();
    stream.stop();
    dns_handler.stop();

    auto counters = dns_handler.metrics()->bucket(0)->counters();

    CHECK(counters.UDP.value() == 12);
    CHECK(counters.RNOERROR.value() == 0);
    CHECK(counters.SRVFAIL.value() == 0);
    CHECK(counters.REFUSED.value() == 0);
    CHECK(counters.NX.value() == 0);
    CHECK(counters.filtered.value() == 12);

    nlohmann::json j;
    dns_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["top_qname2"][0]["name"] == ".mwbsys.com");
    CHECK(j["top_qname3"][0]["name"] == "sirius.mwbsys.com");
}

TEST_CASE("DNS Configs: only_responses", "[pcap][dns]")
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

    dns_handler.config_set<bool>("only_responses", true);
    dns_handler.start();
    stream.start();
    stream.stop();
    dns_handler.stop();

    auto counters = dns_handler.metrics()->bucket(0)->counters();

    CHECK(counters.UDP.value() == 12);
    CHECK(counters.RNOERROR.value() == 10);
    CHECK(counters.SRVFAIL.value() == 0);
    CHECK(counters.REFUSED.value() == 1);
    CHECK(counters.NX.value() == 1);
    CHECK(counters.filtered.value() == 12);

    nlohmann::json j;
    dns_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["top_qname2"][0]["name"] == ".mwbsys.com");
    CHECK(j["top_qname3"][0]["name"] == "sirius.mwbsys.com");
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

    auto counters = dns_handler.metrics()->bucket(0)->counters();
    auto event_data = dns_handler.metrics()->bucket(0)->event_data_locked();

    CHECK(event_data.num_events->value() == 36);
    CHECK(event_data.num_samples->value() == 36);
    CHECK(counters.TCP.value() == 4);
    CHECK(counters.UDP.value() == 32);
    CHECK(counters.IPv4.value() == 6);
    CHECK(counters.IPv6.value() == 30);
    CHECK(counters.queries.value() == 22);
    CHECK(counters.replies.value() == 14);
    CHECK(counters.filtered.value() == 0);
    CHECK(counters.queryECS.value() == 5);

    nlohmann::json j;
    dns_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["cardinality"]["qname"] == 9);

    CHECK(j["top_query_ecs"][0]["name"] == "2001:470:1f0b:1600::"); // wireshark
    CHECK(j["top_query_ecs"][0]["estimate"] == 5);
    CHECK(j["top_query_ecs"][1] == nullptr);
    CHECK(j["top_geoLoc_ecs"][0]["name"] == "Unknown");
    CHECK(j["top_geoLoc_ecs"][0]["estimate"] == 5);
    CHECK(j["top_asn_ecs"][0]["name"] == "Unknown");
    CHECK(j["top_asn_ecs"][0]["estimate"] == 5);
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

    auto counters = dns_handler.metrics()->bucket(0)->counters();
    auto event_data = dns_handler.metrics()->bucket(0)->event_data_locked();

    CHECK(event_data.num_events->value() == 36);
    CHECK(event_data.num_samples->value() == 36);
    CHECK(counters.TCP.value() == 0);
    CHECK(counters.UDP.value() == 5);
    CHECK(counters.IPv4.value() == 1);
    CHECK(counters.IPv6.value() == 4);
    CHECK(counters.queries.value() == 5);
    CHECK(counters.replies.value() == 0);
    CHECK(counters.filtered.value() == 31);
    CHECK(counters.queryECS.value() == 5);

    nlohmann::json j;
    dns_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["cardinality"]["qname"] == 2);

    CHECK(j["top_query_ecs"][0]["name"] == "2001:470:1f0b:1600::"); // wireshark
    CHECK(j["top_query_ecs"][0]["estimate"] == 5);
    CHECK(j["top_query_ecs"][1] == nullptr);
    CHECK(j["top_geoLoc_ecs"][0]["name"] == "Unknown");
    CHECK(j["top_geoLoc_ecs"][0]["estimate"] == 5);
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

    auto counters = dns_handler.metrics()->bucket(0)->counters();
    auto event_data = dns_handler.metrics()->bucket(0)->event_data_locked();

    CHECK(event_data.num_events->value() == 36);
    CHECK(event_data.num_samples->value() == 36);
    CHECK(counters.TCP.value() == 0);
    CHECK(counters.UDP.value() == 5);
    CHECK(counters.IPv4.value() == 1);
    CHECK(counters.IPv6.value() == 4);
    CHECK(counters.queries.value() == 5);
    CHECK(counters.replies.value() == 0);
    CHECK(counters.filtered.value() == 31);
    CHECK(counters.queryECS.value() == 5);

    nlohmann::json j;
    dns_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["cardinality"]["qname"] == 2);

    CHECK(j["top_query_ecs"][0]["name"] == "2001:470:1f0b:1600::"); // wireshark
    CHECK(j["top_query_ecs"][0]["estimate"] == 5);
    CHECK(j["top_query_ecs"][1] == nullptr);
    CHECK(j["top_asn_ecs"][0]["name"] == "Unknown");
    CHECK(j["top_asn_ecs"][0]["estimate"] == 5);
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

    SECTION("disable cardinality and counters and enable histograms")
    {
        dns_handler.config_set<visor::Configurable::StringList>("disable", {"cardinality", "counters"});
        dns_handler.config_set<visor::Configurable::StringList>("enable", {"histograms"});

        dns_handler.start();
        stream.start();
        stream.stop();
        dns_handler.stop();

        auto counters = dns_handler.metrics()->bucket(0)->counters();
        auto event_data = dns_handler.metrics()->bucket(0)->event_data_locked();

        CHECK(event_data.num_events->value() == 5851);
        CHECK(event_data.num_samples->value() == 5851);
        CHECK(counters.TCP.value() == 0);
        CHECK(counters.UDP.value() == 0);
        CHECK(counters.IPv4.value() == 0);
        CHECK(counters.IPv6.value() == 0);
        CHECK(counters.queries.value() == 0);
        CHECK(counters.replies.value() == 0);
        CHECK(counters.xacts_total.value() == 2921);
        CHECK(counters.xacts_in.value() == 0);
        CHECK(counters.xacts_out.value() == 2921);
        CHECK(counters.xacts_timed_out.value() == 0);

        nlohmann::json j;
        dns_handler.metrics()->bucket(0)->to_json(j);

        CHECK(j["cardinality"]["qname"] == nullptr);
        CHECK(j["top_qname2"][0]["name"] == ".test.com");
        CHECK(j["xact"]["ratio"]["quantiles"]["p50"] != nullptr);
        CHECK(j["xact"]["out"]["histogram_us"]["buckets"] != nullptr);
    }

    SECTION("disable TopQname and Dns Transactions")
    {
        dns_handler.config_set<visor::Configurable::StringList>("disable", {"top_qnames", "dns_transaction"});

        dns_handler.start();
        stream.start();
        stream.stop();
        dns_handler.stop();

        auto counters = dns_handler.metrics()->bucket(0)->counters();
        auto event_data = dns_handler.metrics()->bucket(0)->event_data_locked();

        CHECK(event_data.num_events->value() == 5851);
        CHECK(event_data.num_samples->value() == 5851);
        CHECK(counters.TCP.value() == 2880);
        CHECK(counters.UDP.value() == 2971);
        CHECK(counters.IPv4.value() == 5851);
        CHECK(counters.IPv6.value() == 0);
        CHECK(counters.queries.value() == 2930);
        CHECK(counters.replies.value() == 2921);
        CHECK(counters.xacts_total.value() == 0);
        CHECK(counters.xacts_in.value() == 0);
        CHECK(counters.xacts_out.value() == 0);
        CHECK(counters.xacts_timed_out.value() == 0);

        nlohmann::json j;
        dns_handler.metrics()->bucket(0)->to_json(j);

        CHECK(j["cardinality"]["qname"] == 2036);
        CHECK(j["top_qname2"][0]["name"] == nullptr);
    }

    SECTION("disable invalid dns group")
    {
        dns_handler.config_set<visor::Configurable::StringList>("disable", {"top_qnames", "dns_top_wired"});
        REQUIRE_THROWS_WITH(dns_handler.start(), "dns_top_wired is an invalid/unsupported metric group. The valid groups are: all, cardinality, counters, dns_transaction, histograms, quantiles, top_ecs, top_ports, top_qnames, top_qnames_details");
    }

    SECTION("enable invalid dns group")
    {
        dns_handler.config_set<visor::Configurable::StringList>("enable", {"top_qnames", "dns_top_wired"});
        REQUIRE_THROWS_WITH(dns_handler.start(), "dns_top_wired is an invalid/unsupported metric group. The valid groups are: all, cardinality, counters, dns_transaction, histograms, quantiles, top_ecs, top_ports, top_qnames, top_qnames_details");
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
    REQUIRE_THROWS_WITH(dns_handler.start(), "invalid_config is an invalid/unsupported config or filter. The valid configs/filters are: exclude_noerror, only_rcode, only_queries, only_responses, only_dnssec_response, answer_count, only_qtype, only_qname, only_qname_suffix, geoloc_notfound, asn_notfound, dnstap_msg_type, public_suffix_list, recorded_stream, xact_ttl_secs, xact_ttl_ms, deep_sample_rate, num_periods, topn_count, topn_percentile_threshold");
}

TEST_CASE("DNS config ttl", "[dns][config]")
{
    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "tests/fixtures/dns_udp_tcp_random.pcap");

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    c.config_set<uint64_t>("xact_ttl_secs", 2);
    DnsStreamHandler dns_handler{"dns-test", stream_proxy, &c};
    REQUIRE_NOTHROW(dns_handler.start());
}

TEST_CASE("DNS Filters: only_rcode with predicate", "[pcap][dns][filter]")
{
    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "tests/fixtures/dns_udp_mixed_rcode.pcap");
    stream.config_set("bpf", "");
    stream.config_set("host_spec", "192.168.0.0/24");
    stream.parse_host_spec();

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    DnsStreamHandler dns_handler_1{"dns-test-1", stream_proxy, &c};
    DnsStreamHandler dns_handler_2{"dns-test-2", stream_proxy, &c};

    dns_handler_1.config_set<uint64_t>("only_rcode", 2);
    dns_handler_2.config_set<uint64_t>("only_rcode", 3);

    dns_handler_1.start();
    dns_handler_2.start();
    stream.start();
    stream.stop();
    dns_handler_1.stop();
    dns_handler_2.stop();

    auto event_data_1 = dns_handler_1.metrics()->bucket(0)->event_data_locked();

    CHECK(event_data_1.num_events->value() == 0);
    CHECK(event_data_1.num_samples->value() == 0);

    auto event_data_2 = dns_handler_2.metrics()->bucket(0)->event_data_locked();

    CHECK(event_data_2.num_events->value() == 1);
    CHECK(event_data_2.num_samples->value() == 1);

    nlohmann::json j;
    dns_handler_2.metrics()->bucket(0)->to_json(j);
}

TEST_CASE("dns to_prometheus and to_opentelemetry backends", "[pcap][dns][backends]")
{
    visor::input::pcap::PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "tests/fixtures/dns_udp_tcp_random.pcap");
    stream.config_set("bpf", "");

    visor::Config c;
    c.config_set<uint64_t>("num_periods", 1);
    auto stream_proxy = stream.add_event_proxy(c);
    visor::handler::dns::DnsStreamHandler handler{"dns-test", stream_proxy, &c};

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
