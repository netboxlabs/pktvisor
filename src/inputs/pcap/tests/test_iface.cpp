#include "PcapInputStream.h"
#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_exception.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

using namespace visor::input::pcap;
using Catch::Matchers::StartsWith;

TEST_CASE("pcap refuses its config as a ConfigException, and a file this host lacks as a PcapException", "[pcap]")
{
    // the admin API answers 422 for a ConfigException a policy's input throws as it starts, and 500 for anything else
    using Catch::Matchers::Message;
    PcapInputStream stream{"pcap-test"};
    SECTION("an unknown pcap_source")
    {
        stream.config_set("pcap_source", "nope");
        CHECK_THROWS_MATCHES(stream.start(), visor::ConfigException, Message("unknown pcap source"));
    }
    SECTION("live capture without an iface")
    {
        stream.config_set("pcap_source", "libpcap");
        CHECK_THROWS_MATCHES(stream.start(), visor::ConfigException, Message("no iface was specified for live capture"));
    }
    SECTION("a host_spec entry that is not a CIDR")
    {
        stream.config_set("pcap_source", "mock");
        stream.config_set("host_spec", "192.168.0.0/24/12ac");
        CHECK_THROWS_MATCHES(stream.start(), visor::ConfigException, Message("invalid CIDR: 192.168.0.0/24/12ac"));
    }
    SECTION("a bpf filter no capture compiles")
    {
        stream.config_set("pcap_file", "tests/fixtures/dns_ipv4_udp.pcap");
        stream.config_set("bpf", "not a ((( filter");
        CHECK_THROWS_MATCHES(stream.start(), visor::ConfigException, Message("bpf \"not a ((( filter\" is not a valid filter"));
    }
    SECTION("a pcap_file this host does not have")
    {
        stream.config_set("pcap_file", "does/not/exist.pcap");
        CHECK_THROWS_MATCHES(stream.start(), PcapException, Message("Cannot open pcap/pcapng file"));
    }
}

// iface may be an interface name or an address, and only an address may be parsed as one. The addresses
// are reserved for documentation (RFC 5737, RFC 3849), so the lookup fails before any capture opens.
TEST_CASE("iface accepts a name, an IPv4 address or an IPv6 address", "[pcap][iface]")
{
    SECTION("name")
    {
        PcapInputStream stream{"pcap-test"};
        stream.config_set("iface", "pktvisor-test0");
        CHECK_THROWS_WITH(stream.start(), StartsWith("Couldn't find interface by provided name: \"pktvisor-test0\""));
    }

    SECTION("IPv4 address")
    {
        PcapInputStream stream{"pcap-test"};
        stream.config_set("iface", "192.0.2.1");
        CHECK_THROWS_WITH(stream.start(), "Couldn't find interface by provided IP: 192.0.2.1");
    }

    SECTION("IPv6 address")
    {
        PcapInputStream stream{"pcap-test"};
        stream.config_set("iface", "2001:db8::1");
        CHECK_THROWS_WITH(stream.start(), "Couldn't find interface by provided IP: 2001:db8::1");
    }

    SECTION("the zero address is looked up as a name")
    {
        PcapInputStream stream{"pcap-test"};
        stream.config_set("iface", "0.0.0.0");
        CHECK_THROWS_WITH(stream.start(), StartsWith("Couldn't find interface by provided name: \"0.0.0.0\""));
    }
}
