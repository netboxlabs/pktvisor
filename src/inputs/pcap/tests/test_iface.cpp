#include "PcapInputStream.h"
#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

using namespace visor::input::pcap;
using Catch::Matchers::StartsWith;

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
