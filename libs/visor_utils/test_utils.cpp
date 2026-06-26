#include <catch2/catch_test_macros.hpp>
#include "utils.h"

#ifdef _WIN32
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

using namespace visor::lib::utils;

TEST_CASE("parseHostSpec", "[utils]")
{

    SECTION("IPv4 /24")
    {
        IPv4subnetList hostIPv4;
        IPv6subnetList hostIPv6;
        parse_host_specs({"192.168.0.0/24"}, hostIPv4, hostIPv6);
        CHECK(hostIPv4.size() == 1);
        char buffer[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &hostIPv4[0].addr.s_addr, buffer, INET_ADDRSTRLEN);
        CHECK(std::string(buffer) == "192.168.0.0");
        CHECK(hostIPv4[0].cidr == 24);
    }

    SECTION("IPv4 /23")
    {
        IPv4subnetList hostIPv4;
        IPv6subnetList hostIPv6;
        parse_host_specs({"192.168.1.1/23"}, hostIPv4, hostIPv6);
        CHECK(hostIPv4.size() == 1);
        char buffer[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &hostIPv4[0].addr.s_addr, buffer, INET_ADDRSTRLEN);
        CHECK(std::string(buffer) == "192.168.1.1");
        CHECK(hostIPv4[0].cidr == 23);
    }

    SECTION("IPv4 /32")
    {
        IPv4subnetList hostIPv4;
        IPv6subnetList hostIPv6;
        parse_host_specs({"192.168.1.5/32"}, hostIPv4, hostIPv6);
        CHECK(hostIPv4.size() == 1);
        char buffer[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &hostIPv4[0].addr.s_addr, buffer, INET_ADDRSTRLEN);
        CHECK(std::string(buffer) == "192.168.1.5");
        CHECK(hostIPv4[0].cidr == 32);
    }

    SECTION("IPv4 2 entries")
    {
        IPv4subnetList hostIPv4;
        IPv6subnetList hostIPv6;
        parse_host_specs(split_str_to_vec_str("192.168.1.5/30,192.168.1.20/32", ','), hostIPv4, hostIPv6);
        CHECK(hostIPv4.size() == 2);
        char buffer[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &hostIPv4[0].addr.s_addr, buffer, INET_ADDRSTRLEN);
        CHECK(std::string(buffer) == "192.168.1.5");
        CHECK(hostIPv4[0].cidr == 30);
        inet_ntop(AF_INET, &hostIPv4[1].addr.s_addr, buffer, INET_ADDRSTRLEN);
        CHECK(std::string(buffer) == "192.168.1.20");
        CHECK(hostIPv4[1].cidr == 32);
    }

    SECTION("IPv6 /48")
    {
        IPv4subnetList hostIPv4;
        IPv6subnetList hostIPv6;
        parse_host_specs({"2001:7f8:1::a506:2597:1/48"}, hostIPv4, hostIPv6);
        CHECK(hostIPv6.size() == 1);
        char buffer[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &hostIPv6[0].addr.s6_addr, buffer, INET6_ADDRSTRLEN);
        CHECK(std::string(buffer) == "2001:7f8:1::a506:2597:1");
        CHECK(hostIPv6[0].cidr == 48);
    }

    SECTION("mixed entries")
    {
        IPv4subnetList hostIPv4;
        IPv6subnetList hostIPv6;
        parse_host_specs(split_str_to_vec_str("192.168.1.5/32,2001:7f8:1::a506:2597:1/48", ','), hostIPv4, hostIPv6);
        CHECK(hostIPv4.size() == 1);
        CHECK(hostIPv6.size() == 1);
        char buffer[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &hostIPv4[0].addr.s_addr, buffer, INET_ADDRSTRLEN);
        CHECK(std::string(buffer) == "192.168.1.5");
        CHECK(hostIPv4[0].cidr == 32);
        char buffer6[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &hostIPv6[0].addr.s6_addr, buffer6, INET6_ADDRSTRLEN);
        CHECK(std::string(buffer6) == "2001:7f8:1::a506:2597:1");
        CHECK(hostIPv6[0].cidr == 48);
    }

    SECTION("ip format conversion")
    {
        pcpp::IPv4Address ip("1.128.0.0");
        uint32_t ip_int(ip.toInt());
        struct sockaddr_in sa;
        CHECK(ipv4_to_sockaddr(ip, &sa));
        CHECK(memcmp(&sa.sin_addr, &ip_int, sizeof(sa.sin_addr)) == 0);
        CHECK(sa.sin_family == AF_INET);
    }
}

// `str` is the canonical inet_ntop rendering of the binary address, not an echo of
// any input string; the inputs below are already canonical so they round-trip. A
// future non-canonical input (e.g. "2001:db8:0:0::1") would need its canonical form.
// (std::pair brace-init resolves via utils.h, which gains #include <utility> in this task.)
TEST_CASE("appendInterfaceHostSubnets", "[utils]")
{
    in_addr a4{};
    REQUIRE(inet_pton(AF_INET, "192.168.50.23", &a4) == 1);
    in6_addr a6{};
    REQUIRE(inet_pton(AF_INET6, "2001:db8::1", &a6) == 1);

    SECTION("skips interface hosts when a host set is already provided")
    {
        IPv4subnetList hostIPv4;
        IPv6subnetList hostIPv6;
        append_interface_host_subnets(true, {{a4, 24}}, {{a6, 64}}, hostIPv4, hostIPv6);
        CHECK(hostIPv4.empty());
        CHECK(hostIPv6.empty());
    }

    SECTION("appends interface hosts at their prefix when no host set provided")
    {
        IPv4subnetList hostIPv4;
        IPv6subnetList hostIPv6;
        append_interface_host_subnets(false, {{a4, 24}}, {{a6, 64}}, hostIPv4, hostIPv6);
        REQUIRE(hostIPv4.size() == 1);
        CHECK(hostIPv4[0].cidr == 24);
        CHECK(hostIPv4[0].str == "192.168.50.23/24");
        REQUIRE(hostIPv6.size() == 1);
        CHECK(hostIPv6[0].cidr == 64);
        CHECK(hostIPv6[0].str == "2001:db8::1/64");
    }

    SECTION("appends multiple addresses of the same family in order")
    {
        in_addr b4{};
        REQUIRE(inet_pton(AF_INET, "10.0.0.1", &b4) == 1);
        IPv4subnetList hostIPv4;
        IPv6subnetList hostIPv6;
        append_interface_host_subnets(false, {{a4, 24}, {b4, 32}}, {}, hostIPv4, hostIPv6);
        REQUIRE(hostIPv4.size() == 2);
        CHECK(hostIPv4[0].str == "192.168.50.23/24");
        CHECK(hostIPv4[1].str == "10.0.0.1/32");
        CHECK(hostIPv6.empty());
    }
}

