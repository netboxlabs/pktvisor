/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#ifdef _WIN32
#include <Ws2tcpip.h>
#include <winsock2.h>
#else
#include <netinet/in.h>
#include <sys/socket.h>
#endif
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#endif
#include <pcapplusplus/IpAddress.h>
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif
#include <array>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace visor::lib::utils {

class UtilsException : public std::runtime_error
{
public:
    UtilsException(const char *msg)
        : std::runtime_error(msg)
    {
    }
    UtilsException(const std::string &msg)
        : std::runtime_error(msg)
    {
    }
};

// list of subnets we count as "host" to determine direction of packets
struct IPv4subnet {
    in_addr addr;
    uint8_t cidr;
    std::string str;
};

struct IPv6subnet {
    in6_addr addr;
    uint8_t cidr;
    std::string str;
};
typedef std::vector<IPv4subnet> IPv4subnetList;
typedef std::vector<IPv6subnet> IPv6subnetList;

bool ipv4_to_sockaddr(const pcpp::IPv4Address &ip, struct sockaddr_in *sa);
bool ipv6_to_sockaddr(const pcpp::IPv6Address &ip, struct sockaddr_in6 *sa);

std::vector<std::string> split_str_to_vec_str(const std::string &spec, const char &delimiter);
void parse_host_specs(const std::vector<std::string> &host_list, IPv4subnetList &ipv4_list, IPv6subnetList &ipv6_list);
void append_interface_host_subnets(bool host_set_provided, const std::vector<std::pair<in_addr, uint8_t>> &v4_addrs, const std::vector<std::pair<in6_addr, uint8_t>> &v6_addrs, IPv4subnetList &host_ipv4, IPv6subnetList &host_ipv6);
std::optional<IPv4subnetList::const_iterator> match_subnet(IPv4subnetList &ipv4_list, uint32_t ipv4_val);
std::optional<IPv6subnetList::const_iterator> match_subnet(IPv6subnetList &ipv6_list, const uint8_t *ipv6_val);
bool match_subnet(IPv4subnetList &ipv4_list, IPv6subnetList &ipv6_list, const std::string &ip_val);
uint8_t get_cidr(uint32_t mask);
uint8_t get_cidr(uint8_t *addr, size_t size);
uint32_t get_subnet(uint32_t addr, uint8_t cidr);
std::array<uint8_t, 16> get_subnet(const uint8_t *addr, uint8_t cidr);
}