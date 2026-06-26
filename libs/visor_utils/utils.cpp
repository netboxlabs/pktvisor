#include "utils.h"
#include "EndianPortable.h"
#include <pcapplusplus/IpAddress.h>
#include <pcapplusplus/IpUtils.h>
#include <fmt/format.h>
#include <sstream>
#include <utility> // std::pair
#ifdef _WIN32
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

namespace visor::lib::utils {

template <typename Out>
static void split(const std::string &s, char delim, Out result)
{
    std::stringstream ss;
    ss.str(s);
    std::string item;
    while (std::getline(ss, item, delim)) {
        *(result++) = item;
    }
}

static uint8_t reverse_bits(uint8_t n)
{
    static constexpr std::array<uint8_t, 9> bit_reverse_masks{0, 128, 192, 224, 240, 248, 252, 254, 255};
    return bit_reverse_masks[n];
}

std::optional<IPv4subnetList::const_iterator> match_subnet(IPv4subnetList &ipv4_list, uint32_t ipv4_val)
{
    if (ipv4_val && !ipv4_list.empty()) {
        in_addr ipv4{};
        std::memcpy(&ipv4, &ipv4_val, sizeof(in_addr));
        for (IPv4subnetList::const_iterator it = ipv4_list.begin(); it != ipv4_list.end(); ++it) {
            uint8_t cidr = it->cidr;
            if (cidr == 0) {
                return it;
            }
            if (!get_subnet((ipv4.s_addr ^ it->addr.s_addr), cidr)) {
                return it;
            }
        }
    }
    return std::nullopt;
}

std::optional<IPv6subnetList::const_iterator> match_subnet(IPv6subnetList &ipv6_list, const uint8_t *ipv6_val)
{
    if (ipv6_val && !ipv6_list.empty()) {
        in6_addr ipv6{};
        std::memcpy(&ipv6, ipv6_val, sizeof(in6_addr));
        for (IPv6subnetList::const_iterator it = ipv6_list.begin(); it != ipv6_list.end(); ++it) {
            uint8_t prefixLength = it->cidr;
            auto network = it->addr;
            uint8_t compareByteCount = prefixLength / 8;
            uint8_t compareBitCount = prefixLength % 8;
            bool result = false;
            if (compareByteCount > 0) {
                result = std::memcmp(&network.s6_addr, &ipv6.s6_addr, compareByteCount) == 0;
            }
            if ((result || prefixLength < 8) && compareBitCount > 0) {
                uint8_t subSubnetByte = network.s6_addr[compareByteCount] >> (8 - compareBitCount);
                uint8_t subThisByte = ipv6.s6_addr[compareByteCount] >> (8 - compareBitCount);
                result = subSubnetByte == subThisByte;
            }
            if (result) {
                return it;
            }
        }
    }
    return std::nullopt;
}

bool match_subnet(IPv4subnetList &ipv4_list, IPv6subnetList &ipv6_list, const std::string &ip_val)
{
    if (pcpp::IPv4Address::isValidIPv4Address(ip_val)) {
        return match_subnet(ipv4_list, pcpp::IPv4Address(ip_val).toInt()).has_value();
    } else if (pcpp::IPv6Address::isValidIPv6Address(ip_val)) {
        return match_subnet(ipv6_list, pcpp::IPv6Address(ip_val).toBytes()).has_value();
    }
    return false;
}

uint8_t get_cidr(uint32_t mask)
{
    uint8_t cidr{0};
    while (mask > 0) {
        mask >>= 1;
        cidr++;
    }
    return cidr;
}

uint8_t get_cidr(uint8_t *addr, size_t size)
{
    uint8_t cidr{0};
    for (size_t i = 0; i < size; i++) {
        while (addr[i]) {
            addr[i] >>= 1;
            cidr++;
        }
    }
    return cidr;
}

uint32_t get_subnet(uint32_t addr, uint8_t cidr)
{
    return addr & (htobe32((0xFFFFFFFFu) << (32 - cidr)));
}

std::array<uint8_t, 16> get_subnet(const uint8_t *addr, uint8_t cidr)
{
    std::array<uint8_t, 16> mask{};
    std::memcpy(mask.data(), addr, mask.size());
    uint8_t byte_count = cidr / 8;
    uint8_t bit_count = cidr % 8;
    for (uint8_t b = mask.size(); b-- > 0;) {
        if (b > byte_count) {
            mask[b] = 0;
        } else if (b == byte_count && bit_count) {
            mask[b] &= reverse_bits(bit_count);
        } else if (b == byte_count) {
            mask[b] = 0;
        }
    }
    return mask;
}

void parse_host_specs(const std::vector<std::string> &host_list, IPv4subnetList &ipv4_list, IPv6subnetList &ipv6_list)
{
    for (const auto &host : host_list) {
        auto delimiter = host.find('/');
        if (delimiter == std::string::npos) {
            throw UtilsException(fmt::format("invalid CIDR: {}", host));
        }
        auto ip = host.substr(0, delimiter);
        auto cidr = host.substr(++delimiter);
        auto not_number = std::count_if(cidr.begin(), cidr.end(),
            [](unsigned char c) { return !std::isdigit(c); });
        if (not_number) {
            throw UtilsException(fmt::format("invalid CIDR: {}", host));
        }

        auto cidr_number = std::stoi(cidr);
        if (ip.find(':') != std::string::npos) {
            if (cidr_number < 0 || cidr_number > 128) {
                throw UtilsException(fmt::format("invalid CIDR: {}", host));
            }
            in6_addr ipv6{};
            if (inet_pton(AF_INET6, ip.c_str(), &ipv6) != 1) {
                throw UtilsException(fmt::format("invalid IPv6 address: {}", ip));
            }
            ipv6_list.push_back({ipv6, static_cast<uint8_t>(cidr_number), host});
        } else {
            if (cidr_number < 0 || cidr_number > 32) {
                throw UtilsException(fmt::format("invalid CIDR: {}", host));
            }
            in_addr ipv4{};
            if (inet_pton(AF_INET, ip.c_str(), &ipv4) != 1) {
                throw UtilsException(fmt::format("invalid IPv4 address: {}", ip));
            }
            ipv4_list.push_back({ipv4, static_cast<uint8_t>(cidr_number), host});
        }
    }
}

void append_interface_host_subnets(
    bool host_set_provided,
    const std::vector<std::pair<in_addr, uint8_t>> &v4_addrs,
    const std::vector<std::pair<in6_addr, uint8_t>> &v6_addrs,
    IPv4subnetList &host_ipv4,
    IPv6subnetList &host_ipv6)
{
    // An explicit host_spec is authoritative: do not widen it with the capture
    // interface's own address/subnet. (When no host_spec is given, the interface
    // subnet is added on purpose, to distinguish inside vs. outside traffic.)
    if (host_set_provided) {
        return;
    }
    char buf[INET6_ADDRSTRLEN];
    for (const auto &[addr, prefix] : v4_addrs) {
        inet_ntop(AF_INET, &addr, buf, sizeof(buf));
        host_ipv4.push_back({addr, prefix, std::string(buf) + "/" + std::to_string(prefix)});
    }
    for (const auto &[addr, prefix] : v6_addrs) {
        inet_ntop(AF_INET6, &addr, buf, sizeof(buf));
        host_ipv6.push_back({addr, prefix, std::string(buf) + "/" + std::to_string(prefix)});
    }
}

std::vector<std::string> split_str_to_vec_str(const std::string &spec, const char &delimiter)
{
    std::vector<std::string> elems;
    split(spec, delimiter, std::back_inserter(elems));
    return elems;
}

bool ipv4_to_sockaddr(const pcpp::IPv4Address &ip, struct sockaddr_in *sa)
{
    memset(sa, 0, sizeof(struct sockaddr_in));
    uint32_t ip_int(ip.toInt());
    memcpy(&sa->sin_addr, &ip_int, sizeof(sa->sin_addr));
    sa->sin_family = AF_INET;
    return true;
}

bool ipv6_to_sockaddr(const pcpp::IPv6Address &ip, struct sockaddr_in6 *sa)
{
    memset(sa, 0, sizeof(struct sockaddr_in6));
    auto ip_bytes = ip.toBytes();
    for (int i = 0; i < 16; ++i) {
        sa->sin6_addr.s6_addr[i] = ip_bytes[i];
    }
    sa->sin6_family = AF_INET6;
    return true;
}

}