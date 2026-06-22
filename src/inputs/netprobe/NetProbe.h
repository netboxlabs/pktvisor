/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wzero-as-null-pointer-constant"
#endif
#include <pcapplusplus/IpAddress.h>
#include <pcapplusplus/Packet.h>
#include <uvw/loop.h>
#include <uvw/dns.h>
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

namespace visor::input::netprobe {

enum class ErrorType {
    Timeout,
    SocketError,
    DnsLookupFailure,
    InvalidIp,
    ConnectFailure
};

enum class TestType {
    Ping,
    HTTP,
    UDP,
    TCP
};

typedef std::function<void(pcpp::Packet &, TestType, const std::string &, timespec)> SendCallback;
typedef std::function<void(pcpp::Packet &, TestType, const std::string &, timespec)> RecvCallback;
typedef std::function<void(ErrorType, TestType, const std::string &)> FailCallback;

static const std::vector<uint8_t> validator = {0x70, 0x6b, 0x74, 0x76, 0x69, 0x73, 0x6f, 0x72}; // "pktvisor" in hex

class NetProbe
{
protected:
    uint16_t _id;
    struct Configs {
        uint64_t interval_msec;
        uint64_t timeout_msec;
        uint64_t packets_per_test;
        uint64_t packets_interval_msec;
        uint64_t packet_payload_size;
    };
    Configs _config{0, 0, 0, 0, 0};
    std::string _name;
    pcpp::IPAddress _ip;
    std::string _dns;
    std::shared_ptr<uvw::loop> _io_loop;
    RecvCallback _recv;
    SendCallback _send;
    FailCallback _fail;

    std::pair<std::string, bool> _resolve_dns(bool first_match = true, bool ipv4 = false)
    {
        auto request = _io_loop->resource<uvw::get_addr_info_req>();
        auto response = request->node_addr_info_sync(_dns);
        if (!response.first) {
            return {std::string(), false};
        }

        auto base = response.second.get();
        // pass 1: IPv4 (preferred) unless caller forces v6
        if (first_match || ipv4) {
            for (auto addr = base; addr != nullptr; addr = addr->ai_next) {
                if (addr->ai_family == AF_INET) {
                    char buffer[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &reinterpret_cast<struct sockaddr_in *>(addr->ai_addr)->sin_addr, buffer, INET_ADDRSTRLEN);
                    return {buffer, true};
                }
            }
        }
        // pass 2: IPv6
        if (first_match || !ipv4) {
            for (auto addr = base; addr != nullptr; addr = addr->ai_next) {
                if (addr->ai_family == AF_INET6) {
                    char buffer[INET6_ADDRSTRLEN];
                    inet_ntop(AF_INET6, &reinterpret_cast<struct sockaddr_in6 *>(addr->ai_addr)->sin6_addr, buffer, INET6_ADDRSTRLEN);
                    return {buffer, false};
                }
            }
        }
        return {std::string(), false};
    }

public:
    NetProbe(uint16_t id, const std::string &name, const pcpp::IPAddress &ip, const std::string &dns)
        : _id(id)
        , _name(name)
        , _ip(ip)
        , _dns(dns)
    {
    }

    virtual ~NetProbe()
    {
    }

    void set_configs(uint64_t interval_msec, uint64_t timeout_msec, uint64_t packets_per_test, uint64_t packets_interval_msec, uint64_t packet_payload_size)
    {
        _config = {interval_msec, timeout_msec, packets_per_test, packets_interval_msec, packet_payload_size};
    }

    void set_callbacks(SendCallback send, RecvCallback recv, FailCallback fail)
    {
        _send = send;
        _recv = recv;
        _fail = fail;
    }

    virtual bool start(std::shared_ptr<uvw::loop> io_loop) = 0;
    virtual bool stop() = 0;
};
}