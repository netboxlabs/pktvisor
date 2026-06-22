/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#ifdef _WIN32
#include <Ws2tcpip.h>
#include <winsock2.h>
typedef int SOCKETLEN;
#else
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#define SOCKET_ERROR -1
#define INVALID_SOCKET -1
typedef socklen_t SOCKETLEN;
typedef int SOCKET;
#endif
#include "NetProbe.h"
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wzero-as-null-pointer-constant"
#pragma clang diagnostic ignored "-Wc99-extensions"
#endif
#include <pcapplusplus/IcmpLayer.h>
#include <pcapplusplus/IcmpV6Layer.h>
#include <pcapplusplus/IpAddress.h>
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif
#include <atomic>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <sigslot/signal.hpp>
#include <uvw/async.h>
#include <uvw/check.h>
#include <uvw/poll.h>
#include <uvw/timer.h>

namespace visor::input::netprobe {

// Build a self-contained pcpp::Packet carrying a received ICMPv6 echo REPLY. A raw ICMPv6 socket
// strips the IPv6 header, so this synthesizes one (DLT_RAW1) so the Packet parses IPv6 -> ICMPv6
// and survives the fan-out deep-copy; returns nullopt if the bytes are not a valid ICMPv6 echo
// reply. Exposed (not a private lambda) so the copy-survival contract can be unit-tested.
std::optional<pcpp::Packet> build_icmpv6_reply_carrier(const uint8_t *data, int len);

/**
 * @class PingReceiver
 * @brief PingReceiver class used for receiving ICMP Echo Responses.
 *
 *  This class is statically created, It means that it will be a single PingReceiver per Pktvisor process.
 */
class PingReceiver
{
    std::array<char, sizeof(pcpp::icmphdr) + 65507> _array;
    SOCKET _sock{INVALID_SOCKET};
    std::shared_ptr<uvw::poll_handle> _poll;
    std::array<char, sizeof(pcpp::icmpv6_echo_hdr) + 65507> _array6;
    SOCKET _sock6{INVALID_SOCKET};
    std::shared_ptr<uvw::poll_handle> _poll6;
    std::unique_ptr<std::thread> _io_thread;
    std::shared_ptr<uvw::loop> _io_loop;
    std::shared_ptr<uvw::async_handle> _async_h;
    std::vector<std::shared_ptr<uvw::async_handle>> _callbacks;
    std::mutex _callbacks_mtx; // guards _callbacks: mutated by register/remove on control threads, iterated by the timer fan-out on the receiver thread
    std::shared_ptr<uvw::timer_handle> _timer;
    std::vector<std::pair<pcpp::Packet, timespec>> _recv_packets;
    void _setup_receiver();

public:
    bool v6_active() const { return _sock6 != INVALID_SOCKET; }

    static std::vector<std::pair<pcpp::Packet, timespec>> recv_packets;
    static std::mutex recv_packets_mtx; // guards recv_packets: published by the receiver timer, read by per-probe async callbacks on other threads

    PingReceiver();
    ~PingReceiver();

    void register_async_callback(std::shared_ptr<uvw::async_handle> callback)
    {
        std::lock_guard<std::mutex> lk(_callbacks_mtx);
        _callbacks.push_back(callback);
    }

    void remove_async_callback(std::shared_ptr<uvw::async_handle> callback)
    {
        std::lock_guard<std::mutex> lk(_callbacks_mtx);
        _callbacks.erase(std::remove(_callbacks.begin(), _callbacks.end(), callback), _callbacks.end());
    }
};

/**
 * @class PingProbe
 * @brief PingProbe class used for sending ICMP Echo Requests.
 *
 *  This class is created for each specified target. However, it reuses a shared socket per thread (per UV_LOOP).
 *  I.e. each unique NetProbeInputStream with Ping Type will have a socket to send ICMP Echo Request.
 */
class PingProbe final : public NetProbe
{
    static std::unique_ptr<PingReceiver> _receiver;
    // Lock-free published view of _receiver for cross-thread readers (receiver_v6_active() is called
    // from the management/HTTP thread via info_json). _receiver owns the lifetime; this is stored
    // (release) once inside the call_once that constructs it and loaded (acquire) by those readers, so
    // a concurrent first construction cannot be observed as a torn pointer.
    static std::atomic<PingReceiver *> _receiver_view;
    static thread_local SOCKET _sock;
    static thread_local SOCKET _sock6;

    bool _init{false};
    bool _is_ipv6{false};
    bool _ip_set{false};
    uint8_t _sequence{0};
    uint8_t _internal_sequence{0};
    std::shared_ptr<uvw::timer_handle> _interval_timer;
    std::shared_ptr<uvw::timer_handle> _internal_timer;
    std::shared_ptr<uvw::async_handle> _recv_handler;
    SOCKETLEN _sin_length{0};
    std::vector<uint8_t> _payload_array;
    sockaddr_in _sa{};
    sockaddr_in6 _sa6{};

    void _send_icmp_v4(uint8_t sequence);
    void _send_icmp_v6(uint8_t sequence);
    std::optional<ErrorType> _get_addr();
    std::optional<ErrorType> _create_socket();
    void _close_socket();
    std::optional<bool> _force_ipv6;

public:
    static thread_local std::atomic<uint32_t> sock_count;
    static bool receiver_v6_active();
    // Close the per-io-thread shared send sockets. MUST run on the io thread that opened them
    // (_sock/_sock6 are thread_local); calling close from the control thread that runs start()/stop()
    // sees only INVALID_SOCKET and silently leaks the raw fd.
    static void close_thread_send_sockets();

    PingProbe(uint16_t id, const std::string &name, const pcpp::IPAddress &ip, const std::string &dns, std::optional<bool> force_ipv6 = std::nullopt)
        : NetProbe(id, name, ip, dns)
        , _force_ipv6(force_ipv6){};
    ~PingProbe() = default;
    bool start(std::shared_ptr<uvw::loop> io_loop) override;
    bool stop() override;
};
}
