#include "PingProbe.h"

#include "NetProbeException.h"
#include "ThreadName.h"
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/TimespecTimeval.h>
#include <spdlog/spdlog.h>
#include <uvw/idle.h>
#include <cstring>
#ifndef _WIN32
#include <netinet/icmp6.h>
#endif

namespace visor::input::netprobe {

std::vector<std::pair<pcpp::Packet, timespec>> PingReceiver::recv_packets{};
std::mutex PingReceiver::recv_packets_mtx{};
std::unique_ptr<PingReceiver> PingProbe::_receiver{nullptr};
std::atomic<PingReceiver *> PingProbe::_receiver_view{nullptr};
thread_local SOCKET PingProbe::_sock{INVALID_SOCKET};
thread_local SOCKET PingProbe::_sock6{INVALID_SOCKET};

std::optional<pcpp::Packet> build_icmpv6_reply_carrier(const uint8_t *data, int len)
{
    if (len < static_cast<int>(sizeof(pcpp::icmpv6_echo_hdr))) {
        return std::nullopt; // too short to be an ICMPv6 echo
    }
    // A raw ICMPv6 socket delivers the bare ICMPv6 message (no IPv6 header). Synthesize a minimal
    // 40-byte IPv6 header so a DLT_RAW1 RawPacket parses IPv6 -> ICMPv6 and the parsed layers are
    // owned by the Packet (no bad delete[] on a freestanding layer). The Packet owns the heap
    // RawPacket (which owns the buffer), so the returned Packet is self-contained and survives the
    // fan-out deep-copy. Mirrors the v4 receive idiom (whose raw socket carries the IP header).
    constexpr int IP6_HDR_LEN = 40;
    auto *buf = new uint8_t[IP6_HDR_LEN + len];
    std::memset(buf, 0, IP6_HDR_LEN);
    buf[0] = 0x60;                                     // IPv6, version 6
    buf[4] = static_cast<uint8_t>((len >> 8) & 0xff);  // payload length (high byte)
    buf[5] = static_cast<uint8_t>(len & 0xff);         // payload length (low byte)
    buf[6] = static_cast<uint8_t>(IPPROTO_ICMPV6);     // next header = 58 (ICMPv6)
    buf[7] = 64;                                       // hop limit
    std::memcpy(buf + IP6_HDR_LEN, data, static_cast<size_t>(len));
    timeval time{};
    auto packet = pcpp::Packet(new pcpp::RawPacket(buf, IP6_HDR_LEN + len, time, true, pcpp::LINKTYPE_DLT_RAW1), true);
    auto *echo = packet.getLayerOfType<pcpp::ICMPv6EchoLayer>();
    if (echo == nullptr || echo->getMessageType() != pcpp::ICMPv6MessageType::ICMPv6_ECHO_REPLY) {
        return std::nullopt; // not an ICMPv6 echo reply
    }
    return packet;
}

PingReceiver::PingReceiver()
{
    _setup_receiver();
}
PingReceiver::~PingReceiver()
{
    _poll->close();
    if (_poll6) {
        _poll6->close();
    }
    if (_async_h && _io_thread) {
        // we have to use AsyncHandle to stop the loop from the same thread the loop is running in
        _async_h->send();
        // waits for _io_loop->run() to return
        if (_io_thread->joinable()) {
            _io_thread->join();
        }
    }
#ifdef _WIN32
    closesocket(_sock);
#else
    close(_sock);
#endif
    _sock = INVALID_SOCKET;
    if (_sock6 != INVALID_SOCKET) {
#ifdef _WIN32
        closesocket(_sock6);
#else
        close(_sock6);
#endif
        _sock6 = INVALID_SOCKET;
    }
}

void PingReceiver::_setup_receiver()
{
    _io_loop = uvw::loop::create();
    if (!_io_loop) {
        throw NetProbeException("unable to create io loop");
    }
    // AsyncHandle lets us stop the loop from its own thread
    _async_h = _io_loop->resource<uvw::async_handle>();
    if (!_async_h) {
        throw NetProbeException("unable to initialize AsyncHandle");
    }
    _async_h->on<uvw::async_event>([this](const auto &, auto &handle) {
        _io_loop->stop();
        _io_loop->close();
        handle.close();
    });

    _sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
#ifdef _WIN32
    if (_sock == INVALID_SOCKET) {
        throw NetProbeException("unable to create receiver socket");
    }
    unsigned long flag = 1;
    if (ioctlsocket(_sock, FIONBIO, &flag) == SOCKET_ERROR) {
        throw NetProbeException("unable to create receiver socket");
    }
#else
    if (_sock == SOCKET_ERROR) {
        _sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    }
    int flag = 1;
    if ((flag = fcntl(_sock, F_GETFL, 0)) == SOCKET_ERROR) {
        throw NetProbeException("unable to create receiver socket");
    }
    if (fcntl(_sock, F_SETFL, flag | O_NONBLOCK) == SOCKET_ERROR) {
        throw NetProbeException("unable to create receiver socket");
    }
#endif

    _poll = _io_loop->resource<uvw::poll_handle>(static_cast<uvw::os_socket_handle>(_sock));
    if (!_poll) {
        throw NetProbeException("PingProbe - unable to initialize PollHandle");
    }
    _poll->on<uvw::error_event>([](const auto &, auto &handler) {
        handler.close();
    });

    _poll->on<uvw::poll_event>([this](const uvw::poll_event &, uvw::poll_handle &) {
        int rc{0};
        while (rc != SOCKET_ERROR) {
            rc = recv(_sock, _array.data(), _array.size(), 0);
            if (rc != SOCKET_ERROR) {
                timespec stamp;
                std::timespec_get(&stamp, TIME_UTC);
                timeval time;
                TIMESPEC_TO_TIMEVAL(&time, &stamp);
                pcpp::RawPacket raw(reinterpret_cast<uint8_t *>(_array.data()), rc, time, false, pcpp::LINKTYPE_DLT_RAW1);
                _recv_packets.emplace_back(pcpp::Packet(&raw, pcpp::ICMP), stamp);
            }
        }
    });

    _timer = _io_loop->resource<uvw::timer_handle>();
    _timer->on<uvw::timer_event>([this](const auto &, auto &) {
        if (!_recv_packets.empty()) {
            {
                // Publish under the lock; consumers snapshot recv_packets under the same lock, so a
                // later publish cannot realloc the vector out from under a mid-iteration consumer.
                std::lock_guard<std::mutex> lk(recv_packets_mtx);
                recv_packets = _recv_packets;
            }
            _recv_packets.clear();
            // Guard the callback list against concurrent register/remove on control threads.
            std::lock_guard<std::mutex> lk(_callbacks_mtx);
            for (const auto &callback : _callbacks) {
                callback->send();
            }
        }
    });
    _timer->start(uvw::timer_handle::time{100}, uvw::timer_handle::time{100});

    _poll->init();
    _poll->start(uvw::poll_handle::poll_event_flags::READABLE);

    // ICMPv6 receive socket — RAW only, opened tolerantly (no throw; warn-log on failure so
    // v4-only/unprivileged hosts keep working). No SOCK_DGRAM fallback: a datagram ICMPv6 socket
    // only receives replies for echoes IT sent, but each probe sends on its own (separate) socket,
    // so a DGRAM receiver would never see the replies (all reported as timeouts). IPv6 ping
    // therefore requires raw-socket privilege (CAP_NET_RAW / root / Administrator).
    _sock6 = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    if (_sock6 == INVALID_SOCKET) {
        if (auto lg = spdlog::get("visor")) {
            lg->warn("netprobe: unable to open ICMPv6 receive socket; IPv6 ping disabled");
        }
    } else {
#ifdef _WIN32
        unsigned long flag6 = 1;
        ioctlsocket(_sock6, FIONBIO, &flag6);
#else
        int flag6 = fcntl(_sock6, F_GETFL, 0);
        if (flag6 != SOCKET_ERROR) {
            fcntl(_sock6, F_SETFL, flag6 | O_NONBLOCK);
        }
        // _sock6 is always RAW here, so ICMP6_FILTER (a RAW-only option) applies: pass only echo
        // replies (type 129), drop everything else in-kernel.
        struct icmp6_filter filt;
        ICMP6_FILTER_SETBLOCKALL(&filt);
        ICMP6_FILTER_SETPASS(ICMP6_ECHO_REPLY, &filt);
        setsockopt(_sock6, IPPROTO_ICMPV6, ICMP6_FILTER, &filt, sizeof(filt));
#endif
        _poll6 = _io_loop->resource<uvw::poll_handle>(static_cast<uvw::os_socket_handle>(_sock6));
        bool v6_ready = false;
        if (_poll6) {
            _poll6->on<uvw::error_event>([](const auto &, auto &handler) { handler.close(); });
            _poll6->on<uvw::poll_event>([this](const uvw::poll_event &, uvw::poll_handle &) {
                // Read one datagram per (level-triggered) poll event. The socket is non-blocking, but
                // looping until EWOULDBLOCK would let a flood of replies starve the v4 poll/timer on
                // this same thread; uvw re-fires the event while data remains, so a single read keeps
                // the receiver fair and matches the v4 path's one-read-per-event behavior.
                int rc = recvfrom(_sock6, _array6.data(), _array6.size(), 0, nullptr, nullptr);
                if (rc <= 0) {
                    return;
                }
                // A raw ICMPv6 socket strips the IPv6 header, so pcpp::Packet cannot parse the bare
                // buffer (createFirstLayer dispatches on link-layer type) and a freestanding
                // ICMPv6EchoLayer over _array6 would make ~Layer() delete[] the std::array storage.
                // build_icmpv6_reply_carrier synthesizes an IPv6 header so a self-owning Packet
                // parses IPv6 -> ICMPv6 and survives the fan-out deep-copy.
                if (auto carrier = build_icmpv6_reply_carrier(reinterpret_cast<uint8_t *>(_array6.data()), rc)) {
                    timespec stamp;
                    std::timespec_get(&stamp, TIME_UTC);
                    _recv_packets.emplace_back(*carrier, stamp);
                }
            });
            // resource<>() already initialized the handle; start() is what actually arms polling, so
            // gate readiness on its return rather than merely on _poll6 being non-null.
            v6_ready = (_poll6->start(uvw::poll_handle::poll_event_flags::READABLE) == 0);
        }
        if (!v6_ready) {
            // The poll handle could not be created or armed for _sock6. With no armed handler nothing
            // ever reads replies, yet v6_active() (which only checks _sock6) would report IPv6 as
            // working and the send path would keep emitting echoes that silently time out. Close and
            // invalidate _sock6 so IPv6 ping is cleanly disabled instead of silently broken.
            if (auto lg = spdlog::get("visor")) {
                lg->warn("netprobe: unable to arm ICMPv6 poll handler; IPv6 ping disabled");
            }
            if (_poll6) {
                // Tear down the (never-armed) poll handle so it isn't held for the receiver's lifetime.
                // Dropping our reference is safe: uvw's poll_handle self-retains on a successful init()
                // (resource<>() stored an internal self_ptr), so the handle stays alive until the loop
                // processes uv_close and the close callback clears that self-reference.
                _poll6->close();
                _poll6.reset();
            }
#ifdef _WIN32
            closesocket(_sock6);
#else
            close(_sock6);
#endif
            _sock6 = INVALID_SOCKET;
        }
    }

    // spawn the loop
    _io_thread = std::make_unique<std::thread>([this] {
        thread::change_self_name("receiver", "ping");
        _io_loop->run();
    });
}

bool PingProbe::receiver_v6_active()
{
    // Read the published view rather than _receiver directly: this is called from the management/HTTP
    // thread (via info_json) and may run concurrently with the call_once that first constructs the
    // receiver. The acquire load pairs with the release store in that call_once.
    auto *r = _receiver_view.load(std::memory_order_acquire);
    return r && r->v6_active();
}

bool PingProbe::start(std::shared_ptr<uvw::loop> io_loop)
{
    if (_init || ((_ip.isIPv4() ? _ip.getIPv4() == pcpp::IPv4Address::Zero : _ip.getIPv6() == pcpp::IPv6Address::Zero) && _dns.empty())) {
        return false;
    }

    // add validator
    _payload_array = validator;
    if (_config.packet_payload_size < validator.size()) {
        _config.packet_payload_size = validator.size();
    }
    _payload_array.resize(_config.packet_payload_size);
    std::fill(_payload_array.begin() + validator.size(), _payload_array.end(), 0);

    _io_loop = io_loop;

    // Construct the process-wide receiver exactly once, even if several input streams start
    // concurrently on different threads. A plain `if (!_receiver)` would race and double-construct
    // (each opening raw sockets + spawning an io thread) while also racing the unique_ptr itself.
    // If the constructor throws, call_once leaves the flag unset so a later start() can retry.
    static std::once_flag receiver_once;
    std::call_once(receiver_once, [] {
        _receiver = std::make_unique<PingReceiver>();
        // Publish for lock-free cross-thread readers (receiver_v6_active); release pairs with their acquire.
        _receiver_view.store(_receiver.get(), std::memory_order_release);
    });

    _interval_timer = _io_loop->resource<uvw::timer_handle>();
    if (!_interval_timer) {
        throw NetProbeException("PingProbe - unable to initialize interval TimerHandle");
    }
    _interval_timer->on<uvw::timer_event>([this](const auto &, auto &) {
        _internal_sequence = 0;

        if (auto error = _get_addr(); error.has_value()) {
            _fail(error.value(), TestType::Ping, _name);
            return;
        }
        if (auto error = _create_socket(); error.has_value()) {
            _fail(error.value(), TestType::Ping, _name);
            return;
        }

        _internal_timer = _io_loop->resource<uvw::timer_handle>();
        _internal_timer->on<uvw::timer_event>([this](const auto &, auto &handle) {
            if (_internal_sequence < static_cast<uint8_t>(_config.packets_per_test)) {
                _internal_sequence++;
                _is_ipv6 ? _send_icmp_v6(_internal_sequence) : _send_icmp_v4(_internal_sequence);
            } else {
                handle.stop();
                handle.close();
            }
        });

        (_sequence == UCHAR_MAX) ? _sequence = 0 : _sequence++;
        _is_ipv6 ? _send_icmp_v6(_internal_sequence) : _send_icmp_v4(_internal_sequence);
        _internal_sequence++;
        _internal_timer->start(uvw::timer_handle::time{_config.packets_interval_msec}, uvw::timer_handle::time{_config.packets_interval_msec});
    });

    _recv_handler = _io_loop->resource<uvw::async_handle>();
    if (!_recv_handler) {
        throw NetProbeException("PingProbe - unable to initialize AsyncHandle receiver");
    }
    _recv_handler->on<uvw::async_event>([this](const auto &, auto &) {
        // note this processes received packets across ALL active ping probes (because of the single receiver thread)
        // the expectation is that packets which did not originate from this probe will be ignored by the handler attached to this probe,
        // since it did not originate from it.
        // Snapshot under the lock so a concurrent publish on the receiver thread cannot reallocate the
        // shared vector while we iterate; process the local copy without holding the lock.
        std::vector<std::pair<pcpp::Packet, timespec>> packets;
        {
            std::lock_guard<std::mutex> lk(PingReceiver::recv_packets_mtx);
            packets = PingReceiver::recv_packets;
        }
        for (auto &[packet, stamp] : packets) {
            _recv(packet, TestType::Ping, _name, stamp);
        }
    });
    _receiver->register_async_callback(_recv_handler);
    _recv_handler->init();

    _interval_timer->start(uvw::timer_handle::time{0}, uvw::timer_handle::time{_config.interval_msec});
    _init = true;
    return true;
}

bool PingProbe::stop()
{
    if (_interval_timer) {
        _interval_timer->stop();
        _interval_timer->close();
    }
    if (_recv_handler) {
        _receiver->remove_async_callback(_recv_handler);
        _recv_handler->close();
    }
    return true;
}

std::optional<ErrorType> PingProbe::_get_addr()
{
    if (_ip_set) {
        return std::nullopt;
    }

    // don't need dns resolution
    if (_dns.empty()) {
        if (_ip.isIPv4()) {
            uint32_t ip_int(_ip.getIPv4().toInt());
            memcpy(&_sa.sin_addr, &ip_int, sizeof(_sa.sin_addr));
            _sa.sin_family = AF_INET;
            _sin_length = sizeof(_sa);
            _ip_set = true;
            return std::nullopt;
        } else {
            _is_ipv6 = true;
            auto ip_bytes = _ip.getIPv6().toBytes();
            for (int i = 0; i < 16; ++i) {
                _sa6.sin6_addr.s6_addr[i] = ip_bytes[i];
            }
            _sa6.sin6_family = AF_INET6;
            _sin_length = sizeof(_sa6);
            _ip_set = true;
            return std::nullopt;
        }
    }

    // do Dns lookup for interval loop
    auto request = _io_loop->resource<uvw::get_addr_info_req>();
    auto response = request->node_addr_info_sync(_dns);
    if (!response.first) {
        return ErrorType::DnsLookupFailure;
    }
    const bool v6_only = _force_ipv6.has_value() && *_force_ipv6;
    const bool v4_only = _force_ipv6.has_value() && !*_force_ipv6;

    if (!v6_only) { // IPv4 (preferred) unless forced v6
        for (auto addr = response.second.get(); addr != nullptr; addr = addr->ai_next) {
            if (addr->ai_family == AF_INET) {
                memcpy(&_sa, reinterpret_cast<sockaddr_in *>(addr->ai_addr), sizeof(struct sockaddr_in));
                _sa.sin_family = AF_INET;
                _sin_length = sizeof(_sa);
                _is_ipv6 = false;
                // NOTE: do not set _ip_set for DNS targets — re-resolve every interval (as develop did)
                // so round-robin / failover / short-TTL names are not pinned to the first address.
                return std::nullopt;
            }
        }
    }
    if (!v4_only) { // IPv6
        for (auto addr = response.second.get(); addr != nullptr; addr = addr->ai_next) {
            if (addr->ai_family == AF_INET6) {
                memcpy(&_sa6, reinterpret_cast<sockaddr_in6 *>(addr->ai_addr), sizeof(struct sockaddr_in6));
                _sa6.sin6_family = AF_INET6;
                _sin_length = sizeof(_sa6);
                _is_ipv6 = true;
                // NOTE: do not set _ip_set for DNS targets — re-resolve every interval (see above).
                return std::nullopt;
            }
        }
    }
    return ErrorType::InvalidIp;
}

std::optional<ErrorType> PingProbe::_create_socket()
{
    // A v6 probe's send socket is separate from the shared receiver's raw ICMPv6 socket; replies are
    // only ever read off the receiver. If the receiver has no working v6 socket, sending would just
    // produce echoes that can never be matched (perpetual silent timeouts), so fail cleanly here and
    // surface a socket error instead. (v4 has no such split — its receiver socket always opens.)
    if (_is_ipv6 && !receiver_v6_active()) {
        return ErrorType::SocketError;
    }
    SOCKET &sock = _is_ipv6 ? _sock6 : _sock;
    if (sock != INVALID_SOCKET) {
        return std::nullopt;
    }
    int domain = _is_ipv6 ? AF_INET6 : AF_INET;
    int proto = _is_ipv6 ? IPPROTO_ICMPV6 : IPPROTO_ICMP;

    sock = socket(domain, SOCK_RAW, proto);
#ifdef _WIN32
    if (sock == INVALID_SOCKET) {
        return ErrorType::SocketError;
    }
    unsigned long flag = 1;
    if (ioctlsocket(sock, FIONBIO, &flag) == SOCKET_ERROR) {
        return ErrorType::SocketError;
    }
    // No IPV6_CHECKSUM setsockopt here: for an IPPROTO_ICMPV6 raw socket the kernel computes and
    // inserts the mandatory ICMPv6 checksum unconditionally (RFC 3542 sec 3.1) on both POSIX and
    // Windows, and attempting to set IPV6_CHECKSUM on such a socket fails. So _send_icmp_v6 leaves
    // the checksum 0 and the kernel fills it. (The Windows v6 send/recv path still needs end-to-end
    // verification on a real Windows host — including inbound raw ICMPv6 delivery.)
#else
    // IPv4 may fall back to an unprivileged SOCK_DGRAM "ping" socket; IPv6 must not. The shared
    // receiver only polls a raw _sock6, and a DGRAM ICMPv6 socket delivers replies to the sending
    // socket instead — which nothing reads — so every v6 reply would be lost. Fail v6 cleanly so the
    // caller reports a socket error rather than silently timing out every probe.
    if (sock == INVALID_SOCKET && !_is_ipv6) {
        sock = socket(domain, SOCK_DGRAM, proto); // best-effort; matching reliable on RAW only
    }
    if (sock == INVALID_SOCKET) {
        return ErrorType::SocketError;
    }
    int flag = 1;
    if ((flag = fcntl(sock, F_GETFL, 0)) == SOCKET_ERROR) {
        return ErrorType::SocketError;
    }
    if (fcntl(sock, F_SETFL, flag | O_NONBLOCK) == SOCKET_ERROR) {
        return ErrorType::SocketError;
    }
#endif
    return std::nullopt;
}

void PingProbe::_send_icmp_v4(uint8_t sequence)
{
    auto icmp = pcpp::IcmpLayer();
    timespec stamp;
    std::timespec_get(&stamp, TIME_UTC);
    const uint64_t stamp64 = stamp.tv_sec * 1000000000ULL + stamp.tv_nsec;
    icmp.setEchoRequestData(_id, (static_cast<uint16_t>(_sequence) << 8) | sequence, stamp64, _payload_array.data(), _payload_array.size());
    icmp.computeCalculateFields();
    int rc = sendto(_sock, reinterpret_cast<char *>(icmp.getData()), icmp.getDataLen(), 0, reinterpret_cast<sockaddr *>(&_sa), _sin_length);
    if (rc != SOCKET_ERROR) {
        pcpp::Packet packet;
        packet.addLayer(&icmp);
        _send(packet, TestType::Ping, _name, stamp);
    }
}

void PingProbe::_send_icmp_v6(uint8_t sequence)
{
    timespec stamp;
    std::timespec_get(&stamp, TIME_UTC);
    uint16_t seq16 = (static_cast<uint16_t>(_sequence) << 8) | sequence;
    // The 8-byte ICMPv6 echo header carries no timestamp; the transaction manager
    // carries the send time, matched by id+sequence (same as v4). Identifier = per-probe _id.
    auto echo = pcpp::ICMPv6EchoLayer(pcpp::ICMPv6EchoLayer::REQUEST, _id, seq16,
        _payload_array.data(), _payload_array.size());
    // Do NOT call computeCalculateFields(): the kernel owns the ICMPv6 checksum and pcpp
    // cannot compute it without an IPv6 prev-layer/pseudo-header. The layer is used only for
    // the in-process metric record (id+seq), never re-serialized to the wire.
    int rc = sendto(_sock6, reinterpret_cast<char *>(echo.getData()), echo.getDataLen(), 0,
        reinterpret_cast<sockaddr *>(&_sa6), _sin_length);
    if (rc != SOCKET_ERROR) {
        pcpp::Packet packet;
        packet.addLayer(&echo);
        _send(packet, TestType::Ping, _name, stamp);
    }
}

void PingProbe::close_thread_send_sockets()
{
#ifdef _WIN32
    if (_sock != INVALID_SOCKET) closesocket(_sock);
    if (_sock6 != INVALID_SOCKET) closesocket(_sock6);
#else
    if (_sock != INVALID_SOCKET) close(_sock);
    if (_sock6 != INVALID_SOCKET) close(_sock6);
#endif
    _sock = INVALID_SOCKET;
    _sock6 = INVALID_SOCKET;
}
}
