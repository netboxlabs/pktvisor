#include "PingProbe.h"

#include "NetProbeException.h"
#include "ThreadName.h"
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/TimespecTimeval.h>
#include <spdlog/spdlog.h>
#include <uvw/idle.h>
#ifndef _WIN32
#include <netinet/icmp6.h>
#endif

namespace visor::input::netprobe {

std::vector<std::pair<pcpp::Packet, timespec>> PingReceiver::recv_packets{};
std::unique_ptr<PingReceiver> PingProbe::_receiver{nullptr};
thread_local std::atomic<uint32_t> PingProbe::sock_count{0};
thread_local SOCKET PingProbe::_sock{INVALID_SOCKET};
thread_local SOCKET PingProbe::_sock6{INVALID_SOCKET};

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
            recv_packets = _recv_packets;
            _recv_packets.clear();
            for (const auto &callback : _callbacks) {
                callback->send();
            }
        }
    });
    _timer->start(uvw::timer_handle::time{100}, uvw::timer_handle::time{100});

    _poll->init();
    _poll->start(uvw::poll_handle::poll_event_flags::READABLE);

    // ICMPv6 receive socket — tolerant open (no throw; warn-log failure so v4-only/unprivileged hosts keep working)
    _sock6 = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    bool sock6_raw = (_sock6 != INVALID_SOCKET);
#ifndef _WIN32
    if (_sock6 == INVALID_SOCKET) {
        _sock6 = socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6); // best-effort
        sock6_raw = false;
    }
#endif
    if (_sock6 == INVALID_SOCKET) {
        spdlog::get("visor")->warn("netprobe: unable to open ICMPv6 receive socket; IPv6 ping disabled");
    } else {
#ifdef _WIN32
        unsigned long flag6 = 1;
        ioctlsocket(_sock6, FIONBIO, &flag6);
#else
        int flag6 = fcntl(_sock6, F_GETFL, 0);
        if (flag6 != SOCKET_ERROR) {
            fcntl(_sock6, F_SETFL, flag6 | O_NONBLOCK);
        }
        if (sock6_raw) { // ICMP6_FILTER is a RAW-only option
            struct icmp6_filter filt;
            ICMP6_FILTER_SETBLOCKALL(&filt);
            ICMP6_FILTER_SETPASS(ICMP6_ECHO_REPLY, &filt);
            setsockopt(_sock6, IPPROTO_ICMPV6, ICMP6_FILTER, &filt, sizeof(filt));
        }
#endif
        _poll6 = _io_loop->resource<uvw::poll_handle>(static_cast<uvw::os_socket_handle>(_sock6));
        if (_poll6) {
            _poll6->on<uvw::error_event>([](const auto &, auto &handler) { handler.close(); });
            _poll6->on<uvw::poll_event>([this](const uvw::poll_event &, uvw::poll_handle &) {
                int rc{0};
                while (rc != SOCKET_ERROR) {
                    rc = recvfrom(_sock6, _array6.data(), _array6.size(), 0, nullptr, nullptr);
                    if (rc == SOCKET_ERROR || rc <= 0) {
                        break;
                    }
                    // raw ICMPv6 has NO IPv6 header: the buffer starts at the ICMPv6 type byte.
                    // pcpp::Packet(&raw, ProtocolType) CANNOT build an ICMPv6 first layer
                    // (createFirstLayer dispatches on link-layer type, not the ProtocolType arg).
                    // So parse a READ-ONLY view over _array6, then rebuild a self-owning REPLY
                    // layer carrying the same id/sequence. The builder ctor allocates+owns its
                    // data (m_IsAllocatedInPacket semantics), exactly like the send path —
                    // no manual heap buffer / no RawPacket ownership juggling.
                    if (rc < static_cast<int>(sizeof(pcpp::icmpv6_echo_hdr))) {
                        continue; // too short for an echo (getEchoDataLen() would underflow)
                    }
                    pcpp::ICMPv6EchoLayer parsed(reinterpret_cast<uint8_t *>(_array6.data()),
                        static_cast<size_t>(rc), nullptr, nullptr); // aliases _array6; no ownership (raw-data ctor)
                    if (parsed.getMessageType() != pcpp::ICMPv6MessageType::ICMPv6_ECHO_REPLY) {
                        continue; // NDP/MLD/echo-request/etc. — dropped
                    }
                    timespec stamp;
                    std::timespec_get(&stamp, TIME_UTC);
                    pcpp::Packet packet;
                    auto echo = pcpp::ICMPv6EchoLayer(pcpp::ICMPv6EchoLayer::REPLY,
                        parsed.getIdentifier(), parsed.getSequenceNr(), nullptr, 0); // payload irrelevant to matching
                    packet.addLayer(&echo); // stack builder layer (owns its data); mirrors _send_icmp_v6
                    _recv_packets.emplace_back(packet, stamp); // copy-ctor deep-copies (same as the v4 recv path)
                }
            });
            _poll6->init();
            _poll6->start(uvw::poll_handle::poll_event_flags::READABLE);
        }
    }

    // spawn the loop
    _io_thread = std::make_unique<std::thread>([this] {
        thread::change_self_name("receiver", "ping");
        _io_loop->run();
    });
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

    if (!_receiver) {
        // only once
        _receiver = std::make_unique<PingReceiver>();
    }

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
        // since it did not originate from it
        for (auto &[packet, stamp] : PingReceiver::recv_packets) {
            _recv(packet, TestType::Ping, _name, stamp);
        }
    });
    _receiver->register_async_callback(_recv_handler);
    _recv_handler->init();

    ++sock_count;
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
    _close_socket();
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
                _ip_set = true;
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
                _ip_set = true;
                return std::nullopt;
            }
        }
    }
    return ErrorType::InvalidIp;
}

std::optional<ErrorType> PingProbe::_create_socket()
{
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
#else
    if (sock == INVALID_SOCKET) {
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

void PingProbe::_close_socket()
{
    if (--sock_count; sock_count) {
        return;
    }
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
