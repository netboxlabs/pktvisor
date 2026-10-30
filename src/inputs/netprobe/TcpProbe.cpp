#include "TcpProbe.h"

#include "NetProbeException.h"
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wzero-as-null-pointer-constant"
#endif
#include <VisorTcpLayer.h>
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

namespace visor::input::netprobe {
bool TcpProbe::start(std::shared_ptr<uvw::loop> io_loop)
{
    if (_init || ((_ip.isIPv4() ? _ip.getIPv4() == pcpp::IPv4Address::Zero : _ip.getIPv6() == pcpp::IPv6Address::Zero) && _dns.empty())) {
        return false;
    }

    if (_dns.empty()) {
        _ip_str = _ip.toString();
        _is_ipv4 = _ip.isIPv4();
    }

    _io_loop = io_loop;
    _interval_timer = _io_loop->resource<uvw::timer_handle>();
    if (!_interval_timer) {
        throw NetProbeException("Netprobe - unable to initialize interval TimerHandle");
    }

    _interval_timer->on<uvw::timer_event>([this](const auto &, auto &) {
        if (!_drop_attempt()) {
            return;
        }
        if (!_dns.empty()) {
            bool first_match = !_force_ipv6.has_value();
            bool want_ipv4 = _force_ipv6.has_value() && !*_force_ipv6;
            auto [ip, ipv4] = _resolve_dns(first_match, want_ipv4);
            _ip_str = ip;
            _is_ipv4 = ipv4;
            if (_ip_str.empty()) {
                _fail(ErrorType::DnsLookupFailure, TestType::TCP, _name);
                return;
            }
        }
        _perform_tcp_process();
    });

    _interval_timer->start(uvw::timer_handle::time{0}, uvw::timer_handle::time{_config.interval_msec});
    _init = true;
    return true;
}

bool TcpProbe::_drop_attempt()
{
    if (_client && !_client->closing()) {
        if (_connecting) {
            // a tick can come early for an attempt that started late, behind a blocked loop, or by the loop clock's
            // rounding to milliseconds: the tick is put off until that attempt has run for timeout_msec
            auto timeout = std::chrono::milliseconds(static_cast<std::chrono::milliseconds::rep>(_config.timeout_msec));
            auto age = std::chrono::steady_clock::now() - _attempt_start;
            if (age < timeout) {
                auto wait = std::chrono::ceil<std::chrono::milliseconds>(timeout - age);
                _interval_timer->start(uvw::timer_handle::time{static_cast<uint64_t>(wait.count())}, uvw::timer_handle::time{_config.interval_msec});
                return false;
            }
            // the stream handler counts a timeout only for a result that comes late, so an attempt still
            // connecting past timeout_msec is reported as one here
            _fail(ErrorType::Timeout, TestType::TCP, _name);
        }
        _client->close();
    }
    _connecting = false;
    return true;
}

void TcpProbe::_perform_tcp_process()
{
    // built here rather than by uvw's connect(ip, port), which cuts an IPv6 address down to a 16-byte sockaddr
    sockaddr_storage addr{};
    if (uv_ip4_addr(_ip_str.c_str(), static_cast<int>(_dst_port), reinterpret_cast<sockaddr_in *>(&addr)) != 0
        && uv_ip6_addr(_ip_str.c_str(), static_cast<int>(_dst_port), reinterpret_cast<sockaddr_in6 *>(&addr)) != 0) {
        _fail(ErrorType::InvalidIp, TestType::TCP, _name);
        return;
    }

    _client = _io_loop->resource<uvw::tcp_handle>();
    _client->on<uvw::error_event>([this](const uvw::error_event &err, uvw::tcp_handle &handle) {
        // a canceled attempt was closed by stop() or by the next attempt, and an error after the connect is the
        // shutdown's: neither is the target refusing
        if (err.code() != UV_ECANCELED && _connecting) {
            _connecting = false;
            _fail(ErrorType::ConnectFailure, TestType::TCP, _name);
        }
        handle.close();
    });
    _client->on<uvw::close_event>([this](const uvw::close_event &, uvw::tcp_handle &) {
    });
    _client->on<uvw::shutdown_event>([this](const uvw::shutdown_event &, uvw::tcp_handle &handle) {
        handle.close();
    });
    _client->on<uvw::connect_event>([this](const uvw::connect_event &, uvw::tcp_handle &handle) {
        _connecting = false;
        timespec stamp;
        std::timespec_get(&stamp, TIME_UTC);
        pcpp::Packet packet;
        auto layer = pcpp::TcpLayer(0, static_cast<uint16_t>(_dst_port));
        packet.addLayer(&layer);
        _recv(packet, TestType::TCP, _name, stamp);
        handle.shutdown();
    });
    timespec stamp;
    std::timespec_get(&stamp, TIME_UTC);
    pcpp::Packet packet;
    auto layer = pcpp::TcpLayer(0, static_cast<uint16_t>(_dst_port));
    packet.addLayer(&layer);
    _send(packet, TestType::TCP, _name, stamp);
    // uvw returns this error rather than emitting it
    if (_client->connect(reinterpret_cast<const sockaddr &>(addr)) < 0) {
        _fail(ErrorType::ConnectFailure, TestType::TCP, _name);
        _client->close();
        return;
    }
    _connecting = true;
    _attempt_start = std::chrono::steady_clock::now();
}

bool TcpProbe::stop()
{
    // Called on the loop thread (from NetProbeInputStream's async stop callback),
    // so closing the handles here is safe and leaves the loop quiescent for close().
    if (_interval_timer && !_interval_timer->closing()) {
        _interval_timer->stop();
        _interval_timer->close();
    }
    if (_client && !_client->closing()) {
        _client->close();
    }
    return true;
}
}
