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

void TcpProbe::_perform_tcp_process()
{
    _client = _io_loop->resource<uvw::tcp_handle>();
    _client->on<uvw::error_event>([this](const auto &, auto &) {
        _fail(ErrorType::ConnectFailure, TestType::TCP, _name);
    });
    _client->on<uvw::close_event>([this](const uvw::close_event &, uvw::tcp_handle &) {
    });
    _client->on<uvw::shutdown_event>([this](const uvw::shutdown_event &, uvw::tcp_handle &handle) {
        handle.close();
    });
    _client->on<uvw::connect_event>([this](const uvw::connect_event &, uvw::tcp_handle &handle) {
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
    _client->connect(_ip_str, _dst_port);
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
