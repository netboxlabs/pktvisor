/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "NetProbeInputStream.h"
#include "NetProbeException.h"
#include "PingProbe.h"
#include "TcpProbe.h"
#include "ThreadName.h"
#include <fmt/ranges.h>
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wzero-as-null-pointer-constant"
#endif
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/IPv6Layer.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/PcapFileDevice.h>
#include <pcapplusplus/UdpLayer.h>
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

namespace visor::input::netprobe {

uint16_t NetProbeInputStream::_id = 1;

NetProbeInputStream::NetProbeInputStream(const std::string &name)
    : visor::InputStream(name)
{
    _logger = spdlog::get("visor");
    assert(_logger);
}

void NetProbeInputStream::start()
{
    if (_running) {
        return;
    }

    validate_configs(_config_defs);

    std::vector<std::string> valid_tests;
    for (const auto &defs : _test_defs) {
        valid_tests.push_back(defs.first);
    }

    // Configs
    if (!config_exists("test_type")) {
        throw NetProbeException(fmt::format("'test_type' config not specified. The valid test types are: {}", fmt::join(valid_tests, ", ")));
    } else {
        auto it = _test_defs.find(config_get<std::string>("test_type"));
        if (it == _test_defs.end()) {
            throw NetProbeException(fmt::format("{} is an invalid/unsupported test type. The valid test types are: {}", config_get<std::string>("test_type"), fmt::join(valid_tests, ", ")));
        }
        _type = it->second;
    }

    if (config_exists("interval_msec")) {
        _interval_msec = config_get<uint64_t>("interval_msec");
    }

    if (config_exists("timeout_msec")) {
        _timeout_msec = config_get<uint64_t>("timeout_msec");
    }

    if (_timeout_msec > _interval_msec) {
        throw NetProbeException(fmt::format("timeout_msec [{}] cannot be greater than interval_msec [{}]", _timeout_msec, _interval_msec));
    }

    if (config_exists("packets_per_test")) {
        _packets_per_test = config_get<uint64_t>("packets_per_test");
        if (!_packets_per_test) {
            throw NetProbeException("packets_per_test needs to be greater than 0");
        }
    }

    if (config_exists("packets_interval_msec")) {
        _packets_interval_msec = config_get<uint64_t>("packets_interval_msec");
    }

    if (_packets_per_test * _packets_interval_msec > _interval_msec) {
        throw NetProbeException(fmt::format("packets_per_test [{}] times packets_interval_msec [{}] cannot be greater than packets_interval_msec [{}]", _packets_per_test, _packets_interval_msec, _interval_msec));
    }

    if (config_exists("packet_payload_size")) {
        _packet_payload_size = config_get<uint64_t>("packet_payload_size");
        if (_packet_payload_size > MAX_PAYLOAD_SIZE) {
            throw NetProbeException(fmt::format("packet_payload_size was set to {} but max supported size is {}", _packet_payload_size, MAX_PAYLOAD_SIZE));
        }
    }

    if (!config_exists("targets")) {
        throw NetProbeException("no targets specified");
    } else {
        auto targets = config_get<std::shared_ptr<Configurable>>("targets");
        auto keys = targets->get_all_keys();
        for (const auto &key : keys) {
            auto config = targets->config_get<std::shared_ptr<Configurable>>(key);
            if (!config->config_exists("target")) {
                throw NetProbeException(fmt::format("'{}' does not have key 'target' which is required", key));
            }
            uint32_t port{0};
            if (!config->config_exists("port") && _type == TestType::TCP) {
                throw NetProbeException(fmt::format("'{}' does not have key 'port' which is required", key));
            } else if (config->config_exists("port")) {
                port = static_cast<uint32_t>(config->config_get<uint64_t>("port"));
            }

            std::optional<bool> force_ipv6;
            if (config->config_exists("ip_version")) {
                auto v = config->config_get<uint64_t>("ip_version");
                if (v != 4 && v != 6) {
                    throw NetProbeException("ip_version must be 4 or 6");
                }
                force_ipv6 = (v == 6);
            }

            auto target = config->config_get<std::string>("target");
            if (pcpp::IPv4Address::isValidIPv4Address(target) || pcpp::IPv6Address::isValidIPv6Address(target)) {
                bool literal_v6 = pcpp::IPv6Address::isValidIPv6Address(target);
                if (force_ipv6.has_value() && *force_ipv6 != literal_v6) {
                    throw NetProbeException(fmt::format("target {} is {} but ip_version is set to {}",
                        target, literal_v6 ? "IPv6" : "IPv4", *force_ipv6 ? 6 : 4));
                }
                _ip_list[key] = IpEntry{pcpp::IPAddress(target), port};
                continue;
            }
            auto dot = target.find(".");
            if (dot == std::string::npos && target != "localhost") {
                throw NetProbeException(fmt::format("{} is an invalid/unsupported DNS", target));
            }
            _dns_list[key] = DnsEntry{target, port, force_ipv6};
        }
    }

    _create_netprobe_loop();

    _running = true;
}

void NetProbeInputStream::_send_cb(pcpp::Packet &payload, TestType type, const std::string &name, timespec stamp)
{
    std::shared_lock lock(_input_mutex);
    for (auto &proxy : _event_proxies) {
        static_cast<NetProbeInputEventProxy *>(proxy.get())->probe_send_cb(payload, type, name, stamp);
    }
}

void NetProbeInputStream::_recv_cb(pcpp::Packet &payload, TestType type, const std::string &name, timespec stamp)
{
    std::shared_lock lock(_input_mutex);
    for (auto &proxy : _event_proxies) {
        static_cast<NetProbeInputEventProxy *>(proxy.get())->probe_recv_cb(payload, type, name, stamp);
    }
}

void NetProbeInputStream::_fail_cb(ErrorType error, TestType type, const std::string &name)
{
    std::shared_lock lock(_input_mutex);
    for (auto &proxy : _event_proxies) {
        static_cast<NetProbeInputEventProxy *>(proxy.get())->probe_fail_cb(error, type, name);
    }
}

void NetProbeInputStream::_create_netprobe_loop()
{
    // main io loop, run in its own thread
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
        _timer->stop();
        _timer->close();
        _io_loop->stop();
        _io_loop->close();
        handle.close();
    });
    _async_h->on<uvw::error_event>([this](const auto &err, auto &handle) {
        _logger->error("[{}] AsyncEvent error: {}", _name, err.what());
        handle.close();
    });

    _timer = _io_loop->resource<uvw::timer_handle>();
    if (!_timer) {
        throw NetProbeException("unable to initialize TimerHandle");
    }
    _timer->on<uvw::timer_event>([this](const auto &, auto &) {
        timespec stamp;
        // use now()
        std::timespec_get(&stamp, TIME_UTC);
        std::shared_lock lock(_input_mutex);
        for (auto &proxy : _event_proxies) {
            proxy->heartbeat_cb(stamp);
        }
    });
    _timer->on<uvw::error_event>([this](const auto &err, auto &handle) {
        _logger->error("[{}] TimerEvent error: {}", _name, err.what());
        handle.close();
    });

    for (const auto &ip : _ip_list) {
        std::unique_ptr<NetProbe> probe{nullptr};
        if (_type == TestType::Ping) {
            probe = std::make_unique<PingProbe>(_id, ip.first, ip.second.ip, std::string());
        } else if (_type == TestType::TCP) {
            probe = std::make_unique<TcpProbe>(_id, ip.first, ip.second.ip, std::string(), ip.second.port);
        } else {
            throw NetProbeException(fmt::format("Test type currently not supported"));
        }
        ++_id;
        probe->set_configs(_interval_msec, _timeout_msec, _packets_per_test, _packets_interval_msec, _packet_payload_size);
        probe->set_callbacks([this](pcpp::Packet &payload, TestType type, const std::string &name, timespec stamp) { _send_cb(payload, type, name, stamp); },
            [this](pcpp::Packet &payload, TestType type, const std::string &name, timespec stamp) { _recv_cb(payload, type, name, stamp); },
            [this](ErrorType error, TestType type, const std::string &name) { _fail_cb(error, type, name); });
        probe->start(_io_loop);
        _probes.push_back(std::move(probe));
    }

    for (const auto &dns : _dns_list) {
        std::unique_ptr<NetProbe> probe{nullptr};
        if (_type == TestType::Ping) {
            probe = std::make_unique<PingProbe>(_id, dns.first, pcpp::IPAddress(), dns.second.dns, dns.second.force_ipv6);
        } else if (_type == TestType::TCP) {
            probe = std::make_unique<TcpProbe>(_id, dns.first, pcpp::IPAddress(), dns.second.dns, dns.second.port, dns.second.force_ipv6);
        } else {
            throw NetProbeException(fmt::format("Test type currently not supported"));
        }
        ++_id;
        probe->set_configs(_interval_msec, _timeout_msec, _packets_per_test, _packets_interval_msec, _packet_payload_size);
        probe->set_callbacks([this](pcpp::Packet &payload, TestType type, const std::string &name, timespec stamp) { _send_cb(payload, type, name, stamp); },
            [this](pcpp::Packet &payload, TestType type, const std::string &name, timespec stamp) { _recv_cb(payload, type, name, stamp); },
            [this](ErrorType error, TestType type, const std::string &name) { _fail_cb(error, type, name); });
        probe->start(_io_loop);
        _probes.push_back(std::move(probe));
    }

    // spawn the loop
    _io_thread = std::make_unique<std::thread>([this] {
        _timer->start(uvw::timer_handle::time{1000}, uvw::timer_handle::time{HEARTBEAT_INTERVAL * 1000});
        thread::change_self_name(schema_key(), name());
        _io_loop->run();
        if (_type == TestType::Ping) {
            // Close the ping send sockets here, on the io thread that opened them: _sock/_sock6 are
            // thread_local, so this is the only thread that can actually close the raw descriptors.
            // Runs after the loop has stopped (and before stop() joins this thread), so no probe is
            // still sending.
            PingProbe::close_thread_send_sockets();
        }
    });
}

void NetProbeInputStream::stop()
{
    if (!_running) {
        return;
    }

    for (const auto &probe : _probes) {
        probe->stop();
    }

    if (_async_h && _io_thread) {
        // we have to use AsyncHandle to stop the loop from the same thread the loop is running in
        _async_h->send();
        // waits for _io_loop->run() to return
        if (_io_thread->joinable()) {
            _io_thread->join();
        }
    }

    _running = false;
}

void NetProbeInputStream::info_json(json &j) const
{
    common_info_json(j);
    j[schema_key()]["current_targets_total"] = _dns_list.size() + _ip_list.size();
    // Report ping socket usage only for ping streams. Derive the probe count from _probes — a stable
    // per-stream member after start() — rather than a thread_local counter, which info_json (invoked
    // on an HTTP worker thread) could never read. The two addends are the shared receiver's v4 socket
    // and, when active, its v6 socket.
    if (_type == TestType::Ping && !_probes.empty()) {
        j[schema_key()]["ping_sockets"] = _probes.size() + 1 + (PingProbe::receiver_v6_active() ? 1 : 0);
    }
}

std::unique_ptr<InputEventProxy> NetProbeInputStream::create_event_proxy(const Configurable &filter)
{
    auto custom_filter = filter;
    custom_filter.config_set("xact_ttl_ms", _timeout_msec);
    return std::make_unique<NetProbeInputEventProxy>(_name, custom_filter);
}
}
