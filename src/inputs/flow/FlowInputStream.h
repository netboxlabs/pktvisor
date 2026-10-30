/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "InputStream.h"
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wsign-compare"
#pragma GCC diagnostic ignored "-Wzero-as-null-pointer-constant"
#endif
#include "NetflowData.h"
#include "SflowData.h"
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif
#include <spdlog/spdlog.h>

namespace uvw {
class loop;
class async_handle;
class udp_handle;
class timer_handle;
}

namespace visor::input::flow {

// a socket bound to :: can also receive from IPv4 peers, as IPv4-mapped addresses (::ffff:192.0.2.1). Gives such an
// address as IPv4 (192.0.2.1) and any other unchanged, so a device has one name however it reached the listener
std::string unmapped_ip(const std::string &ip);

enum class Type {
    SFLOW,
    NETFLOW,
    UNKNOWN
};
class FlowInputStream : public visor::InputStream
{
    Type _flow_type;
    std::atomic<uint64_t> _error_count;
    std::shared_ptr<spdlog::logger> _logger;

    std::unique_ptr<std::thread> _io_thread;
    std::shared_ptr<uvw::loop> _io_loop;
    std::shared_ptr<uvw::async_handle> _async_h;
    std::shared_ptr<uvw::timer_handle> _timer;

    std::shared_ptr<uvw::udp_handle> _udp_server_h;

    static const inline ConfigsDefType _config_defs = {
        "flow_type",
        "bind",
        "port",
        "pcap_file"};

    void _read_from_pcap_file();
    void _create_frame_stream_udp_socket();
    void _close_unstarted_loop();

public:
    FlowInputStream(const std::string &name);
    ~FlowInputStream() = default;

    // visor::AbstractModule
    std::string schema_key() const override
    {
        return "flow";
    }
    void start() override;
    void stop() override;
    void info_json(json &j) const override;
    std::unique_ptr<InputEventProxy> create_event_proxy(const Configurable &filter) override;
};

class FlowInputEventProxy : public visor::InputEventProxy
{
public:
    FlowInputEventProxy(const std::string &name, const Configurable &filter)
        : InputEventProxy(name, filter)
    {
    }

    ~FlowInputEventProxy() = default;

    size_t consumer_count() const override
    {
        return policy_signal.slot_count() + heartbeat_signal.slot_count() + sflow_signal.slot_count() + netflow_signal.slot_count();
    }

    void sflow_cb(const SFSample &sflow, std::size_t size)
    {
        sflow_signal(sflow, size);
    }

    void netflow_cb(const std::string &srcip, const NFSample &netflow, std::size_t size)
    {
        netflow_signal(srcip, netflow, size);
    }

    // handler functionality
    // IF THIS changes, see consumer_count()
    // note: these are mutable because consumer_count() calls slot_count() which is not const (unclear if it could/should be)
    mutable sigslot::signal<const SFSample &, std::size_t> sflow_signal;
    mutable sigslot::signal<const std::string &, const NFSample &, std::size_t> netflow_signal;
};

}
