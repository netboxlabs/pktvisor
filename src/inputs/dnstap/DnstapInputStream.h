/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#ifdef _WIN32
// Dnstap is currently not supported on Windows
#include "WinFrameSession.h"
#else
#include "UnixFrameSession.h"
#endif
#include "InputStream.h"
#include "utils.h"
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#pragma GCC diagnostic ignored "-Woverflow"
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wzero-as-null-pointer-constant"
#endif
#include "pb/dnstap.pb.h"
#include <pcapplusplus/DnsLayer.h>
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif
#include <bitset>
#include <spdlog/spdlog.h>
#include <unordered_map>
#include <utility>
#include <uv.h>

namespace uvw {
class loop;
class async_handle;
class pipe_handle;
class tcp_handle;
class timer_handle;
}

struct fstrm_reader;

namespace visor::input::dnstap {

const static std::string CONTENT_TYPE = "protobuf:dnstap.Dnstap";

class DnstapInputStream : public visor::InputStream
{
    std::shared_ptr<spdlog::logger> _logger;

    std::unique_ptr<std::thread> _io_thread;
    std::shared_ptr<uvw::loop> _io_loop;
    std::shared_ptr<uvw::async_handle> _async_h;
    std::shared_ptr<uvw::timer_handle> _timer;

    std::shared_ptr<uvw::pipe_handle> _unix_server_h;
    std::unordered_map<uv_os_fd_t, std::unique_ptr<FrameSessionData<uvw::pipe_handle>>> _unix_sessions;

    std::shared_ptr<uvw::tcp_handle> _tcp_server_h;
    std::unordered_map<uv_os_fd_t, std::unique_ptr<FrameSessionData<uvw::tcp_handle>>> _tcp_sessions;

    static const inline ConfigsDefType _config_defs = {
        "tcp",
        "socket",
        "dnstap_file",
        "only_hosts"};

    void _read_frame_stream_file();
    void _create_frame_stream_unix_socket();
    void _create_frame_stream_tcp_socket();

    inline bool _filtering([[maybe_unused]] const ::dnstap::Dnstap &d)
    {
        return false;
    }

public:
    DnstapInputStream(const std::string &name);
    ~DnstapInputStream() = default;

    // visor::AbstractModule
    std::string schema_key() const override
    {
        return "dnstap";
    }
    void start() override;
    void stop() override;
    void info_json(json &j) const override;
    std::unique_ptr<InputEventProxy> create_event_proxy(const Configurable &filter) override;
};

class DnstapInputEventProxy : public visor::InputEventProxy
{

    enum Filters {
        OnlyHosts,
        FiltersMAX
    };
    std::bitset<Filters::FiltersMAX> _f_enabled;

    lib::utils::IPv4subnetList _IPv4_host_list;
    lib::utils::IPv6subnetList _IPv6_host_list;

public:
    DnstapInputEventProxy(const std::string &name, const Configurable &filter)
        : InputEventProxy(name, filter)
    {
        if (config_exists("only_hosts")) {
            lib::utils::parse_host_specs(config_get<StringList>("only_hosts"), _IPv4_host_list, _IPv6_host_list);
            _f_enabled.set(Filters::OnlyHosts);
        }
    }

    ~DnstapInputEventProxy() = default;

    size_t consumer_count() const override
    {
        return policy_signal.slot_count() + heartbeat_signal.slot_count() + dnstap_signal.slot_count();
    }

    void dnstap_cb(const ::dnstap::Dnstap &dnstap, size_t size)
    {
        if (_f_enabled[Filters::OnlyHosts]) {
            if (dnstap.message().has_query_address() && dnstap.message().has_response_address()) {
                if (!lib::utils::match_subnet(_IPv4_host_list, _IPv6_host_list, dnstap.message().query_address())
                    && !lib::utils::match_subnet(_IPv4_host_list, _IPv6_host_list, dnstap.message().response_address())) {
                    // message had both query and response address, and neither matched, so filter
                    return;
                }
            } else if (dnstap.message().has_query_address()
                && !lib::utils::match_subnet(_IPv4_host_list, _IPv6_host_list, dnstap.message().query_address())) {
                // message had only query address and it didn't match, so filter
                return;
            } else if (dnstap.message().has_response_address()
                && !lib::utils::match_subnet(_IPv4_host_list, _IPv6_host_list, dnstap.message().response_address())) {
                // message had only response address and it didn't match, so filter
                return;
            } else {
                // message had neither query nor response address, so filter
                return;
            }
        }

        dnstap_signal(dnstap, size);
    }

    // handler functionality
    // IF THIS changes, see consumer_count()
    // note: these are mutable because consumer_count() calls slot_count() which is not const (unclear if it could/should be)
    mutable sigslot::signal<const ::dnstap::Dnstap &, size_t> dnstap_signal;
};

}
