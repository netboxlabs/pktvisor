/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "NetProbe.h"

#include <optional>
#include <uvw/tcp.h>
#include <uvw/timer.h>

namespace visor::input::netprobe {

class TcpProbe final : public NetProbe
{
    uint32_t _dst_port;
    bool _init{false};
    bool _is_ipv4{false};
    std::string _ip_str;
    std::shared_ptr<uvw::timer_handle> _interval_timer;
    std::optional<bool> _force_ipv6;

    std::shared_ptr<uvw::tcp_handle> _client;

    void _perform_tcp_process();

public:
    TcpProbe(uint16_t id, const std::string &name, const pcpp::IPAddress &ip, const std::string &dns, uint32_t port, std::optional<bool> force_ipv6 = std::nullopt)
        : NetProbe(id, name, ip, dns)
        , _dst_port(port)
        , _force_ipv6(force_ipv6) {};
    ~TcpProbe() = default;
    bool start(std::shared_ptr<uvw::loop> io_loop) override;
    bool stop() override;
};
}
