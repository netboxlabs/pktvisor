/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once
#include "HttpClient.h"
#include "NetProbe.h"
#include <functional>
#include <uvw/timer.h>

namespace visor::input::netprobe {

// http_status, rcode, parse_ok, timings, name, stamp
using DohResultCallback = std::function<void(uint16_t, uint8_t, bool, visor::http::HttpTimings, const std::string &, timespec)>;

class DohProbe final : public NetProbe
{
    std::string _url;
    std::string _method;     // "POST" or "GET"
    std::string _qname;
    std::string _qtype;      // e.g. "A"
    std::shared_ptr<visor::http::HttpClient> _client;
    DohResultCallback _doh_result;
    std::shared_ptr<uvw::timer_handle> _interval_timer;
    std::string _query_wire; // pre-built DNS query (wire format), built in start()
    std::string _get_url;    // pre-built URL with ?dns=<base64url> for GET
    uint16_t _qtype_code{0}; // numeric DNS qtype (from QTypeNumbers), for response question validation
    bool _init{false};

public:
    DohProbe(uint16_t id, const std::string &name, std::string url, std::string method,
        std::string qname, std::string qtype,
        std::shared_ptr<visor::http::HttpClient> client, DohResultCallback doh_result)
        : NetProbe(id, name, pcpp::IPAddress(), std::string())
        , _url(std::move(url))
        , _method(std::move(method))
        , _qname(std::move(qname))
        , _qtype(std::move(qtype))
        , _client(std::move(client))
        , _doh_result(std::move(doh_result)) {}
    ~DohProbe() = default;
    bool start(std::shared_ptr<uvw::loop> io_loop) override;
    bool stop() override;
};
}
