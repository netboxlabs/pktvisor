/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once
#include "HttpClient.h"
#include "NetProbe.h"
#include <functional>
#include <optional>
#include <uvw/timer.h>

namespace visor::input::netprobe {

using HttpResultCallback = std::function<void(uint16_t status, visor::http::HttpTimings, const std::string &, timespec)>;

class HttpProbe final : public NetProbe
{
    std::string _url;
    std::string _method;
    std::shared_ptr<visor::http::HttpClient> _client;
    HttpResultCallback _http_result;
    std::shared_ptr<uvw::timer_handle> _interval_timer;
    bool _init{false};

public:
    HttpProbe(uint16_t id, const std::string &name, std::string url, std::string method,
        std::shared_ptr<visor::http::HttpClient> client, HttpResultCallback http_result)
        : NetProbe(id, name, pcpp::IPAddress(), std::string())
        , _url(std::move(url))
        , _method(std::move(method))
        , _client(std::move(client))
        , _http_result(std::move(http_result)) {}
    ~HttpProbe() = default;
    bool start(std::shared_ptr<uvw::loop> io_loop) override;
    bool stop() override;
};
}
