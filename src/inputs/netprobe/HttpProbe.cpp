/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "HttpProbe.h"
#include "NetProbeException.h"
#include <spdlog/spdlog.h>

namespace visor::input::netprobe {

bool HttpProbe::start(std::shared_ptr<uvw::loop> io_loop)
{
    if (_init || _url.empty()) {
        return false;
    }
    _io_loop = io_loop;
    _interval_timer = _io_loop->resource<uvw::timer_handle>();
    if (!_interval_timer) {
        throw NetProbeException("Netprobe - unable to initialize interval TimerHandle");
    }
    _interval_timer->on<uvw::timer_event>([this](const auto &, auto &) {
        // The outer timer lambda captures `this` — safe because the interval timer is
        // stopped and closed on the loop thread (HttpProbe::stop()) before the probe is
        // destroyed, and the loop is single-threaded, so no timer event fires after stop().
        // The inner completion callback captures _http_result/_fail BY VALUE so it can run
        // after this timer tick returns without referencing the probe.
        visor::http::HttpRequest req;
        req.url = _url;
        req.method = _method;
        req.timeout_ms = _config.timeout_msec;
        const std::string name = _name;
        auto http_result = _http_result;
        auto fail = _fail;
        _client->request(req, [http_result, fail, name](const visor::http::HttpResult &r) {
            timespec stamp;
            std::timespec_get(&stamp, TIME_UTC);
            if (r.transport_ok) {
                http_result(static_cast<uint16_t>(r.status_code), r.timings, name, stamp);
            } else {
                if (auto logger = spdlog::get("visor")) {
                    logger->debug("netprobe http[{}]: transport error: {} (curl code {})", name, r.error_msg, r.curl_code);
                }
                ErrorType err = ErrorType::SocketError;
                if (r.curl_code == CURLE_COULDNT_RESOLVE_HOST || r.curl_code == CURLE_COULDNT_RESOLVE_PROXY) {
                    err = ErrorType::DnsLookupFailure;
                } else if (r.curl_code == CURLE_COULDNT_CONNECT) {
                    err = ErrorType::ConnectFailure;
                } else if (r.curl_code == CURLE_OPERATION_TIMEDOUT) {
                    err = ErrorType::Timeout;
                }
                fail(err, TestType::HTTP, name);
            }
        });
    });
    _interval_timer->start(uvw::timer_handle::time{0}, uvw::timer_handle::time{_config.interval_msec});
    _init = true;
    return true;
}

bool HttpProbe::stop()
{
    // Called on the loop thread (matches the netprobe loop-quiescent teardown).
    if (_interval_timer && !_interval_timer->closing()) {
        _interval_timer->stop();
        _interval_timer->close();
    }
    return true;
}
}
