/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "DohProbe.h"
#include "NetProbeException.h"
#include "dns.h"
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wzero-as-null-pointer-constant"
#endif
#include <pcapplusplus/DnsLayer.h>
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif
#include <cstring>
#include <memory>

namespace visor::input::netprobe {

// RFC 4648 §5 base64url, no padding (for DoH GET ?dns=).
static std::string base64url(const std::string &in)
{
    static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string out;
    out.reserve((in.size() + 2) / 3 * 4);
    size_t i = 0;
    while (i + 3 <= in.size()) {
        uint32_t n = (uint8_t(in[i]) << 16) | (uint8_t(in[i + 1]) << 8) | uint8_t(in[i + 2]);
        out.push_back(tbl[(n >> 18) & 63]); out.push_back(tbl[(n >> 12) & 63]);
        out.push_back(tbl[(n >> 6) & 63]);  out.push_back(tbl[n & 63]);
        i += 3;
    }
    if (i + 1 == in.size()) {
        uint32_t n = uint8_t(in[i]) << 16;
        out.push_back(tbl[(n >> 18) & 63]); out.push_back(tbl[(n >> 12) & 63]);
    } else if (i + 2 == in.size()) {
        uint32_t n = (uint8_t(in[i]) << 16) | (uint8_t(in[i + 1]) << 8);
        out.push_back(tbl[(n >> 18) & 63]); out.push_back(tbl[(n >> 12) & 63]); out.push_back(tbl[(n >> 6) & 63]);
    }
    return out;
}

bool DohProbe::start(std::shared_ptr<uvw::loop> io_loop)
{
    if (_init || _url.empty()) {
        return false;
    }
    // Build the DNS query once (qname/qtype are stream-fixed).
    pcpp::DnsLayer q;
    auto qtype = static_cast<pcpp::DnsType>(visor::lib::dns::QTypeNumbers.at(_qtype));
    q.addQuery(_qname, qtype, pcpp::DNS_CLASS_IN);
    q.getDnsHeader()->recursionDesired = 1;
    q.getDnsHeader()->transactionID = 0; // RFC 8484 §4.1
    _query_wire.assign(reinterpret_cast<const char *>(q.getData()), q.getDataLen());
    if (_method == "GET") {
        _get_url = _url + (_url.find('?') == std::string::npos ? "?" : "&") + "dns=" + base64url(_query_wire);
    }

    _io_loop = io_loop;
    _interval_timer = _io_loop->resource<uvw::timer_handle>();
    if (!_interval_timer) {
        throw NetProbeException("Netprobe - unable to initialize interval TimerHandle");
    }
    _interval_timer->on<uvw::timer_event>([this](const auto &, auto &) {
        // Same capture contract as HttpProbe: outer lambda captures `this` (timer stopped on the
        // loop thread before destruction); inner completion captures BY VALUE.
        visor::http::HttpRequest req;
        req.timeout_ms = _config.timeout_msec;
        req.capture_response = true;
        if (_method == "GET") {
            req.url = _get_url;
            req.method = "GET";
            req.headers = {"Accept: application/dns-message"};
        } else {
            req.url = _url;
            req.method = "POST";
            req.body = _query_wire;
            req.headers = {"Content-Type: application/dns-message", "Accept: application/dns-message"};
        }
        const std::string name = _name;
        auto doh_result = _doh_result;
        auto fail = _fail;
        _client->request(req, [doh_result, fail, name](const visor::http::HttpResult &r) {
            timespec stamp;
            std::timespec_get(&stamp, TIME_UTC);
            if (r.transport_ok) {
                uint8_t rcode = 0;
                bool parse_ok = false;
                if (r.response_body.size() >= sizeof(pcpp::dnshdr)) {
                    // pcpp::DnsLayer, when not attached to a Packet, OWNS its buffer and
                    // delete[]s it in ~Layer(). So it MUST be given a new[]-allocated buffer
                    // (a std::string's internal buffer is NOT new[] => delete[] on it is UB /
                    // heap corruption). Mirror DnsStreamHandler's TCP path: hand the Layer a
                    // new[] buffer and release ownership to it.
                    auto rawbuf = std::make_unique<uint8_t[]>(r.response_body.size());
                    std::memcpy(rawbuf.get(), r.response_body.data(), r.response_body.size());
                    pcpp::DnsLayer dns(rawbuf.release(), r.response_body.size(), nullptr, nullptr);
                    auto *h = dns.getDnsHeader();
                    if (h->queryOrResponse == 1) {
                        parse_ok = true;
                        rcode = h->responseCode;
                    }
                }
                doh_result(static_cast<uint16_t>(r.status_code), rcode, parse_ok, r.timings, name, stamp);
            } else {
                ErrorType err = ErrorType::SocketError;
                if (r.curl_code == CURLE_COULDNT_RESOLVE_HOST || r.curl_code == CURLE_COULDNT_RESOLVE_PROXY) {
                    err = ErrorType::DnsLookupFailure;
                } else if (r.curl_code == CURLE_COULDNT_CONNECT) {
                    err = ErrorType::ConnectFailure;
                } else if (r.curl_code == CURLE_OPERATION_TIMEDOUT) {
                    err = ErrorType::Timeout;
                }
                fail(err, TestType::DOH, name);
            }
        });
    });
    _interval_timer->start(uvw::timer_handle::time{0}, uvw::timer_handle::time{_config.interval_msec});
    _init = true;
    return true;
}

bool DohProbe::stop()
{
    if (_interval_timer && !_interval_timer->closing()) {
        _interval_timer->stop();
        _interval_timer->close();
    }
    return true;
}
}
