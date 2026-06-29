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
#include <cctype>
#include <cstring>
#include <memory>
#include <spdlog/spdlog.h>

namespace visor::input::netprobe {

// Case-insensitive string equality (DNS names compare case-insensitively).
static bool iequals(const std::string &a, const std::string &b)
{
    if (a.size() != b.size()) {
        return false;
    }
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) != std::tolower(static_cast<unsigned char>(b[i]))) {
            return false;
        }
    }
    return true;
}

// RFC 8484: a DoH response must be Content-Type application/dns-message. Compare the media type
// case-insensitively, ignoring any parameters (e.g. "; charset=...") and surrounding whitespace.
static bool doh_content_type_ok(const std::string &ct)
{
    std::string base = ct.substr(0, ct.find(';'));
    auto first = base.find_first_not_of(" \t");
    if (first == std::string::npos) {
        return false;
    }
    auto last = base.find_last_not_of(" \t");
    base = base.substr(first, last - first + 1);
    return iequals(base, "application/dns-message");
}

// Verify the response's answer + authority sections fully parsed. pcpp's getAnswerCount()/
// getAuthorityCount() return the HEADER-DECLARED counts, while parseResources() silently stops at
// the first record that runs past the buffer — so a truncated/malformed section leaves the parsed
// record list shorter than declared. Comparing parsed vs declared catches that. A valid NODATA
// response (0 answers) passes (declared==parsed==0). The additional section is intentionally NOT
// checked: it commonly carries an EDNS OPT record, and we don't want any OPT-parsing edge case to
// false-reject a healthy resolver.
static bool doh_response_fully_parsed(pcpp::DnsLayer &dns)
{
    size_t answers_parsed = 0;
    for (auto *r = dns.getFirstAnswer(); r != nullptr; r = dns.getNextAnswer(r)) {
        ++answers_parsed;
    }
    if (answers_parsed < dns.getAnswerCount()) {
        return false;
    }
    size_t authority_parsed = 0;
    for (auto *r = dns.getFirstAuthority(); r != nullptr; r = dns.getNextAuthority(r)) {
        ++authority_parsed;
    }
    return authority_parsed >= dns.getAuthorityCount();
}

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
    _qtype_code = visor::lib::dns::QTypeNumbers.at(_qtype);
    q.addQuery(_qname, static_cast<pcpp::DnsType>(_qtype_code), pcpp::DNS_CLASS_IN);
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
        const std::string qname = _qname;
        const uint16_t qtype_code = _qtype_code;
        auto doh_result = _doh_result;
        auto fail = _fail;
        _client->request(req, [doh_result, fail, name, qname, qtype_code](const visor::http::HttpResult &r) {
            timespec stamp;
            std::timespec_get(&stamp, TIME_UTC);
            auto logger = spdlog::get("visor");
            if (r.transport_ok) {
                uint8_t rcode = 0;
                bool parse_ok = false;
                if (!doh_content_type_ok(r.content_type)) {
                    // RFC 8484: a valid DoH reply is application/dns-message. A wrong content type
                    // (e.g. an HTML/JSON error page returned with HTTP 200) is a DNS-level failure.
                    if (logger) {
                        logger->debug("netprobe doh[{}]: unexpected response Content-Type '{}' (want application/dns-message)", name, r.content_type);
                    }
                } else if (r.response_body.size() >= sizeof(pcpp::dnshdr)) {
                    // pcpp::DnsLayer, when not attached to a Packet, OWNS its buffer and
                    // delete[]s it in ~Layer(). So it MUST be given a new[]-allocated buffer
                    // (a std::string's internal buffer is NOT new[] => delete[] on it is UB /
                    // heap corruption). Mirror DnsStreamHandler's TCP path: hand the Layer a
                    // new[] buffer and release ownership to it.
                    auto rawbuf = std::make_unique<uint8_t[]>(r.response_body.size());
                    std::memcpy(rawbuf.get(), r.response_body.data(), r.response_body.size());
                    pcpp::DnsLayer dns(rawbuf.release(), r.response_body.size(), nullptr, nullptr);
                    auto *h = dns.getDnsHeader();
                    if (h->queryOrResponse != 1) {
                        if (logger) {
                            logger->debug("netprobe doh[{}]: response is not a DNS reply (QR=0)", name);
                        }
                    } else {
                        // Validate the response echoes our question (qname + qtype) per RFC 8484,
                        // so a mismatched/unrelated answer isn't counted as a success.
                        auto *query = dns.getFirstQuery();
                        if (!(query && static_cast<uint16_t>(query->getDnsType()) == qtype_code && iequals(query->getName(), qname))) {
                            if (logger) {
                                logger->debug("netprobe doh[{}]: response question mismatch (got '{}' type {})", name,
                                    query ? query->getName() : std::string("<none>"), query ? static_cast<int>(query->getDnsType()) : -1);
                            }
                        } else if (h->truncation) {
                            // Server set the TC (truncated) bit (RFC 1035 §4.1.1): the response is incomplete.
                            if (logger) {
                                logger->debug("netprobe doh[{}]: response has the TC (truncated) bit set", name);
                            }
                        } else if (!doh_response_fully_parsed(dns)) {
                            // A declared answer/authority record failed to parse (truncated/malformed).
                            if (logger) {
                                logger->debug("netprobe doh[{}]: response truncated/malformed (a declared record did not parse)", name);
                            }
                        } else {
                            parse_ok = true;
                            rcode = h->responseCode;
                        }
                    }
                } else if (logger) {
                    logger->debug("netprobe doh[{}]: response too short for a DNS message ({} bytes)", name, r.response_body.size());
                }
                doh_result(static_cast<uint16_t>(r.status_code), rcode, parse_ok, r.timings, name, stamp);
            } else {
                if (logger) {
                    logger->debug("netprobe doh[{}]: transport error: {} (curl code {})", name, r.error_msg, r.curl_code);
                }
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
