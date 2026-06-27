#include "HttpClient.h"
#include <mutex>
#include <utility>
#include <vector>

namespace visor::http {

// libcurl requires a one-time, NOT-thread-safe global init before the first
// easy/multi handle. Multiple netprobe streams construct HttpClients on different
// control threads, so serialize it once (mirrors PingProbe's std::call_once).
// HttpClient is the ONLY conan-libcurl user in the tree (grep-confirmed; the vendored
// breakpad/sentry curl is a separate static copy with its own global state). The first
// HttpClient — hence this init — is constructed only when an HTTP netprobe stream starts,
// well after process/web-server startup. OpenSSL 3.x (the project's openssl/3.6.3) does
// thread-safe, idempotent auto-init, so curl_global_init(CURL_GLOBAL_DEFAULT) initializing
// OpenSSL does not destructively race other OpenSSL users. curl_global_cleanup() is
// intentionally omitted: it's a process-lifetime singleton; leaking it at exit is the
// conventional choice.
static void ensure_curl_global_init()
{
    static std::once_flag flag;
    std::call_once(flag, [] { curl_global_init(CURL_GLOBAL_DEFAULT); });
}

HttpClient::HttpClient(std::shared_ptr<uvw::loop> loop)
    : _loop(std::move(loop))
{
    ensure_curl_global_init();
    _multi = curl_multi_init();
    curl_multi_setopt(_multi, CURLMOPT_SOCKETFUNCTION, &HttpClient::socket_cb);
    curl_multi_setopt(_multi, CURLMOPT_SOCKETDATA, this);
    curl_multi_setopt(_multi, CURLMOPT_TIMERFUNCTION, &HttpClient::timer_cb);
    curl_multi_setopt(_multi, CURLMOPT_TIMERDATA, this);
    _timer = _loop->resource<uvw::timer_handle>();
    _timer->on<uvw::timer_event>([this](const auto &, auto &) { on_timeout(); });
}

HttpClient::~HttpClient()
{
    close();
}

// MUST be called on the loop thread (from NetProbeInputStream's async stop callback),
// BEFORE _io_loop->stop()/close(). uv_close is async, but it is requested here during
// the loop's poll phase, so the same iteration's closing-handles phase drains the poll
// handles/timer before run() returns — the loop is then quiescent for _io_loop->close()
// (the netprobe loop-quiescent teardown contract). In-flight transfers are dropped
// WITHOUT invoking their on_done (no metric recorded for an interrupted request).
void HttpClient::close()
{
    if (_closed) {
        return; // idempotent (dtor may call after an explicit close)
    }
    _closed = true;
    // 1) Tear curl down FIRST, while the SocketContexts are still alive. curl_multi_cleanup()
    //    and curl_multi_remove_handle() can synchronously invoke socket_cb(CURL_POLL_REMOVE),
    //    which dereferences the SocketContext stored via curl_multi_assign — so freeing the
    //    contexts before cleanup would be a use-after-free. Detaching the socket/timer
    //    callbacks first makes cleanup not call back at all.
    if (_multi) {
        curl_multi_setopt(_multi, CURLMOPT_SOCKETFUNCTION, nullptr);
        curl_multi_setopt(_multi, CURLMOPT_TIMERFUNCTION, nullptr);
        for (auto &kv : _easy) {
            curl_multi_remove_handle(_multi, kv.first);
            curl_easy_cleanup(kv.first);
        }
        _easy.clear();
        curl_multi_cleanup(_multi);
        _multi = nullptr;
    }
    // 2) Now no curl callback can fire — close the uvw poll handles + timer on the loop
    //    thread. uv_close is async, but requested here in the loop's poll phase the close
    //    callbacks run in the SAME iteration's closing phase, so the loop is quiescent
    //    before _io_loop->close() (the netprobe loop-quiescent teardown contract).
    for (auto &kv : _sockets) {
        if (kv.second->poll && !kv.second->poll->closing()) {
            kv.second->poll->close();
        }
    }
    _sockets.clear();
    if (_timer && !_timer->closing()) {
        _timer->stop();
        _timer->close();
    }
}

size_t HttpClient::write_discard(char *, size_t size, size_t nmemb, void *)
{
    return size * nmemb; // we don't keep the body
}

void HttpClient::request(const HttpRequest &req, ResultCallback on_done)
{
    if (_closed || !_multi) {
        return; // client is closed; do not touch curl_multi
    }
    auto ctx = std::make_unique<EasyContext>();
    ctx->on_done = std::move(on_done);
    CURL *easy = curl_easy_init();
    ctx->easy = easy;
    curl_easy_setopt(easy, CURLOPT_URL, req.url.c_str());
    // Don't force CUSTOMREQUEST for GET (it can subtly change curl's behavior); use the
    // native verb opts. HEAD => NOBODY; anything other than GET/HEAD => CUSTOMREQUEST.
    if (req.method == "HEAD") {
        curl_easy_setopt(easy, CURLOPT_NOBODY, 1L);
    } else if (req.method != "GET") {
        curl_easy_setopt(easy, CURLOPT_CUSTOMREQUEST, req.method.c_str());
    }
    curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION, &HttpClient::write_discard);
    curl_easy_setopt(easy, CURLOPT_FOLLOWLOCATION, req.follow_redirects ? 1L : 0L);
    // Bound the redirect chain (curl's default is unlimited) so a redirect loop can't burn
    // the whole timeout budget. curl 8.x already restricts followed protocols to HTTP/HTTPS.
    curl_easy_setopt(easy, CURLOPT_MAXREDIRS, 10L);
    curl_easy_setopt(easy, CURLOPT_SSL_VERIFYPEER, req.verify_tls ? 1L : 0L);
    curl_easy_setopt(easy, CURLOPT_SSL_VERIFYHOST, req.verify_tls ? 2L : 0L);
    if (req.timeout_ms) curl_easy_setopt(easy, CURLOPT_TIMEOUT_MS, static_cast<long>(req.timeout_ms));
    curl_easy_setopt(easy, CURLOPT_PRIVATE, ctx.get());
    curl_easy_setopt(easy, CURLOPT_ERRORBUFFER, ctx->errbuf);
    _easy[easy] = std::move(ctx);
    curl_multi_add_handle(_multi, easy);
    // Kick the transfer immediately rather than relying solely on curl's timer callback
    // firing — matches curl's multi-socket examples and avoids a stalled first request.
    int running = 0;
    curl_multi_socket_action(_multi, CURL_SOCKET_TIMEOUT, 0, &running);
    check_multi_info();
}

int HttpClient::timer_cb(CURLM *, long timeout_ms, void *userp)
{
    auto *self = static_cast<HttpClient *>(userp);
    if (self->_closed) {
        return 0;
    }
    if (!self->_timer) return 0;
    if (timeout_ms < 0) {
        self->_timer->stop();
    } else {
        // time is duration<uint64_t,milli>; cast to avoid narrowing from signed long.
        self->_timer->start(uvw::timer_handle::time{static_cast<uint64_t>(timeout_ms == 0 ? 1 : timeout_ms)}, uvw::timer_handle::time{0});
    }
    return 0;
}

void HttpClient::on_timeout()
{
    if (!_multi) return;
    int running = 0;
    curl_multi_socket_action(_multi, CURL_SOCKET_TIMEOUT, 0, &running);
    check_multi_info();
}

int HttpClient::socket_cb(CURL *, curl_socket_t s, int what, void *userp, void *socketp)
{
    auto *self = static_cast<HttpClient *>(userp);
    auto *sctx = static_cast<SocketContext *>(socketp);
    if (what == CURL_POLL_REMOVE) {
        if (sctx) {
            curl_multi_assign(self->_multi, s, nullptr);
            if (sctx->poll && !sctx->poll->closing()) sctx->poll->close();
            self->_sockets.erase(s); // owns + drops the SocketContext (uvw keeps the poll alive until its close cb fires)
        }
        return 0;
    }
    if (!sctx) {
        auto owned = std::make_unique<SocketContext>();
        sctx = owned.get();
        sctx->sockfd = s;
        sctx->poll = self->_loop->resource<uvw::poll_handle>(static_cast<uvw::os_socket_handle>(s));
        if (!sctx->poll) {
            return -1; // uv_poll_init failed (EMFILE/ENOMEM); signal curl to abort this transfer
        }
        sctx->poll->on<uvw::poll_event>([self, s](const uvw::poll_event &ev, uvw::poll_handle &) {
            using flags_t = uvw::poll_handle::poll_event_flags;
            // NB: uvw's operator&(enum,enum) returns the enum (not bool), so compare explicitly.
            int flags = 0;
            if ((ev.flags & flags_t::READABLE) == flags_t::READABLE) flags |= CURL_CSELECT_IN;
            if ((ev.flags & flags_t::WRITABLE) == flags_t::WRITABLE) flags |= CURL_CSELECT_OUT;
            self->on_socket_event(s, flags);
        });
        self->_sockets[s] = std::move(owned);
        curl_multi_assign(self->_multi, s, sctx);
    }
    uvw::poll_handle::poll_event_flags ev{};
    if (what & CURL_POLL_IN) ev = ev | uvw::poll_handle::poll_event_flags::READABLE;
    if (what & CURL_POLL_OUT) ev = ev | uvw::poll_handle::poll_event_flags::WRITABLE;
    if (sctx->poll && !sctx->poll->closing()) {
        sctx->poll->start(ev);
    }
    return 0;
}

void HttpClient::on_socket_event(curl_socket_t sockfd, int events)
{
    if (!_multi) return;
    int running = 0;
    curl_multi_socket_action(_multi, sockfd, events, &running);
    check_multi_info();
}

void HttpClient::check_multi_info()
{
    if (!_multi) return;
    // Drain + clean up FIRST, collecting (callback,result) pairs; invoke callbacks only
    // afterwards so a callback that calls request()/close() can't mutate _easy mid-loop.
    std::vector<std::pair<ResultCallback, HttpResult>> done;
    CURLMsg *msg = nullptr;
    int pending = 0;
    while ((msg = curl_multi_info_read(_multi, &pending))) {
        if (msg->msg != CURLMSG_DONE) continue;
        CURL *easy = msg->easy_handle;
        auto it = _easy.find(easy);
        ResultCallback cb = (it != _easy.end()) ? it->second->on_done : ResultCallback{};
        HttpResult result;
        if (msg->data.result == CURLE_OK) {
            result.transport_ok = true;
            long code = 0;
            curl_easy_getinfo(easy, CURLINFO_RESPONSE_CODE, &code);
            result.status_code = code;
            // *_TIME_T are cumulative-from-start microseconds; deltas are best-effort
            // phase splits (can be 0 on plain HTTP / across redirects — guarded below).
            curl_off_t total = 0, dns = 0, conn = 0, app = 0, ttfb = 0;
            curl_easy_getinfo(easy, CURLINFO_TOTAL_TIME_T, &total);
            curl_easy_getinfo(easy, CURLINFO_NAMELOOKUP_TIME_T, &dns);
            curl_easy_getinfo(easy, CURLINFO_CONNECT_TIME_T, &conn);
            curl_easy_getinfo(easy, CURLINFO_APPCONNECT_TIME_T, &app);
            curl_easy_getinfo(easy, CURLINFO_STARTTRANSFER_TIME_T, &ttfb);
            result.timings.total_us = static_cast<uint64_t>(total);
            result.timings.dns_us = static_cast<uint64_t>(dns);
            result.timings.connect_us = conn > dns ? static_cast<uint64_t>(conn - dns) : 0;
            result.timings.tls_us = app > conn ? static_cast<uint64_t>(app - conn) : 0;
            result.timings.ttfb_us = ttfb > (app ? app : conn) ? static_cast<uint64_t>(ttfb - (app ? app : conn)) : 0;
        } else {
            result.transport_ok = false;
            result.curl_code = msg->data.result;
        }
        curl_multi_remove_handle(_multi, easy);
        curl_easy_cleanup(easy);
        _easy.erase(easy);
        if (cb) done.emplace_back(std::move(cb), result);
    }
    for (auto &d : done) {
        d.first(d.second);
    }
}
}
