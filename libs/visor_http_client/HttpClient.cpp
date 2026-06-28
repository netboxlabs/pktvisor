#include "HttpClient.h"
#include <mutex>
#include <stdexcept>
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

std::optional<std::string> validate_http_url(const std::string &url)
{
    // This may be the FIRST libcurl call (config validation runs before any HttpClient is
    // constructed), and libcurl requires curl_global_init() before any other API. Ensure it
    // (idempotent via std::call_once) so the URL API can't run pre-init on non-thread-safe builds.
    ensure_curl_global_init();
    CURLU *h = curl_url();
    if (!h) {
        return std::nullopt; // allocation failure — can't validate, so don't reject
    }
    auto rc = curl_url_set(h, CURLUPART_URL, url.c_str(), 0);
    bool scheme_ok = false;
    if (rc == CURLUE_OK) {
        char *scheme = nullptr;
        if (curl_url_get(h, CURLUPART_SCHEME, &scheme, 0) == CURLUE_OK && scheme) {
            scheme_ok = (std::string(scheme) == "http" || std::string(scheme) == "https");
            curl_free(scheme);
        }
    }
    curl_url_cleanup(h);
    if (rc != CURLUE_OK || !scheme_ok) {
        return std::string("is not a valid http(s) URL: '") + url + "'";
    }
    return std::nullopt;
}

HttpClient::HttpClient(std::shared_ptr<uvw::loop> loop)
    : _loop(std::move(loop))
{
    ensure_curl_global_init();
    _multi = curl_multi_init();
    if (!_multi) {
        throw std::runtime_error("HttpClient: curl_multi_init() failed");
    }
    curl_multi_setopt(_multi, CURLMOPT_SOCKETFUNCTION, &HttpClient::socket_cb);
    curl_multi_setopt(_multi, CURLMOPT_SOCKETDATA, this);
    curl_multi_setopt(_multi, CURLMOPT_TIMERFUNCTION, &HttpClient::timer_cb);
    curl_multi_setopt(_multi, CURLMOPT_TIMERDATA, this);
    _timer = _loop->resource<uvw::timer_handle>();
    if (!_timer) {
        curl_multi_cleanup(_multi);
        _multi = nullptr;
        throw std::runtime_error("HttpClient: unable to initialize timer handle");
    }
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

size_t HttpClient::write_capture(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    size_t n = size * nmemb;
    auto *ctx = static_cast<EasyContext *>(userdata);
    if (ctx) {
        constexpr size_t kMaxBody = 64 * 1024; // a DNS-over-HTTPS message is well under 64 KB
        if (ctx->response.size() < kMaxBody) {
            ctx->response.append(ptr, (n < kMaxBody - ctx->response.size()) ? n : (kMaxBody - ctx->response.size()));
        }
    }
    return n; // always consume so curl doesn't abort the transfer
}

void HttpClient::request(const HttpRequest &req, ResultCallback on_done)
{
    if (_closed || !_multi) {
        return; // client is closed; do not touch curl_multi
    }
    auto ctx = std::make_unique<EasyContext>();
    ctx->on_done = std::move(on_done);
    CURL *easy = curl_easy_init();
    if (!easy) {
        HttpResult fail;
        fail.transport_ok = false;
        fail.curl_code = CURLE_FAILED_INIT;
        if (ctx->on_done) ctx->on_done(fail);
        return;
    }
    ctx->easy = easy;
    curl_easy_setopt(easy, CURLOPT_URL, req.url.c_str());
    // Don't force CUSTOMREQUEST for GET (it can subtly change curl's behavior); use the
    // native verb opts. HEAD => NOBODY; anything other than GET/HEAD => CUSTOMREQUEST.
    if (req.method == "HEAD") {
        curl_easy_setopt(easy, CURLOPT_NOBODY, 1L);
    } else if (req.method != "GET") {
        curl_easy_setopt(easy, CURLOPT_CUSTOMREQUEST, req.method.c_str());
    }
    curl_easy_setopt(easy, CURLOPT_FOLLOWLOCATION, req.follow_redirects ? 1L : 0L);
    // Bound the redirect chain (curl's default is unlimited) so a redirect loop can't burn
    // the whole timeout budget. curl 8.x already restricts followed protocols to HTTP/HTTPS.
    curl_easy_setopt(easy, CURLOPT_MAXREDIRS, 10L);
    curl_easy_setopt(easy, CURLOPT_SSL_VERIFYPEER, req.verify_tls ? 1L : 0L);
    curl_easy_setopt(easy, CURLOPT_SSL_VERIFYHOST, req.verify_tls ? 2L : 0L);
    if (req.timeout_ms) curl_easy_setopt(easy, CURLOPT_TIMEOUT_MS, static_cast<long>(req.timeout_ms));
    // We run on the netprobe io thread, not the main thread; CURLOPT_NOSIGNAL stops curl from
    // using signals (e.g. SIGALRM with the standard name resolver), which is unsafe off-main-thread.
    curl_easy_setopt(easy, CURLOPT_NOSIGNAL, 1L);
    if (!req.body.empty()) {
        // COPYPOSTFIELDS copies the bytes (curl owns them); size set first => binary-safe.
        curl_easy_setopt(easy, CURLOPT_POSTFIELDSIZE, static_cast<long>(req.body.size()));
        curl_easy_setopt(easy, CURLOPT_COPYPOSTFIELDS, req.body.data());
    }
    for (const auto &h : req.headers) {
        struct curl_slist *appended = curl_slist_append(ctx->headers, h.c_str());
        if (!appended) {
            // OOM: curl_slist_append returns null and leaves the existing list intact. Don't
            // overwrite ctx->headers with null (that would leak the partial list and drop headers);
            // abort the request cleanly. The partial list is freed by ~EasyContext at return.
            curl_easy_cleanup(easy);
            HttpResult fail;
            fail.transport_ok = false;
            fail.curl_code = CURLE_OUT_OF_MEMORY;
            fail.error_msg = "curl_slist_append failed (out of memory)";
            if (ctx->on_done) ctx->on_done(fail);
            return;
        }
        ctx->headers = appended;
    }
    if (ctx->headers) {
        curl_easy_setopt(easy, CURLOPT_HTTPHEADER, ctx->headers);
    }
    ctx->capture = req.capture_response;
    curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION, ctx->capture ? &HttpClient::write_capture : &HttpClient::write_discard);
    curl_easy_setopt(easy, CURLOPT_WRITEDATA, ctx.get());
    curl_easy_setopt(easy, CURLOPT_PRIVATE, ctx.get());
    curl_easy_setopt(easy, CURLOPT_ERRORBUFFER, ctx->errbuf);
    _easy[easy] = std::move(ctx);
    if (curl_multi_add_handle(_multi, easy) != CURLM_OK) {
        // add_handle failed: deliver a transport failure and drop the handle/context so it
        // doesn't leak in _easy or stall the loop (the easy handle was never added to multi).
        ResultCallback cb;
        auto it = _easy.find(easy);
        if (it != _easy.end()) {
            cb = it->second->on_done;
        }
        curl_easy_cleanup(easy);
        _easy.erase(easy); // frees the EasyContext (+ header slist via ~EasyContext)
        if (cb) {
            HttpResult fail;
            fail.transport_ok = false;
            fail.curl_code = CURLE_FAILED_INIT;
            cb(fail);
        }
        return;
    }
    // Kick the transfer. If we're inside a completion callback (check_multi_info() is draining),
    // do NOT drive curl synchronously — that would re-enter the drain. Arm the timer for 0 ms so
    // the kick runs on the next loop iteration, after the outer drain unwinds. Otherwise kick now
    // (matches curl's multi-socket examples and avoids a stalled first request).
    if (_processing) {
        if (_timer && !_timer->closing()) {
            _timer->start(uvw::timer_handle::time{0}, uvw::timer_handle::time{0});
        }
        return;
    }
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
        if (what & (CURL_POLL_IN | CURL_POLL_OUT)) {
            sctx->poll->start(ev);
        } else {
            // CURL_POLL_NONE: curl wants no events right now — stop polling rather than call
            // start() with an empty (invalid) libuv event mask.
            sctx->poll->stop();
        }
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
    if (_processing) return; // re-entrancy guard: a callback issued work that re-entered the drain
    _processing = true;
    struct ProcessingReset {
        bool &flag;
        ~ProcessingReset() { flag = false; }
    } processing_reset{_processing};
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
            if (it != _easy.end() && it->second->capture) {
                result.response_body = std::move(it->second->response);
            }
            char *ct = nullptr;
            curl_easy_getinfo(easy, CURLINFO_CONTENT_TYPE, &ct); // may be null (no Content-Type)
            if (ct) {
                result.content_type = ct; // raw header value; consumers compare case-insensitively
            }
        } else {
            result.transport_ok = false;
            result.curl_code = msg->data.result;
            // Prefer curl's per-handle error buffer (set via CURLOPT_ERRORBUFFER); fall back to
            // the generic code string. Surfaced for logging by the probes.
            if (it != _easy.end() && it->second->errbuf[0] != '\0') {
                result.error_msg = it->second->errbuf;
            } else {
                result.error_msg = curl_easy_strerror(msg->data.result);
            }
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
