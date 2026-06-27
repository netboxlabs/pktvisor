#pragma once
#include "HttpTypes.h"
#include <curl/curl.h>
#include <functional>
#include <memory>
#include <unordered_map>
#include <uvw/loop.h>
#include <uvw/poll.h>
#include <uvw/timer.h>

namespace visor::http {

// Threading contract: HttpClient is CONSTRUCTED on the control thread, before the
// netprobe io thread is spawned (no concurrency at that point — same as _async_h/_timer
// in NetProbeInputStream). Thereafter request(), the curl/uvw callbacks, and close()
// run ONLY on the netprobe io (loop) thread. curl_multi is not thread-safe, so one
// HttpClient is touched by exactly one thread for its whole active life.
//
// Reentrancy contract: the ResultCallback (on_done) MUST NOT call request() or close()
// synchronously. Here is why each layer of protection is insufficient on its own:
//
//   check_multi_info() deferred-drain: it collects (callback, result) pairs FIRST,
//   then fires callbacks after the drain loop — so a callback cannot mutate _easy
//   mid-iteration of the *current* drain pass. This protects only that single pass.
//
//   request() is NOT protected: it calls curl_multi_socket_action + check_multi_info()
//   inline. If on_done calls request() synchronously, check_multi_info() re-enters
//   recursively from inside the outer check_multi_info()'s callback-fire loop, which
//   can mutate _easy/_sockets under the outer drain.
//
//   close() is similarly unsafe: it clears _easy/_sockets while the outer drain may
//   hold iterators or pointers into those collections.
//
// Therefore: on_done must not call request() or close() synchronously. Defer follow-up
// requests onto the loop (uvw idle/timer). If future callers require synchronous chaining,
// add an explicit reentrancy guard (e.g. a processing-depth counter) — see DoH note.
class HttpClient
{
public:
    using ResultCallback = std::function<void(const HttpResult &)>;
    explicit HttpClient(std::shared_ptr<uvw::loop> loop);
    ~HttpClient();
    void request(const HttpRequest &req, ResultCallback on_done);
    void close();

private:
    // per-easy-handle context (owns the result callback + a write sink)
    struct EasyContext {
        CURL *easy{nullptr};
        ResultCallback on_done;
        char errbuf[CURL_ERROR_SIZE]{};
        curl_slist *headers{nullptr};   // owned; freed in dtor (after curl_easy_cleanup)
        bool capture{false};
        std::string response;           // captured body (bounded to 64 KB)
        ~EasyContext() { if (headers) curl_slist_free_all(headers); }
    };
    // per-socket context: a uvw poll handle curl watches (owned in _sockets below)
    struct SocketContext {
        std::shared_ptr<uvw::poll_handle> poll;
        curl_socket_t sockfd{};
    };

    static int socket_cb(CURL *easy, curl_socket_t s, int what, void *userp, void *socketp);
    static int timer_cb(CURLM *multi, long timeout_ms, void *userp);
    static size_t write_discard(char *ptr, size_t size, size_t nmemb, void *userdata);
    static size_t write_capture(char *ptr, size_t size, size_t nmemb, void *userdata);
    void on_socket_event(curl_socket_t sockfd, int events);
    void on_timeout();
    void check_multi_info();

    std::shared_ptr<uvw::loop> _loop;
    CURLM *_multi{nullptr};
    bool _closed{false};
    std::shared_ptr<uvw::timer_handle> _timer;
    std::unordered_map<CURL *, std::unique_ptr<EasyContext>> _easy;
    // we OWN the socket contexts here (curl_multi_assign stores the bare pointer);
    // close() sweeps these directly rather than relying on CURL_POLL_REMOVE firing for all.
    std::unordered_map<curl_socket_t, std::unique_ptr<SocketContext>> _sockets;
};
}
