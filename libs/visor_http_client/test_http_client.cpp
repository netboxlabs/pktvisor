#include "HttpClient.h"
#include <catch2/catch_test_macros.hpp>
#include <httplib.h>
#include <uvw/loop.h>
#include <thread>

using namespace visor::http;

// Spin a throwaway httplib server on an ephemeral port; returns port.
static int start_test_server(httplib::Server &svr, std::thread &t)
{
    svr.Get("/ok", [](const httplib::Request &, httplib::Response &res) { res.set_content("hi", "text/plain"); });
    svr.Get("/notfound", [](const httplib::Request &, httplib::Response &res) { res.status = 404; });
    svr.Get("/error", [](const httplib::Request &, httplib::Response &res) { res.status = 500; });
    svr.Get("/slow", [](const httplib::Request &, httplib::Response &res) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        res.set_content("late", "text/plain");
    });
    svr.Post("/echo", [](const httplib::Request &req, httplib::Response &res) {
        res.set_content(req.body, "application/octet-stream");
    });
    int port = svr.bind_to_any_port("127.0.0.1");
    REQUIRE(port > 0);
    t = std::thread([&svr] { svr.listen_after_bind(); });
    // Wait until the server is actually accepting connections before the test
    // connects — avoids a connect-before-listen race on slow/loaded CI machines.
    svr.wait_until_ready();
    return port;
}

// Arm a watchdog timer that calls loop->stop() after timeout_ms.
// The handle is unreferenced so loop->run() returns as soon as the real work
// handles close — the watchdog fires only if the loop would otherwise stall
// forever (hang-guard). The caller must close the returned handle after
// loop->run() completes.
static std::shared_ptr<uvw::timer_handle> arm_watchdog(std::shared_ptr<uvw::loop> loop, uint64_t timeout_ms)
{
    auto wd = loop->resource<uvw::timer_handle>();
    wd->on<uvw::timer_event>([loop](const auto &, auto &) { loop->stop(); });
    wd->start(uvw::timer_handle::time{timeout_ms}, uvw::timer_handle::time{0});
    // Unreference: the watchdog must not prevent the loop from exiting when all
    // real work handles (curl poll + timer) have closed. uv_unref makes the
    // handle "idle" w.r.t. loop liveness — the loop exits when only unreferenced
    // handles remain active, then we close the watchdog in disarm_watchdog.
    wd->unreference();
    return wd;
}

// Disarm the watchdog and drain its close on the loop.
static void disarm_watchdog(std::shared_ptr<uvw::loop> loop, std::shared_ptr<uvw::timer_handle> wd)
{
    if (wd && !wd->closing()) {
        wd->stop();
        wd->close();
        loop->run();
    }
}

TEST_CASE("HttpClient basic results", "[http][client]")
{
    httplib::Server svr;
    std::thread server_thread;
    int port = start_test_server(svr, server_thread);

    auto loop = uvw::loop::create();
    HttpClient client(loop);
    std::string base = "http://127.0.0.1:" + std::to_string(port);

    std::vector<HttpResult> results;
    auto on_done = [&](const HttpResult &r) { results.push_back(r); };
    // Named init (not positional aggregate) so adding HttpRequest fields doesn't warn.
    auto get_req = [](std::string url, uint64_t timeout_ms) {
        HttpRequest r;
        r.url = std::move(url);
        r.timeout_ms = timeout_ms;
        return r;
    };

    SECTION("200 OK")
    {
        client.request(get_req(base + "/ok", 2000), on_done);
        auto wd = arm_watchdog(loop, 5000);
        loop->run();
        disarm_watchdog(loop, wd);
        REQUIRE(results.size() == 1);
        CHECK(results[0].transport_ok);
        CHECK(results[0].status_code == 200);
        const auto &t = results[0].timings;
        CHECK(t.total_us > 0);
        // Per-phase delta sanity (plain HTTP, no TLS): the TLS phase must be 0, and every
        // phase delta must stay within the total — guards the delta arithmetic against a
        // wrong base or an unsigned underflow producing a huge bogus value.
        CHECK(t.tls_us == 0);
        CHECK(t.dns_us <= t.total_us);
        CHECK(t.connect_us <= t.total_us);
        CHECK(t.ttfb_us <= t.total_us);
    }
    SECTION("404")
    {
        client.request(get_req(base + "/notfound", 2000), on_done);
        auto wd = arm_watchdog(loop, 5000);
        loop->run();
        disarm_watchdog(loop, wd);
        REQUIRE(results.size() == 1);
        CHECK(results[0].transport_ok);
        CHECK(results[0].status_code == 404);
    }
    SECTION("connection refused")
    {
        client.request(get_req("http://127.0.0.1:1/x", 2000), on_done);
        auto wd = arm_watchdog(loop, 5000);
        loop->run();
        disarm_watchdog(loop, wd);
        REQUIRE(results.size() == 1);
        CHECK_FALSE(results[0].transport_ok);
    }
    SECTION("timeout")
    {
        client.request(get_req(base + "/slow", 100), on_done);
        auto wd = arm_watchdog(loop, 5000);
        loop->run();
        disarm_watchdog(loop, wd);
        REQUIRE(results.size() == 1);
        CHECK_FALSE(results[0].transport_ok);
        CHECK(results[0].curl_code == CURLE_OPERATION_TIMEDOUT);
    }
    SECTION("close while in flight")
    {
        // Issue the slow request but then immediately close() before loop->run() completes it.
        // The process must not crash and results must stay empty (interrupted = no metric recorded).
        client.request(get_req(base + "/slow", 5000), on_done);
        client.close();
        auto wd = arm_watchdog(loop, 3000);
        loop->run();
        disarm_watchdog(loop, wd);
        CHECK(results.empty());
    }

    // close() is idempotent — this is a no-op for the "close while in flight" section.
    client.close();
    loop->run();          // drain handle closes
    svr.stop();
    if (server_thread.joinable()) server_thread.join();
}

TEST_CASE("HttpClient POST body + headers + response capture", "[http][client]")
{
    httplib::Server svr;
    std::thread server_thread;
    int port = start_test_server(svr, server_thread);
    auto loop = uvw::loop::create();
    HttpClient client(loop);
    std::string base = "http://127.0.0.1:" + std::to_string(port);

    std::vector<HttpResult> results;
    auto on_done = [&](const HttpResult &r) { results.push_back(r); };

    SECTION("POST echoes body when capture_response")
    {
        HttpRequest req;
        req.url = base + "/echo";
        req.method = "POST";
        req.body = std::string("\x00\x01hello", 7); // binary-safe
        req.headers = {"Content-Type: application/octet-stream"};
        req.capture_response = true;
        req.timeout_ms = 2000;
        client.request(req, on_done);
        auto wd = arm_watchdog(loop, 5000);
        loop->run();
        disarm_watchdog(loop, wd);
        REQUIRE(results.size() == 1);
        CHECK(results[0].transport_ok);
        CHECK(results[0].status_code == 200);
        CHECK(results[0].response_body == std::string("\x00\x01hello", 7));
    }
    SECTION("body NOT captured by default")
    {
        HttpRequest req;
        req.url = base + "/ok";
        req.capture_response = false;
        req.timeout_ms = 2000;
        client.request(req, on_done);
        auto wd = arm_watchdog(loop, 5000);
        loop->run();
        disarm_watchdog(loop, wd);
        REQUIRE(results.size() == 1);
        CHECK(results[0].response_body.empty());
    }

    client.close();
    loop->run();
    svr.stop();
    if (server_thread.joinable()) server_thread.join();
}
