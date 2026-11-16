#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_test_visor.hpp>
#include <catch2/otel_helpers.hpp>

#include <sstream>

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wzero-as-null-pointer-constant"
#endif
#include <pcapplusplus/IcmpLayer.h>
#include <pcapplusplus/IcmpV6Layer.h>
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

#include "NetProbeInputStream.h"
#include "NetProbeStreamHandler.h"

using namespace visor::handler::netprobe;
using namespace visor::input::netprobe;
using namespace std::chrono;
using namespace nlohmann;

namespace {

// Holds the boilerplate needed to construct a NetProbeStreamHandler so that the
// metrics manager's `_groups` bitset is initialized. `start()` is what calls
// process_groups() which in turn calls _metrics->configure_groups(&_groups);
// without it, `group_enabled()` dereferences a null pointer and segfaults.
struct UnitFixture {
    visor::Config c;
    NetProbeInputStream stream{"netprobe-unit"};
    visor::InputEventProxy *proxy;
    std::unique_ptr<NetProbeStreamHandler> handler;

    explicit UnitFixture(uint64_t num_periods = 1)
    {
        c.config_set<uint64_t>("num_periods", num_periods);
        proxy = stream.add_event_proxy(c);
        handler = std::make_unique<NetProbeStreamHandler>("netprobe-unit", proxy, &c);
        handler->start();
    }

    ~UnitFixture()
    {
        handler->stop();
    }

    NetProbeMetricsManager *manager() { return const_cast<NetProbeMetricsManager *>(handler->metrics()); }
};

// Same as UnitFixture but enables the "quantiles" group (needed for response_size_bytes,
// which is fed under group::NetProbeMetrics::Quantiles).
struct QuantilesFixture {
    visor::Config c;
    NetProbeInputStream stream;
    visor::InputEventProxy *proxy;
    std::unique_ptr<NetProbeStreamHandler> handler;

    explicit QuantilesFixture(const std::string &name, uint64_t num_periods = 1)
        : stream(name)
    {
        c.config_set<uint64_t>("num_periods", num_periods);
        proxy = stream.add_event_proxy(c);
        handler = std::make_unique<NetProbeStreamHandler>(name, proxy, &c);
        handler->config_set<visor::Configurable::StringList>("enable", {"quantiles"});
        handler->start();
    }

    ~QuantilesFixture()
    {
        handler->stop();
    }

    NetProbeMetricsManager *manager() { return const_cast<NetProbeMetricsManager *>(handler->metrics()); }
};

enum class Path {
    Send,
    Recv
};

// Pass an ICMP layer through the input's event proxy wrapped in a Packet, as PingProbe does: Send
// carries a probe's own request, Recv whatever the shared ping receiver read. The receiver hands
// each packet to every probe in turn, under that probe's target name.
void emit_ping(visor::InputEventProxy *proxy, Path path, pcpp::Layer &layer, timespec stamp,
    const std::vector<std::string> &targets = {"lo"})
{
    auto *netprobe_proxy = static_cast<NetProbeInputEventProxy *>(proxy);
    pcpp::Packet packet;
    packet.addLayer(&layer);
    for (const auto &target : targets) {
        if (path == Path::Send) {
            netprobe_proxy->probe_send_cb(packet, TestType::Ping, target, stamp);
        } else {
            netprobe_proxy->probe_recv_cb(packet, TestType::Ping, target, stamp);
        }
    }
}

}

TEST_CASE("Net Probe ping tests", "[netprobe][ping]")
{
    // Requires raw-socket privileges + external network and only asserts
    // attempts >= 0 (always true). Bus-errors in CI; the unit tests below
    // cover the same code paths deterministically.
    SKIP("requires raw-socket privileges and external network");
    NetProbeInputStream stream{"net-probe-test"};
    stream.config_set("test_type", "ping");
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", "localhost");
    targets->config_set<std::shared_ptr<visor::Configurable>>("my_target", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);

    visor::Config c;
    c.config_set<uint64_t>("num_periods", 1);
    auto stream_proxy = stream.add_event_proxy(c);
    NetProbeStreamHandler netprobe_handler{"net-probe-test", stream_proxy, &c};

    netprobe_handler.start();
    stream.start();
    std::this_thread::sleep_for(1s);
    netprobe_handler.stop();
    stream.stop();

    auto event_data = netprobe_handler.metrics()->bucket(0)->event_data_locked();

    CHECK(netprobe_handler.metrics()->current_periods() == 1);
    CHECK(netprobe_handler.metrics()->bucket(0)->period_length() >= 1);

    json j;
    netprobe_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["targets"]["my_target"]["attempts"] >= 0);
}

TEST_CASE("NetProbe metrics process_failure each ErrorType", "[netprobe][unit]")
{
    UnitFixture fx;

    fx.manager()->process_failure(ErrorType::DnsLookupFailure, "host-dns");
    fx.manager()->process_failure(ErrorType::Timeout, "host-timeout");
    fx.manager()->process_failure(ErrorType::SocketError, "host-socket");
    fx.manager()->process_failure(ErrorType::InvalidIp, "host-invalid");
    fx.manager()->process_failure(ErrorType::ConnectFailure, "host-connect");

    json j;
    fx.manager()->bucket(0)->to_json(j);

    CHECK(j["targets"]["host-dns"]["dns_lookup_failures"] == 1);
    CHECK(j["targets"]["host-timeout"]["packets_timeout"] == 1);
    // SocketError, InvalidIp, ConnectFailure all map to connect_failures
    CHECK(j["targets"]["host-socket"]["connect_failures"] == 1);
    CHECK(j["targets"]["host-invalid"]["connect_failures"] == 1);
    CHECK(j["targets"]["host-connect"]["connect_failures"] == 1);
}

TEST_CASE("NetProbe TCP send/recv transaction", "[netprobe][unit]")
{
    UnitFixture fx;

    timespec ts_send{100, 0};
    timespec ts_recv{100, 50'000'000}; // 50ms later

    fx.manager()->process_netprobe_tcp(true, "tcp-target", ts_send);
    fx.manager()->process_netprobe_tcp(false, "tcp-target", ts_recv);

    json j;
    fx.manager()->bucket(0)->to_json(j);

    CHECK(j["targets"]["tcp-target"]["attempts"] == 1);
    CHECK(j["targets"]["tcp-target"]["successes"] == 1);
}

TEST_CASE("NetProbe TCP transaction timeout", "[netprobe][unit]")
{
    UnitFixture fx;
    // Default ttl is 5000ms. Use a recv timestamp 6s after send so the
    // transaction is detected as TimedOut by maybe_end_transaction.
    timespec ts_send{100, 0};
    timespec ts_recv_late{106, 0};

    fx.manager()->process_netprobe_tcp(true, "tcp-late", ts_send);
    fx.manager()->process_netprobe_tcp(false, "tcp-late", ts_recv_late);

    json j;
    fx.manager()->bucket(0)->to_json(j);

    CHECK(j["targets"]["tcp-late"]["attempts"] == 1);
    CHECK(j["targets"]["tcp-late"]["packets_timeout"] == 1);
}

TEST_CASE("NetProbe ICMP request/reply transaction lifecycle", "[netprobe][unit]")
{
    // Drive process_netprobe_icmp directly with handcrafted IcmpLayers
    // (setEchoRequestData / setEchoReplyData), covering the ICMP_ECHO_REQUEST
    // start-transaction path and the ICMP_ECHO_REPLY end-transaction path —
    // both branches inside NetProbeMetricsManager::process_netprobe_icmp.
    UnitFixture fx;

    const uint8_t payload[] = {0xde, 0xad, 0xbe, 0xef};
    timespec ts_req{200, 0};
    timespec ts_rep{200, 12'000'000}; // 12ms later, well inside the default 5s TTL

    pcpp::IcmpLayer req;
    req.setEchoRequestData(/*id=*/0x1234, /*sequence=*/1, /*timestamp=*/0, payload, sizeof(payload));
    fx.manager()->process_netprobe_icmp(&req, "icmp-tgt", ts_req);

    pcpp::IcmpLayer reply;
    reply.setEchoReplyData(/*id=*/0x1234, /*sequence=*/1, /*timestamp=*/0, payload, sizeof(payload));
    fx.manager()->process_netprobe_icmp(&reply, "icmp-tgt", ts_rep);

    json j;
    fx.manager()->bucket(0)->to_json(j);
    CHECK(j["targets"]["icmp-tgt"]["attempts"] == 1);
    CHECK(j["targets"]["icmp-tgt"]["successes"] == 1);
}

TEST_CASE("NetProbe ICMP reply that times out records a failure", "[netprobe][unit]")
{
    // ECHO_REQUEST → start transaction; ECHO_REPLY 6s later (default TTL is
    // 5s) → maybe_end_transaction returns TimedOut → process_failure(Timeout).
    UnitFixture fx;

    const uint8_t payload[] = {0x00, 0x11, 0x22, 0x33};
    timespec ts_req{100, 0};
    timespec ts_rep{106, 0};

    pcpp::IcmpLayer req;
    req.setEchoRequestData(0xCAFE, 7, 0, payload, sizeof(payload));
    fx.manager()->process_netprobe_icmp(&req, "icmp-slow", ts_req);

    pcpp::IcmpLayer reply;
    reply.setEchoReplyData(0xCAFE, 7, 0, payload, sizeof(payload));
    fx.manager()->process_netprobe_icmp(&reply, "icmp-slow", ts_rep);

    json j;
    fx.manager()->bucket(0)->to_json(j);
    CHECK(j["targets"]["icmp-slow"]["attempts"] == 1);
    CHECK(j["targets"]["icmp-slow"]["packets_timeout"] == 1);
}

TEST_CASE("NetProbe ICMP reply with no prior request is ignored", "[netprobe][unit]")
{
    // ECHO_REPLY with no matching start_transaction → Result::NotExist branch
    // in maybe_end_transaction → neither new_transaction nor process_failure
    // fires. Counters must stay at zero.
    UnitFixture fx;

    const uint8_t payload[] = {0xAA};
    timespec ts{300, 0};

    pcpp::IcmpLayer orphan_reply;
    orphan_reply.setEchoReplyData(0xBEEF, 99, 0, payload, sizeof(payload));
    fx.manager()->process_netprobe_icmp(&orphan_reply, "icmp-orphan", ts);

    json j;
    fx.manager()->bucket(0)->to_json(j);
    // No targets created — the orphan reply produced no metrics.
    CHECK(!j.contains("targets"));
}

TEST_CASE("NetProbe ICMP v4 matching: single-target request+reply", "[netprobe][unit]")
{
    // Verifies the per-id matching contract: a REQUEST with id=0xABCD/seq=5 is
    // matched exclusively by the REPLY carrying the same id+seq tuple. The
    // transaction key is (id << 16) | seq — unchanged from the existing impl.
    UnitFixture fx;

    const uint8_t payload[] = {0x01, 0x02, 0x03, 0x04};
    timespec ts_req{400, 0};
    timespec ts_rep{400, 20'000'000}; // 20 ms later, well inside 5s TTL

    pcpp::IcmpLayer req;
    req.setEchoRequestData(/*id=*/0xABCD, /*sequence=*/5, /*timestamp=*/0, payload, sizeof(payload));
    fx.manager()->process_netprobe_icmp(&req, "v4-match-tgt", ts_req);

    pcpp::IcmpLayer reply;
    reply.setEchoReplyData(/*id=*/0xABCD, /*sequence=*/5, /*timestamp=*/0, payload, sizeof(payload));
    fx.manager()->process_netprobe_icmp(&reply, "v4-match-tgt", ts_rep);

    json j;
    fx.manager()->bucket(0)->to_json(j);
    CHECK(j["targets"]["v4-match-tgt"]["attempts"] == 1);
    CHECK(j["targets"]["v4-match-tgt"]["successes"] == 1);
}

TEST_CASE("NetProbe ICMP v4 matching: two targets with distinct ids do not cross-match", "[netprobe][unit]")
{
    // Two separate targets each use a distinct ping_id. Sending both requests
    // then both replies must close each transaction against only its own target.
    // Neither target should see the other's success.
    UnitFixture fx;

    const uint8_t payload[] = {0xFF};
    timespec ts_req_a{500, 0};
    timespec ts_rep_a{500, 10'000'000};
    timespec ts_req_b{500, 1'000'000};
    timespec ts_rep_b{500, 11'000'000};

    // Target A: id=0x0001, seq=1
    pcpp::IcmpLayer req_a;
    req_a.setEchoRequestData(0x0001, 1, 0, payload, sizeof(payload));
    fx.manager()->process_netprobe_icmp(&req_a, "v4-tgt-a", ts_req_a);

    // Target B: id=0x0002, seq=1 (different id)
    pcpp::IcmpLayer req_b;
    req_b.setEchoRequestData(0x0002, 1, 0, payload, sizeof(payload));
    fx.manager()->process_netprobe_icmp(&req_b, "v4-tgt-b", ts_req_b);

    // Reply for A only
    pcpp::IcmpLayer rep_a;
    rep_a.setEchoReplyData(0x0001, 1, 0, payload, sizeof(payload));
    fx.manager()->process_netprobe_icmp(&rep_a, "v4-tgt-a", ts_rep_a);

    // Reply for B only
    pcpp::IcmpLayer rep_b;
    rep_b.setEchoReplyData(0x0002, 1, 0, payload, sizeof(payload));
    fx.manager()->process_netprobe_icmp(&rep_b, "v4-tgt-b", ts_rep_b);

    json j;
    fx.manager()->bucket(0)->to_json(j);
    // Each target gets exactly one success — no cross-match
    CHECK(j["targets"]["v4-tgt-a"]["attempts"] == 1);
    CHECK(j["targets"]["v4-tgt-a"]["successes"] == 1);
    CHECK(j["targets"]["v4-tgt-b"]["attempts"] == 1);
    CHECK(j["targets"]["v4-tgt-b"]["successes"] == 1);
}

TEST_CASE("NetProbe ICMPv6 matching: single-target request+reply", "[netprobe][unit]")
{
    // Verifies process_netprobe_icmpv6: a REQUEST with id=0x1111/seq=3 is
    // matched exclusively by the REPLY carrying the same id+seq. successes==1.
    UnitFixture fx;

    timespec ts_req{600, 0};
    timespec ts_rep{600, 15'000'000}; // 15 ms later, well inside 5s TTL

    pcpp::ICMPv6EchoLayer req(pcpp::ICMPv6EchoLayer::REQUEST, /*id=*/0x1111, /*seq=*/3, nullptr, 0);
    fx.manager()->process_netprobe_icmpv6(&req, "v6-match-tgt", ts_req);

    pcpp::ICMPv6EchoLayer reply(pcpp::ICMPv6EchoLayer::REPLY, /*id=*/0x1111, /*seq=*/3, nullptr, 0);
    fx.manager()->process_netprobe_icmpv6(&reply, "v6-match-tgt", ts_rep);

    json j;
    fx.manager()->bucket(0)->to_json(j);
    CHECK(j["targets"]["v6-match-tgt"]["attempts"] == 1);
    CHECK(j["targets"]["v6-match-tgt"]["successes"] == 1);
}

TEST_CASE("NetProbe ICMPv6 matching: two targets with distinct ids do not cross-match", "[netprobe][unit]")
{
    // Two separate targets each use a distinct v6 ping_id. Sending both requests
    // then both replies must close each transaction against only its own target.
    UnitFixture fx;

    timespec ts_req_a{700, 0};
    timespec ts_rep_a{700, 10'000'000};
    timespec ts_req_b{700, 1'000'000};
    timespec ts_rep_b{700, 11'000'000};

    // Target A: id=0x0010, seq=1
    pcpp::ICMPv6EchoLayer req_a(pcpp::ICMPv6EchoLayer::REQUEST, 0x0010, 1, nullptr, 0);
    fx.manager()->process_netprobe_icmpv6(&req_a, "v6-tgt-a", ts_req_a);

    // Target B: id=0x0020, seq=1 (different id)
    pcpp::ICMPv6EchoLayer req_b(pcpp::ICMPv6EchoLayer::REQUEST, 0x0020, 1, nullptr, 0);
    fx.manager()->process_netprobe_icmpv6(&req_b, "v6-tgt-b", ts_req_b);

    // Reply for A only
    pcpp::ICMPv6EchoLayer rep_a(pcpp::ICMPv6EchoLayer::REPLY, 0x0010, 1, nullptr, 0);
    fx.manager()->process_netprobe_icmpv6(&rep_a, "v6-tgt-a", ts_rep_a);

    // Reply for B only
    pcpp::ICMPv6EchoLayer rep_b(pcpp::ICMPv6EchoLayer::REPLY, 0x0020, 1, nullptr, 0);
    fx.manager()->process_netprobe_icmpv6(&rep_b, "v6-tgt-b", ts_rep_b);

    json j;
    fx.manager()->bucket(0)->to_json(j);
    // Each target gets exactly one success — no cross-match
    CHECK(j["targets"]["v6-tgt-a"]["attempts"] == 1);
    CHECK(j["targets"]["v6-tgt-a"]["successes"] == 1);
    CHECK(j["targets"]["v6-tgt-b"]["attempts"] == 1);
    CHECK(j["targets"]["v6-tgt-b"]["successes"] == 1);
}

TEST_CASE("NetProbe ping: a local target's looped-back request is not a second attempt", "[netprobe][unit]")
{
    // A ping to a local address comes back through the shared receiver twice: once as the
    // request itself, then as the reply.
    UnitFixture fx;
    const uint8_t payload[] = {0x01, 0x02};

    pcpp::IcmpLayer sent;
    sent.setEchoRequestData(0x2a, 1, 0, payload, sizeof(payload));
    emit_ping(fx.proxy, Path::Send, sent, {100, 0});

    pcpp::IcmpLayer looped;
    looped.setEchoRequestData(0x2a, 1, 0, payload, sizeof(payload));
    emit_ping(fx.proxy, Path::Recv, looped, {100, 1'000'000});

    pcpp::IcmpLayer reply;
    reply.setEchoReplyData(0x2a, 1, 0, payload, sizeof(payload));
    emit_ping(fx.proxy, Path::Recv, reply, {100, 12'000'000});

    json j;
    fx.manager()->bucket(0)->to_json(j);
    CHECK(j["targets"]["lo"]["attempts"] == 1);
    CHECK(j["targets"]["lo"]["successes"] == 1);
    // the round trip is timed from the send, not from the looped-back request
    CHECK(j["targets"]["lo"]["response_max_us"] == 12000);
}

TEST_CASE("NetProbe ping: echo requests from another host are not attempts", "[netprobe][unit]")
{
    // The shared IPv4 receiver also hands every ping probe the requests of a host pinging this one.
    UnitFixture fx;
    const uint8_t payload[] = {0x01, 0x02};

    pcpp::IcmpLayer sent;
    sent.setEchoRequestData(0x2a, 1, 0, payload, sizeof(payload));
    emit_ping(fx.proxy, Path::Send, sent, {100, 0});

    // the same id and sequence as the probe's request, so it would restart the probe's transaction
    pcpp::IcmpLayer foreign;
    foreign.setEchoRequestData(0x2a, 1, 0, payload, sizeof(payload));
    emit_ping(fx.proxy, Path::Recv, foreign, {100, 5'000'000});

    // the ICMPv6 receiver passes only replies; this exercises the handler's defensive check
    pcpp::ICMPv6EchoLayer foreign6(pcpp::ICMPv6EchoLayer::REQUEST, 0x77, 9, nullptr, 0);
    emit_ping(fx.proxy, Path::Recv, foreign6, {100, 6'000'000});

    pcpp::IcmpLayer reply;
    reply.setEchoReplyData(0x2a, 1, 0, payload, sizeof(payload));
    emit_ping(fx.proxy, Path::Recv, reply, {100, 12'000'000});

    json j;
    fx.manager()->bucket(0)->to_json(j);
    CHECK(j["targets"]["lo"]["attempts"] == 1);
    CHECK(j["targets"]["lo"]["successes"] == 1);
    CHECK(j["targets"]["lo"]["response_max_us"] == 12000);
}

TEST_CASE("NetProbe ping: a looped-back request does not move a probe to another target", "[netprobe][unit]")
{
    // Two targets in one policy: only "local" probes here. The receiver hands each packet to
    // every probe in turn, so the looped-back request and the reply reach both, each under its
    // own target name.
    UnitFixture fx;
    const uint8_t payload[] = {0x01, 0x02};
    const std::vector<std::string> both{"local", "remote"};

    pcpp::IcmpLayer sent;
    sent.setEchoRequestData(0x2a, 1, 0, payload, sizeof(payload));
    emit_ping(fx.proxy, Path::Send, sent, {100, 0}, {"local"});

    pcpp::IcmpLayer looped;
    looped.setEchoRequestData(0x2a, 1, 0, payload, sizeof(payload));
    emit_ping(fx.proxy, Path::Recv, looped, {100, 1'000'000}, both);

    pcpp::IcmpLayer reply;
    reply.setEchoReplyData(0x2a, 1, 0, payload, sizeof(payload));
    emit_ping(fx.proxy, Path::Recv, reply, {100, 12'000'000}, both);

    json j;
    fx.manager()->bucket(0)->to_json(j);
    // "remote" sent nothing and was answered nothing: it has no metrics at all
    CHECK(!j["targets"].contains("remote"));
    CHECK(j["targets"]["local"]["attempts"] == 1);
    CHECK(j["targets"]["local"]["successes"] == 1);
    CHECK(j["targets"]["local"]["response_max_us"] == 12000);
}

TEST_CASE("NetProbe process_filtered increments event count", "[netprobe][unit]")
{
    UnitFixture fx;

    timespec stamp{200, 0};
    fx.manager()->process_filtered(stamp);
    fx.manager()->process_filtered(stamp);

    auto event_data = fx.manager()->bucket(0)->event_data_locked();
    CHECK(event_data.num_events->value() == 2);
}

TEST_CASE("NetProbe to_prometheus emits configured metrics", "[netprobe][unit]")
{
    UnitFixture fx;

    fx.manager()->process_failure(ErrorType::Timeout, "tprom");

    visor::PrometheusSerializer out;
    fx.manager()->bucket(0)->to_prometheus(out, {});
    auto s = out.finalize();

    // Counter name is registered in Target ctor as "packets_timeout".
    CHECK(s.find("packets_timeout") != std::string::npos);
    CHECK(s.find("tprom") != std::string::npos);
}

TEST_CASE("NetProbe to_opentelemetry emits gauge values per target", "[netprobe][unit]")
{
    UnitFixture fx;

    // tgt-ok: send (attempts++) then recv within ttl (successes++)
    timespec ts_send{500, 0};
    timespec ts_recv{500, 50'000'000};
    fx.manager()->process_netprobe_tcp(true, "tgt-ok", ts_send);
    fx.manager()->process_netprobe_tcp(false, "tgt-ok", ts_recv);

    // tgt-fail: bare Timeout failure (no attempts increment per process_failure)
    fx.manager()->process_failure(ErrorType::Timeout, "tgt-fail");
    fx.manager()->process_failure(ErrorType::DnsLookupFailure, "tgt-fail");

    opentelemetry::proto::metrics::v1::ScopeMetrics scope;
    timespec start_ts{500, 0};
    timespec end_ts{501, 0};
    fx.manager()->bucket(0)->to_opentelemetry(scope, start_ts, end_ts, {});

    using visor::test::otel_gauge_sum;
    // Each Counter::to_opentelemetry emits a separate metric entry per target,
    // so the bucket-level total for each name is the sum across all targets.
    CHECK(otel_gauge_sum(scope, "netprobe_attempts") == 1);
    CHECK(otel_gauge_sum(scope, "netprobe_successes") == 1);
    CHECK(otel_gauge_sum(scope, "netprobe_packets_timeout") == 1);
    CHECK(otel_gauge_sum(scope, "netprobe_dns_lookup_failures") == 1);
    CHECK(otel_gauge_sum(scope, "netprobe_connect_failures") == 0);
}

TEST_CASE("NetProbe specialized_merge aggregates targets across buckets", "[netprobe][unit]")
{
    UnitFixture fx_a(2);
    UnitFixture fx_b(2);

    fx_a.manager()->process_failure(ErrorType::Timeout, "shared");
    fx_a.manager()->process_failure(ErrorType::Timeout, "shared");
    fx_b.manager()->process_failure(ErrorType::Timeout, "shared");
    fx_b.manager()->process_failure(ErrorType::DnsLookupFailure, "only-in-b");

    UnitFixture fx_merged(2);
    auto *merged = const_cast<NetProbeMetricsBucket *>(fx_merged.manager()->bucket(0));
    merged->specialized_merge(*fx_a.manager()->bucket(0), visor::Metric::Aggregate::DEFAULT);
    merged->specialized_merge(*fx_b.manager()->bucket(0), visor::Metric::Aggregate::DEFAULT);

    json j;
    merged->to_json(j);
    CHECK(j["targets"]["shared"]["packets_timeout"] == 3);
    CHECK(j["targets"]["only-in-b"]["dns_lookup_failures"] == 1);
}

TEST_CASE("NetProbe HTTP status-aware metrics: counters and top_status_codes", "[netprobe][http][unit]")
{
    UnitFixture fx;

    timespec stamp{1000, 0};
    auto timings = visor::http::HttpTimings{/*total_us*/ 1234, /*dns_us*/ 100, /*connect_us*/ 200, /*tls_us*/ 300, /*ttfb_us*/ 400};

    // 200 → success; 404 → http_status_failures; ConnectFailure → connect_failures
    visor::http::HttpSample s200;
    s200.status = 200;
    s200.status_ok = (s200.status >= 200 && s200.status < 400);
    s200.timings = timings;
    visor::http::HttpSample s404;
    s404.status = 404;
    s404.status_ok = (s404.status >= 200 && s404.status < 400);
    s404.timings = timings;
    fx.manager()->process_netprobe_http_result(s200, "t1", stamp);
    fx.manager()->process_netprobe_http_result(s404, "t1", stamp);
    fx.manager()->process_netprobe_http_failure(ErrorType::ConnectFailure, "t1");

    json j;
    fx.manager()->bucket(0)->to_json(j);

    CHECK(j["targets"]["t1"]["attempts"] == 3);
    CHECK(j["targets"]["t1"]["successes"] == 1);
    CHECK(j["targets"]["t1"]["http_status_failures"] == 1);
    CHECK(j["targets"]["t1"]["connect_failures"] == 1);

    // top_status_codes should contain entries for "200" and "404"
    REQUIRE(j["targets"]["t1"].contains("top_status_codes"));
    auto &top = j["targets"]["t1"]["top_status_codes"];
    bool found_200 = false;
    bool found_404 = false;
    for (const auto &entry : top) {
        if (entry.contains("name") && entry["name"] == "200") {
            found_200 = true;
        }
        if (entry.contains("name") && entry["name"] == "404") {
            found_404 = true;
        }
    }
    CHECK(found_200);
    CHECK(found_404);

    // Histograms is default-ON so response_min_us and response_max_us should appear
    CHECK(j["targets"]["t1"].contains("response_min_us"));
    CHECK(j["targets"]["t1"].contains("response_max_us"));
}

TEST_CASE("NetProbe HTTP status boundary: 3xx is success, 1xx and 0 are failures", "[netprobe][http][unit]")
{
    UnitFixture fx;

    timespec stamp{2000, 0};
    auto timings = visor::http::HttpTimings{500, 50, 100, 0, 200};

    auto make_sample = [&timings](uint16_t status) {
        visor::http::HttpSample s;
        s.status = status;
        s.status_ok = (status >= 200 && status < 400);
        s.timings = timings;
        return s;
    };
    fx.manager()->process_netprobe_http_result(make_sample(301), "redir", stamp);  // 3xx → success
    fx.manager()->process_netprobe_http_result(make_sample(500), "redir", stamp);  // 5xx → http_status_failures
    fx.manager()->process_netprobe_http_result(make_sample(100), "redir", stamp);  // 1xx → http_status_failures
    fx.manager()->process_netprobe_http_result(make_sample(0),   "redir", stamp);  // 0   → http_status_failures

    json j;
    fx.manager()->bucket(0)->to_json(j);

    CHECK(j["targets"]["redir"]["attempts"] == 4);
    CHECK(j["targets"]["redir"]["successes"] == 1);
    CHECK(j["targets"]["redir"]["http_status_failures"] == 3);
}

TEST_CASE("NetProbe HTTP http_response_phases group: quantiles present when enabled", "[netprobe][http][unit]")
{
    visor::Config c;
    c.config_set<uint64_t>("num_periods", 1);
    NetProbeInputStream stream{"netprobe-http-phases"};
    auto *proxy = stream.add_event_proxy(c);
    auto handler = std::make_unique<NetProbeStreamHandler>("netprobe-http-phases", proxy, &c);
    // Enable http_response_phases group before starting (via "enable" config key)
    handler->config_set<visor::Configurable::StringList>("enable", {"http_response_phases"});
    handler->start();

    auto *mgr = const_cast<NetProbeMetricsManager *>(handler->metrics());

    timespec stamp{3000, 0};
    auto timings = visor::http::HttpTimings{2000, 150, 300, 400, 600};
    visor::http::HttpSample sample;
    sample.status = 200;
    sample.status_ok = (sample.status >= 200 && sample.status < 400);
    sample.timings = timings;
    mgr->process_netprobe_http_result(sample, "phases-tgt", stamp);

    json j;
    mgr->bucket(0)->to_json(j);

    // response_ttfb_us should appear when http_response_phases is enabled
    CHECK(j["targets"]["phases-tgt"].contains("response_ttfb_us"));
    CHECK(j["targets"]["phases-tgt"].contains("response_dns_us"));
    CHECK(j["targets"]["phases-tgt"].contains("response_connect_us"));
    CHECK(j["targets"]["phases-tgt"].contains("response_tls_us"));

    handler->stop();
}

TEST_CASE("NetProbe HTTP http_response_phases group: quantiles absent when not enabled", "[netprobe][http][unit]")
{
    // Default fixture has Counters + Histograms enabled, NOT HttpResponsePhases
    UnitFixture fx;

    timespec stamp{4000, 0};
    auto timings = visor::http::HttpTimings{2000, 150, 300, 400, 600};
    visor::http::HttpSample sample;
    sample.status = 200;
    sample.status_ok = (sample.status >= 200 && sample.status < 400);
    sample.timings = timings;
    fx.manager()->process_netprobe_http_result(sample, "no-phases", stamp);

    json j;
    fx.manager()->bucket(0)->to_json(j);

    CHECK(!j["targets"]["no-phases"].contains("response_ttfb_us"));
    CHECK(!j["targets"]["no-phases"].contains("response_dns_us"));
    CHECK(!j["targets"]["no-phases"].contains("response_connect_us"));
    CHECK(!j["targets"]["no-phases"].contains("response_tls_us"));
}

TEST_CASE("NetProbe HTTP metrics merge across buckets", "[netprobe][http][unit]")
{
    UnitFixture fx_a(2);
    UnitFixture fx_b(2);

    timespec stamp{5000, 0};
    auto timings = visor::http::HttpTimings{1000, 50, 100, 0, 300};

    auto make_sample = [&timings](uint16_t status) {
        visor::http::HttpSample s;
        s.status = status;
        s.status_ok = (status >= 200 && status < 400);
        s.timings = timings;
        return s;
    };
    fx_a.manager()->process_netprobe_http_result(make_sample(200), "shared", stamp);
    fx_a.manager()->process_netprobe_http_result(make_sample(404), "shared", stamp);
    fx_b.manager()->process_netprobe_http_result(make_sample(500), "shared", stamp);

    UnitFixture fx_merged(2);
    auto *merged = const_cast<NetProbeMetricsBucket *>(fx_merged.manager()->bucket(0));
    merged->specialized_merge(*fx_a.manager()->bucket(0), visor::Metric::Aggregate::DEFAULT);
    merged->specialized_merge(*fx_b.manager()->bucket(0), visor::Metric::Aggregate::DEFAULT);

    json j;
    merged->to_json(j);

    CHECK(j["targets"]["shared"]["successes"] == 1);
    CHECK(j["targets"]["shared"]["http_status_failures"] == 2);

    // top_status_codes should reflect merged counts
    REQUIRE(j["targets"]["shared"].contains("top_status_codes"));
}

TEST_CASE("NetProbe HTTP classification: content_failures vs successes vs http_status_failures", "[netprobe][http][unit]")
{
    UnitFixture fx;

    timespec stamp{9000, 0};
    auto timings = visor::http::HttpTimings{100, 10, 20, 0, 40};

    auto make_sample = [&timings](bool status_ok, uint8_t content_check) {
        visor::http::HttpSample s;
        s.status = status_ok ? 200 : 500;
        s.status_ok = status_ok;
        s.content_check = content_check;
        s.timings = timings;
        return s;
    };

    fx.manager()->process_netprobe_http_result(make_sample(true, 0), "t1", stamp);  // NotChecked  → successes
    fx.manager()->process_netprobe_http_result(make_sample(true, 1), "t1", stamp);  // Match       → successes
    fx.manager()->process_netprobe_http_result(make_sample(true, 2), "t1", stamp);  // Mismatch    → content_failures, NOT successes
    fx.manager()->process_netprobe_http_result(make_sample(false, 2), "t1", stamp); // bad status  → http_status_failures (content ignored)

    json j;
    fx.manager()->bucket(0)->to_json(j);

    CHECK(j["targets"]["t1"]["successes"] == 2);
    CHECK(j["targets"]["t1"]["content_failures"] == 1);
    CHECK(j["targets"]["t1"]["http_status_failures"] == 1);
}

TEST_CASE("NetProbe HTTP tls_cert_expiry_epoch_sec: latest non-zero wins, zero sample leaves unchanged, absent when never set", "[netprobe][http][unit]")
{
    UnitFixture fx;

    timespec stamp{9100, 0};
    auto timings = visor::http::HttpTimings{100, 10, 20, 0, 40};

    auto make_sample = [&timings](uint64_t cert_expiry_epoch) {
        visor::http::HttpSample s;
        s.status = 200;
        s.status_ok = true;
        s.cert_expiry_epoch = cert_expiry_epoch;
        s.timings = timings;
        return s;
    };

    // absent when never set (cert_expiry_epoch == 0 on every sample for this target)
    fx.manager()->process_netprobe_http_result(make_sample(0), "no-cert", stamp);
    json j0;
    fx.manager()->bucket(0)->to_json(j0);
    CHECK(!j0["targets"]["no-cert"].contains("tls_cert_expiry_epoch_sec"));

    fx.manager()->process_netprobe_http_result(make_sample(1786795200), "t1", stamp);
    json j1;
    fx.manager()->bucket(0)->to_json(j1);
    CHECK(j1["targets"]["t1"]["tls_cert_expiry_epoch_sec"] == 1786795200);

    // a later sample with a SMALLER non-zero value REPLACES it (latest-wins, not max)
    fx.manager()->process_netprobe_http_result(make_sample(1700000000), "t1", stamp);
    json j2;
    fx.manager()->bucket(0)->to_json(j2);
    CHECK(j2["targets"]["t1"]["tls_cert_expiry_epoch_sec"] == 1700000000);

    // a zero sample leaves the prior non-zero value unchanged
    fx.manager()->process_netprobe_http_result(make_sample(0), "t1", stamp);
    json j3;
    fx.manager()->bucket(0)->to_json(j3);
    CHECK(j3["targets"]["t1"]["tls_cert_expiry_epoch_sec"] == 1700000000);
}

TEST_CASE("NetProbe HTTP response_size_bytes: quantiles present when enabled", "[netprobe][http][unit]")
{
    QuantilesFixture fx("netprobe-http-respsize");

    timespec stamp{9200, 0};
    visor::http::HttpSample sample;
    sample.status = 200;
    sample.status_ok = true;
    sample.response_size = 512;
    sample.timings = visor::http::HttpTimings{100, 10, 20, 0, 40};
    fx.manager()->process_netprobe_http_result(sample, "respsize-tgt", stamp);

    json j;
    fx.manager()->bucket(0)->to_json(j);

    REQUIRE(j["targets"]["respsize-tgt"].contains("response_size_bytes"));
    CHECK(j["targets"]["respsize-tgt"]["response_size_bytes"]["p50"] == 512);
}

TEST_CASE("NetProbe HTTP response_size_bytes: absent when quantiles group not enabled", "[netprobe][http][unit]")
{
    // Default fixture has Counters + Histograms enabled, NOT Quantiles
    UnitFixture fx;

    timespec stamp{9300, 0};
    visor::http::HttpSample sample;
    sample.status = 200;
    sample.status_ok = true;
    sample.response_size = 512;
    sample.timings = visor::http::HttpTimings{100, 10, 20, 0, 40};
    fx.manager()->process_netprobe_http_result(sample, "no-respsize", stamp);

    json j;
    fx.manager()->bucket(0)->to_json(j);

    CHECK(!j["targets"]["no-respsize"].contains("response_size_bytes"));
}

TEST_CASE("NetProbe HTTP merge: content_failures sums, tls_cert_expiry_epoch_sec keeps the newest window (not max), q_response_size survives merge", "[netprobe][http][unit]")
{
    QuantilesFixture fx_a("netprobe-http-merge-a", 2);
    QuantilesFixture fx_b("netprobe-http-merge-b", 2);

    timespec stamp{9400, 0};
    auto make_sample = [](bool status_ok, uint8_t content_check, uint64_t cert_expiry_epoch, uint64_t response_size) {
        visor::http::HttpSample s;
        s.status = status_ok ? 200 : 500;
        s.status_ok = status_ok;
        s.content_check = content_check;
        s.cert_expiry_epoch = cert_expiry_epoch;
        s.response_size = response_size;
        s.timings = visor::http::HttpTimings{100, 10, 20, 0, 40};
        return s;
    };

    // fx_a is merged first (it stands in for the NEWEST window) and carries the SHORTER-lived cert
    // (1700000000); fx_b (older) carries a LATER date (1800000000). Newest must win, so the merged
    // value is fx_a's — proving we do NOT take the max, which would keep the stale later date and
    // suppress expiry alerts after a cert reissue/rollback to a shorter-lived cert.
    fx_a.manager()->process_netprobe_http_result(make_sample(true, 2, 1700000000, 256), "shared", stamp);
    fx_a.manager()->process_netprobe_http_result(make_sample(true, 2, 0, 512), "shared", stamp);
    fx_b.manager()->process_netprobe_http_result(make_sample(true, 2, 1800000000, 1024), "shared", stamp);

    QuantilesFixture fx_merged("netprobe-http-merge-out", 2);
    auto *merged = const_cast<NetProbeMetricsBucket *>(fx_merged.manager()->bucket(0));
    merged->specialized_merge(*fx_a.manager()->bucket(0), visor::Metric::Aggregate::DEFAULT);
    merged->specialized_merge(*fx_b.manager()->bucket(0), visor::Metric::Aggregate::DEFAULT);

    json j;
    merged->to_json(j);

    CHECK(j["targets"]["shared"]["content_failures"] == 3);
    CHECK(j["targets"]["shared"]["tls_cert_expiry_epoch_sec"] == 1700000000);
    REQUIRE(j["targets"]["shared"].contains("response_size_bytes"));
}

TEST_CASE("NetProbe DoH DNS-aware metrics: counters and top_rcodes", "[netprobe][doh][unit]")
{
    UnitFixture fx;

    timespec stamp{6000, 0};
    auto timings = visor::http::HttpTimings{/*total_us*/ 1234, /*dns_us*/ 100, /*connect_us*/ 200, /*tls_us*/ 300, /*ttfb_us*/ 400};

    // 200 + rcode 0 + parse_ok=true  → success
    fx.manager()->process_netprobe_doh_result(200, 0, true, 0, timings, "t1", stamp);
    // 200 + rcode 2 + parse_ok=true  → dns_response_failures (SRVFAIL)
    fx.manager()->process_netprobe_doh_result(200, 2, true, 0, timings, "t1", stamp);
    // 200 + rcode 0 + parse_ok=false → dns_response_failures (PARSE_ERROR)
    fx.manager()->process_netprobe_doh_result(200, 0, false, 0, timings, "t1", stamp);
    // 503 + parse_ok=false           → http_status_failures
    fx.manager()->process_netprobe_doh_result(503, 0, false, 0, timings, "t1", stamp);
    // transport failure              → connect_failures
    fx.manager()->process_netprobe_doh_failure(ErrorType::ConnectFailure, "t1");

    json j;
    fx.manager()->bucket(0)->to_json(j);

    CHECK(j["targets"]["t1"]["attempts"] == 5);
    CHECK(j["targets"]["t1"]["successes"] == 1);
    CHECK(j["targets"]["t1"]["dns_response_failures"] == 2);
    CHECK(j["targets"]["t1"]["http_status_failures"] == 1);
    CHECK(j["targets"]["t1"]["connect_failures"] == 1);

    // top_rcodes should contain entries for "NOERROR", "SRVFAIL", "PARSE_ERROR"
    REQUIRE(j["targets"]["t1"].contains("top_rcodes"));
    auto &top = j["targets"]["t1"]["top_rcodes"];
    bool found_noerror = false;
    bool found_srvfail = false;
    bool found_parse_error = false;
    for (const auto &entry : top) {
        if (entry.contains("name") && entry["name"] == "NOERROR") {
            found_noerror = true;
            CHECK(entry["estimate"] == 1); // fed exactly once
        }
        if (entry.contains("name") && entry["name"] == "SRVFAIL") {
            found_srvfail = true;
            CHECK(entry["estimate"] == 1);
        }
        if (entry.contains("name") && entry["name"] == "PARSE_ERROR") {
            found_parse_error = true;
            CHECK(entry["estimate"] == 1);
        }
    }
    CHECK(found_noerror);
    CHECK(found_srvfail);
    CHECK(found_parse_error);
    // The 503 (HTTP-failure) response must NOT add an rcode entry — top_rcodes is only
    // recorded for HTTP-success responses, so exactly the three above are present.
    CHECK(top.size() == 3);

    // Histograms is default-ON so response_min_us and response_max_us should appear
    CHECK(j["targets"]["t1"].contains("response_min_us"));
    CHECK(j["targets"]["t1"].contains("response_max_us"));
}

TEST_CASE("NetProbe DoH populates tls_cert_expiry_epoch_sec", "[netprobe][doh][unit]")
{
    UnitFixture fx;

    timespec stamp{9500, 0};
    auto timings = visor::http::HttpTimings{100, 10, 20, 30, 40};
    fx.manager()->process_netprobe_doh_result(200, 0, true, 1786795200, timings, "t1", stamp);

    json j;
    fx.manager()->bucket(0)->to_json(j);

    CHECK(j["targets"]["t1"]["tls_cert_expiry_epoch_sec"] == 1786795200);
}

TEST_CASE("NetProbe DoH http_response_phases group: quantiles present when enabled", "[netprobe][doh][unit]")
{
    visor::Config c;
    c.config_set<uint64_t>("num_periods", 1);
    NetProbeInputStream stream{"netprobe-doh-phases"};
    auto *proxy = stream.add_event_proxy(c);
    auto handler = std::make_unique<NetProbeStreamHandler>("netprobe-doh-phases", proxy, &c);
    handler->config_set<visor::Configurable::StringList>("enable", {"http_response_phases"});
    handler->start();

    auto *mgr = const_cast<NetProbeMetricsManager *>(handler->metrics());

    timespec stamp{7000, 0};
    auto timings = visor::http::HttpTimings{2000, 150, 300, 400, 600};
    mgr->process_netprobe_doh_result(200, 0, true, 0, timings, "doh-phases-tgt", stamp);

    json j;
    mgr->bucket(0)->to_json(j);

    CHECK(j["targets"]["doh-phases-tgt"].contains("response_ttfb_us"));
    CHECK(j["targets"]["doh-phases-tgt"].contains("response_dns_us"));
    CHECK(j["targets"]["doh-phases-tgt"].contains("response_connect_us"));
    CHECK(j["targets"]["doh-phases-tgt"].contains("response_tls_us"));
    // Value assertions (single update => p50 is the fed value): proves each phase field is
    // wired to the right HttpTimings member (dns_us=150, ttfb_us=600), not swapped.
    CHECK(j["targets"]["doh-phases-tgt"]["response_dns_us"]["p50"] == 150);
    CHECK(j["targets"]["doh-phases-tgt"]["response_ttfb_us"]["p50"] == 600);

    handler->stop();
}

TEST_CASE("NetProbe DoH top_rcodes honors topn_count", "[netprobe][doh][unit]")
{
    visor::Config c;
    c.config_set<uint64_t>("num_periods", 1);
    c.config_set<uint64_t>("topn_count", 2); // cap TopN output at 2 entries
    NetProbeInputStream stream{"netprobe-doh-topn"};
    auto *proxy = stream.add_event_proxy(c);
    auto handler = std::make_unique<NetProbeStreamHandler>("netprobe-doh-topn", proxy, &c);
    handler->start();

    auto *mgr = const_cast<NetProbeMetricsManager *>(handler->metrics());
    timespec stamp{7000, 0};
    auto timings = visor::http::HttpTimings{1000, 0, 0, 0, 0};
    // Feed 3 distinct rcodes; with topn_count=2 the settings must be applied to the per-target
    // TopN, so top_rcodes emits at most 2 entries (without the fix it would emit all 3).
    mgr->process_netprobe_doh_result(200, 0, true, 0, timings, "t1", stamp); // NOERROR
    mgr->process_netprobe_doh_result(200, 2, true, 0, timings, "t1", stamp); // SRVFAIL
    mgr->process_netprobe_doh_result(200, 3, true, 0, timings, "t1", stamp); // NXDOMAIN

    json j;
    mgr->bucket(0)->to_json(j);
    REQUIRE(j["targets"]["t1"].contains("top_rcodes"));
    CHECK(j["targets"]["t1"]["top_rcodes"].size() <= 2);

    handler->stop();
}

TEST_CASE("NetProbe DoH http_response_phases group: quantiles absent when not enabled", "[netprobe][doh][unit]")
{
    // Default fixture has Counters + Histograms enabled, NOT HttpResponsePhases
    UnitFixture fx;

    timespec stamp{8000, 0};
    auto timings = visor::http::HttpTimings{2000, 150, 300, 400, 600};
    fx.manager()->process_netprobe_doh_result(200, 0, true, 0, timings, "doh-no-phases", stamp);

    json j;
    fx.manager()->bucket(0)->to_json(j);

    CHECK(!j["targets"]["doh-no-phases"].contains("response_ttfb_us"));
    CHECK(!j["targets"]["doh-no-phases"].contains("response_dns_us"));
    CHECK(!j["targets"]["doh-no-phases"].contains("response_connect_us"));
    CHECK(!j["targets"]["doh-no-phases"].contains("response_tls_us"));
}

TEST_CASE("Net Probe TCP tests", "[netprobe][tcp]")
{
    // Requires external network (www.google.com:80) and only asserts
    // attempts >= 0 (always true). The unit tests above cover TCP send/recv
    // and timeout deterministically.
    SKIP("requires external network");
    NetProbeInputStream stream{"net-probe-test"};
    stream.config_set("test_type", "tcp");
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", "www.google.com");
    target->config_set<uint64_t>("port", 80);
    targets->config_set<std::shared_ptr<visor::Configurable>>("my_target", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);

    visor::Config c;
    c.config_set<uint64_t>("num_periods", 1);
    auto stream_proxy = stream.add_event_proxy(c);
    NetProbeStreamHandler netprobe_handler{"net-probe-test", stream_proxy, &c};

    netprobe_handler.start();
    stream.start();
    std::this_thread::sleep_for(1s);
    netprobe_handler.stop();
    stream.stop();

    auto event_data = netprobe_handler.metrics()->bucket(0)->event_data_locked();

    CHECK(netprobe_handler.metrics()->current_periods() == 1);
    CHECK(netprobe_handler.metrics()->bucket(0)->period_length() >= 1);

    json j;
    netprobe_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["targets"]["my_target"]["attempts"] >= 0);
}
