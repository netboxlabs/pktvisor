#include "NetProbeInputStream.h"
#include "NetProbeStreamHandler.h"
#include "PingProbe.h"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>
#include <catch2/catch_test_visor.hpp>
#include <algorithm>
#include <atomic>
#include <functional>
#include <httplib.h>
#include <mutex>
#include <nlohmann/json.hpp>
#include <thread>
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wzero-as-null-pointer-constant"
#endif
#include <pcapplusplus/DnsLayer.h>
#include <pcapplusplus/DnsResourceData.h>
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

using namespace visor::input::netprobe;
using namespace visor::handler::netprobe;
using namespace nlohmann;
using namespace std::chrono;

TEST_CASE("NetProbe Configs", "[netprobe][ping]")
{
    // Sends real ICMP pings to localhost; needs raw-socket privileges and
    // segfaults in unprivileged CI. Only asserts the config round-trips,
    // which the config-validation tests below already cover deterministically.
    SKIP("requires raw-socket privileges");
    NetProbeInputStream stream{"net-probe-test"};
    stream.config_set("test_type", "ping");
    stream.config_set<uint64_t>("interval_msec", 2000);
    stream.config_set<uint64_t>("timeout_msec", 1000);
    stream.config_set<uint64_t>("packets_interval_msec", 25);
    stream.config_set<uint64_t>("packets_per_test", 2);
    stream.config_set<uint64_t>("packet_payload_size", 56);
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", "localhost");
    targets->config_set<std::shared_ptr<visor::Configurable>>("my_target", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);

    CHECK_NOTHROW(stream.start());
    std::this_thread::sleep_for(1s);
    CHECK_NOTHROW(stream.stop());

    nlohmann::json j;
    stream.info_json(j);
    CHECK(j["module"]["config"]["test_type"] == "ping");
}

TEST_CASE("NetProbe TCP config", "[netprobe][tcp]")
{
    // Resolves example.com and opens a TCP socket; segfaults in CI when DNS
    // or outbound network is restricted. Same justification as the [ping]
    // case above — the assertion is purely a config round-trip.
    SKIP("requires external network");
    NetProbeInputStream stream{"net-probe-test"};
    stream.config_set("test_type", "tcp");
    stream.config_set<uint64_t>("interval_msec", 500);
    stream.config_set<uint64_t>("timeout_msec", 200);
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", "example.com");
    target->config_set<uint64_t>("port", 80);
    targets->config_set<std::shared_ptr<visor::Configurable>>("my_target", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);

    CHECK_NOTHROW(stream.start());
    std::this_thread::sleep_for(1s);
    CHECK_NOTHROW(stream.stop());

    nlohmann::json j;
    stream.info_json(j);
    CHECK(j["module"]["config"]["test_type"] == "tcp");
}

TEST_CASE("NetProbe Boundaries", "[netprobe]")
{
    NetProbeInputStream stream{"net-probe-test"};
    stream.config_set("test_type", "ping");
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", "localhost");
    targets->config_set<std::shared_ptr<visor::Configurable>>("my_target", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);

    SECTION("timeout greater than interval")
    {
        stream.config_set<uint64_t>("interval_msec", 2000);
        stream.config_set<uint64_t>("timeout_msec", 5000);
        CHECK_THROWS_WITH(stream.start(), "timeout_msec [5000] cannot be greater than interval_msec [2000]");
    }

    SECTION("huge payload size")
    {
        stream.config_set<uint64_t>("packet_payload_size", 50000000000);
        CHECK_THROWS_WITH(stream.start(), "packet_payload_size was set to 50000000000 but max supported size is 65500");
    }

    SECTION("num packets times packets interval greater than interval")
    {
        stream.config_set<uint64_t>("interval_msec", 2000);
        stream.config_set<uint64_t>("packets_interval_msec", 100);
        stream.config_set<uint64_t>("packets_per_test", 25);
        CHECK_THROWS_WITH(stream.start(), "packets_per_test [25] times packets_interval_msec [100] cannot be greater than packets_interval_msec [2000]");
    }
}

TEST_CASE("Test Configs fail", "[netprobe][config]")
{
    NetProbeInputStream stream{"net-probe-test"};
    stream.config_set("test_type", "ping");

    CHECK_THROWS_WITH(stream.start(), "no targets specified");
}

TEST_CASE("Netprobe invalid config", "[netprobe][config]")
{
    NetProbeInputStream stream{"net-probe-test"};
    stream.config_set("invalid_config", true);

    CHECK_THROWS_WITH(stream.start(), "invalid_config is an invalid/unsupported config or filter. The valid configs/filters are: test_type, interval_msec, timeout_msec, packets_per_test, packets_interval_msec, packet_payload_size, targets, http_method, qname, qtype, expected_status, failure_status, expected_body, expected_body_regex, body, body_check_max_bytes, proxy, tls, json_path, json_equals, not_contains, body_not_matches_regex, min_response_size_bytes, max_response_size_bytes, fail_if_header_matches, fail_if_header_not_matches, max_last_modified_diff_secs, valid_http_versions");
}

TEST_CASE("NetProbe ip_version config", "[netprobe][config][ipv6]")
{
    auto make = [](const std::string &tgt, std::optional<uint64_t> ipv) {
        auto targets = std::make_shared<visor::Configurable>();
        auto target = std::make_shared<visor::Configurable>();
        target->config_set("target", tgt);
        if (ipv) target->config_set<uint64_t>("ip_version", *ipv);
        targets->config_set<std::shared_ptr<visor::Configurable>>("my_target", target);
        return targets;
    };
    auto stream_with = [&](const std::shared_ptr<visor::Configurable> &targets) {
        auto s = std::make_unique<NetProbeInputStream>("net-probe-test");
        s->config_set("test_type", "ping");
        s->config_set<std::shared_ptr<visor::Configurable>>("targets", targets);
        return s;
    };

    SECTION("invalid ip_version value") {
        auto s = stream_with(make("localhost", 5));
        CHECK_THROWS_WITH(s->start(), "ip_version must be 4 or 6");
    }
    SECTION("literal IPv4 with ip_version 6 conflicts") {
        auto s = stream_with(make("1.2.3.4", 6));
        CHECK_THROWS_WITH(s->start(), "target 1.2.3.4 is IPv4 but ip_version is set to 6");
    }
    SECTION("literal IPv6 with ip_version 4 conflicts") {
        auto s = stream_with(make("2001:db8::1", 4));
        CHECK_THROWS_WITH(s->start(), "target 2001:db8::1 is IPv6 but ip_version is set to 4");
    }
    SECTION("top-level valid-keys string unchanged") {
        NetProbeInputStream s{"net-probe-test"};
        s.config_set("invalid_config", true);
        CHECK_THROWS_WITH(s.start(), "invalid_config is an invalid/unsupported config or filter. The valid configs/filters are: test_type, interval_msec, timeout_msec, packets_per_test, packets_interval_msec, packet_payload_size, targets, http_method, qname, qtype, expected_status, failure_status, expected_body, expected_body_regex, body, body_check_max_bytes, proxy, tls, json_path, json_equals, not_contains, body_not_matches_regex, min_response_size_bytes, max_response_size_bytes, fail_if_header_matches, fail_if_header_not_matches, max_last_modified_diff_secs, valid_http_versions");
    }
}

TEST_CASE("NetProbe ip_version config: literal IPv6 target is auto-detected and routed to a probe", "[netprobe][config][ipv6]")
{
    // Design-spec test #3. A ping stream cannot start unprivileged (the shared receiver opens raw
    // sockets), so exercise the literal-target parse/route path — shared by ping and tcp — through
    // the tcp test type: "::1" must be accepted as an IPv6 literal without any ip_version hint,
    // survive start(), and be counted as one target.
    NetProbeInputStream stream{"net-probe-test-v6-literal"};
    stream.config_set("test_type", "tcp");
    stream.config_set<uint64_t>("interval_msec", 60000);
    stream.config_set<uint64_t>("timeout_msec", 100);
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", "::1");
    target->config_set<uint64_t>("port", 9);
    targets->config_set<std::shared_ptr<visor::Configurable>>("v6_literal", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);

    CHECK_NOTHROW(stream.start());
    nlohmann::json j;
    stream.info_json(j);
    CHECK(j[stream.schema_key()]["current_targets_total"] == 1);
    CHECK(j["module"]["config"]["targets"]["v6_literal"]["target"] == "::1");
    CHECK_NOTHROW(stream.stop());
}

TEST_CASE("NetProbe ip_version config: DNS target with ip_version 6 round-trips through start and info_json", "[netprobe][config][ipv6]")
{
    // Design-spec test #4: a DNS (non-literal) target may carry ip_version: 6. It must parse,
    // reach start() as a DNS-entry probe, and echo the per-target ip_version back via info_json.
    // Same tcp-instead-of-ping justification as the literal-IPv6 case above.
    NetProbeInputStream stream{"net-probe-test-v6-dns"};
    stream.config_set("test_type", "tcp");
    stream.config_set<uint64_t>("interval_msec", 60000);
    stream.config_set<uint64_t>("timeout_msec", 100);
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", "localhost");
    target->config_set<uint64_t>("port", 9);
    target->config_set<uint64_t>("ip_version", 6);
    targets->config_set<std::shared_ptr<visor::Configurable>>("v6_dns", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);

    CHECK_NOTHROW(stream.start());
    nlohmann::json j;
    stream.info_json(j);
    CHECK(j[stream.schema_key()]["current_targets_total"] == 1);
    CHECK(j["module"]["config"]["targets"]["v6_dns"]["ip_version"] == 6);
    CHECK_NOTHROW(stream.stop());
}

TEST_CASE("NetProbe http_method config validates", "[netprobe][config][http]")
{
    // Validates that the http_method key is accepted by validate_configs (no throw before
    // targets-missing is hit). This exercises the _config_defs registration path without
    // requiring network access or curl.
    NetProbeInputStream stream{"net-probe-test"};
    stream.config_set("test_type", "http");
    stream.config_set("http_method", std::string("GET"));
    // No targets → throws "no targets specified", NOT a config-validation error.
    // That means http_method was accepted as a valid key.
    CHECK_THROWS_WITH(stream.start(), "no targets specified");
}

TEST_CASE("NetProbe DoH config: qname required", "[netprobe][config][doh]")
{
    // test_type=doh without qname must throw the 'qname' is required error.
    NetProbeInputStream stream{"net-probe-test-doh-noqname"};
    stream.config_set("test_type", "doh");
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", "https://1.1.1.1/dns-query");
    targets->config_set<std::shared_ptr<visor::Configurable>>("cf_doh", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);
    // No qname → must throw.
    CHECK_THROWS_WITH(stream.start(), "netprobe: 'qname' is required when test_type is 'doh'");
}

TEST_CASE("NetProbe DoH config: unsupported http_method rejected", "[netprobe][config][doh]")
{
    // test_type=doh only supports GET/POST; any other method must throw a clear error.
    NetProbeInputStream stream{"net-probe-test-doh-badmethod"};
    stream.config_set("test_type", "doh");
    stream.config_set("qname", std::string("example.com"));
    stream.config_set("http_method", std::string("PUT"));
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", "https://1.1.1.1/dns-query");
    targets->config_set<std::shared_ptr<visor::Configurable>>("cf_doh", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);
    CHECK_THROWS_WITH(stream.start(), "unsupported http_method 'PUT' for doh (use GET or POST)");
}

TEST_CASE("NetProbe DoH config: qname accepted", "[netprobe][config][doh]")
{
    // test_type=doh with qname set must pass config validation
    // (throws "no targets specified" only when targets aren't set — here we omit targets
    // to confirm that qname/qtype keys are accepted before the targets check fires).
    NetProbeInputStream stream{"net-probe-test-doh-valid"};
    stream.config_set("test_type", "doh");
    stream.config_set("qname", std::string("example.com"));
    stream.config_set("qtype", std::string("A"));
    // No targets → throws "no targets specified", meaning qname/qtype were accepted as valid keys.
    CHECK_THROWS_WITH(stream.start(), "no targets specified");
}

TEST_CASE("NetProbe DoH config: qtype is normalized to uppercase", "[netprobe][config][doh]")
{
    // A lowercase qtype must be accepted (normalized to uppercase before lookup), matching the
    // rest of the codebase. Verify via the rejection message: an invalid lowercase "zzz" is
    // uppercased to "ZZZ" before the not-found error fires (which happens before any stream start).
    NetProbeInputStream stream{"net-probe-test-doh-qtype-case"};
    stream.config_set("test_type", "doh");
    stream.config_set("qname", std::string("example.com"));
    stream.config_set("qtype", std::string("zzz"));
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", "https://1.1.1.1/dns-query");
    targets->config_set<std::shared_ptr<visor::Configurable>>("cf_doh", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);
    CHECK_THROWS_WITH(stream.start(), "netprobe: unknown qtype 'ZZZ'");
}

TEST_CASE("NetProbe DoH config: qname exceeding DNS label limit rejected", "[netprobe][config][doh]")
{
    // A label longer than 63 chars is outside DNS limits and must be rejected at config time
    // (before it reaches DnsLayer::addQuery()).
    NetProbeInputStream stream{"net-probe-test-doh-badqname"};
    stream.config_set("test_type", "doh");
    std::string long_label(64, 'a'); // 64 > 63
    stream.config_set("qname", long_label + ".example.com");
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", "https://1.1.1.1/dns-query");
    targets->config_set<std::shared_ptr<visor::Configurable>>("cf_doh", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);
    CHECK_THROWS_WITH(stream.start(), "netprobe: qname '" + long_label + ".example.com' has a DNS label longer than 63 characters");
}

TEST_CASE("NetProbe http/doh config: invalid target URL rejected", "[netprobe][config]")
{
    // A target whose URL has a non-http(s) scheme must be rejected at config time with a clear error.
    NetProbeInputStream stream{"net-probe-test-badurl"};
    stream.config_set("test_type", "http");
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", std::string("ftp://example.com/x"));
    targets->config_set<std::shared_ptr<visor::Configurable>>("bad", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);
    CHECK_THROWS_WITH(stream.start(), "target 'bad' is not a valid http(s) URL: 'ftp://example.com/x'");
}

TEST_CASE("NetProbe v2 config: expected_status grammar errors bubble the bad entry", "[netprobe][config][http]")
{
    NetProbeInputStream stream{"net-probe-test-status-bad"};
    stream.config_set("test_type", "http");
    stream.config_set<visor::Configurable::StringList>("expected_status", {"2x"});
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", std::string("https://example.com/"));
    targets->config_set<std::shared_ptr<visor::Configurable>>("t", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);
    CHECK_THROWS_WITH(stream.start(), Catch::Matchers::ContainsSubstring("invalid status entry '2x'"));
}

TEST_CASE("NetProbe v2 config: proxy with an embedded control character is rejected without leaking the value", "[netprobe][config][http]")
{
    NetProbeInputStream stream{"net-probe-test-proxy-bad"};
    stream.config_set("test_type", "http");
    stream.config_set("proxy", std::string("bad\nvalue"));
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", std::string("https://example.com/"));
    targets->config_set<std::shared_ptr<visor::Configurable>>("t", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);
    CHECK_THROWS_WITH(stream.start(), "netprobe: 'proxy' value is invalid");
    // A second, independent check that the raw value never appears in the exception message.
    try {
        stream.start();
        FAIL("expected NetProbeException");
    } catch (const std::exception &e) {
        CHECK_THAT(std::string(e.what()), !Catch::Matchers::ContainsSubstring("bad\nvalue"));
    }
}

TEST_CASE("NetProbe v2 config: unclosed expected_body_regex is rejected without quoting the pattern", "[netprobe][config][http]")
{
    NetProbeInputStream stream{"net-probe-test-regex-bad"};
    stream.config_set("test_type", "http");
    stream.config_set("expected_body_regex", std::string("(unclosed"));
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", std::string("https://example.com/"));
    targets->config_set<std::shared_ptr<visor::Configurable>>("t", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);
    CHECK_THROWS_WITH(stream.start(),
        Catch::Matchers::ContainsSubstring("expected_body_regex") && !Catch::Matchers::ContainsSubstring("(unclosed"));
}

TEST_CASE("NetProbe v2 config: body requires a method that carries one", "[netprobe][config][http]")
{
    NetProbeInputStream stream{"net-probe-test-body-get"};
    stream.config_set("test_type", "http");
    stream.config_set("http_method", std::string("GET"));
    stream.config_set("body", std::string("payload"));
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", std::string("https://example.com/"));
    targets->config_set<std::shared_ptr<visor::Configurable>>("t", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);
    CHECK_THROWS_WITH(stream.start(), "'body' requires http_method POST, PUT, or PATCH");
}

TEST_CASE("NetProbe v2 config: http-only keys are rejected on a doh stream", "[netprobe][config][doh]")
{
    auto make_doh_stream = [](const std::string &name) {
        auto s = std::make_unique<NetProbeInputStream>(name);
        s->config_set("test_type", "doh");
        s->config_set("qname", std::string("example.com"));
        auto targets = std::make_shared<visor::Configurable>();
        auto target = std::make_shared<visor::Configurable>();
        target->config_set("target", std::string("https://1.1.1.1/dns-query"));
        targets->config_set<std::shared_ptr<visor::Configurable>>("t", target);
        s->config_set<std::shared_ptr<visor::Configurable>>("targets", targets);
        return s;
    };

    SECTION("expected_body")
    {
        auto s = make_doh_stream("doh-expected-body");
        s->config_set("expected_body", std::string("x"));
        CHECK_THROWS_WITH(s->start(), "'expected_body' is not supported for test_type 'doh'");
    }
    SECTION("expected_body_regex")
    {
        auto s = make_doh_stream("doh-expected-body-regex");
        s->config_set("expected_body_regex", std::string("x"));
        CHECK_THROWS_WITH(s->start(), "'expected_body_regex' is not supported for test_type 'doh'");
    }
    SECTION("body")
    {
        auto s = make_doh_stream("doh-body");
        s->config_set("body", std::string("x"));
        CHECK_THROWS_WITH(s->start(), "'body' is not supported for test_type 'doh'");
    }
    SECTION("expected_status")
    {
        auto s = make_doh_stream("doh-expected-status");
        s->config_set<visor::Configurable::StringList>("expected_status", {"200"});
        CHECK_THROWS_WITH(s->start(), "'expected_status' is not supported for test_type 'doh'");
    }
    SECTION("failure_status")
    {
        auto s = make_doh_stream("doh-failure-status");
        s->config_set<visor::Configurable::StringList>("failure_status", {"500"});
        CHECK_THROWS_WITH(s->start(), "'failure_status' is not supported for test_type 'doh'");
    }
}

TEST_CASE("NetProbe v2 config: per-target headers are not supported for doh", "[netprobe][config][doh]")
{
    NetProbeInputStream stream{"net-probe-test-doh-headers"};
    stream.config_set("test_type", "doh");
    stream.config_set("qname", std::string("example.com"));
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", std::string("https://1.1.1.1/dns-query"));
    auto headers = std::make_shared<visor::Configurable>();
    headers->config_set("Authorization", std::string("Bearer secret"));
    target->config_set<std::shared_ptr<visor::Configurable>>("headers", headers);
    targets->config_set<std::shared_ptr<visor::Configurable>>("t", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);
    CHECK_THROWS_WITH(stream.start(), "per-target 'headers' is not supported for test_type 'doh'");
}

TEST_CASE("NetProbe v2 config: tls.cert_file requires tls.key_file", "[netprobe][config][http]")
{
    NetProbeInputStream stream{"net-probe-test-tls-xor"};
    stream.config_set("test_type", "http");
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", std::string("https://example.com/"));
    targets->config_set<std::shared_ptr<visor::Configurable>>("t", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);
    auto tls = std::make_shared<visor::Configurable>();
    tls->config_set("cert_file", std::string("/tmp/does_not_matter.pem"));
    stream.config_set<std::shared_ptr<visor::Configurable>>("tls", tls);
    CHECK_THROWS_WITH(stream.start(), "tls.cert_file and tls.key_file must be set together");
}

TEST_CASE("NetProbe v2 config: tls.ca_file must exist", "[netprobe][config][http]")
{
    NetProbeInputStream stream{"net-probe-test-tls-ca-missing"};
    stream.config_set("test_type", "http");
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", std::string("https://example.com/"));
    targets->config_set<std::shared_ptr<visor::Configurable>>("t", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);
    auto tls = std::make_shared<visor::Configurable>();
    tls->config_set("ca_file", std::string("/nonexistent/ca.pem"));
    stream.config_set<std::shared_ptr<visor::Configurable>>("tls", tls);
    CHECK_THROWS_WITH(stream.start(), Catch::Matchers::ContainsSubstring("/nonexistent/ca.pem"));
}

TEST_CASE("NetProbe v2 config: proxy and tls are not supported for tcp", "[netprobe][config][tcp]")
{
    auto make_tcp_stream = [](const std::string &name) {
        auto s = std::make_unique<NetProbeInputStream>(name);
        s->config_set("test_type", "tcp");
        auto targets = std::make_shared<visor::Configurable>();
        auto target = std::make_shared<visor::Configurable>();
        target->config_set("target", std::string("example.com"));
        target->config_set<uint64_t>("port", 80);
        targets->config_set<std::shared_ptr<visor::Configurable>>("t", target);
        s->config_set<std::shared_ptr<visor::Configurable>>("targets", targets);
        return s;
    };

    SECTION("proxy")
    {
        auto s = make_tcp_stream("tcp-proxy");
        s->config_set("proxy", std::string("http://x"));
        CHECK_THROWS_WITH(s->start(), "'proxy' is only supported for test_type 'http' or 'doh'");
    }
    SECTION("tls")
    {
        auto s = make_tcp_stream("tcp-tls");
        auto tls = std::make_shared<visor::Configurable>();
        tls->config_set("verify", false);
        s->config_set<std::shared_ptr<visor::Configurable>>("tls", tls);
        CHECK_THROWS_WITH(s->start(), "'tls' is only supported for test_type 'http' or 'doh'");
    }
}

// ---------------------------------------------------------------------------
// v3: stream-level response-assertion config — parse + validate.
// ---------------------------------------------------------------------------

namespace {
// Shared helper: an http-typed stream with a single valid target, ready for v3 config keys to be
// layered on top before start() is called.
std::unique_ptr<NetProbeInputStream> make_v3_http_stream(const std::string &name)
{
    auto s = std::make_unique<NetProbeInputStream>(name);
    s->config_set("test_type", "http");
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", std::string("https://example.com/"));
    targets->config_set<std::shared_ptr<visor::Configurable>>("t", target);
    s->config_set<std::shared_ptr<visor::Configurable>>("targets", targets);
    return s;
}
}

TEST_CASE("NetProbe v3 config: json_path must be a valid JSON Pointer", "[netprobe][config][http]")
{
    auto s = make_v3_http_stream("v3-json-path-bad");
    s->config_set("json_path", std::string("data/status")); // missing leading '/'
    CHECK_THROWS_WITH(s->start(), Catch::Matchers::ContainsSubstring("json_path is not a valid JSON Pointer"));
}

TEST_CASE("NetProbe v3 config: json_equals requires json_path", "[netprobe][config][http]")
{
    auto s = make_v3_http_stream("v3-json-equals-no-path");
    s->config_set("json_equals", std::string("ok"));
    CHECK_THROWS_WITH(s->start(), "netprobe: 'json_equals' requires 'json_path'");
}

TEST_CASE("NetProbe v3 config: unclosed body_not_matches_regex is rejected without quoting the pattern", "[netprobe][config][http]")
{
    auto s = make_v3_http_stream("v3-body-not-matches-bad");
    s->config_set("body_not_matches_regex", std::string("(unclosed"));
    CHECK_THROWS_WITH(s->start(),
        Catch::Matchers::ContainsSubstring("body_not_matches_regex") && !Catch::Matchers::ContainsSubstring("(unclosed"));
}

TEST_CASE("NetProbe v3 config: fail_if_header_matches with an invalid regex names the header, not the pattern", "[netprobe][config][http]")
{
    auto s = make_v3_http_stream("v3-header-matcher-bad");
    auto matchers = std::make_shared<visor::Configurable>();
    matchers->config_set("X-Debug", std::string("(bad"));
    s->config_set<std::shared_ptr<visor::Configurable>>("fail_if_header_matches", matchers);
    CHECK_THROWS_WITH(s->start(),
        Catch::Matchers::ContainsSubstring("value_regex") && Catch::Matchers::ContainsSubstring("X-Debug") && !Catch::Matchers::ContainsSubstring("(bad"));
}

TEST_CASE("NetProbe v3 config: min_response_size_bytes must not exceed max_response_size_bytes", "[netprobe][config][http]")
{
    auto s = make_v3_http_stream("v3-size-bounds-bad");
    s->config_set<uint64_t>("min_response_size_bytes", 100);
    s->config_set<uint64_t>("max_response_size_bytes", 10);
    CHECK_THROWS_WITH(s->start(), "netprobe: min_response_size_bytes must not exceed max_response_size_bytes");
}

TEST_CASE("NetProbe v3 config: valid_http_versions rejects an unsupported entry", "[netprobe][config][http]")
{
    auto s = make_v3_http_stream("v3-http-version-bad");
    s->config_set<visor::Configurable::StringList>("valid_http_versions", {"9"});
    CHECK_THROWS_WITH(s->start(), "netprobe: invalid valid_http_versions entry '9' (use 1.0, 1.1, 2, or 3)");
}

TEST_CASE("NetProbe v3 config: json_path is not supported for test_type 'doh'", "[netprobe][config][doh]")
{
    auto s = std::make_unique<NetProbeInputStream>("v3-doh-json-path");
    s->config_set("test_type", "doh");
    s->config_set("qname", std::string("example.com"));
    s->config_set("json_path", std::string("/status"));
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", std::string("https://1.1.1.1/dns-query"));
    targets->config_set<std::shared_ptr<visor::Configurable>>("t", target);
    s->config_set<std::shared_ptr<visor::Configurable>>("targets", targets);
    CHECK_THROWS_WITH(s->start(), "'json_path' is not supported for test_type 'doh'");
}

TEST_CASE("NetProbe v3 config: json_path/not_contains/size/version all parse successfully together", "[netprobe][config][http]")
{
    // Positive case: every v3 key is accepted and parses/validates without throwing. start()
    // only builds the io loop and schedules probe timers — it does not perform any network I/O
    // synchronously — so calling stop() immediately after, with no sleep, exercises the
    // config-parse path only and never actually contacts the (non-existent) https://example.com/
    // target.
    auto s = make_v3_http_stream("v3-all-keys-ok");
    s->config_set("json_path", std::string("/status"));
    s->config_set("json_equals", std::string("ok"));
    s->config_set("not_contains", std::string("error"));
    s->config_set("body_not_matches_regex", std::string("fail-[0-9]+"));
    s->config_set<uint64_t>("min_response_size_bytes", 10);
    s->config_set<uint64_t>("max_response_size_bytes", 1000);
    s->config_set<uint64_t>("max_last_modified_diff_secs", 3600);
    s->config_set<visor::Configurable::StringList>("valid_http_versions", {"1.1", "2"});
    auto fm = std::make_shared<visor::Configurable>();
    fm->config_set("X-Error", std::string("^true$"));
    s->config_set<std::shared_ptr<visor::Configurable>>("fail_if_header_matches", fm);
    auto fnm = std::make_shared<visor::Configurable>();
    fnm->config_set("X-Ok", std::string("^true$"));
    s->config_set<std::shared_ptr<visor::Configurable>>("fail_if_header_not_matches", fnm);

    CHECK_NOTHROW(s->start());
    s->stop();
}

TEST_CASE("NetProbe v3 scrub helper: redacts not_contains/json_equals/body_not_matches_regex/header-matcher secrets", "[netprobe][http][config]")
{
    // Mirrors the v2 scrub-helper test: feed a tap-shaped config JSON and prove every v3
    // secret-bearing value is masked (never quoted/echoed) while non-secret keys survive.
    json cfg;
    cfg["not_contains"] = "v3-not-contains-sekrit";
    cfg["json_equals"] = "v3-json-equals-sekrit";
    cfg["body_not_matches_regex"] = "v3-regex-sekrit";
    cfg["json_path"] = "/status"; // not a secret; survives untouched
    cfg["fail_if_header_matches"]["X-Debug"] = "v3-header-matcher-sekrit";
    cfg["fail_if_header_not_matches"]["X-Ok"] = "v3-header-not-matcher-sekrit";

    visor::input::netprobe::scrub_netprobe_config_json(cfg);

    auto dumped = cfg.dump();
    CHECK(dumped.find("v3-not-contains-sekrit") == std::string::npos);
    CHECK(dumped.find("v3-json-equals-sekrit") == std::string::npos);
    CHECK(dumped.find("v3-regex-sekrit") == std::string::npos);
    CHECK(dumped.find("v3-header-matcher-sekrit") == std::string::npos);
    CHECK(dumped.find("v3-header-not-matcher-sekrit") == std::string::npos);
    // Names and non-secret values survive.
    CHECK(dumped.find("X-Debug") != std::string::npos);
    CHECK(dumped.find("X-Ok") != std::string::npos);
    CHECK(cfg["json_path"] == "/status");
    CHECK(cfg["not_contains"] == "<redacted>");
    CHECK(cfg["json_equals"] == "<redacted>");
    CHECK(cfg["body_not_matches_regex"] == "<redacted>");
    CHECK(cfg["fail_if_header_matches"]["X-Debug"] == "<redacted>");
    CHECK(cfg["fail_if_header_not_matches"]["X-Ok"] == "<redacted>");
}

TEST_CASE("NetProbe v3 scrub helper: a malformed (non-object) header-matcher value is fully redacted", "[netprobe][http][config]")
{
    // The header matchers are normally maps (header-name: value_regex). If a config arrives with
    // the key set to a scalar or list instead, the value can still carry a secret — redact the
    // whole key rather than echo the raw value.
    json cfg;
    cfg["fail_if_header_matches"] = "v3-scalar-matcher-sekrit";                     // malformed: scalar
    cfg["fail_if_header_not_matches"] = json::array({"v3-list-matcher-sekrit"});    // malformed: list

    visor::input::netprobe::scrub_netprobe_config_json(cfg);

    auto dumped = cfg.dump();
    CHECK(dumped.find("v3-scalar-matcher-sekrit") == std::string::npos);
    CHECK(dumped.find("v3-list-matcher-sekrit") == std::string::npos);
    CHECK(cfg["fail_if_header_matches"] == "<redacted>");
    CHECK(cfg["fail_if_header_not_matches"] == "<redacted>");
}

// ---------------------------------------------------------------------------
// v3: per-target ip_version/resolve — parse + validate (threaded into probe ctors,
// evaluated by libcurl itself; not asserted here).
// ---------------------------------------------------------------------------

TEST_CASE("NetProbe v3 config: per-target resolve entry must be host:port:address", "[netprobe][config][http]")
{
    NetProbeInputStream stream{"net-probe-test-resolve-bad"};
    stream.config_set("test_type", "http");
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", std::string("https://example.com/"));
    target->config_set<visor::Configurable::StringList>("resolve", {"bad-no-colons"});
    targets->config_set<std::shared_ptr<visor::Configurable>>("t", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);
    CHECK_THROWS_WITH(stream.start(), "netprobe: target 't' has an invalid resolve entry 'bad-no-colons' (expected host:port:address)");
}

TEST_CASE("NetProbe v3 config: per-target ip_version must be 4 or 6", "[netprobe][config][http]")
{
    NetProbeInputStream stream{"net-probe-test-ipver-bad"};
    stream.config_set("test_type", "http");
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", std::string("https://example.com/"));
    target->config_set<uint64_t>("ip_version", 5);
    targets->config_set<std::shared_ptr<visor::Configurable>>("t", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);
    CHECK_THROWS_WITH(stream.start(), "ip_version must be 4 or 6");
}

TEST_CASE("NetProbe v3 config: per-target ip_version + resolve happy path reaches start", "[netprobe][config][http]")
{
    NetProbeInputStream stream{"net-probe-test-ipver-resolve-ok"};
    stream.config_set("test_type", "http");
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", std::string("https://example.com/"));
    target->config_set<uint64_t>("ip_version", 4);
    target->config_set<visor::Configurable::StringList>("resolve", {"example.com:443:127.0.0.1"});
    targets->config_set<std::shared_ptr<visor::Configurable>>("t", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);

    CHECK_NOTHROW(stream.start());
    stream.stop();
}

TEST_CASE("NetProbe v3 config: per-target resolve accepts an (unbracketed) IPv6 address", "[netprobe][config][http]")
{
    // The address field may itself contain colons (IPv6). Validation keys off the first two colons
    // (host, port) and must accept the IPv6 remainder; bracketing for curl happens in the transport.
    NetProbeInputStream stream{"net-probe-test-resolve-v6"};
    stream.config_set("test_type", "http");
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", std::string("https://example.com/"));
    target->config_set<visor::Configurable::StringList>("resolve", {"example.com:443:2001:db8::1"});
    targets->config_set<std::shared_ptr<visor::Configurable>>("t", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);

    CHECK_NOTHROW(stream.start());
    stream.stop();
}

TEST_CASE("NetProbe v3 config: per-target ip_version + resolve also parse for doh targets", "[netprobe][config][doh]")
{
    NetProbeInputStream stream{"net-probe-test-doh-ipver-resolve-ok"};
    stream.config_set("test_type", "doh");
    stream.config_set("qname", std::string("example.com"));
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", std::string("https://1.1.1.1/dns-query"));
    target->config_set<uint64_t>("ip_version", 6);
    target->config_set<visor::Configurable::StringList>("resolve", {"1.1.1.1:443:127.0.0.1"});
    targets->config_set<std::shared_ptr<visor::Configurable>>("t", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);

    CHECK_NOTHROW(stream.start());
    stream.stop();
}

TEST_CASE("ICMPv6 reply carrier survives the fan-out Packet deep-copy", "[netprobe][ipv6]")
{
    // Wire bytes of an ICMPv6 echo REPLY: type=129, code=0, checksum=0, id=0xBEEF, seq=0x0102 (network order).
    const uint8_t reply[8] = {129, 0, 0, 0, 0xBE, 0xEF, 0x01, 0x02};

    auto carrier = build_icmpv6_reply_carrier(reply, sizeof(reply));
    REQUIRE(carrier.has_value());

    // The receiver enqueues a COPY of this Packet; the handler later does getLayerOfType<ICMPv6EchoLayer>()
    // on the copy. That deep-copy is exactly where the ICMPv6 layer used to be lost (every reply dropped).
    pcpp::Packet copy(*carrier);
    auto *echo = copy.getLayerOfType<pcpp::ICMPv6EchoLayer>();
    REQUIRE(echo != nullptr);
    CHECK(echo->getMessageType() == pcpp::ICMPv6MessageType::ICMPv6_ECHO_REPLY);
    CHECK(echo->getIdentifier() == 0xBEEF);
    CHECK(echo->getSequenceNr() == 0x0102);

    // An echo REQUEST (type 128) is not a reply and must not be enqueued.
    const uint8_t request[8] = {128, 0, 0, 0, 0xBE, 0xEF, 0x01, 0x02};
    CHECK_FALSE(build_icmpv6_reply_carrier(request, sizeof(request)).has_value());

    // A buffer shorter than the 8-byte echo header is rejected (getEchoDataLen would underflow).
    const uint8_t too_short[4] = {129, 0, 0, 0};
    CHECK_FALSE(build_icmpv6_reply_carrier(too_short, sizeof(too_short)).has_value());
}

// ---------------------------------------------------------------------------
// End-to-end HTTP probe tests: real NetProbeInputStream + NetProbeStreamHandler
// against an in-process httplib server bound to an ephemeral port.
// ---------------------------------------------------------------------------

// RAII guard: ensures httplib server is stopped and thread joined even if a
// Catch2 REQUIRE macro throws an exception that unwinds the test frame.
struct ServerGuard {
    httplib::Server &svr;
    std::thread &t;
    ~ServerGuard()
    {
        svr.stop();
        if (t.joinable()) t.join();
    }
};

TEST_CASE("NetProbe HTTP e2e: success path records attempt, success, and 200 in top_status_codes", "[netprobe][http][e2e]")
{
    // Start an in-process httplib server on an ephemeral port.
    httplib::Server svr;
    svr.Get("/ok", [](const httplib::Request &, httplib::Response &res) {
        res.set_content("ok", "text/plain");
    });
    int port = svr.bind_to_any_port("127.0.0.1");
    REQUIRE(port > 0);
    std::thread server_thread([&svr] { svr.listen_after_bind(); });
    ServerGuard guard{svr, server_thread};
    svr.wait_until_ready();

    std::string url = "http://127.0.0.1:" + std::to_string(port) + "/ok";

    // Configure stream: interval=500ms, timeout=400ms (timeout must not exceed interval).
    // A 500ms interval gives ≥1 tick in the 1s sleep window.
    NetProbeInputStream stream{"netprobe-http-e2e"};
    stream.config_set("test_type", "http");
    stream.config_set<uint64_t>("interval_msec", 500);
    stream.config_set<uint64_t>("timeout_msec", 400);
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", url);
    targets->config_set<std::shared_ptr<visor::Configurable>>("ok_target", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);

    // Wire up the handler (mirrors the ping/tcp test pattern).
    visor::Config c;
    c.config_set<uint64_t>("num_periods", 1);
    auto *proxy = stream.add_event_proxy(c);
    NetProbeStreamHandler handler{"netprobe-http-e2e", proxy, &c};

    handler.start();
    stream.start();
    // Sleep generously: 1.5s covers 2+ interval ticks + request round-trip.
    std::this_thread::sleep_for(1500ms);
    stream.stop();
    handler.stop();

    json j;
    handler.metrics()->bucket(0)->to_json(j);

    REQUIRE(j.contains("targets"));
    REQUIRE(j["targets"].contains("ok_target"));
    auto &tgt = j["targets"]["ok_target"];

    CHECK(tgt["attempts"].get<int>() >= 1);
    CHECK(tgt["successes"].get<int>() >= 1);

    // top_status_codes must have a "200" entry.
    REQUIRE(tgt.contains("top_status_codes"));
    bool found_200 = false;
    for (const auto &entry : tgt["top_status_codes"]) {
        if (entry.contains("name") && entry["name"] == "200") {
            found_200 = true;
        }
    }
    CHECK(found_200);
}

TEST_CASE("NetProbe v2 scrub helper: redacts a raw tap-style config echo", "[netprobe][http][config]")
{
    // Tap::info_json echoes the tap's raw config (exposed via GET /api/v1/taps and
    // Policy::info_json) and calls the input plugin's redact hook, which uses this helper.
    // Feed it a tap-shaped config JSON and prove every secret-bearing value is masked.
    json cfg;
    cfg["proxy"] = "http://user:pass@myproxy:3128";
    cfg["body"] = "{\"token\":\"tap-body-sekrit\"}";
    cfg["expected_body"] = "tap-expected-sekrit";
    cfg["expected_body_regex"] = "tap-regex-sekrit";
    cfg["interval_msec"] = 200; // non-secret keys must survive untouched
    cfg["targets"]["api"]["target"] = "https://api.example.com/health";
    cfg["targets"]["api"]["headers"]["Authorization"] = "Bearer tap-header-sekrit";
    cfg["targets"]["api"]["headers"]["X-Num"] = 12345;

    visor::input::netprobe::scrub_netprobe_config_json(cfg);

    auto dumped = cfg.dump();
    CHECK(dumped.find("tap-header-sekrit") == std::string::npos);
    CHECK(dumped.find("tap-body-sekrit") == std::string::npos);
    CHECK(dumped.find("tap-expected-sekrit") == std::string::npos);
    CHECK(dumped.find("tap-regex-sekrit") == std::string::npos);
    CHECK(dumped.find("user:pass") == std::string::npos);
    CHECK(dumped.find("12345") == std::string::npos);
    // Names and non-secret values survive.
    CHECK(dumped.find("Authorization") != std::string::npos);
    CHECK(dumped.find("X-Num") != std::string::npos);
    CHECK(cfg["interval_msec"] == 200);
    CHECK(cfg["targets"]["api"]["target"] == "https://api.example.com/health");
    CHECK(cfg["proxy"] == "<redacted>");
    CHECK(cfg["targets"]["api"]["headers"]["Authorization"] == "<redacted>");
}

TEST_CASE("NetProbe v2 info_json: proxy/body/expected_body(_regex)/header values are scrubbed", "[netprobe][http][config]")
{
    // common_info_json() echoes the raw module config verbatim; without scrubbing this would leak
    // the Authorization header, the numeric header, the proxy URL, and both body-check patterns.
    httplib::Server svr;
    svr.Post("/submit", [](const httplib::Request &, httplib::Response &res) {
        res.set_content("ok", "text/plain");
    });
    int port = svr.bind_to_any_port("127.0.0.1");
    REQUIRE(port > 0);
    std::thread server_thread([&svr] { svr.listen_after_bind(); });
    ServerGuard guard{svr, server_thread};
    svr.wait_until_ready();

    std::string url = "http://127.0.0.1:" + std::to_string(port) + "/submit";

    NetProbeInputStream stream{"netprobe-http-redact"};
    stream.config_set("test_type", "http");
    stream.config_set("http_method", std::string("POST"));
    stream.config_set<uint64_t>("interval_msec", 500);
    stream.config_set<uint64_t>("timeout_msec", 400);
    stream.config_set("body", std::string("super-secret-payload"));
    stream.config_set("expected_body", std::string("super-secret-expected"));
    stream.config_set("expected_body_regex", std::string("^ok-[0-9]+$"));
    stream.config_set("proxy", std::string("http://proxy.invalid.example:3128"));

    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", url);
    auto headers = std::make_shared<visor::Configurable>();
    headers->config_set("Authorization", std::string("Bearer super-secret-token"));
    headers->config_set<uint64_t>("X-Request-Id", 424242);
    target->config_set<std::shared_ptr<visor::Configurable>>("headers", headers);
    targets->config_set<std::shared_ptr<visor::Configurable>>("t", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);

    stream.start();
    std::this_thread::sleep_for(50ms);
    stream.stop();

    nlohmann::json j;
    stream.info_json(j);
    auto &cfg = j["module"]["config"];

    CHECK(cfg["proxy"] == "<redacted>");
    CHECK(cfg["body"] == "<redacted>");
    CHECK(cfg["expected_body"] == "<redacted>");
    CHECK(cfg["expected_body_regex"] == "<redacted>");
    REQUIRE(cfg["targets"]["t"].contains("headers"));
    CHECK(cfg["targets"]["t"]["headers"]["Authorization"] == "<redacted>");
    CHECK(cfg["targets"]["t"]["headers"]["X-Request-Id"] == "<redacted>");
    REQUIRE(cfg["targets"]["t"].contains("header_names"));
    auto names = cfg["targets"]["t"]["header_names"].get<std::vector<std::string>>();
    CHECK(std::find(names.begin(), names.end(), "Authorization") != names.end());
    CHECK(std::find(names.begin(), names.end(), "X-Request-Id") != names.end());

    // Belt-and-suspenders: none of the secret literals may survive anywhere in the serialized JSON.
    std::string dump = j.dump();
    CHECK(dump.find("super-secret-token") == std::string::npos);
    CHECK(dump.find("super-secret-payload") == std::string::npos);
    CHECK(dump.find("super-secret-expected") == std::string::npos);
    CHECK(dump.find("proxy.invalid.example") == std::string::npos);
    CHECK(dump.find("424242") == std::string::npos);
    CHECK(dump.find("^ok-[0-9]+$") == std::string::npos);
    CHECK(dump.find("<redacted>") != std::string::npos);
}

TEST_CASE("NetProbe HTTP e2e: stop while request in flight does not crash or hang", "[netprobe][http][e2e]")
{
    // The slow handler sleeps 500ms — longer than our start/stop window.
    // This test verifies that stop() returns cleanly even with a curl request in flight,
    // exercising the loop-quiescent teardown of curl poll handles (_http_client->close()).
    // interval=300ms, timeout=250ms (timeout must not exceed interval); the /slow handler sleeps 500ms
    // so the request will still be in flight when we call stop() after 200ms.
    httplib::Server svr;
    svr.Get("/slow", [](const httplib::Request &, httplib::Response &res) {
        std::this_thread::sleep_for(500ms);
        res.set_content("late", "text/plain");
    });
    int port = svr.bind_to_any_port("127.0.0.1");
    REQUIRE(port > 0);
    std::thread server_thread([&svr] { svr.listen_after_bind(); });
    ServerGuard guard{svr, server_thread};
    svr.wait_until_ready();

    std::string url = "http://127.0.0.1:" + std::to_string(port) + "/slow";

    NetProbeInputStream stream{"netprobe-http-e2e-inflight"};
    stream.config_set("test_type", "http");
    // interval=300ms, timeout=250ms; timeout must not exceed interval.
    stream.config_set<uint64_t>("interval_msec", 300);
    stream.config_set<uint64_t>("timeout_msec", 250);
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", url);
    targets->config_set<std::shared_ptr<visor::Configurable>>("slow_target", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);

    visor::Config c;
    c.config_set<uint64_t>("num_periods", 1);
    auto *proxy = stream.add_event_proxy(c);
    NetProbeStreamHandler handler{"netprobe-http-e2e-inflight", proxy, &c};

    handler.start();
    stream.start();
    // Sleep just long enough for the first request to be in flight (interval fired, curl running).
    std::this_thread::sleep_for(350ms);
    // stop() must return without hanging or crashing even though the curl request is still in flight.
    CHECK_NOTHROW(stream.stop());
    CHECK_NOTHROW(handler.stop());
}

// ---------------------------------------------------------------------------
// End-to-end DoH probe tests: real NetProbeInputStream (test_type=doh) +
// NetProbeStreamHandler against an in-process httplib server that returns a
// canned NOERROR DNS response as application/dns-message.
// ---------------------------------------------------------------------------

// Build a minimal but valid NOERROR DNS response wire-format using pcpp::DnsLayer.
// The probe only requires: size >= 12, QR==1, rcode==0.
// The EMPTY DnsLayer constructor manages its own buffer (no heap-ownership hazard here
// unlike the parse path); addAnswer with IPv4DnsResourceData is straightforward.
static std::string make_doh_response()
{
    pcpp::DnsLayer resp;
    resp.getDnsHeader()->queryOrResponse = 1;
    resp.getDnsHeader()->responseCode = 0; // NOERROR
    resp.addQuery("example.com", pcpp::DNS_TYPE_A, pcpp::DNS_CLASS_IN);
    pcpp::IPv4DnsResourceData answerData(std::string("1.2.3.4"));
    resp.addAnswer("example.com", pcpp::DNS_TYPE_A, pcpp::DNS_CLASS_IN, 60, &answerData);
    return std::string(reinterpret_cast<const char *>(resp.getData()), resp.getDataLen());
}

TEST_CASE("NetProbe DoH e2e POST: success path records attempt, success, and NOERROR in top_rcodes", "[netprobe][doh][e2e]")
{
    httplib::Server svr;
    const std::string doh_body = make_doh_response();
    svr.Post("/dns-query", [&](const httplib::Request &, httplib::Response &res) {
        res.set_content(doh_body, "application/dns-message");
    });
    svr.Get("/dns-query", [&](const httplib::Request &, httplib::Response &res) {
        res.set_content(doh_body, "application/dns-message");
    });
    int port = svr.bind_to_any_port("127.0.0.1");
    REQUIRE(port > 0);
    std::thread server_thread([&svr] { svr.listen_after_bind(); });
    ServerGuard guard{svr, server_thread};
    svr.wait_until_ready();

    std::string url = "http://127.0.0.1:" + std::to_string(port) + "/dns-query";

    NetProbeInputStream stream{"netprobe-doh-e2e-post"};
    stream.config_set("test_type", "doh");
    stream.config_set("qname", std::string("example.com"));
    stream.config_set("qtype", std::string("A"));
    stream.config_set<uint64_t>("interval_msec", 200);
    stream.config_set<uint64_t>("timeout_msec", 150);
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", url);
    targets->config_set<std::shared_ptr<visor::Configurable>>("doh_target", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);

    visor::Config c;
    c.config_set<uint64_t>("num_periods", 1);
    auto *proxy = stream.add_event_proxy(c);
    NetProbeStreamHandler handler{"netprobe-doh-e2e-post", proxy, &c};

    handler.start();
    stream.start();
    std::this_thread::sleep_for(750ms);
    stream.stop();
    handler.stop();

    json j;
    handler.metrics()->bucket(0)->to_json(j);

    REQUIRE(j.contains("targets"));
    REQUIRE(j["targets"].contains("doh_target"));
    auto &tgt = j["targets"]["doh_target"];

    CHECK(tgt["attempts"].get<int>() >= 1);
    CHECK(tgt["successes"].get<int>() >= 1);

    REQUIRE(tgt.contains("top_rcodes"));
    bool found_noerror = false;
    for (const auto &entry : tgt["top_rcodes"]) {
        if (entry.contains("name") && entry["name"] == "NOERROR") {
            found_noerror = true;
        }
    }
    CHECK(found_noerror);

    // DoH records the HTTP status breakdown (top_status_codes) too, like the HTTP probe.
    REQUIRE(tgt.contains("top_status_codes"));
    bool found_200 = false;
    for (const auto &entry : tgt["top_status_codes"]) {
        if (entry.contains("name") && entry["name"] == "200") {
            found_200 = true;
        }
    }
    CHECK(found_200);
}

TEST_CASE("NetProbe DoH e2e GET: success path records attempt, success, and NOERROR in top_rcodes", "[netprobe][doh][e2e]")
{
    httplib::Server svr;
    const std::string doh_body = make_doh_response();
    svr.Post("/dns-query", [&](const httplib::Request &, httplib::Response &res) {
        res.set_content(doh_body, "application/dns-message");
    });
    svr.Get("/dns-query", [&](const httplib::Request &, httplib::Response &res) {
        res.set_content(doh_body, "application/dns-message");
    });
    int port = svr.bind_to_any_port("127.0.0.1");
    REQUIRE(port > 0);
    std::thread server_thread([&svr] { svr.listen_after_bind(); });
    ServerGuard guard{svr, server_thread};
    svr.wait_until_ready();

    std::string url = "http://127.0.0.1:" + std::to_string(port) + "/dns-query";

    NetProbeInputStream stream{"netprobe-doh-e2e-get"};
    stream.config_set("test_type", "doh");
    stream.config_set("qname", std::string("example.com"));
    stream.config_set("qtype", std::string("A"));
    stream.config_set("http_method", std::string("GET"));
    stream.config_set<uint64_t>("interval_msec", 200);
    stream.config_set<uint64_t>("timeout_msec", 150);
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", url);
    targets->config_set<std::shared_ptr<visor::Configurable>>("doh_get_target", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);

    visor::Config c;
    c.config_set<uint64_t>("num_periods", 1);
    auto *proxy = stream.add_event_proxy(c);
    NetProbeStreamHandler handler{"netprobe-doh-e2e-get", proxy, &c};

    handler.start();
    stream.start();
    std::this_thread::sleep_for(750ms);
    stream.stop();
    handler.stop();

    json j;
    handler.metrics()->bucket(0)->to_json(j);

    REQUIRE(j.contains("targets"));
    REQUIRE(j["targets"].contains("doh_get_target"));
    auto &tgt = j["targets"]["doh_get_target"];

    CHECK(tgt["attempts"].get<int>() >= 1);
    CHECK(tgt["successes"].get<int>() >= 1);

    REQUIRE(tgt.contains("top_rcodes"));
    bool found_noerror = false;
    for (const auto &entry : tgt["top_rcodes"]) {
        if (entry.contains("name") && entry["name"] == "NOERROR") {
            found_noerror = true;
        }
    }
    CHECK(found_noerror);

    // DoH records the HTTP status breakdown (top_status_codes) too, like the HTTP probe.
    REQUIRE(tgt.contains("top_status_codes"));
    bool found_200 = false;
    for (const auto &entry : tgt["top_status_codes"]) {
        if (entry.contains("name") && entry["name"] == "200") {
            found_200 = true;
        }
    }
    CHECK(found_200);
}

TEST_CASE("NetProbe DoH e2e: stop while request in flight does not crash or hang", "[netprobe][doh][e2e]")
{
    // The slow handler sleeps 500ms — longer than our start/stop window.
    // Mirrors the HTTP in-flight-stop test to exercise DohProbe teardown.
    httplib::Server svr;
    svr.Post("/dns-query", [](const httplib::Request &, httplib::Response &res) {
        std::this_thread::sleep_for(500ms);
        const std::string body = make_doh_response();
        res.set_content(body, "application/dns-message");
    });
    svr.Get("/dns-query", [](const httplib::Request &, httplib::Response &res) {
        std::this_thread::sleep_for(500ms);
        const std::string body = make_doh_response();
        res.set_content(body, "application/dns-message");
    });
    int port = svr.bind_to_any_port("127.0.0.1");
    REQUIRE(port > 0);
    std::thread server_thread([&svr] { svr.listen_after_bind(); });
    ServerGuard guard{svr, server_thread};
    svr.wait_until_ready();

    std::string url = "http://127.0.0.1:" + std::to_string(port) + "/dns-query";

    NetProbeInputStream stream{"netprobe-doh-e2e-inflight"};
    stream.config_set("test_type", "doh");
    stream.config_set("qname", std::string("example.com"));
    stream.config_set<uint64_t>("interval_msec", 300);
    stream.config_set<uint64_t>("timeout_msec", 250);
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", url);
    targets->config_set<std::shared_ptr<visor::Configurable>>("doh_slow_target", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);

    visor::Config c;
    c.config_set<uint64_t>("num_periods", 1);
    auto *proxy = stream.add_event_proxy(c);
    NetProbeStreamHandler handler{"netprobe-doh-e2e-inflight", proxy, &c};

    handler.start();
    stream.start();
    std::this_thread::sleep_for(350ms);
    CHECK_NOTHROW(stream.stop());
    CHECK_NOTHROW(handler.stop());
}

TEST_CASE("NetProbe DoH e2e: wrong response Content-Type is a DNS failure (not a success)", "[netprobe][doh][e2e]")
{
    // A valid DNS body returned with the WRONG Content-Type (not application/dns-message) must be
    // rejected per RFC 8484 — counted as dns_response_failures, never as a success.
    httplib::Server svr;
    const std::string doh_body = make_doh_response();
    svr.Post("/dns-query", [&](const httplib::Request &, httplib::Response &res) {
        res.set_content(doh_body, "text/html");
    });
    svr.Get("/dns-query", [&](const httplib::Request &, httplib::Response &res) {
        res.set_content(doh_body, "text/html");
    });
    int port = svr.bind_to_any_port("127.0.0.1");
    REQUIRE(port > 0);
    std::thread server_thread([&svr] { svr.listen_after_bind(); });
    ServerGuard guard{svr, server_thread};
    svr.wait_until_ready();

    std::string url = "http://127.0.0.1:" + std::to_string(port) + "/dns-query";
    NetProbeInputStream stream{"netprobe-doh-e2e-badct"};
    stream.config_set("test_type", "doh");
    stream.config_set("qname", std::string("example.com"));
    stream.config_set<uint64_t>("interval_msec", 200);
    stream.config_set<uint64_t>("timeout_msec", 150);
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", url);
    targets->config_set<std::shared_ptr<visor::Configurable>>("doh_target", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);

    visor::Config c;
    c.config_set<uint64_t>("num_periods", 1);
    auto *proxy = stream.add_event_proxy(c);
    NetProbeStreamHandler handler{"netprobe-doh-e2e-badct", proxy, &c};

    handler.start();
    stream.start();
    std::this_thread::sleep_for(750ms);
    stream.stop();
    handler.stop();

    json j;
    handler.metrics()->bucket(0)->to_json(j);
    REQUIRE(j["targets"].contains("doh_target"));
    auto &tgt = j["targets"]["doh_target"];
    CHECK(tgt["attempts"].get<int>() >= 1);
    CHECK(tgt["successes"].get<int>() == 0);
    CHECK(tgt["dns_response_failures"].get<int>() >= 1);
}

TEST_CASE("NetProbe DoH e2e: malformed DNS response body is a DNS failure (not a success)", "[netprobe][doh][e2e]")
{
    // Correct Content-Type but a body that is not a valid DNS message (too short to be a header)
    // must be rejected — counted as dns_response_failures, never as a success.
    httplib::Server svr;
    svr.Post("/dns-query", [](const httplib::Request &, httplib::Response &res) {
        res.set_content(std::string("garbage", 7), "application/dns-message");
    });
    svr.Get("/dns-query", [](const httplib::Request &, httplib::Response &res) {
        res.set_content(std::string("garbage", 7), "application/dns-message");
    });
    int port = svr.bind_to_any_port("127.0.0.1");
    REQUIRE(port > 0);
    std::thread server_thread([&svr] { svr.listen_after_bind(); });
    ServerGuard guard{svr, server_thread};
    svr.wait_until_ready();

    std::string url = "http://127.0.0.1:" + std::to_string(port) + "/dns-query";
    NetProbeInputStream stream{"netprobe-doh-e2e-malformed"};
    stream.config_set("test_type", "doh");
    stream.config_set("qname", std::string("example.com"));
    stream.config_set<uint64_t>("interval_msec", 200);
    stream.config_set<uint64_t>("timeout_msec", 150);
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", url);
    targets->config_set<std::shared_ptr<visor::Configurable>>("doh_target", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);

    visor::Config c;
    c.config_set<uint64_t>("num_periods", 1);
    auto *proxy = stream.add_event_proxy(c);
    NetProbeStreamHandler handler{"netprobe-doh-e2e-malformed", proxy, &c};

    handler.start();
    stream.start();
    std::this_thread::sleep_for(750ms);
    stream.stop();
    handler.stop();

    json j;
    handler.metrics()->bucket(0)->to_json(j);
    REQUIRE(j["targets"].contains("doh_target"));
    auto &tgt = j["targets"]["doh_target"];
    CHECK(tgt["attempts"].get<int>() >= 1);
    CHECK(tgt["successes"].get<int>() == 0);
    CHECK(tgt["dns_response_failures"].get<int>() >= 1);
}

TEST_CASE("NetProbe DoH e2e: response declaring more answers than present is a DNS failure", "[netprobe][doh][e2e]")
{
    // NOERROR with a valid echoed question, but the header declares more answers than the body
    // contains (a truncated/incomplete answer section). pcpp parses fewer records than declared,
    // so this must be rejected, never counted as a success.
    httplib::Server svr;
    std::string body = make_doh_response(); // valid: 1 answer, ANCOUNT=1
    // Corrupt ANCOUNT (DNS header bytes 6-7, network byte order) to claim 2 answers while only 1 is present.
    REQUIRE(body.size() > 7);
    body[6] = 0x00;
    body[7] = 0x02;
    svr.Post("/dns-query", [&](const httplib::Request &, httplib::Response &res) {
        res.set_content(body, "application/dns-message");
    });
    svr.Get("/dns-query", [&](const httplib::Request &, httplib::Response &res) {
        res.set_content(body, "application/dns-message");
    });
    int port = svr.bind_to_any_port("127.0.0.1");
    REQUIRE(port > 0);
    std::thread server_thread([&svr] { svr.listen_after_bind(); });
    ServerGuard guard{svr, server_thread};
    svr.wait_until_ready();

    std::string url = "http://127.0.0.1:" + std::to_string(port) + "/dns-query";
    NetProbeInputStream stream{"netprobe-doh-e2e-truncated"};
    stream.config_set("test_type", "doh");
    stream.config_set("qname", std::string("example.com"));
    stream.config_set<uint64_t>("interval_msec", 200);
    stream.config_set<uint64_t>("timeout_msec", 150);
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", url);
    targets->config_set<std::shared_ptr<visor::Configurable>>("doh_target", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);

    visor::Config c;
    c.config_set<uint64_t>("num_periods", 1);
    auto *proxy = stream.add_event_proxy(c);
    NetProbeStreamHandler handler{"netprobe-doh-e2e-truncated", proxy, &c};

    handler.start();
    stream.start();
    std::this_thread::sleep_for(750ms);
    stream.stop();
    handler.stop();

    json j;
    handler.metrics()->bucket(0)->to_json(j);
    REQUIRE(j["targets"].contains("doh_target"));
    auto &tgt = j["targets"]["doh_target"];
    CHECK(tgt["attempts"].get<int>() >= 1);
    CHECK(tgt["successes"].get<int>() == 0);
    CHECK(tgt["dns_response_failures"].get<int>() >= 1);
}

TEST_CASE("NetProbe DoH e2e: root qname (dot) probe succeeds", "[netprobe][doh][e2e]")
{
    // End-to-end root probe: qname "." must build a valid root query and match the echoed root
    // question in the response (both encode/decode as the empty name in pcpp).
    httplib::Server svr;
    // Canned NOERROR response echoing a ROOT question of type A (the probe's default qtype).
    pcpp::DnsLayer resp;
    resp.getDnsHeader()->queryOrResponse = 1;
    resp.getDnsHeader()->responseCode = 0; // NOERROR
    REQUIRE(resp.addQuery("", pcpp::DNS_TYPE_A, pcpp::DNS_CLASS_IN) != nullptr);
    const std::string body(reinterpret_cast<const char *>(resp.getData()), resp.getDataLen());
    svr.Post("/dns-query", [&](const httplib::Request &, httplib::Response &res) {
        res.set_content(body, "application/dns-message");
    });
    svr.Get("/dns-query", [&](const httplib::Request &, httplib::Response &res) {
        res.set_content(body, "application/dns-message");
    });
    int port = svr.bind_to_any_port("127.0.0.1");
    REQUIRE(port > 0);
    std::thread server_thread([&svr] { svr.listen_after_bind(); });
    ServerGuard guard{svr, server_thread};
    svr.wait_until_ready();

    std::string url = "http://127.0.0.1:" + std::to_string(port) + "/dns-query";
    NetProbeInputStream stream{"netprobe-doh-e2e-root"};
    stream.config_set("test_type", "doh");
    stream.config_set("qname", std::string("."));
    stream.config_set<uint64_t>("interval_msec", 200);
    stream.config_set<uint64_t>("timeout_msec", 150);
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", url);
    targets->config_set<std::shared_ptr<visor::Configurable>>("doh_target", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);

    visor::Config c;
    c.config_set<uint64_t>("num_periods", 1);
    auto *proxy = stream.add_event_proxy(c);
    NetProbeStreamHandler handler{"netprobe-doh-e2e-root", proxy, &c};

    handler.start();
    stream.start();
    std::this_thread::sleep_for(750ms);
    stream.stop();
    handler.stop();

    json j;
    handler.metrics()->bucket(0)->to_json(j);
    REQUIRE(j["targets"].contains("doh_target"));
    auto &tgt = j["targets"]["doh_target"];
    CHECK(tgt["attempts"].get<int>() >= 1);
    CHECK(tgt["successes"].get<int>() >= 1);
}

// ---------------------------------------------------------------------------
// End-to-end v2 tests: real NetProbeInputStream + NetProbeStreamHandler proving
// the evaluation precedence (failure_status > expected_status > default 2xx/3xx,
// then body checks) through a LIVE probe, not just unit-level HttpSample fixtures.
// Mirrors the http/doh e2e scaffolding above: ServerGuard, wait_until_ready(),
// ephemeral ports, 200ms interval / 150ms timeout / ~750ms sleep.
// ---------------------------------------------------------------------------

TEST_CASE("NetProbe HTTP e2e v2: per-target headers determine per-target auth outcome", "[netprobe][http][e2e]")
{
    // /auth returns 200 iff Authorization == "Bearer sekrit", else 401 — proves per-target headers
    // are actually threaded through to the outbound request, not just accepted by config validation.
    httplib::Server svr;
    svr.Get("/auth", [](const httplib::Request &req, httplib::Response &res) {
        if (req.get_header_value("Authorization") == "Bearer sekrit") {
            res.status = 200;
            res.set_content("ok", "text/plain");
        } else {
            res.status = 401;
            res.set_content("nope", "text/plain");
        }
    });
    int port = svr.bind_to_any_port("127.0.0.1");
    REQUIRE(port > 0);
    std::thread server_thread([&svr] { svr.listen_after_bind(); });
    ServerGuard guard{svr, server_thread};
    svr.wait_until_ready();

    std::string url = "http://127.0.0.1:" + std::to_string(port) + "/auth";

    NetProbeInputStream stream{"netprobe-http-e2e-headers"};
    stream.config_set("test_type", "http");
    stream.config_set<uint64_t>("interval_msec", 200);
    stream.config_set<uint64_t>("timeout_msec", 150);
    auto targets = std::make_shared<visor::Configurable>();

    // Target A carries the correct Authorization header.
    auto target_a = std::make_shared<visor::Configurable>();
    target_a->config_set("target", url);
    auto headers = std::make_shared<visor::Configurable>();
    headers->config_set("Authorization", std::string("Bearer sekrit"));
    target_a->config_set<std::shared_ptr<visor::Configurable>>("headers", headers);
    targets->config_set<std::shared_ptr<visor::Configurable>>("with_auth", target_a);

    // Target B hits the same URL with no headers at all.
    auto target_b = std::make_shared<visor::Configurable>();
    target_b->config_set("target", url);
    targets->config_set<std::shared_ptr<visor::Configurable>>("no_auth", target_b);

    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);

    visor::Config c;
    c.config_set<uint64_t>("num_periods", 1);
    auto *proxy = stream.add_event_proxy(c);
    NetProbeStreamHandler handler{"netprobe-http-e2e-headers", proxy, &c};

    handler.start();
    stream.start();
    std::this_thread::sleep_for(750ms);
    stream.stop();
    handler.stop();

    json j;
    handler.metrics()->bucket(0)->to_json(j);

    REQUIRE(j["targets"].contains("with_auth"));
    CHECK(j["targets"]["with_auth"]["successes"].get<int>() >= 1);

    REQUIRE(j["targets"].contains("no_auth"));
    auto &no_auth = j["targets"]["no_auth"];
    CHECK(no_auth["http_status_failures"].get<int>() >= 1);
    REQUIRE(no_auth.contains("top_status_codes"));
    bool found_401 = false;
    for (const auto &entry : no_auth["top_status_codes"]) {
        if (entry.contains("name") && entry["name"] == "401") {
            found_401 = true;
        }
    }
    CHECK(found_401);
}

TEST_CASE("NetProbe HTTP e2e v2: expected_status flips a 401 endpoint into a success", "[netprobe][http][e2e]")
{
    httplib::Server svr;
    svr.Get("/unauth", [](const httplib::Request &, httplib::Response &res) {
        res.status = 401;
        res.set_content("nope", "text/plain");
    });
    int port = svr.bind_to_any_port("127.0.0.1");
    REQUIRE(port > 0);
    std::thread server_thread([&svr] { svr.listen_after_bind(); });
    ServerGuard guard{svr, server_thread};
    svr.wait_until_ready();

    std::string url = "http://127.0.0.1:" + std::to_string(port) + "/unauth";

    NetProbeInputStream stream{"netprobe-http-e2e-expected-status"};
    stream.config_set("test_type", "http");
    stream.config_set<uint64_t>("interval_msec", 200);
    stream.config_set<uint64_t>("timeout_msec", 150);
    stream.config_set<visor::Configurable::StringList>("expected_status", {"401"});
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", url);
    targets->config_set<std::shared_ptr<visor::Configurable>>("unauth_target", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);

    visor::Config c;
    c.config_set<uint64_t>("num_periods", 1);
    auto *proxy = stream.add_event_proxy(c);
    NetProbeStreamHandler handler{"netprobe-http-e2e-expected-status", proxy, &c};

    handler.start();
    stream.start();
    std::this_thread::sleep_for(750ms);
    stream.stop();
    handler.stop();

    json j;
    handler.metrics()->bucket(0)->to_json(j);

    REQUIRE(j["targets"].contains("unauth_target"));
    auto &tgt = j["targets"]["unauth_target"];
    CHECK(tgt["successes"].get<int>() >= 1);
    CHECK(tgt["http_status_failures"].get<int>() == 0);
}

TEST_CASE("NetProbe HTTP e2e v2: failure_status wins over expected_status", "[netprobe][http][e2e]")
{
    // expected_status accepts the whole 2xx class, but failure_status carves 200 back out of it.
    // failure_status must win: a 200 response must be counted as a failure, never a success.
    httplib::Server svr;
    svr.Get("/ok", [](const httplib::Request &, httplib::Response &res) {
        res.set_content("ok", "text/plain");
    });
    int port = svr.bind_to_any_port("127.0.0.1");
    REQUIRE(port > 0);
    std::thread server_thread([&svr] { svr.listen_after_bind(); });
    ServerGuard guard{svr, server_thread};
    svr.wait_until_ready();

    std::string url = "http://127.0.0.1:" + std::to_string(port) + "/ok";

    NetProbeInputStream stream{"netprobe-http-e2e-failure-wins"};
    stream.config_set("test_type", "http");
    stream.config_set<uint64_t>("interval_msec", 200);
    stream.config_set<uint64_t>("timeout_msec", 150);
    stream.config_set<visor::Configurable::StringList>("expected_status", {"2xx"});
    stream.config_set<visor::Configurable::StringList>("failure_status", {"200"});
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", url);
    targets->config_set<std::shared_ptr<visor::Configurable>>("ok_target", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);

    visor::Config c;
    c.config_set<uint64_t>("num_periods", 1);
    auto *proxy = stream.add_event_proxy(c);
    NetProbeStreamHandler handler{"netprobe-http-e2e-failure-wins", proxy, &c};

    handler.start();
    stream.start();
    std::this_thread::sleep_for(750ms);
    stream.stop();
    handler.stop();

    json j;
    handler.metrics()->bucket(0)->to_json(j);

    REQUIRE(j["targets"].contains("ok_target"));
    auto &tgt = j["targets"]["ok_target"];
    CHECK(tgt["http_status_failures"].get<int>() >= 1);
    CHECK(tgt["successes"].get<int>() == 0);
}

TEST_CASE("NetProbe HTTP e2e v2: expected_body + expected_body_regex both match -> success", "[netprobe][http][e2e]")
{
    httplib::Server svr;
    svr.Get("/health", [](const httplib::Request &, httplib::Response &res) {
        res.set_content(R"({"status":"ok","state":"up"})", "application/json");
    });
    int port = svr.bind_to_any_port("127.0.0.1");
    REQUIRE(port > 0);
    std::thread server_thread([&svr] { svr.listen_after_bind(); });
    ServerGuard guard{svr, server_thread};
    svr.wait_until_ready();

    std::string url = "http://127.0.0.1:" + std::to_string(port) + "/health";

    NetProbeInputStream stream{"netprobe-http-e2e-body-match"};
    stream.config_set("test_type", "http");
    stream.config_set<uint64_t>("interval_msec", 200);
    stream.config_set<uint64_t>("timeout_msec", 150);
    stream.config_set("expected_body", std::string("\"status\":\"ok\""));
    stream.config_set("expected_body_regex", std::string("up|healthy"));
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", url);
    targets->config_set<std::shared_ptr<visor::Configurable>>("health_target", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);

    visor::Config c;
    c.config_set<uint64_t>("num_periods", 1);
    auto *proxy = stream.add_event_proxy(c);
    NetProbeStreamHandler handler{"netprobe-http-e2e-body-match", proxy, &c};

    handler.start();
    stream.start();
    std::this_thread::sleep_for(750ms);
    stream.stop();
    handler.stop();

    json j;
    handler.metrics()->bucket(0)->to_json(j);

    REQUIRE(j["targets"].contains("health_target"));
    auto &tgt = j["targets"]["health_target"];
    CHECK(tgt["successes"].get<int>() >= 1);
    CHECK(tgt["content_failures"].get<int>() == 0);
}

TEST_CASE("NetProbe HTTP e2e v2: expected_body mismatch -> content_failures, never successes", "[netprobe][http][e2e]")
{
    httplib::Server svr;
    svr.Get("/health", [](const httplib::Request &, httplib::Response &res) {
        res.set_content(R"({"status":"ok","state":"up"})", "application/json");
    });
    int port = svr.bind_to_any_port("127.0.0.1");
    REQUIRE(port > 0);
    std::thread server_thread([&svr] { svr.listen_after_bind(); });
    ServerGuard guard{svr, server_thread};
    svr.wait_until_ready();

    std::string url = "http://127.0.0.1:" + std::to_string(port) + "/health";

    NetProbeInputStream stream{"netprobe-http-e2e-body-mismatch"};
    stream.config_set("test_type", "http");
    stream.config_set<uint64_t>("interval_msec", 200);
    stream.config_set<uint64_t>("timeout_msec", 150);
    stream.config_set("expected_body", std::string("nope"));
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", url);
    targets->config_set<std::shared_ptr<visor::Configurable>>("health_target", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);

    visor::Config c;
    c.config_set<uint64_t>("num_periods", 1);
    auto *proxy = stream.add_event_proxy(c);
    NetProbeStreamHandler handler{"netprobe-http-e2e-body-mismatch", proxy, &c};

    handler.start();
    stream.start();
    std::this_thread::sleep_for(750ms);
    stream.stop();
    handler.stop();

    json j;
    handler.metrics()->bucket(0)->to_json(j);

    REQUIRE(j["targets"].contains("health_target"));
    auto &tgt = j["targets"]["health_target"];
    // Bulletproof invariant: successes must be exactly zero when the body check fails.
    CHECK(tgt["successes"].get<int>() == 0);
    CHECK(tgt["content_failures"].get<int>() >= 1);
}

TEST_CASE("NetProbe HTTP e2e v2: body match past the capture cap is not a false content_failure", "[netprobe][http][e2e]")
{
    // The match text lives after a large padding prefix; with a small body_check_max_bytes the
    // captured body is truncated before the marker. The check must NOT be reported as a
    // content_failure on a partial body — the sample is classified on status alone (success).
    httplib::Server svr;
    std::string body = std::string(64 * 1024, 'x') + "MARKER_AT_END";
    svr.Get("/health", [&](const httplib::Request &, httplib::Response &res) {
        res.set_content(body, "text/plain");
    });
    int port = svr.bind_to_any_port("127.0.0.1");
    REQUIRE(port > 0);
    std::thread server_thread([&svr] { svr.listen_after_bind(); });
    ServerGuard guard{svr, server_thread};
    svr.wait_until_ready();

    std::string url = "http://127.0.0.1:" + std::to_string(port) + "/health";

    NetProbeInputStream stream{"netprobe-http-e2e-body-truncated"};
    stream.config_set("test_type", "http");
    stream.config_set<uint64_t>("interval_msec", 200);
    stream.config_set<uint64_t>("timeout_msec", 150);
    stream.config_set("expected_body", std::string("MARKER_AT_END"));
    stream.config_set<uint64_t>("body_check_max_bytes", 1024); // marker is well beyond this
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", url);
    targets->config_set<std::shared_ptr<visor::Configurable>>("health_target", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);

    visor::Config c;
    c.config_set<uint64_t>("num_periods", 1);
    auto *proxy = stream.add_event_proxy(c);
    NetProbeStreamHandler handler{"netprobe-http-e2e-body-truncated", proxy, &c};

    handler.start();
    stream.start();
    std::this_thread::sleep_for(750ms);
    stream.stop();
    handler.stop();

    json j;
    handler.metrics()->bucket(0)->to_json(j);

    REQUIRE(j["targets"].contains("health_target"));
    auto &tgt = j["targets"]["health_target"];
    CHECK(tgt["attempts"].get<int>() >= 1);
    // Truncated body => body check skipped, classified on status (200) => success, NOT content_failures.
    CHECK(tgt["successes"].get<int>() >= 1);
    CHECK(tgt["content_failures"].get<int>() == 0);
}

TEST_CASE("NetProbe HTTP e2e v3: truncated body still lets a size assertion fail", "[netprobe][http][e2e]")
{
    // The AND-fold's subtle case: a truncated body SKIPS body assertions, but a NON-body assertion
    // (size, which uses the true downloaded size) must still run and can fail. Body is ~64 KB but
    // body_check_max_bytes caps capture at 1 KB (so the body assertion is skipped); max_response_size
    // is far below the true size, so the size check fails => content_failures, not a false success.
    httplib::Server svr;
    std::string body(64 * 1024, 'x');
    svr.Get("/health", [&](const httplib::Request &, httplib::Response &res) {
        res.set_content(body, "text/plain");
    });
    int port = svr.bind_to_any_port("127.0.0.1");
    REQUIRE(port > 0);
    std::thread server_thread([&svr] { svr.listen_after_bind(); });
    ServerGuard guard{svr, server_thread};
    svr.wait_until_ready();

    std::string url = "http://127.0.0.1:" + std::to_string(port) + "/health";
    NetProbeInputStream stream{"netprobe-http-e2e-trunc-size"};
    stream.config_set("test_type", "http");
    stream.config_set<uint64_t>("interval_msec", 200);
    stream.config_set<uint64_t>("timeout_msec", 150);
    stream.config_set("expected_body", std::string("never-present")); // body assertion — will be SKIPPED (truncated)
    stream.config_set<uint64_t>("body_check_max_bytes", 1024);          // truncate the captured body to 1 KB
    // max sits BETWEEN the capture cap (1024) and the true size (64 KB): a captured-length comparison
    // would PASS (1024 <= 2048) but the true size (65536) FAILS — so this pins that the size check
    // uses r.response_size (true downloaded size), not the truncated captured length.
    stream.config_set<uint64_t>("max_response_size_bytes", 2048);
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", url);
    targets->config_set<std::shared_ptr<visor::Configurable>>("health_target", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);

    visor::Config c;
    c.config_set<uint64_t>("num_periods", 1);
    auto *proxy = stream.add_event_proxy(c);
    NetProbeStreamHandler handler{"netprobe-http-e2e-trunc-size", proxy, &c};

    handler.start();
    stream.start();
    std::this_thread::sleep_for(750ms);
    stream.stop();
    handler.stop();

    json j;
    handler.metrics()->bucket(0)->to_json(j);
    REQUIRE(j["targets"].contains("health_target"));
    auto &tgt = j["targets"]["health_target"];
    CHECK(tgt["attempts"].get<int>() >= 1);
    // Size assertion ran despite the truncated body and failed => content_failures, NOT a false success.
    CHECK(tgt["successes"].get<int>() == 0);
    CHECK(tgt["content_failures"].get<int>() >= 1);
}

// Helper: run one http probe stream against `url` with `configure(stream)` applied, for ~750ms,
// and return the target's metrics JSON node (target key "t").
static json run_v3_http_probe(const std::string &name, const std::string &url,
    const std::function<void(NetProbeInputStream &)> &configure)
{
    NetProbeInputStream stream{name};
    stream.config_set("test_type", "http");
    stream.config_set<uint64_t>("interval_msec", 200);
    stream.config_set<uint64_t>("timeout_msec", 150);
    configure(stream);
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", url);
    targets->config_set<std::shared_ptr<visor::Configurable>>("t", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);

    visor::Config c;
    c.config_set<uint64_t>("num_periods", 1);
    auto *proxy = stream.add_event_proxy(c);
    NetProbeStreamHandler handler{name, proxy, &c};
    handler.start();
    stream.start();
    std::this_thread::sleep_for(750ms);
    stream.stop();
    handler.stop();
    json j;
    handler.metrics()->bucket(0)->to_json(j);
    return j["targets"].contains("t") ? j["targets"]["t"] : json::object();
}

TEST_CASE("NetProbe HTTP e2e v3: json_path pass and fail", "[netprobe][http][e2e]")
{
    httplib::Server svr;
    svr.Get("/j", [](const httplib::Request &, httplib::Response &res) {
        res.set_content(R"({"data":{"status":"ok"}})", "application/json");
    });
    int port = svr.bind_to_any_port("127.0.0.1");
    REQUIRE(port > 0);
    std::thread th([&svr] { svr.listen_after_bind(); });
    ServerGuard guard{svr, th};
    svr.wait_until_ready();
    std::string url = "http://127.0.0.1:" + std::to_string(port) + "/j";

    auto pass = run_v3_http_probe("v3-json-pass", url, [](NetProbeInputStream &s) {
        s.config_set("json_path", std::string("/data/status"));
        s.config_set("json_equals", std::string("ok"));
    });
    CHECK(pass["successes"].get<int>() >= 1);
    CHECK(pass["content_failures"].get<int>() == 0);

    auto fail = run_v3_http_probe("v3-json-fail", url, [](NetProbeInputStream &s) {
        s.config_set("json_path", std::string("/data/status"));
        s.config_set("json_equals", std::string("down"));
    });
    CHECK(fail["successes"].get<int>() == 0);
    CHECK(fail["content_failures"].get<int>() >= 1);
}

TEST_CASE("NetProbe HTTP e2e v3: not_contains fail", "[netprobe][http][e2e]")
{
    httplib::Server svr;
    svr.Get("/b", [](const httplib::Request &, httplib::Response &res) {
        res.set_content("python traceback (most recent call last)", "text/plain");
    });
    int port = svr.bind_to_any_port("127.0.0.1");
    REQUIRE(port > 0);
    std::thread th([&svr] { svr.listen_after_bind(); });
    ServerGuard guard{svr, th};
    svr.wait_until_ready();
    auto tgt = run_v3_http_probe("v3-not-contains", "http://127.0.0.1:" + std::to_string(port) + "/b",
        [](NetProbeInputStream &s) { s.config_set("not_contains", std::string("traceback")); });
    CHECK(tgt["successes"].get<int>() == 0);
    CHECK(tgt["content_failures"].get<int>() >= 1);
}

TEST_CASE("NetProbe HTTP e2e v3: size bound fail", "[netprobe][http][e2e]")
{
    httplib::Server svr;
    svr.Get("/s", [](const httplib::Request &, httplib::Response &res) {
        res.set_content("tiny", "text/plain");
    });
    int port = svr.bind_to_any_port("127.0.0.1");
    REQUIRE(port > 0);
    std::thread th([&svr] { svr.listen_after_bind(); });
    ServerGuard guard{svr, th};
    svr.wait_until_ready();
    auto tgt = run_v3_http_probe("v3-size", "http://127.0.0.1:" + std::to_string(port) + "/s",
        [](NetProbeInputStream &s) { s.config_set<uint64_t>("min_response_size_bytes", 100000); });
    CHECK(tgt["successes"].get<int>() == 0);
    CHECK(tgt["content_failures"].get<int>() >= 1);
}

TEST_CASE("NetProbe HTTP e2e v3: header matchers", "[netprobe][http][e2e]")
{
    httplib::Server svr;
    svr.Get("/h", [](const httplib::Request &, httplib::Response &res) {
        res.set_header("X-Debug", "1");
        res.set_content("{}", "application/json");
    });
    int port = svr.bind_to_any_port("127.0.0.1");
    REQUIRE(port > 0);
    std::thread th([&svr] { svr.listen_after_bind(); });
    ServerGuard guard{svr, th};
    svr.wait_until_ready();
    std::string url = "http://127.0.0.1:" + std::to_string(port) + "/h";

    // fail_if_header_matches: X-Debug present with any value => content failure
    auto fm = run_v3_http_probe("v3-hdr-fail", url, [](NetProbeInputStream &s) {
        auto m = std::make_shared<visor::Configurable>();
        m->config_set("X-Debug", std::string(".+"));
        s.config_set<std::shared_ptr<visor::Configurable>>("fail_if_header_matches", m);
    });
    CHECK(fm["successes"].get<int>() == 0);
    CHECK(fm["content_failures"].get<int>() >= 1);

    // fail_if_header_not_matches: Content-Type must match application/json (it does) => success
    auto fnm = run_v3_http_probe("v3-hdr-pass", url, [](NetProbeInputStream &s) {
        auto m = std::make_shared<visor::Configurable>();
        m->config_set("Content-Type", std::string("application/json"));
        s.config_set<std::shared_ptr<visor::Configurable>>("fail_if_header_not_matches", m);
    });
    CHECK(fnm["successes"].get<int>() >= 1);
    CHECK(fnm["content_failures"].get<int>() == 0);
}

TEST_CASE("NetProbe HTTP e2e v3: header matcher fails conservatively when header capture truncates", "[netprobe][http][e2e]")
{
    // The response carries so many headers that capture stops at the byte cap (headers_truncated).
    // fail_if_header_matches targets a header that is NOT among the captured ones, so matches()
    // alone would PASS — but because a forbidden header could be hiding in the dropped tail, the
    // probe must fail the assertion conservatively.
    httplib::Server svr;
    svr.Get("/many", [](const httplib::Request &, httplib::Response &res) {
        for (int i = 0; i < 1400; ++i) {
            res.set_header("X-Pad-" + std::to_string(i), std::string(48, 'y'));
        }
        res.set_content("ok", "text/plain");
    });
    int port = svr.bind_to_any_port("127.0.0.1");
    REQUIRE(port > 0);
    std::thread th([&svr] { svr.listen_after_bind(); });
    ServerGuard guard{svr, th};
    svr.wait_until_ready();
    std::string url = "http://127.0.0.1:" + std::to_string(port) + "/many";

    auto tgt = run_v3_http_probe("v3-hdr-trunc", url, [](NetProbeInputStream &s) {
        auto m = std::make_shared<visor::Configurable>();
        m->config_set("X-Absent", std::string(".+")); // never present => matches() would pass
        s.config_set<std::shared_ptr<visor::Configurable>>("fail_if_header_matches", m);
    });
    CHECK(tgt["successes"].get<int>() == 0);
    CHECK(tgt["content_failures"].get<int>() >= 1);
}

TEST_CASE("NetProbe HTTP e2e v3: required-header check passes despite header truncation", "[netprobe][http][e2e]")
{
    // A fail_if_header_not_matches (required-header) PASS is a positive presence proof: the required
    // header was FOUND in the captured headers. Dropping headers past the 64 KiB cap cannot un-find
    // it, so truncation must NOT fail this check.
    //
    // Robust, order-independent construction (httplib stores headers in an unordered_multimap, so
    // iteration order is NOT alphabetical): three ~40 KiB pad headers guarantee truncation, and
    // because any TWO of them already exceed the 64 KiB cap, at most ONE pad is ever admitted before
    // capture stops growing — so the tiny "A-Required" line always fits with a ~24 KiB margin no
    // matter where it lands in the header order.
    httplib::Server svr;
    svr.Get("/many", [](const httplib::Request &, httplib::Response &res) {
        res.set_header("A-Required", "yes");
        for (int i = 0; i < 3; ++i) {
            res.set_header("X-Pad-" + std::to_string(i), std::string(40000, 'y'));
        }
        res.set_content("ok", "text/plain");
    });
    int port = svr.bind_to_any_port("127.0.0.1");
    REQUIRE(port > 0);
    std::thread th([&svr] { svr.listen_after_bind(); });
    ServerGuard guard{svr, th};
    svr.wait_until_ready();
    std::string url = "http://127.0.0.1:" + std::to_string(port) + "/many";

    auto tgt = run_v3_http_probe("v3-hdr-req-trunc", url, [](NetProbeInputStream &s) {
        auto m = std::make_shared<visor::Configurable>();
        m->config_set("A-Required", std::string("yes")); // present & matched pre-cap => real PASS
        s.config_set<std::shared_ptr<visor::Configurable>>("fail_if_header_not_matches", m);
    });
    CHECK(tgt["successes"].get<int>() >= 1);
    CHECK(tgt["content_failures"].get<int>() == 0);
}

TEST_CASE("NetProbe HTTP e2e v3: truncation still fails when forbidden rules coexist with required", "[netprobe][http][e2e]")
{
    // When BOTH a required (fail_if_header_not_matches, satisfied) and a forbidden
    // (fail_if_header_matches, not seen) rule are configured, truncation must still fail: a forbidden
    // header could be hiding in the dropped tail. has_forbidden_rules() keeps the fail-safe on here.
    // Same order-independent construction as the required-only test (at most one ~40 KiB pad is
    // admitted, so "A-Required" is always captured while truncation is still triggered).
    httplib::Server svr;
    svr.Get("/many", [](const httplib::Request &, httplib::Response &res) {
        res.set_header("A-Required", "yes");
        for (int i = 0; i < 3; ++i) {
            res.set_header("X-Pad-" + std::to_string(i), std::string(40000, 'y'));
        }
        res.set_content("ok", "text/plain");
    });
    int port = svr.bind_to_any_port("127.0.0.1");
    REQUIRE(port > 0);
    std::thread th([&svr] { svr.listen_after_bind(); });
    ServerGuard guard{svr, th};
    svr.wait_until_ready();
    std::string url = "http://127.0.0.1:" + std::to_string(port) + "/many";

    auto tgt = run_v3_http_probe("v3-hdr-both-trunc", url, [](NetProbeInputStream &s) {
        auto req = std::make_shared<visor::Configurable>();
        req->config_set("A-Required", std::string("yes"));
        s.config_set<std::shared_ptr<visor::Configurable>>("fail_if_header_not_matches", req);
        auto forbid = std::make_shared<visor::Configurable>();
        forbid->config_set("X-Absent", std::string(".+")); // absent from captured set => matches() PASS
        s.config_set<std::shared_ptr<visor::Configurable>>("fail_if_header_matches", forbid);
    });
    CHECK(tgt["successes"].get<int>() == 0);
    CHECK(tgt["content_failures"].get<int>() >= 1);
}

TEST_CASE("NetProbe HTTP e2e v3: valid_http_versions rejects the negotiated version", "[netprobe][http][e2e]")
{
    httplib::Server svr; // plain httplib serves HTTP/1.1
    svr.Get("/v", [](const httplib::Request &, httplib::Response &res) {
        res.set_content("ok", "text/plain");
    });
    int port = svr.bind_to_any_port("127.0.0.1");
    REQUIRE(port > 0);
    std::thread th([&svr] { svr.listen_after_bind(); });
    ServerGuard guard{svr, th};
    svr.wait_until_ready();
    auto tgt = run_v3_http_probe("v3-httpver", "http://127.0.0.1:" + std::to_string(port) + "/v",
        [](NetProbeInputStream &s) { s.config_set<visor::Configurable::StringList>("valid_http_versions", {"2"}); });
    // Negotiated 1.1 is not in {"2"} => content failure.
    CHECK(tgt["successes"].get<int>() == 0);
    CHECK(tgt["content_failures"].get<int>() >= 1);
}

TEST_CASE("NetProbe HTTP e2e v3: header assertion sees only the FINAL response across a redirect", "[netprobe][http][e2e]")
{
    // Server A (301) carries X-Debug that WOULD trip fail_if_header_matches; server B (200) does not.
    // No request body/custom request headers => redirects are followed. The per-response capture
    // reset must keep only B's headers, so content_failures stays 0.
    httplib::Server svr_b;
    svr_b.Get("/final", [](const httplib::Request &, httplib::Response &res) {
        res.set_content("ok", "text/plain"); // no X-Debug on the final response
    });
    int port_b = svr_b.bind_to_any_port("127.0.0.1");
    REQUIRE(port_b > 0);
    std::thread tb([&svr_b] { svr_b.listen_after_bind(); });
    ServerGuard gb{svr_b, tb};
    svr_b.wait_until_ready();

    httplib::Server svr_a;
    std::string loc = "http://127.0.0.1:" + std::to_string(port_b) + "/final";
    svr_a.Get("/redirect", [&](const httplib::Request &, httplib::Response &res) {
        res.status = 301;
        res.set_header("X-Debug", "intermediate"); // only on the intermediate response
        res.set_header("Location", loc);
    });
    int port_a = svr_a.bind_to_any_port("127.0.0.1");
    REQUIRE(port_a > 0);
    std::thread ta([&svr_a] { svr_a.listen_after_bind(); });
    ServerGuard ga{svr_a, ta};
    svr_a.wait_until_ready();

    auto tgt = run_v3_http_probe("v3-redirect-hdr", "http://127.0.0.1:" + std::to_string(port_a) + "/redirect",
        [](NetProbeInputStream &s) {
            auto m = std::make_shared<visor::Configurable>();
            m->config_set("X-Debug", std::string(".+"));
            s.config_set<std::shared_ptr<visor::Configurable>>("fail_if_header_matches", m);
        });
    // X-Debug lived only on the 301; the final 200 is clean => no content failure.
    CHECK(tgt["successes"].get<int>() >= 1);
    CHECK(tgt["content_failures"].get<int>() == 0);
}

TEST_CASE("NetProbe HTTP e2e v3: not_contains hit in a truncated prefix still fails", "[netprobe][http][e2e]")
{
    // The forbidden token sits in the FIRST bytes of a large body. Even though the body is truncated
    // at the capture cap, a visible not_contains hit is a definitive failure (its presence does not
    // depend on the dropped tail) — must be content_failures, never a false success.
    httplib::Server svr;
    std::string body = std::string("traceback: boom\n") + std::string(64 * 1024, 'x');
    svr.Get("/e", [&](const httplib::Request &, httplib::Response &res) {
        res.set_content(body, "text/plain");
    });
    int port = svr.bind_to_any_port("127.0.0.1");
    REQUIRE(port > 0);
    std::thread th([&svr] { svr.listen_after_bind(); });
    ServerGuard guard{svr, th};
    svr.wait_until_ready();
    auto tgt = run_v3_http_probe("v3-trunc-notcontains", "http://127.0.0.1:" + std::to_string(port) + "/e",
        [](NetProbeInputStream &s) {
            s.config_set("not_contains", std::string("traceback"));
            s.config_set<uint64_t>("body_check_max_bytes", 1024); // truncates, but 'traceback' is in the prefix
        });
    CHECK(tgt["successes"].get<int>() == 0);
    CHECK(tgt["content_failures"].get<int>() >= 1);
}

TEST_CASE("NetProbe HTTP e2e v3: max_response_size_bytes 0 requires an empty body", "[netprobe][http][e2e]")
{
    // 0 is a real bound (require empty body), not "unset": a non-empty response must fail, an empty
    // response must pass.
    httplib::Server svr;
    svr.Get("/nonempty", [](const httplib::Request &, httplib::Response &res) { res.set_content("x", "text/plain"); });
    svr.Get("/empty", [](const httplib::Request &, httplib::Response &res) { res.set_content("", "text/plain"); });
    int port = svr.bind_to_any_port("127.0.0.1");
    REQUIRE(port > 0);
    std::thread th([&svr] { svr.listen_after_bind(); });
    ServerGuard guard{svr, th};
    svr.wait_until_ready();
    std::string base = "http://127.0.0.1:" + std::to_string(port);

    auto ne = run_v3_http_probe("v3-maxsize0-ne", base + "/nonempty",
        [](NetProbeInputStream &s) { s.config_set<uint64_t>("max_response_size_bytes", 0); });
    CHECK(ne["successes"].get<int>() == 0);
    CHECK(ne["content_failures"].get<int>() >= 1);

    auto em = run_v3_http_probe("v3-maxsize0-e", base + "/empty",
        [](NetProbeInputStream &s) { s.config_set<uint64_t>("max_response_size_bytes", 0); });
    CHECK(em["successes"].get<int>() >= 1);
    CHECK(em["content_failures"].get<int>() == 0);
}

TEST_CASE("NetProbe HTTP e2e v3: stale Last-Modified fails max_last_modified_diff_secs", "[netprobe][http][e2e]")
{
    httplib::Server svr;
    svr.Get("/lm", [](const httplib::Request &, httplib::Response &res) {
        res.set_header("Last-Modified", "Wed, 21 Oct 2015 07:28:00 GMT"); // ancient => older than the diff
        res.set_content("ok", "text/plain");
    });
    int port = svr.bind_to_any_port("127.0.0.1");
    REQUIRE(port > 0);
    std::thread th([&svr] { svr.listen_after_bind(); });
    ServerGuard guard{svr, th};
    svr.wait_until_ready();
    auto tgt = run_v3_http_probe("v3-lastmod", "http://127.0.0.1:" + std::to_string(port) + "/lm",
        [](NetProbeInputStream &s) { s.config_set<uint64_t>("max_last_modified_diff_secs", 3600); });
    CHECK(tgt["successes"].get<int>() == 0);
    CHECK(tgt["content_failures"].get<int>() >= 1);
}

TEST_CASE("NetProbe HTTP e2e v3: per-target resolve pins a bogus host to the test server", "[netprobe][http][e2e]")
{
    // Proves CURLOPT_RESOLVE is applied: the target host "bogus.invalid" would never resolve via DNS,
    // so a recorded success can only happen if the resolve override mapped it to 127.0.0.1.
    httplib::Server svr;
    svr.Get("/ok", [](const httplib::Request &, httplib::Response &res) { res.set_content("ok", "text/plain"); });
    int port = svr.bind_to_any_port("127.0.0.1");
    REQUIRE(port > 0);
    std::thread th([&svr] { svr.listen_after_bind(); });
    ServerGuard guard{svr, th};
    svr.wait_until_ready();

    NetProbeInputStream stream{"v3-resolve"};
    stream.config_set("test_type", "http");
    stream.config_set<uint64_t>("interval_msec", 200);
    stream.config_set<uint64_t>("timeout_msec", 150);
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", std::string("http://bogus.invalid:" + std::to_string(port) + "/ok"));
    target->config_set<visor::Configurable::StringList>("resolve",
        {"bogus.invalid:" + std::to_string(port) + ":127.0.0.1"});
    targets->config_set<std::shared_ptr<visor::Configurable>>("t", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);

    visor::Config c;
    c.config_set<uint64_t>("num_periods", 1);
    auto *proxy = stream.add_event_proxy(c);
    NetProbeStreamHandler handler{"v3-resolve", proxy, &c};
    handler.start();
    stream.start();
    std::this_thread::sleep_for(750ms);
    stream.stop();
    handler.stop();
    json j;
    handler.metrics()->bucket(0)->to_json(j);
    REQUIRE(j["targets"].contains("t"));
    CHECK(j["targets"]["t"]["successes"].get<int>() >= 1);
}

TEST_CASE("NetProbe HTTP e2e v3: a per-target resolve override does not leak to another target", "[netprobe][http][e2e]")
{
    // Two targets for the SAME host:port on one stream (shared curl_multi). "pinned" overrides
    // bogus.invalid -> 127.0.0.1 (the test server); "unpinned" has NO override and must NOT be
    // silently sent to the pinned address. With CONNECT_TO (per-handle, no shared DNS cache) the
    // unpinned target does real DNS for bogus.invalid and fails — proving the override is scoped.
    httplib::Server svr;
    svr.Get("/ok", [](const httplib::Request &, httplib::Response &res) { res.set_content("ok", "text/plain"); });
    int port = svr.bind_to_any_port("127.0.0.1");
    REQUIRE(port > 0);
    std::thread th([&svr] { svr.listen_after_bind(); });
    ServerGuard guard{svr, th};
    svr.wait_until_ready();
    std::string ps = std::to_string(port);

    NetProbeInputStream stream{"v3-resolve-leak"};
    stream.config_set("test_type", "http");
    stream.config_set<uint64_t>("interval_msec", 200);
    stream.config_set<uint64_t>("timeout_msec", 150);
    auto targets = std::make_shared<visor::Configurable>();
    auto pinned = std::make_shared<visor::Configurable>();
    pinned->config_set("target", std::string("http://bogus.invalid:" + ps + "/ok"));
    pinned->config_set<visor::Configurable::StringList>("resolve", {"bogus.invalid:" + ps + ":127.0.0.1"});
    targets->config_set<std::shared_ptr<visor::Configurable>>("pinned", pinned);
    auto unpinned = std::make_shared<visor::Configurable>();
    unpinned->config_set("target", std::string("http://bogus.invalid:" + ps + "/ok")); // same host:port, NO resolve
    targets->config_set<std::shared_ptr<visor::Configurable>>("unpinned", unpinned);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);

    visor::Config c;
    c.config_set<uint64_t>("num_periods", 1);
    auto *proxy = stream.add_event_proxy(c);
    NetProbeStreamHandler handler{"v3-resolve-leak", proxy, &c};
    handler.start();
    stream.start();
    std::this_thread::sleep_for(750ms);
    stream.stop();
    handler.stop();
    json j;
    handler.metrics()->bucket(0)->to_json(j);
    REQUIRE(j["targets"].contains("pinned"));
    REQUIRE(j["targets"].contains("unpinned"));
    CHECK(j["targets"]["pinned"]["successes"].get<int>() >= 1);
    CHECK(j["targets"]["unpinned"]["successes"].get<int>() == 0); // override must NOT have leaked
}

TEST_CASE("NetProbe HTTP e2e v2: custom headers are not forwarded across redirects", "[netprobe][http][e2e]")
{
    // Server A redirects to server B; B records whether it ever received the secret header. With a
    // custom per-target header configured, the probe must NOT follow the 302, so B is never hit and
    // the secret never leaves A (libcurl would otherwise re-send custom headers to the new host).
    std::atomic<bool> b_saw_header{false};
    std::atomic<int> b_hits{0};
    httplib::Server svr_b;
    svr_b.Get("/leak", [&](const httplib::Request &req, httplib::Response &res) {
        ++b_hits;
        if (req.has_header("X-Api-Key")) {
            b_saw_header = true;
        }
        res.set_content("leaked", "text/plain");
    });
    int port_b = svr_b.bind_to_any_port("127.0.0.1");
    REQUIRE(port_b > 0);
    std::thread thread_b([&svr_b] { svr_b.listen_after_bind(); });
    ServerGuard guard_b{svr_b, thread_b};
    svr_b.wait_until_ready();

    httplib::Server svr_a;
    std::string loc = "http://127.0.0.1:" + std::to_string(port_b) + "/leak";
    svr_a.Get("/redirect", [&](const httplib::Request &, httplib::Response &res) {
        res.status = 302;
        res.set_header("Location", loc);
    });
    int port_a = svr_a.bind_to_any_port("127.0.0.1");
    REQUIRE(port_a > 0);
    std::thread thread_a([&svr_a] { svr_a.listen_after_bind(); });
    ServerGuard guard_a{svr_a, thread_a};
    svr_a.wait_until_ready();

    std::string url = "http://127.0.0.1:" + std::to_string(port_a) + "/redirect";
    NetProbeInputStream stream{"netprobe-http-e2e-redirect-headers"};
    stream.config_set("test_type", "http");
    stream.config_set<uint64_t>("interval_msec", 200);
    stream.config_set<uint64_t>("timeout_msec", 150);
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", url);
    auto headers = std::make_shared<visor::Configurable>();
    headers->config_set("X-Api-Key", std::string("sekrit"));
    target->config_set<std::shared_ptr<visor::Configurable>>("headers", headers);
    targets->config_set<std::shared_ptr<visor::Configurable>>("redir_target", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);

    visor::Config c;
    c.config_set<uint64_t>("num_periods", 1);
    auto *proxy = stream.add_event_proxy(c);
    NetProbeStreamHandler handler{"netprobe-http-e2e-redirect-headers", proxy, &c};

    handler.start();
    stream.start();
    std::this_thread::sleep_for(750ms);
    stream.stop();
    handler.stop();

    // The redirect must not have been followed: server B was never contacted, so the secret header
    // never left server A.
    CHECK(b_hits.load() == 0);
    CHECK(b_saw_header.load() == false);
}

TEST_CASE("NetProbe HTTP e2e v2: request body is not resent across redirects", "[netprobe][http][e2e]")
{
    // Body-bearing probe with NO custom headers (isolates the body gate). Server A replies 308
    // (preserves method + body); server B records whether it was ever hit. The probe must not
    // follow, so the secret payload never leaves A.
    std::atomic<int> b_hits{0};
    httplib::Server svr_b;
    auto record = [&](const httplib::Request &, httplib::Response &res) {
        ++b_hits;
        res.set_content("ok", "text/plain");
    };
    svr_b.Post("/leak", record);
    svr_b.Get("/leak", record); // also count a method-degraded follow
    int port_b = svr_b.bind_to_any_port("127.0.0.1");
    REQUIRE(port_b > 0);
    std::thread thread_b([&svr_b] { svr_b.listen_after_bind(); });
    ServerGuard guard_b{svr_b, thread_b};
    svr_b.wait_until_ready();

    httplib::Server svr_a;
    std::string loc = "http://127.0.0.1:" + std::to_string(port_b) + "/leak";
    svr_a.Post("/redirect", [&](const httplib::Request &, httplib::Response &res) {
        res.status = 308; // 308 preserves the method and body across the redirect
        res.set_header("Location", loc);
    });
    int port_a = svr_a.bind_to_any_port("127.0.0.1");
    REQUIRE(port_a > 0);
    std::thread thread_a([&svr_a] { svr_a.listen_after_bind(); });
    ServerGuard guard_a{svr_a, thread_a};
    svr_a.wait_until_ready();

    std::string url = "http://127.0.0.1:" + std::to_string(port_a) + "/redirect";
    NetProbeInputStream stream{"netprobe-http-e2e-redirect-body"};
    stream.config_set("test_type", "http");
    stream.config_set("http_method", std::string("POST"));
    stream.config_set("body", std::string("{\"secret\":\"sekrit\"}"));
    stream.config_set<uint64_t>("interval_msec", 200);
    stream.config_set<uint64_t>("timeout_msec", 150);
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", url);
    targets->config_set<std::shared_ptr<visor::Configurable>>("redir_target", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);

    visor::Config c;
    c.config_set<uint64_t>("num_periods", 1);
    auto *proxy = stream.add_event_proxy(c);
    NetProbeStreamHandler handler{"netprobe-http-e2e-redirect-body", proxy, &c};

    handler.start();
    stream.start();
    std::this_thread::sleep_for(750ms);
    stream.stop();
    handler.stop();

    CHECK(b_hits.load() == 0);
}

TEST_CASE("NetProbe HTTP e2e v2: POST body is delivered to the server", "[netprobe][http][e2e]")
{
    std::atomic<bool> body_seen{false};
    std::mutex body_mutex;
    std::string seen_body;

    httplib::Server svr;
    svr.Post("/echo-len", [&](const httplib::Request &req, httplib::Response &res) {
        {
            std::lock_guard<std::mutex> lock(body_mutex);
            seen_body = req.body;
        }
        body_seen = true;
        res.set_content("ok", "text/plain");
    });
    int port = svr.bind_to_any_port("127.0.0.1");
    REQUIRE(port > 0);
    std::thread server_thread([&svr] { svr.listen_after_bind(); });
    ServerGuard guard{svr, server_thread};
    svr.wait_until_ready();

    std::string url = "http://127.0.0.1:" + std::to_string(port) + "/echo-len";

    NetProbeInputStream stream{"netprobe-http-e2e-post-body"};
    stream.config_set("test_type", "http");
    stream.config_set<uint64_t>("interval_msec", 200);
    stream.config_set<uint64_t>("timeout_msec", 150);
    stream.config_set("http_method", std::string("POST"));
    stream.config_set("body", std::string(R"({"ping":true})"));
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", url);
    targets->config_set<std::shared_ptr<visor::Configurable>>("echo_target", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);

    visor::Config c;
    c.config_set<uint64_t>("num_periods", 1);
    auto *proxy = stream.add_event_proxy(c);
    NetProbeStreamHandler handler{"netprobe-http-e2e-post-body", proxy, &c};

    handler.start();
    stream.start();
    std::this_thread::sleep_for(750ms);
    stream.stop();
    handler.stop();

    REQUIRE(body_seen.load());
    {
        std::lock_guard<std::mutex> lock(body_mutex);
        CHECK(seen_body == R"({"ping":true})");
    }

    json j;
    handler.metrics()->bucket(0)->to_json(j);
    REQUIRE(j["targets"].contains("echo_target"));
    CHECK(j["targets"]["echo_target"]["successes"].get<int>() >= 1);
}
