#include "PrometheusSerializer.h"
#include "Metrics.h"
#include <catch2/catch_test_macros.hpp>
#include <sstream>

using namespace visor;
using Type = PrometheusSerializer::Type;

TEST_CASE("single gauge family", "[prometheus][serializer]")
{
    Metric::reset_static_labels();
    PrometheusSerializer s;
    s.write("net_packets_total", Type::Gauge, "Total packets", {}, {}, 42);
    CHECK(s.finalize() ==
        "# HELP net_packets_total Total packets\n"
        "# TYPE net_packets_total gauge\n"
        "net_packets_total{} 42\n");
}

TEST_CASE("repeated family writes one header, contiguous series", "[prometheus][serializer]")
{
    Metric::reset_static_labels();
    PrometheusSerializer s;
    s.write("flow_bytes", Type::Gauge, "bytes", {}, {{"device", "A"}}, 10);
    s.write("other_metric", Type::Gauge, "x", {}, {}, 1);
    s.write("flow_bytes", Type::Gauge, "bytes", {}, {{"device", "B"}}, 20);
    CHECK(s.finalize() ==
        "# HELP flow_bytes bytes\n"
        "# TYPE flow_bytes gauge\n"
        "flow_bytes{device=\"A\"} 10\n"
        "flow_bytes{device=\"B\"} 20\n"
        "# HELP other_metric x\n"
        "# TYPE other_metric gauge\n"
        "other_metric{} 1\n");
}

TEST_CASE("histogram suffix + le label", "[prometheus][serializer]")
{
    Metric::reset_static_labels();
    PrometheusSerializer s;
    s.write("dns_xact", Type::Histogram, "latency", {"bucket"}, {{"le", "10"}}, 3.0);
    s.write("dns_xact", Type::Histogram, "latency", {"count"}, {}, 7);
    CHECK(s.finalize() ==
        "# HELP dns_xact latency\n"
        "# TYPE dns_xact histogram\n"
        "dns_xact_bucket{le=\"10\"} 3\n"
        "dns_xact_count{} 7\n");
}

TEST_CASE("static labels merged before passed labels", "[prometheus][serializer]")
{
    Metric::reset_static_labels();
    Metric::add_static_label("instance", "host1");
    PrometheusSerializer s;
    s.write("net_x", Type::Gauge, "d", {}, {{"dir", "in"}}, 1);
    CHECK(s.finalize() ==
        "# HELP net_x d\n"
        "# TYPE net_x gauge\n"
        "net_x{instance=\"host1\",dir=\"in\"} 1\n");
    Metric::reset_static_labels();
}

TEST_CASE("label values are escaped", "[prometheus][serializer]")
{
    Metric::reset_static_labels();
    PrometheusSerializer s;
    s.write("m", Type::Gauge, "d", {}, {{"desc", "a\"b\\c\nd"}}, 1);
    CHECK(s.finalize() ==
        "# HELP m d\n"
        "# TYPE m gauge\n"
        "m{desc=\"a\\\"b\\\\c\\nd\"} 1\n");
}

TEST_CASE("numeric formatting matches ostream operator<<", "[prometheus][serializer]")
{
    Metric::reset_static_labels();
    auto oss = [](auto v) { std::stringstream o; o << v; return o.str(); };
    PrometheusSerializer s;
    s.write("i", Type::Gauge, "d", {}, {}, int64_t{1234567});
    s.write("neg", Type::Gauge, "d", {}, {}, int64_t{-5});
    s.write("d_half", Type::Gauge, "d", {}, {}, 0.5);
    s.write("d_third", Type::Gauge, "d", {}, {}, 1.0 / 3.0);
    s.write("d_big", Type::Gauge, "d", {}, {}, 1000000.0);
    s.write("d_huge", Type::Gauge, "d", {}, {}, 1e20);
    s.write("d_zero", Type::Gauge, "d", {}, {}, 0.0);
    s.write("d_small", Type::Gauge, "d", {}, {}, 0.00001);
    auto out = s.finalize();
    for (auto pair : {std::make_pair("i", oss(int64_t{1234567})),
                      std::make_pair("neg", oss(int64_t{-5})),
                      std::make_pair("d_half", oss(0.5)),
                      std::make_pair("d_third", oss(1.0 / 3.0)),
                      std::make_pair("d_big", oss(1000000.0)),
                      std::make_pair("d_huge", oss(1e20)),
                      std::make_pair("d_zero", oss(0.0)),
                      std::make_pair("d_small", oss(0.00001))}) {
        CHECK(out.find(std::string(pair.first) + "{} " + pair.second + "\n") != std::string::npos);
    }
}

TEST_CASE("a later non-empty HELP fills an initially-empty one", "[prometheus][serializer]")
{
    Metric::reset_static_labels();
    PrometheusSerializer s;
    s.write("m", Type::Gauge, "", {}, {}, 1);          // first write: empty HELP
    s.write("m", Type::Gauge, "real help", {}, {}, 2); // later write supplies HELP
    auto out = s.finalize();
    // single family, one header pair, the non-empty HELP wins, both series present
    CHECK(out ==
        "# HELP m real help\n"
        "# TYPE m gauge\n"
        "m{} 1\n"
        "m{} 2\n");
}
