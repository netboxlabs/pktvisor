#include "AbstractMetricsManager.h"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers.hpp>

using namespace visor;

class TestMetricsBucket final : public AbstractMetricsBucket
{
public:
    void specialized_merge([[maybe_unused]] const AbstractMetricsBucket &other, [[maybe_unused]] Metric::Aggregate agg_operator)
    {
    }
    void to_json([[maybe_unused]] json &j) const
    {
    }
    void to_prometheus([[maybe_unused]] PrometheusSerializer &ser,
        [[maybe_unused]] Metric::LabelMap add_labels = {}) const
    {
        ser.write("test_performed", PrometheusSerializer::Type::Gauge, "", {}, {}, 1);
    }
    void to_opentelemetry(metrics::v1::ScopeMetrics &scope, timespec &start, timespec &, Metric::LabelMap) const
    {
        // The description carries the window start, so a test can see the order
        // windows are pushed in.
        for (const auto *name : {"test1", "test2"}) {
            auto metric = scope.add_metrics();
            metric->set_name(name);
            metric->set_description(std::to_string(start.tv_sec) + "." + std::to_string(start.tv_nsec));
        }
    }
    void update_topn_metrics(size_t, uint64_t)
    {
    }
};

class TestMetricsManager : public AbstractMetricsManager<TestMetricsBucket>
{
public:
    TestMetricsManager(const Configurable *windowConfig)
        : AbstractMetricsManager(windowConfig){};
    ~TestMetricsManager() = default;
};

TEST_CASE("Abstract metrics manager", "[metrics][abstract]")
{
    json j;
    std::stringstream output;
    metrics::v1::ScopeMetrics scope;
    std::string line;
    visor::Config c;
    c.config_set<uint64_t>("num_periods", 1);
    c.config_set<uint64_t>("deep_sample_rate", 102);
    std::unique_ptr<TestMetricsManager> manager = std::make_unique<TestMetricsManager>(&c);

    SECTION("Check Configs")
    {
        CHECK(manager->num_periods() == 1);
        CHECK(manager->deep_sample_rate() == 100);
    }

    SECTION("Abstract window single json")
    {
        manager->window_single_json(j, "metrics");
        CHECK(j["metrics"]["period"]["length"] == 0);
    }

    SECTION("Abstract window single json failed")
    {
        CHECK_THROWS_WITH(manager->window_single_json(j, "metrics", 2), "invalid metrics period, specify [0, 0]");
    }

    SECTION("Abstract window single prometheus")
    {
        PrometheusSerializer ser;
        manager->window_single_prometheus(ser, 0, {{"policy", "default"}});
        CHECK(ser.finalize().find("test_performed{") != std::string::npos);
    }

    SECTION("Abstract window single opentelemetry")
    {
        manager->window_single_opentelemetry(scope);
        CHECK(scope.metrics_size() == 2);
    }

    SECTION("Abstract window single prometheus failed")
    {
        PrometheusSerializer ser;
        CHECK_THROWS_WITH(manager->window_single_prometheus(ser, 2, {{"policy", "default"}}),
            "invalid metrics period, specify [0, 0]");
    }

    SECTION("Abstract window merged json failed")
    {
        CHECK_THROWS_WITH(manager->window_merged_json(j, "metrics", 0), "invalid metrics period, specify [2, 1]");
    }

    SECTION("Abstract window external json")
    {
        auto live = static_cast<AbstractMetricsBucket *>(manager->live_bucket());
        manager->window_external_json(j, "metrics", live);
        CHECK(j["metrics"]["period"]["length"] == 0);
    }

    SECTION("Abstract window external prometheus")
    {
        auto live = static_cast<AbstractMetricsBucket *>(manager->live_bucket());
        PrometheusSerializer ser;
        manager->window_external_prometheus(ser, live, {{"policy", "default"}});
        CHECK(ser.finalize().find("test_performed{") != std::string::npos);
    }

    SECTION("Abstract simple merge without bucket")
    {
        auto new_bucket = manager->simple_merge(nullptr, 0);
        CHECK(nullptr != dynamic_cast<TestMetricsBucket *>(new_bucket.get()));
    }

    SECTION("Abstract simple merge with bucket")
    {
        auto bucket = std::make_unique<TestMetricsBucket>();
        auto new_bucket = manager->simple_merge(bucket.get(), 0);
        CHECK(nullptr == new_bucket);
        CHECK(nullptr != dynamic_cast<TestMetricsBucket *>(bucket.get()));
    }

    SECTION("Abstract simple merge failed")
    {
        CHECK_THROWS_WITH(manager->simple_merge(nullptr, 2), "invalid metrics period, specify [0, 0]");
    }

    SECTION("Abstract multiple merge failed")
    {
        CHECK_THROWS_WITH(manager->multiple_merge(nullptr, 0), "invalid metrics period, specify [2, 1]");
    }
}

TEST_CASE("Counter metrics", "[metrics][counter]")
{
    Metric::add_static_label("instance", "test instance");

    json j;
    std::stringstream output;
    metrics::v1::ScopeMetrics scope;
    std::string line;
    Counter c("root", {"test", "metric"}, "A counter test metric");

    SECTION("Counter increment")
    {
        c.name_json_assign(j, 58);
        CHECK(j["test"]["metric"] == 58);
        ++c;
        c.to_json(j["top"]);
        CHECK(j["top"]["test"]["metric"] == 1);
        c += 4;
        c.to_json(j["top"]);
        CHECK(j["top"]["test"]["metric"] == 5);
    }

    SECTION("Counter add")
    {
        c.name_json_assign(j, {"add"}, 60);
        CHECK(j["test"]["metric"]["add"] == 60);
    }

    SECTION("Counter prometheus")
    {
        ++c;
        PrometheusSerializer ser;
        c.to_prometheus(ser, {{"policy", "default"}});
        output << ser.finalize();
        std::getline(output, line);
        CHECK(line == "# HELP root_test_metric A counter test metric");
        std::getline(output, line);
        CHECK(line == "# TYPE root_test_metric gauge");
        std::getline(output, line);
        CHECK(line == R"(root_test_metric{instance="test instance",policy="default"} 1)");
    }

    SECTION("Counter opentelemetry")
    {
        ++c;
        timespec stamp;
        c.to_opentelemetry(scope, stamp, stamp, {{"policy", "default"}});
        CHECK(scope.metrics(0).name() == "root_test_metric");
        CHECK(scope.metrics(0).has_gauge());
    }
}

TEST_CASE("Quantile metrics", "[metrics][quantile]")
{
    Metric::add_static_label("instance", "test instance");

    json j;
    std::stringstream output;
    metrics::v1::ScopeMetrics scope;
    std::string line;
    Quantile<int_fast32_t> q("root", {"test", "metric"}, "A quantile test metric");

    SECTION("Quantile to json")
    {
        q.name_json_assign(j, 58);
        CHECK(j["test"]["metric"] == 58);
        int_fast32_t value = 12;
        q.update(value);
        q.to_json(j["top"]);
        CHECK(j["top"]["test"]["metric"]["p50"] == 12);
        CHECK(j["top"]["test"]["metric"]["p90"] == 12);
        CHECK(j["top"]["test"]["metric"]["p95"] == 12);
        CHECK(j["top"]["test"]["metric"]["p99"] == 12);
    }

    SECTION("Quantile get n")
    {
        q.update(12);
        auto other = q.get_n();
        CHECK(other == 1);
    }

    SECTION("Quantile get quantile")
    {
        q.update(12);
        auto result = q.get_quantile(0.5);
        CHECK(result == 12);
    }

    SECTION("Quantile prometheus")
    {
        q.update(12);
        PrometheusSerializer ser;
        q.to_prometheus(ser, {{"policy", "default"}});
        output << ser.finalize();
        std::getline(output, line);
        CHECK(line == "# HELP root_test_metric A quantile test metric");
        std::getline(output, line);
        CHECK(line == "# TYPE root_test_metric summary");
        std::getline(output, line);
        CHECK(line == R"(root_test_metric{instance="test instance",policy="default",quantile="0.5"} 12)");
        std::getline(output, line);
        CHECK(line == R"(root_test_metric{instance="test instance",policy="default",quantile="0.9"} 12)");
        std::getline(output, line);
        CHECK(line == R"(root_test_metric{instance="test instance",policy="default",quantile="0.95"} 12)");
        std::getline(output, line);
        CHECK(line == R"(root_test_metric{instance="test instance",policy="default",quantile="0.99"} 12)");
        std::getline(output, line);
        CHECK(line == R"(root_test_metric_sum{instance="test instance",policy="default"} 12)");
        std::getline(output, line);
        CHECK(line == R"(root_test_metric_count{instance="test instance",policy="default"} 1)");
    }

    SECTION("Quantile opentelemetry")
    {
        q.update(12);
        timespec stamp;
        q.to_opentelemetry(scope, stamp, stamp, {{"policy", "default"}});
        CHECK(scope.metrics(0).name() == "root_test_metric");
        CHECK(scope.metrics(0).has_summary());
    }
}

TEST_CASE("Histogram int metrics", "[metrics][histogram]")
{
    Metric::add_static_label("instance", "test instance");

    json j;
    std::stringstream output;
    metrics::v1::ScopeMetrics scope;
    std::string line;
    Histogram<uint64_t> h("root", {"test", "metric"}, "A histogram test metric");

    SECTION("Histogram to json")
    {
        h.name_json_assign(j, 58);
        CHECK(j["test"]["metric"] == 58);
        uint64_t value = 12;
        h.update(value);
        h.update(value);
        h.update(value);
        value = 8;
        h.update(value);
        h.to_json(j["top"]);

        CHECK(j["top"]["test"]["metric"]["buckets"]["+Inf"] == 4.0);
        CHECK(j["top"]["test"]["metric"]["buckets"]["12"] == 4.0);
        CHECK(j["top"]["test"]["metric"]["buckets"]["8"] == 1.0);
    }

    SECTION("Histogram get n")
    {
        h.update(12);
        auto other = h.get_n();
        CHECK(other == 1);
    }

    SECTION("Histogram prometheus")
    {
        h.update(12);
        h.update(12);
        h.update(1);
        h.update(8);
        h.update(12);
        PrometheusSerializer ser;
        h.to_prometheus(ser, {{"policy", "default"}});
        output << ser.finalize();
        std::getline(output, line);
        CHECK(line == "# HELP root_test_metric A histogram test metric");
        std::getline(output, line);
        CHECK(line == "# TYPE root_test_metric histogram");
        std::getline(output, line);
        CHECK(line == R"(root_test_metric_bucket{instance="test instance",le="1",policy="default"} 1)");
        std::getline(output, line);
        CHECK(line == R"(root_test_metric_bucket{instance="test instance",le="8",policy="default"} 2)");
        std::getline(output, line);
        CHECK(line == R"(root_test_metric_bucket{instance="test instance",le="12",policy="default"} 5)");
        std::getline(output, line);
        CHECK(line == R"(root_test_metric_bucket{instance="test instance",le="+Inf",policy="default"} 5)");
        std::getline(output, line);
        CHECK(line == R"(root_test_metric_count{instance="test instance",policy="default"} 5)");
    }

    SECTION("Histogram opentelemetry")
    {
        h.update(12);
        h.update(12);
        h.update(1);
        h.update(8);
        h.update(12);
        timespec stamp;
        h.to_opentelemetry(scope, stamp, stamp, {{"policy", "default"}});
        CHECK(scope.metrics(0).name() == "root_test_metric");
        CHECK(scope.metrics(0).has_histogram());
    }
}

TEST_CASE("Histogram double metrics", "[metrics][histogram]")
{
    Metric::add_static_label("instance", "test instance");

    json j;
    std::stringstream output;
    metrics::v1::ScopeMetrics scope;
    std::string line;
    Histogram<double> h("root", {"test", "metric"}, "A histogram test metric");

    SECTION("Histogram to json")
    {
        h.update(12.00);
        h.update(12.00);
        h.update(12.00);
        h.update(8.000);
        h.to_json(j["top"]);

        CHECK(j["top"]["test"]["metric"]["buckets"]["12.915497"] == 4.0);
        CHECK(j["top"]["test"]["metric"]["buckets"]["8.799225"] == 1.0);
    }

    SECTION("Histogram get n")
    {
        h.update(12.12);
        auto other = h.get_n();
        CHECK(other == 1);
    }

    SECTION("Histogram prometheus")
    {
        h.update(12.00);
        h.update(12.0001);
        h.update(1);
        h.update(8);
        h.update(12);
        PrometheusSerializer ser;
        h.to_prometheus(ser, {{"policy", "default"}});
        output << ser.finalize();
        std::getline(output, line);
        CHECK(line == "# HELP root_test_metric A histogram test metric");
        std::getline(output, line);
        CHECK(line == "# TYPE root_test_metric histogram");
        std::getline(output, line);
        CHECK(line == R"(root_test_metric_bucket{instance="test instance",le="1.000000",policy="default"} 1)");
        std::getline(output, line);
        CHECK(line == R"(root_test_metric_bucket{instance="test instance",le="8.799225",policy="default"} 2)");
        std::getline(output, line);
        CHECK(line == R"(root_test_metric_bucket{instance="test instance",le="12.915497",policy="default"} 5)");
        std::getline(output, line);
        CHECK(line == R"(root_test_metric_bucket{instance="test instance",le="+Inf",policy="default"} 5)");
        std::getline(output, line);
        CHECK(line == R"(root_test_metric_count{instance="test instance",policy="default"} 5)");
    }

    SECTION("Histogram opentelemetry")
    {
        h.update(12.00);
        h.update(12.0001);
        h.update(1);
        h.update(8);
        h.update(12);
        timespec stamp;
        h.to_opentelemetry(scope, stamp, stamp, {{"policy", "default"}});
        CHECK(scope.metrics(0).name() == "root_test_metric");
        CHECK(scope.metrics(0).has_histogram());
    }
}

TEST_CASE("TopN metrics", "[metrics][topn]")
{
    Metric::add_static_label("instance", "test instance");

    json j;
    std::stringstream output;
    metrics::v1::ScopeMetrics scope;
    std::string line;
    TopN<std::string> top_sting("root", "string", {"test", "metric"}, "A topn test metric");
    TopN<uint16_t> top_int("root", "integer", {"test", "metric"}, "A topn test metric");

    SECTION("TopN to json")
    {
        top_sting.name_json_assign(j, 58);
        CHECK(j["test"]["metric"] == 58);
        top_sting.update("top1");
        top_sting.to_json(j["top"]);
        CHECK(j["top"]["test"]["metric"][0]["estimate"] == 1);
        CHECK(j["top"]["test"]["metric"][0]["name"] == "top1");
    }

    SECTION("TopN to json formatter")
    {
        top_int.name_json_assign(j, 58);
        CHECK(j["test"]["metric"] == 58);
        top_int.update(123);
        top_int.to_json(j["top"], [](const uint16_t &val) { return std::to_string(val); });
        CHECK(j["top"]["test"]["metric"][0]["estimate"] == 1);
        CHECK(j["top"]["test"]["metric"][0]["name"] == "123");
    }

    SECTION("TopN prometheus")
    {
        top_sting.update("top1");
        top_sting.update("top2");
        top_sting.update("top1");
        PrometheusSerializer ser;
        top_sting.to_prometheus(ser, {{"policy", "default"}});
        output << ser.finalize();
        std::getline(output, line);
        CHECK(line == "# HELP root_test_metric A topn test metric");
        std::getline(output, line);
        CHECK(line == "# TYPE root_test_metric gauge");
        std::getline(output, line);
        CHECK(line == R"(root_test_metric{instance="test instance",policy="default",string="top1"} 2)");
        std::getline(output, line);
        CHECK(line == R"(root_test_metric{instance="test instance",policy="default",string="top2"} 1)");
    }

    SECTION("TopN opentelemetry")
    {
        top_sting.update("top1");
        top_sting.update("top2");
        top_sting.update("top1");
        timespec stamp;
        top_sting.to_opentelemetry(scope, stamp, stamp, {{"policy", "default"}});
        CHECK(scope.metrics(0).name() == "root_test_metric");
        CHECK(scope.metrics(0).has_gauge());
        CHECK(scope.metrics_size() == 1);
        CHECK(scope.metrics(0).gauge().data_points_size() == 2);
    }

    SECTION("TopN prometheus formatter")
    {
        top_int.update(123);
        top_int.update(10);
        top_int.update(123);
        PrometheusSerializer ser;
        top_int.to_prometheus(ser, {{"policy", "default"}},
            [](const uint16_t &val) { return std::to_string(val); });
        output << ser.finalize();
        std::getline(output, line);
        CHECK(line == "# HELP root_test_metric A topn test metric");
        std::getline(output, line);
        CHECK(line == "# TYPE root_test_metric gauge");
        std::getline(output, line);
        CHECK(line == R"(root_test_metric{instance="test instance",integer="123",policy="default"} 2)");
        std::getline(output, line);
        CHECK(line == R"(root_test_metric{instance="test instance",integer="10",policy="default"} 1)");
    }

    SECTION("TopN opentelemetry formatter")
    {
        top_int.update(123);
        top_int.update(10);
        top_int.update(123);
        timespec stamp;
        top_int.to_opentelemetry(scope, stamp, stamp, {{"policy", "default"}},
            [](const uint16_t &val) { return std::to_string(val); });
        CHECK(scope.metrics(0).name() == "root_test_metric");
        CHECK(scope.metrics(0).has_gauge());
        CHECK(scope.metrics_size() == 1);
        CHECK(scope.metrics(0).gauge().data_points_size() == 2);
    }

    SECTION("TopN get count size")
    {
        CHECK(top_sting.topn_count() == 10);
        CHECK(top_int.topn_count() == 10);
    }

    SECTION("TopN update count size")
    {
        top_sting.update("top1");
        top_sting.update("top2");
        top_sting.update("top1");
        CHECK(top_sting.topn_count() == 10);
        top_sting.set_settings(1, 0);
        CHECK(top_sting.topn_count() == 1);
        top_sting.to_json(j["top"]);
        CHECK(j["top"]["test"]["metric"][0]["estimate"] == 2);
        CHECK(j["top"]["test"]["metric"][0]["name"] == "top1");
        CHECK(j["top"]["test"]["metric"][1] == nullptr);
    }
}

TEST_CASE("Cardinality metrics", "[metrics][cardinality]")
{
    Metric::add_static_label("instance", "test instance");

    json j;
    std::stringstream output;
    metrics::v1::ScopeMetrics scope;
    std::string line;
    Cardinality c("root", {"test", "metric"}, "A cardinality test metric");

    SECTION("Cardinality update")
    {
        c.name_json_assign(j, 58);
        CHECK(j["test"]["metric"] == 58);
        c.update("metric");
        c.to_json(j);
        CHECK(j["test"]["metric"] == 1);
        uint8_t data[16] = {2, 0, 0, 1, ':', 'd', 'b', 8, ':', 3, 'c', 4, 'd', ':', 1, 5};
        c.update(reinterpret_cast<const void *>(data), 16);
        c.to_json(j["top"]);
        CHECK(j["top"]["test"]["metric"] == 2);
    }

    SECTION("Cardinality prometheus")
    {
        c.update("metric");
        PrometheusSerializer ser;
        c.to_prometheus(ser, {{"policy", "default"}});
        output << ser.finalize();
        std::getline(output, line);
        CHECK(line == "# HELP root_test_metric A cardinality test metric");
        std::getline(output, line);
        CHECK(line == "# TYPE root_test_metric gauge");
        std::getline(output, line);
        CHECK(line == R"(root_test_metric{instance="test instance",policy="default"} 1)");
    }

    SECTION("Cardinality opentelemetry")
    {
        c.update("metric");
        timespec stamp;
        c.to_opentelemetry(scope, stamp, stamp, {{"policy", "default"}});
        CHECK(scope.metrics(0).name() == "root_test_metric");
        CHECK(scope.metrics(0).has_gauge());
        CHECK(scope.metrics_size() == 1);
    }
}

TEST_CASE("Rate metrics", "[metrics][rate]")
{
    Metric::add_static_label("instance", "test instance");

    json j;
    std::stringstream output;
    metrics::v1::ScopeMetrics scope;
    std::string line;
    Rate r("root", {"test", "metric"}, "A rate test metric");

    SECTION("rate set info invalid name")
    {
        CHECK_THROWS_WITH(r.set_info("root", {"test*", "metric"}, "A rate test metric"), "invalid metric name: test*");
    }

    SECTION("rate set info invalid scheme")
    {
        CHECK_THROWS_WITH(r.set_info("root*", {"test", "metric"}, "A rate test metric"), "invalid schema name: root*");
    }

    SECTION("rate live json")
    {
        r.name_json_assign(j, 58);
        CHECK(j["test"]["metric"] == 58);
        r.to_json(j["top"], true);
        CHECK(j["top"]["test"]["metric"]["live"] == 0);
    }

    SECTION("rate prometheus")
    {
        PrometheusSerializer ser;
        r.to_prometheus(ser, {{"policy", "default"}});
        output << ser.finalize();
    }

    SECTION("rate opentelemetry")
    {
        timespec stamp;
        r.to_opentelemetry(scope, stamp, stamp, {{"policy", "default"}});
    }
}

static std::string otel_attribute(const metrics::v1::NumberDataPoint &point, const std::string &key)
{
    for (const auto &attribute : point.attributes()) {
        if (attribute.key() == key) {
            return attribute.value().string_value();
        }
    }
    return {};
}

TEST_CASE("Label values that are not UTF-8", "[metrics][utf8]")
{
    SECTION("valid UTF-8 is unchanged")
    {
        for (const auto &value : std::vector<std::string>{"", "dns.example", "caf\xc3\xa9", "\xe0\xa0\x80", "\xed\x9f\xbf", "\xee\x80\x80", "\xf0\x90\x80\x80", "\xf0\x9f\x98\x80", "\xf4\x8f\xbf\xbf", std::string("a\0b", 3)}) {
            CHECK(is_utf8(value));
            CHECK_FALSE(label_value_needs_escape(value));
            CHECK(utf8_label_value(value) == value);
        }
    }

    SECTION("a backslash is escaped only before three digits")
    {
        for (const auto &value : std::vector<std::string>{R"(\Device\NPF_{0})", R"(a\12)", R"(a\12b)", "\\"}) {
            CHECK_FALSE(label_value_needs_escape(value));
            CHECK(utf8_label_value(value) == value);
        }
        CHECK(utf8_label_value(R"(a\255b)") == R"(a\092255b)");
        CHECK(utf8_label_value("\\\xff") == R"(\\255)");
        // The literal text \255 and the byte 0xff must not render the same.
        CHECK(utf8_label_value(R"(\255)") != utf8_label_value("\xff"));
    }

    SECTION("each byte outside a UTF-8 sequence gets a decimal escape")
    {
        const std::vector<std::pair<std::string, std::string>> cases{
            {"\xff", R"(\255)"},
            {"a\x80", R"(a\128)"},                       // lone continuation byte
            {"\xc3(", R"(\195()"},                       // truncated sequence, next byte kept
            {"\xe2\x82", R"(\226\130)"},                 // truncated at the end of the value
            {"\xf0\x9f\x98", R"(\240\159\152)"},         // truncated at the end of the value
            {"\xc0\xaf", R"(\192\175)"},                 // overlong form
            {"\xc1\x81", R"(\193\129)"},                 // overlong form
            {"\xe0\x80\xaf", R"(\224\128\175)"},         // overlong form
            {"\xf0\x8f\xbf\xbf", R"(\240\143\191\191)"}, // overlong form
            {"\xed\xa0\x80", R"(\237\160\128)"},         // surrogate
            {"\xf4\x90\x80\x80", R"(\244\144\128\128)"}, // above U+10FFFF
            {"\xf5\x80\x80\x80", R"(\245\128\128\128)"},
            {"caf\xc3\xa9\xff", "caf\xc3\xa9\\255"},
        };
        for (const auto &[value, escaped] : cases) {
            CHECK_FALSE(is_utf8(value));
            CHECK(label_value_needs_escape(value));
            CHECK(utf8_label_value(value) == escaped);
            CHECK(is_utf8(utf8_label_value(value)));
        }
    }

    SECTION("every output escapes them")
    {
        Metric::reset_static_labels();
        const std::string raw = "bad\xff"
                                "name";
        const std::string escaped = R"(bad\255name)";
        TopN<std::string> top("root", "string", {"test", "metric"}, "A topn test metric");
        top.update(raw);

        json j;
        top.to_json(j);
        CHECK(j["test"]["metric"][0]["name"] == escaped);
        CHECK_NOTHROW(j.dump());

        PrometheusSerializer ser;
        top.to_prometheus(ser, {{"policy", "default"}});
        CHECK(ser.finalize().find(R"(string="bad\\255name")") != std::string::npos);

        metrics::v1::ScopeMetrics scope;
        timespec stamp{};
        top.to_opentelemetry(scope, stamp, stamp, {{"policy", "default"}});
        Counter c("root", {"counter"}, "A counter test metric");
        c.to_opentelemetry(scope, stamp, stamp, {{"policy", raw}});
        CHECK(otel_attribute(scope.metrics(0).gauge().data_points(0), "string") == escaped);
        CHECK(otel_attribute(scope.metrics(1).gauge().data_points(0), "policy") == escaped);

        metrics::v1::ScopeMetrics decoded;
        CHECK(decoded.ParseFromString(scope.SerializeAsString()));
    }
}

TEST_CASE("Closed windows are pushed to OpenTelemetry once", "[metrics][abstract][opentelemetry]")
{
    visor::Config c;
    c.config_set<uint64_t>("num_periods", 4);
    auto manager = std::make_unique<TestMetricsManager>(&c);
    metrics::v1::ScopeMetrics scope;
    std::optional<timespec> last;
    timespec stamp;
    timespec_get(&stamp, TIME_UTC);
    auto close_window = [&]() {
        stamp.tv_sec += TestMetricsManager::PERIOD_SEC;
        manager->check_period_shift(stamp);
    };

    // The live window is still filling, so nothing is pushed.
    CHECK_FALSE(manager->next_closed_window_start(std::nullopt));
    CHECK_FALSE(manager->window_closed_opentelemetry(scope, last));
    CHECK(scope.metrics_size() == 0);

    close_window();
    REQUIRE(manager->current_periods() == 2);
    CHECK(manager->window_closed_opentelemetry(scope, last));
    CHECK(scope.metrics_size() == 2);
    scope.Clear();
    CHECK_FALSE(manager->window_closed_opentelemetry(scope, last));
    CHECK(scope.metrics_size() == 0);

    // Two windows closing between pushes are both pushed.
    close_window();
    close_window();
    CHECK(manager->window_closed_opentelemetry(scope, last));
    REQUIRE(scope.metrics_size() == 4);
    // Oldest first: a backend refuses a sample older than one it already has.
    CHECK(std::stod(scope.metrics(0).description()) < std::stod(scope.metrics(2).description()));
    REQUIRE(last);
    CHECK(last->tv_sec == manager->bucket(1)->start_tstamp().tv_sec);
    scope.Clear();
    CHECK_FALSE(manager->window_closed_opentelemetry(scope, last));
}

TEST_CASE("A recorded stream's last window is pushed once it ends", "[metrics][abstract][opentelemetry]")
{
    visor::Config c;
    c.config_set<uint64_t>("num_periods", 4);
    auto manager = std::make_unique<TestMetricsManager>(&c);
    metrics::v1::ScopeMetrics scope;
    std::optional<timespec> last;
    timespec stamp;
    timespec_get(&stamp, TIME_UTC);
    manager->set_start_tstamp(stamp);

    SECTION("Shorter than a window")
    {
        CHECK_FALSE(manager->window_closed_opentelemetry(scope, last));
        stamp.tv_sec += 10;
        manager->set_end_tstamp(stamp);
        REQUIRE(manager->current_periods() == 1);
        CHECK(manager->window_closed_opentelemetry(scope, last));
        CHECK(scope.metrics_size() == 2);
        scope.Clear();
        CHECK_FALSE(manager->window_closed_opentelemetry(scope, last));
    }

    SECTION("Longer than a window")
    {
        stamp.tv_sec += TestMetricsManager::PERIOD_SEC;
        manager->check_period_shift(stamp);
        stamp.tv_sec += 10;
        manager->set_end_tstamp(stamp);
        REQUIRE(manager->current_periods() == 2);
        CHECK(manager->window_closed_opentelemetry(scope, last));
        CHECK(scope.metrics_size() == 4);
        scope.Clear();
        CHECK_FALSE(manager->window_closed_opentelemetry(scope, last));
    }
}

TEST_CASE("Closed windows are merged by their start", "[metrics][abstract]")
{
    visor::Config c;
    c.config_set<uint64_t>("num_periods", 4);
    auto manager = std::make_unique<TestMetricsManager>(&c);
    timespec stamp;
    timespec_get(&stamp, TIME_UTC);
    auto close_window = [&]() {
        stamp.tv_sec += TestMetricsManager::PERIOD_SEC;
        manager->check_period_shift(stamp);
    };

    close_window();
    auto first = manager->next_closed_window_start(std::nullopt);
    REQUIRE(first);

    // A window that closes before the merge leaves the one asked for in place.
    close_window();
    CHECK(manager->next_closed_window_start(std::nullopt)->tv_sec == first->tv_sec);
    auto second = manager->next_closed_window_start(first);
    REQUIRE(second);
    CHECK(second->tv_sec > first->tv_sec);
    CHECK_FALSE(manager->next_closed_window_start(second));
    auto merged = manager->closed_merge(nullptr, *first);
    REQUIRE(merged);
    CHECK(merged->start_tstamp().tv_sec == first->tv_sec);
    CHECK(merged->end_tstamp().tv_sec == manager->bucket(2)->end_tstamp().tv_sec);

    // Merging into a bucket adds to it.
    CHECK(manager->closed_merge(merged.get(), *second) == nullptr);

    // A window no longer held is refused.
    CHECK_THROWS_AS(manager->closed_merge(nullptr, timespec{1, 0}), PeriodException);
}
