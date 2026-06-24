#include "StreamHandler.h"

#include <catch2/catch_test_macros.hpp>

using namespace visor;

namespace group {
enum TestHandler : MetricGroupIntType {
    Test,
};
}

class HandlerBucket : public AbstractMetricsBucket
{
public:
    std::string type;
    void specialized_merge(const AbstractMetricsBucket &, Metric::Aggregate) override{};
    void to_json(json &) const override{};
    void to_prometheus(PrometheusSerializer &,
        Metric::LabelMap) const override{};
    void to_opentelemetry(metrics::v1::ScopeMetrics &, timespec &, timespec &, Metric::LabelMap) const override{};
    void update_topn_metrics(size_t, uint64_t) override{};
};

class TestHandlerMetricsManager : public AbstractMetricsManager<HandlerBucket>
{
    const Configurable _config;
    HandlerBucket _bucket;

public:
    TestHandlerMetricsManager(const Configurable *window_config)
        : AbstractMetricsManager<HandlerBucket>(window_config)
        , _config(*window_config){};
    auto current_periods() const
    {
        return _config.config_get<uint64_t>("period");
    }
    const HandlerBucket *bucket(uint64_t) const
    {
        return &_bucket;
    }
    void window_single_json(json &j, const std::string &, uint64_t) const
    {
        j["window"] = "single";
    }
    void window_single_prometheus(PrometheusSerializer &ser, uint64_t period, Metric::LabelMap) const
    {
        if (period) {
            ser.write("first_window", PrometheusSerializer::Type::Gauge, "", {}, {}, 1);
        } else {
            ser.write("live_window", PrometheusSerializer::Type::Gauge, "", {}, {}, 1);
        }
    }
    void window_single_opentelemetry(metrics::v1::ScopeMetrics &scope, uint64_t period, Metric::LabelMap) const
    {
        if (period) {
            scope.add_metrics()->set_name("first_window");
        } else {
            scope.add_metrics()->set_name("live_window");
        }
    }
    void window_external_opentelemetry(metrics::v1::ScopeMetrics &scope, AbstractMetricsBucket *, Metric::LabelMap) const
    {
        scope.add_metrics()->set_name("external_window");
    }
    void window_external_prometheus(PrometheusSerializer &ser, AbstractMetricsBucket *, Metric::LabelMap) const
    {
        ser.write("external_window", PrometheusSerializer::Type::Gauge, "", {}, {}, 1);
    }
    void window_external_json(json &j, const std::string &, AbstractMetricsBucket *) const
    {
        j["window"] = "external";
    }
    void window_merged_json(json &j, const std::string &, uint64_t) const
    {
        j["window"] = "merged";
    }
    std::unique_ptr<AbstractMetricsBucket> simple_merge(AbstractMetricsBucket *, uint64_t)
    {
        auto result = std::make_unique<HandlerBucket>();
        result->type = "simple";
        return result;
    }
    std::unique_ptr<AbstractMetricsBucket> multiple_merge(AbstractMetricsBucket *, uint64_t)
    {
        auto result = std::make_unique<HandlerBucket>();
        result->type = "multiple";
        return result;
    }
};

class TestStreamMetricsHandler : public StreamMetricsHandler<TestHandlerMetricsManager>
{
public:
    TestStreamMetricsHandler(const std::string &name, const Configurable *config)
        : StreamMetricsHandler<TestHandlerMetricsManager>(name, config){};
    void start() override{};
    void stop() override{};
    std::string schema_key() const override
    {
        return "test";
    }
    void test_common_info(json &j) const
    {
        common_info_json(j);
    }
    void test_process_groups()
    {
        const StreamMetricsHandler::GroupDefType group_defs = {
            {"test", group::TestHandler::Test},
        };
        process_groups(group_defs);
    }
};

TEST_CASE("StreamMetricsHandler tests", "[metrics][handler]")
{
    Configurable config;

    SECTION("Common info")
    {
        config.config_set<uint64_t>("period", 1);
        TestStreamMetricsHandler handler("my_handler", &config);
        nlohmann::json j;
        handler.test_common_info(j);
        CHECK(j["module"]["name"] == "my_handler");
        CHECK(handler.metrics()->current_periods() == 1);
    }

    SECTION("Process groups")
    {
        config.config_set<uint64_t>("period", 1);
        TestStreamMetricsHandler handler("my_handler", &config);
        handler.config_set<Configurable::StringList>("disable", {"all"});
        handler.config_set<Configurable::StringList>("enable", {"all"});
        CHECK_NOTHROW(handler.test_process_groups());

        handler.config_set<Configurable::StringList>("disable", {"test"});
        handler.config_set<Configurable::StringList>("enable", {"test"});
        CHECK_NOTHROW(handler.test_process_groups());

        handler.config_set<Configurable::StringList>("disable", {"invalid"});
        CHECK_THROWS(handler.test_process_groups());

        handler.config_set<Configurable::StringList>("disable", {"test"});
        handler.config_set<Configurable::StringList>("enable", {"invalid"});
        CHECK_THROWS(handler.test_process_groups());
    }

    SECTION("Period shift")
    {
        config.config_set<uint64_t>("period", 0);
        TestStreamMetricsHandler handler("my_handler", &config);
        timespec now;
        timespec_get(&now, TIME_UTC);
        CHECK_NOTHROW(handler.check_period_shift(now));
    }

    SECTION("JSON window")
    {
        TestStreamMetricsHandler handler("my_handler", &config);
        json j;
        handler.window_json(j, 0, false);
        CHECK(j["window"] == "single");
        handler.window_json(j, 0, true);
        CHECK(j["window"] == "merged");
        handler.window_json(j, nullptr);
        CHECK(j["window"] == "external");
    }

    SECTION("Prometheus window")
    {
        config.config_set<uint64_t>("period", 0);
        auto handler = std::make_unique<TestStreamMetricsHandler>("my_handler", &config);
        {
            PrometheusSerializer ser;
            handler->window_prometheus(ser);
            CHECK(ser.finalize().find("live_window{") != std::string::npos);
        }

        config.config_set<uint64_t>("period", 3);
        handler = std::make_unique<TestStreamMetricsHandler>("my_handler", &config);
        {
            PrometheusSerializer ser;
            handler->window_prometheus(ser);
            CHECK(ser.finalize().find("first_window{") != std::string::npos);
        }

        {
            PrometheusSerializer ser;
            handler->window_prometheus(ser, nullptr);
            CHECK(ser.finalize().find("external_window{") != std::string::npos);
        }
    }

    SECTION("Opentelemetry window")
    {
        metrics::v1::ScopeMetrics scope;
        config.config_set<uint64_t>("period", 0);
        auto handler = std::make_unique<TestStreamMetricsHandler>("my_handler", &config);
        handler->window_opentelemetry(scope);
        CHECK(scope.metrics().at(0).name() == "live_window");
        scope.Clear();

        config.config_set<uint64_t>("period", 3);
        handler = std::make_unique<TestStreamMetricsHandler>("my_handler", &config);
        handler->window_opentelemetry(scope);
        CHECK(scope.metrics().at(0).name() == "first_window");
        scope.Clear();

        handler->window_opentelemetry(scope, nullptr);
        CHECK(scope.metrics().at(0).name() == "external_window");
        scope.Clear();
    }

    SECTION("Merge")
    {
        config.config_set<uint64_t>("period", 0);
        auto handler = std::make_unique<TestStreamMetricsHandler>("my_handler", &config);
        auto result = handler->merge(nullptr, 0, false, true);
        CHECK(dynamic_cast<HandlerBucket *>(result.get())->type == "multiple");

        result = handler->merge(nullptr, 0, true, false);
        CHECK(dynamic_cast<HandlerBucket *>(result.get())->type == "simple");
    }
}