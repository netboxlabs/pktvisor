#include "Policies.h"
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
    // Read as the test changes it, so a test can close the next window.
    const Configurable *_live_config;
    HandlerBucket _bucket;

public:
    TestHandlerMetricsManager(const Configurable *window_config)
        : AbstractMetricsManager<HandlerBucket>(window_config)
        , _config(*window_config)
        , _live_config(window_config){};
    auto current_periods() const
    {
        return _config.config_get<uint64_t>("period");
    }
    // One window has closed from two periods on, and "window_start" says which.
    std::optional<timespec> next_closed_window_start(const std::optional<timespec> &after) const
    {
        if (current_periods() < 2) {
            return std::nullopt;
        }
        timespec start{};
        if (_live_config->config_exists("window_start")) {
            start.tv_sec = static_cast<time_t>(_live_config->config_get<uint64_t>("window_start"));
        }
        if (after && after->tv_sec >= start.tv_sec) {
            return std::nullopt;
        }
        return start;
    }
    bool window_closed_opentelemetry(metrics::v1::ScopeMetrics &scope, std::optional<timespec> &last_start, Metric::LabelMap) const
    {
        auto start = next_closed_window_start(last_start);
        if (!start) {
            return false;
        }
        last_start = start;
        scope.add_metrics()->set_name("first_window");
        return true;
    }
    std::unique_ptr<AbstractMetricsBucket> closed_merge(AbstractMetricsBucket *, timespec start)
    {
        auto result = std::make_unique<HandlerBucket>();
        result->type = "closed " + std::to_string(start.tv_sec);
        return result;
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
        // One period never closes, so the live window is pushed, and not again
        // within the window length.
        config.config_set<uint64_t>("num_periods", 1);
        config.config_set<uint64_t>("period", 0);
        auto handler = std::make_unique<TestStreamMetricsHandler>("my_handler", &config);
        CHECK_FALSE(handler->closes_windows());
        handler->window_opentelemetry(scope);
        CHECK(scope.metrics().at(0).name() == "live_window");
        scope.Clear();
        handler->window_opentelemetry(scope);
        CHECK(scope.metrics().empty());

        // A closed window is pushed once, and the next one once it closes.
        config.config_set<uint64_t>("num_periods", 5);
        config.config_set<uint64_t>("period", 3);
        config.config_set<uint64_t>("window_start", 100);
        handler = std::make_unique<TestStreamMetricsHandler>("my_handler", &config);
        CHECK(handler->closes_windows());
        handler->window_opentelemetry(scope);
        CHECK(scope.metrics().at(0).name() == "first_window");
        scope.Clear();
        handler->window_opentelemetry(scope);
        CHECK(scope.metrics().empty());
        config.config_set<uint64_t>("window_start", 160);
        handler->window_opentelemetry(scope);
        CHECK(scope.metrics().at(0).name() == "first_window");
        scope.Clear();

        handler->window_opentelemetry(scope, nullptr);
        CHECK(scope.metrics().at(0).name() == "external_window");
        scope.Clear();
    }

    SECTION("Live window push interval")
    {
        std::optional<std::chrono::steady_clock::time_point> last_live;
        auto now = std::chrono::steady_clock::now();
        CHECK(StreamHandler::live_window_due(last_live, now));
        CHECK_FALSE(StreamHandler::live_window_due(last_live, now + std::chrono::seconds(59)));
        CHECK(StreamHandler::live_window_due(last_live, now + std::chrono::seconds(61)));
    }

    SECTION("Merged windows")
    {
        std::vector<timespec> last_starts;
        CHECK_FALSE(next_merged_windows({}, last_starts));

        // Merged windows go once every handler has closed a new one.
        Configurable other;
        for (auto c : {&config, &other}) {
            c->config_set<uint64_t>("num_periods", 5);
            c->config_set<uint64_t>("period", 3);
            c->config_set<uint64_t>("window_start", 100);
        }
        TestStreamMetricsHandler first("first", &config);
        TestStreamMetricsHandler second("second", &other);
        std::vector<StreamHandler *> handlers{&first, &second};
        auto next = next_merged_windows(handlers, last_starts);
        REQUIRE(next);
        REQUIRE(next->size() == 2);
        CHECK(next->at(0).tv_sec == 100);
        CHECK(next->at(1).tv_sec == 100);
        last_starts = *next;
        CHECK_FALSE(next_merged_windows(handlers, last_starts));
        config.config_set<uint64_t>("window_start", 160);
        CHECK_FALSE(next_merged_windows(handlers, last_starts));
        other.config_set<uint64_t>("window_start", 160);
        next = next_merged_windows(handlers, last_starts);
        REQUIRE(next);
        CHECK(next->at(0).tv_sec == 160);
        CHECK(next->at(1).tv_sec == 160);

        // The window merged is the one asked for.
        auto merged = first.merge_closed(nullptr, next->at(0));
        CHECK(dynamic_cast<HandlerBucket *>(merged.get())->type == "closed 160");
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