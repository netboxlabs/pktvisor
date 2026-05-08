/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "AbstractMetricsManager.h"
#include "MockInputStream.h"
#include "StreamHandler.h"
#include <limits>
#include <spdlog/spdlog.h>
#include <string>

namespace visor::handler::mock {

using namespace visor::input::mock;

class MockMetricsBucket final : public visor::AbstractMetricsBucket
{

protected:
    mutable std::shared_mutex _mutex;

    // total numPackets is tracked in base class num_events
    struct counters {

        Counter mock_counter;

        counters()
            : mock_counter("mock", {"counter"}, "Count of random ints from mock input source")
        {
        }
    };
    counters _counters;

public:
    MockMetricsBucket()
    {
    }

    // get a copy of the counters
    counters counters() const
    {
        std::shared_lock lock(_mutex);
        return _counters;
    }

    // visor::AbstractMetricsBucket
    void specialized_merge(const AbstractMetricsBucket &other, Metric::Aggregate agg_operator) override;
    void to_json(json &j) const override;
    void to_prometheus(std::stringstream &out, Metric::LabelMap add_labels = {}) const override;
    void to_opentelemetry(metrics::v1::ScopeMetrics &scope, timespec &start_ts, timespec &end_ts, Metric::LabelMap add_labels = {}) const override;
    void update_topn_metrics(size_t, uint64_t) override
    {
    }

    void process_random_int(uint64_t i);
};

class MockMetricsManager final : public visor::AbstractMetricsManager<MockMetricsBucket>
{
public:
    MockMetricsManager(const Configurable *window_config)
        : visor::AbstractMetricsManager<MockMetricsBucket>(window_config)
    {
    }

    void process_random_int(uint64_t i);
};

class MockStreamHandler final : public visor::StreamMetricsHandler<MockMetricsManager>
{

    MockInputEventProxy *_mock_proxy;
    std::shared_ptr<spdlog::logger> _logger;

    sigslot::connection _random_int_connection;

    void process_random_int(uint64_t i);

public:
    MockStreamHandler(const std::string &name, InputEventProxy *proxy, const Configurable *window_config);
    ~MockStreamHandler();

    // visor::AbstractModule
    std::string schema_key() const override
    {
        return "mock";
    }

    void start() override;
    void stop() override;
};

}
