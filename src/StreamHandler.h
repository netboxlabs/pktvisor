/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "AbstractMetricsManager.h"
#include "AbstractModule.h"
#include "CoreRegistry.h"
#include "InputEventProxy.h"
#include <ctime>
#include <fmt/ostream.h>
#include <nlohmann/json.hpp>
#include <sstream>

namespace visor {

using json = nlohmann::json;

class StreamHandlerException : public std::runtime_error
{
public:
    explicit StreamHandlerException(const std::string &msg)
        : std::runtime_error(msg)
    {
    }
};

class StreamHandler : public AbstractRunnableModule
{
protected:
    std::unique_ptr<InputEventProxy> _event_proxy;
    std::string _version{CoreRegistry::DEFAULT_HANDLER_PLUGIN_VERSION};

public:
    StreamHandler(const std::string &name)
        : AbstractRunnableModule(name)
    {
    }

    virtual ~StreamHandler(){};

    size_t consumer_count() const
    {
        if (_event_proxy) {
            return _event_proxy->consumer_count();
        }
        return 0;
    }

    void set_event_proxy(std::unique_ptr<InputEventProxy> proxy)
    {
        _event_proxy = std::move(proxy);
    }

    InputEventProxy *get_event_proxy()
    {
        return _event_proxy.get();
    }

    void set_version(const std::string &version)
    {
        _version = version;
    }

    const std::string &version() const
    {
        return _version;
    }

    virtual void window_json(json &j, uint64_t period, bool merged) = 0;
    virtual void window_json(json &j, AbstractMetricsBucket *bucket) = 0;
    virtual void window_prometheus(std::stringstream &out, Metric::LabelMap add_labels = {}) = 0;
    virtual void window_prometheus(std::stringstream &out, AbstractMetricsBucket *bucket, Metric::LabelMap add_labels = {}) = 0;
    virtual void window_opentelemetry(metrics::v1::ScopeMetrics &scope, Metric::LabelMap add_labels = {}) = 0;
    virtual void window_opentelemetry(metrics::v1::ScopeMetrics &scope, AbstractMetricsBucket *bucket, Metric::LabelMap add_labels = {}) = 0;
    virtual std::unique_ptr<AbstractMetricsBucket> merge(AbstractMetricsBucket *bucket, uint64_t period, bool prometheus, bool merged) = 0;
};

template <class MetricsManagerClass>
class StreamMetricsHandler : public StreamHandler
{
public:
    typedef std::map<std::string, MetricGroupIntType> GroupDefType;
    typedef std::vector<std::string> ConfigsDefType;

private:
    static const inline ConfigsDefType _window_config_defs = {
        "deep_sample_rate",
        "num_periods",
        "topn_count",
        "topn_percentile_threshold"};

    MetricGroupIntType _process_group(const GroupDefType &group_defs, const std::string &group)
    {
        auto it = group_defs.find(group);
        if (it == group_defs.end()) {
            std::vector<std::string> valid_groups;
            for (const auto &defs : group_defs) {
                valid_groups.push_back(defs.first);
            }
            throw StreamHandlerException(fmt::format("{} is an invalid/unsupported metric group. The valid groups are: all, {}", group, fmt::join(valid_groups, ", ")));
        }
        return it->second;
    }

protected:
    std::unique_ptr<MetricsManagerClass> _metrics;
    std::bitset<GROUP_SIZE> _groups;

    void process_groups(const GroupDefType &group_defs)
    {
        if (config_exists("disable")) {
            for (const auto &group : config_get<StringList>("disable")) {
                if (group == "all") {
                    _groups.reset();
                    break;
                }
                _groups.reset(_process_group(group_defs, group));
            }
        }
        if (config_exists("enable")) {
            for (const auto &group : config_get<StringList>("enable")) {
                if (group == "all") {
                    _groups.set();
                    break;
                }
                _groups.set(_process_group(group_defs, group));
            }
        }

        _metrics->configure_groups(&_groups);
    }

    void validate_configs(const ConfigsDefType &config_defs)
    {
        auto all_configs = get_all_keys();
        for (const auto &config : all_configs) {
            if (std::any_of(_window_config_defs.begin(), _window_config_defs.end(), [config](const auto &def) { return config == def; })) {
                continue;
            } else if (std::any_of(config_defs.begin(), config_defs.end(), [config](const auto &def) { return config == def; })) {
                continue;
            } else if (config == "enable") {
                continue;
            } else if (config == "disable") {
                continue;
            } else if (config == "_internal_tap_name") {
                continue;
            }
            throw StreamHandlerException(fmt::format("{} is an invalid/unsupported config or filter. The valid configs/filters are: {}, {}", config, fmt::join(config_defs, ", "), fmt::join(_window_config_defs, ", ")));
        }
    }

    void common_info_json(json &j) const
    {
        AbstractRunnableModule::common_info_json(j);

        j["metrics"]["deep_sample_rate"] = _metrics->deep_sample_rate();
        j["metrics"]["periods_configured"] = _metrics->num_periods();

        j["metrics"]["periods"] = json::array();
        for (auto i = 0UL; i < _metrics->current_periods(); ++i) {
            {
                std::stringstream ssts;
                time_t b_time_t = _metrics->bucket(i)->start_tstamp().tv_sec;
#if defined(_MSC_VER)
                struct tm *bt;
                bt = gmtime(&b_time_t);
                ssts << std::put_time(bt, "%Y-%m-%d %X");
#else
                std::tm bt{};
                gmtime_r(&b_time_t, &bt);
                ssts << std::put_time(&bt, "%Y-%m-%d %X");
#endif
                j["metrics"]["periods"][i]["start_tstamp"] = ssts.str();
            }
            if (_metrics->bucket(i)->read_only()) {
                std::stringstream ssts;
                time_t b_time_t = _metrics->bucket(i)->end_tstamp().tv_sec;
#if defined(_MSC_VER)
                struct tm *bt;
                bt = gmtime(&b_time_t);
                ssts << std::put_time(bt, "%Y-%m-%d %X");
#else
                std::tm bt{};
                gmtime_r(&b_time_t, &bt);
                ssts << std::put_time(&bt, "%Y-%m-%d %X");
#endif
                j["metrics"]["periods"][i]["end_tstamp"] = ssts.str();
            }
            j["metrics"]["periods"][i]["read_only"] = _metrics->bucket(i)->read_only();
            j["metrics"]["periods"][i]["length"] = _metrics->bucket(i)->period_length();
            auto [num_events, num_samples, event_rate, event_lock] = _metrics->bucket(i)->event_data_locked();
            num_events->to_json(j["metrics"]["periods"][i]["events"]);
            num_samples->to_json(j["metrics"]["periods"][i]["events"]);
            event_rate->to_json(j["metrics"]["periods"][i]["events"]["rates"], !_metrics->bucket(i)->read_only());
        }
    }

public:
    StreamMetricsHandler(const std::string &name, const Configurable *window_config)
        : StreamHandler(name)
    {
        _metrics = std::make_unique<MetricsManagerClass>(window_config);
    }

    const MetricsManagerClass *metrics() const
    {
        return _metrics.get();
    }

    void window_json(json &j, uint64_t period, bool merged) override
    {
        if (merged) {
            _metrics->window_merged_json(j, schema_key(), period);
        } else {
            _metrics->window_single_json(j, schema_key(), period);
        }
    }

    void window_json(json &j, AbstractMetricsBucket *bucket) override
    {
        _metrics->window_external_json(j, schema_key(), bucket);
    }

    void window_prometheus(std::stringstream &out, Metric::LabelMap add_labels = {}) override
    {
        if (_metrics->current_periods() > 1) {
            _metrics->window_single_prometheus(out, 1, add_labels);
        } else {
            _metrics->window_single_prometheus(out, 0, add_labels);
        }
    }

    void window_prometheus(std::stringstream &out, AbstractMetricsBucket *bucket, Metric::LabelMap add_labels = {}) override
    {
        _metrics->window_external_prometheus(out, bucket, add_labels);
    };

    void window_opentelemetry(metrics::v1::ScopeMetrics &scope, Metric::LabelMap add_labels = {}) override
    {
        if (_metrics->current_periods() > 1) {
            _metrics->window_single_opentelemetry(scope, 1, add_labels);
        } else {
            _metrics->window_single_opentelemetry(scope, 0, add_labels);
        }
    }

    void window_opentelemetry(metrics::v1::ScopeMetrics &scope, AbstractMetricsBucket *bucket, Metric::LabelMap add_labels = {}) override
    {
        _metrics->window_external_opentelemetry(scope, bucket, add_labels);
    };

    void check_period_shift(timespec stamp)
    {
        _metrics->check_period_shift(stamp);
    }

    std::unique_ptr<AbstractMetricsBucket> merge(AbstractMetricsBucket *bucket, uint64_t period, bool prometheus, bool merged) override
    {
        if (prometheus) {
            (_metrics->current_periods() > 1) ? period = 1 : period = 0;
            merged = false;
        }
        if (merged) {
            return _metrics->multiple_merge(bucket, period);
        }
        return _metrics->simple_merge(bucket, period);
    }

    virtual ~StreamMetricsHandler(){};
};

}
