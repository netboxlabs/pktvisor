/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "AbstractManager.h"
#include "AbstractModule.h"
#include "Configurable.h"
#include "HandlerModulePlugin.h"
#include "InputModulePlugin.h"
#include "OpenTelemetry.h"
#include "Taps.h"
#include <chrono>
#include <ctime>
#include <functional>
#include <map>
#include <optional>
#include <vector>
#include <yaml-cpp/yaml.h>

namespace visor {

class CoreRegistry;
class AbstractMetricsBucket;
class PrometheusSerializer;

// The start of the window each handler merges next, or none until every handler
// has one. A handler's next window is its oldest closed one after last_starts,
// the windows it last merged; empty means none merged yet. Handlers usually
// close their windows on the same input event but can close them on different
// ones, so taking the next window rather than the newest keeps a handler that
// closed one more from being merged with the others' previous window.
std::optional<std::vector<timespec>> next_merged_windows(const std::vector<StreamHandler *> &handlers,
    const std::vector<timespec> &last_starts);

class PolicyException : public std::runtime_error
{
public:
    explicit PolicyException(const std::string &msg)
        : std::runtime_error(msg)
    {
    }
};

class Policy : public AbstractRunnableModule
{
protected:
    typedef std::map<std::unique_ptr<AbstractMetricsBucket>, StreamHandler *> BucketMap;

private:
    static constexpr size_t HANDLERS_SEQUENCE_SIZE = 1;

    std::vector<Tap *> _taps;
    std::vector<InputStream *> _input_streams;
    bool _modules_sequence{false};
    bool _merge_like_handlers{false};
    std::vector<AbstractRunnableModule *> _modules;
    // What the merged OpenTelemetry export last pushed: each handler's closed
    // window, or when a window that never closes was last pushed.
    std::vector<timespec> _otel_last_merged;
    std::optional<std::chrono::steady_clock::time_point> _otel_last_merged_live;

    BucketMap _get_merged_buckets(bool prometheus = true, uint64_t period = 0, bool merged = false);
    BucketMap _get_merged_buckets(const std::function<std::unique_ptr<AbstractMetricsBucket>(StreamHandler *, AbstractMetricsBucket *)> &merge);
    void _merged_opentelemetry(metrics::v1::ScopeMetrics &scope);

public:
    Policy(const std::string &name)
        : AbstractRunnableModule(name)
    {
    }

    std::string schema_key() const override
    {
        return "policy";
    }

    void set_modules_sequence(bool sequence)
    {
        _modules_sequence = sequence;
    }

    void add_tap(Tap *tap)
    {
        _taps.push_back(tap);
    }

    void remove_tap(const Tap *tap)
    {
        _taps.erase(std::remove(_taps.begin(), _taps.end(), tap), _taps.end());
    }

    void add_input_stream(InputStream *input_stream)
    {
        _input_streams.push_back(input_stream);
    }

    const std::vector<InputStream *> &input_stream() const
    {
        return _input_streams;
    }

    void add_module(AbstractRunnableModule *m)
    {
        _modules.push_back(m);
    }

    const std::vector<AbstractRunnableModule *> &modules()
    {
        return _modules;
    }

    size_t get_handlers_list_size() const
    {
        if (_modules_sequence) {
            return HANDLERS_SEQUENCE_SIZE;
        } else {
            return _modules.size();
        }
    }

    // life cycle
    void start() override;
    void stop() override;

    void info_json(json &j) const override;

    void json_metrics(json &j, uint64_t period, bool merge);
    void prometheus_metrics(std::stringstream &out);
    void prometheus_metrics(PrometheusSerializer &ser);
    void opentelemetry_metrics(metrics::v1::ScopeMetrics &scope);
};

class PolicyManager : public AbstractManager<Policy>
{
    mutable std::mutex _load_mutex;
    CoreRegistry *_registry;

    std::string _get_policy_name(YAML::const_iterator it);
    // once leaving_policy is off input: removes the input's resources policy if it is the only one left, then
    // the input if none is. the caller holds _map_mutex, which keeps any other removal from freeing the input
    void _remove_input_if_unused(const std::string &input_name, InputStream *input, const std::string &leaving_policy);

public:
    PolicyManager(CoreRegistry *registry)
        : _registry(registry)
    {
    }

    virtual ~PolicyManager()
    {
    }

    std::vector<Policy *> load_from_str(const std::string &str);
    std::vector<Policy *> load(const YAML::Node &tap_yaml, bool single = false);
    std::pair<std::unique_ptr<Policy>, std::string> create_resources_policy(InputStream *input, const Config &window_config);
    void remove_policy(const std::string &name);
    // Adds one scope per policy with a window to push, and returns whether any
    // policy had one, so the exporter sends nothing when none has.
    bool opentelemetry_metrics(metrics::v1::ResourceMetrics &resource);
};

}