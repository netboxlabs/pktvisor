/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
#include <exception>
#include <nlohmann/json.hpp>
#include "Configurable.h"
#include "Metrics.h"
#include <bitset>
#include <shared_mutex>
#include <sstream>
#include <unordered_map>

namespace visor {

constexpr size_t GROUP_SIZE = 64;
typedef uint32_t MetricGroupIntType;

using json = nlohmann::json;

class PeriodException : public std::runtime_error
{
public:
    PeriodException(const char *msg)
        : std::runtime_error(msg)
    {
    }
    PeriodException(const std::string &msg)
        : std::runtime_error(msg)
    {
    }
};

using namespace std::chrono;

/**
 * This class should be specialized to contain metrics and sketches specific to this handler
 * It *MUST* be thread safe, and should expect mostly writes.
 */
class AbstractMetricsBucket
{
private:
    mutable std::shared_mutex _base_mutex;
    Counter _num_samples;
    Counter _num_events;

    Rate _rate_events;

    timespec _start_tstamp;
    timespec _end_tstamp;
    unsigned int _period_length = 0;
    bool _read_only = false;
    bool _recorded_stream = false;

protected:
    const std::bitset<GROUP_SIZE> *_groups{nullptr};

    // merge the metrics of the specialized metric bucket
    virtual void specialized_merge(const AbstractMetricsBucket &other, Metric::Aggregate agg_operator) = 0;

    // should be thread safe
    // can be used to set any bucket metrics to read only, e.g. cancel Rate metrics
    virtual void on_set_read_only(){};

public:
    AbstractMetricsBucket()
        : _num_samples("base", {"deep_samples"}, "Total number of deep samples")
        , _num_events("base", {"total"}, "Total number of events")
        , _rate_events("base", {"event_rate"}, "Rate of events")
        , _start_tstamp{0, 0}
        , _end_tstamp{0, 0}
    {
        timespec_get(&_start_tstamp, TIME_UTC);
    }

    virtual ~AbstractMetricsBucket() = default;

    timespec start_tstamp() const
    {
        std::shared_lock r_lock(_base_mutex);
        return _start_tstamp;
    }

    timespec end_tstamp() const
    {
        std::shared_lock r_lock(_base_mutex);
        return _end_tstamp;
    }

    unsigned int period_length() const
    {
        std::shared_lock r_lock(_base_mutex);
        if (_read_only || _recorded_stream) {
            return _period_length;
        }
        timespec now;
        timespec_get(&now, TIME_UTC);
        return now.tv_sec - _start_tstamp.tv_sec;
    }

    void set_start_tstamp(timespec stamp)
    {
        std::unique_lock w_lock(_base_mutex);
        _start_tstamp = stamp;
    }

    bool read_only() const
    {
        std::shared_lock r_lock(_base_mutex);
        return _read_only;
    }

    void set_read_only(timespec stamp)
    {
        {
            std::unique_lock w_lock(_base_mutex);
            _end_tstamp = stamp;
            _period_length = _end_tstamp.tv_sec - _start_tstamp.tv_sec;
            _read_only = true;
        }
        _rate_events.cancel();
        on_set_read_only();
    }

    bool recorded_stream() const
    {
        std::shared_lock r_lock(_base_mutex);
        return _recorded_stream;
    }

    void set_recorded_stream()
    {
        std::unique_lock w_lock(_base_mutex);
        _recorded_stream = true;
    }

    void set_event_rate_info(std::string schema_key, std::initializer_list<std::string> names, const std::string &desc)
    {
        _rate_events.set_info(schema_key, names, desc);
    }

    void set_num_sample_info(std::string schema_key, std::initializer_list<std::string> names, const std::string &desc)
    {
        _num_samples.set_info(schema_key, names, desc);
    }

    void set_num_events_info(std::string schema_key, std::initializer_list<std::string> names, const std::string &desc)
    {
        _num_events.set_info(schema_key, names, desc);
    }

    auto event_data_locked() const
    {
        struct eventData {
            const Counter *num_events;
            const Counter *num_samples;
            const Rate *event_rate;
            std::shared_lock<std::shared_mutex> r_lock;
        };
        std::shared_lock lock(_base_mutex);
        return eventData{&_num_events, &_num_samples, &_rate_events, std::move(lock)};
    }

    void merge(const AbstractMetricsBucket &other, Metric::Aggregate agg_operator = Metric::Aggregate::DEFAULT)
    {
        {
            std::shared_lock r_lock(other._base_mutex);
            std::unique_lock w_lock(_base_mutex);
            _num_events += other._num_events;
            _num_samples += other._num_samples;
            _period_length += other.period_length();
            if (other._start_tstamp.tv_sec < _start_tstamp.tv_sec) {
                _start_tstamp.tv_sec = other._start_tstamp.tv_sec;
            }
            if (other._end_tstamp.tv_sec > _end_tstamp.tv_sec) {
                _end_tstamp.tv_sec = other._end_tstamp.tv_sec;
            }
            _rate_events.merge(other._rate_events, agg_operator);
            _groups = other._groups;
        }
        specialized_merge(other, agg_operator);
    }

    void new_event(bool deep)
    {
        // note, currently not enforcing _read_only
        ++_rate_events;
        std::unique_lock lock(_base_mutex);
        ++_num_events;
        if (deep) {
            ++_num_samples;
        }
    }

    void configure_groups(const std::bitset<GROUP_SIZE> *groups)
    {
        std::unique_lock lock(_base_mutex);
        _groups = groups;
    }

    inline bool group_enabled(MetricGroupIntType g) const
    {
        return (*_groups)[g];
    }

    virtual void to_json(json &j) const = 0;
    virtual void to_prometheus(std::stringstream &out, Metric::LabelMap add_labels = {}) const = 0;
    virtual void to_opentelemetry(metrics::v1::ScopeMetrics &scope, timespec &start_ts, timespec &end_ts, Metric::LabelMap add_labels = {}) const = 0;
    virtual void update_topn_metrics(size_t topn_count, uint64_t percentile_threshold) = 0;
};

// Fixed-seed PRNG for the deep-sampling gate (SplitMix64, public domain). Seed only from a fixed
// constant, never from std::random_device or hardware entropy: RDRAND-based seeding faults and
// throws on some hardware, and cryptographic randomness isn't needed to decide which events get
// sampled.
struct splitmix64 {
    uint64_t state{0x9e3779b97f4a7c15ULL};
    uint64_t operator()()
    {
        uint64_t z = (state += 0x9e3779b97f4a7c15ULL);
        z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
        z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
        return z ^ (z >> 31);
    }
};

template <typename MetricsBucketClass>
class AbstractMetricsManager
{
    static_assert(std::is_base_of<AbstractMetricsBucket, MetricsBucketClass>::value, "MetricsBucketClass must inherit from AbstractMetricsBucket");

private:
    // this protects changes to the bucket container, _not_ changes to the bucket itself
    mutable std::shared_mutex _bucket_mutex;
    std::deque<std::unique_ptr<MetricsBucketClass>> _metric_buckets;
    std::string _tap_name;
    mutable std::shared_mutex _base_mutex;

    /**
     * the total number of periods we will maintain in the window
     */
    unsigned int _num_periods{5};

    /**
     * sampling
     */
    splitmix64 _rng; // fixed-seeded; never seed from entropy (see note above)
    uint32_t _deep_sample_rate{100};
    size_t _topn_count{10};
    uint64_t _topn_percentile_threshold{0};

protected:
    std::atomic_bool _deep_sampling_now; // atomic so we can reference without mutex

    /**
     * indicates if the stream we are processing was pre recorded, not live
     */
    bool _recorded_stream = false;

    const std::bitset<GROUP_SIZE> *_groups{nullptr};

private:
    /**
     * window maintenance
     */
    timespec _last_shift_tstamp;
    timespec _next_shift_tstamp;

    /**
     * simple cache for json results
     */
    mutable std::unordered_map<unsigned int, std::pair<std::chrono::high_resolution_clock::time_point, json>> _mergeResultCache;

    /**
     * manage the time window
     * @param stamp time stamp of the event
     */
    void _period_shift(timespec stamp)
    {
        // ensure access to the buckets is locked while we period shift
        std::unique_lock wl(_bucket_mutex);
        std::unique_ptr<MetricsBucketClass> expiring_bucket;
        // this changes the live bucket
        _metric_buckets.emplace_front(std::make_unique<MetricsBucketClass>());
        _metric_buckets[0]->configure_groups(_groups);
        _metric_buckets[0]->set_start_tstamp(stamp);
        _metric_buckets[0]->update_topn_metrics(_topn_count, _topn_percentile_threshold);
        if (_recorded_stream) {
            _metric_buckets[0]->set_recorded_stream();
        }
        // notify second most recent bucket that it is now read only, save end time
        _metric_buckets[1]->set_read_only(stamp);
        // if we're at our period history length max, pop the oldest
        if (_metric_buckets.size() > _num_periods) {
            // before popping, take ownership of the bucket we are expiring so that it can be examined by the period shift callback handler
            expiring_bucket = std::move(_metric_buckets.back());
            _metric_buckets.pop_back();
        }
        // unlock bucket lock as fast as possible, in particular before period shift callback
        wl.unlock();
        std::unique_lock wlb(_base_mutex);
        _last_shift_tstamp.tv_sec = stamp.tv_sec;
        _next_shift_tstamp.tv_sec = stamp.tv_sec + AbstractMetricsManager::PERIOD_SEC;
        wlb.unlock();
        on_period_shift(stamp, (expiring_bucket) ? expiring_bucket.get() : nullptr);
        // expiring bucket will destruct here if it exists
    }

public:
    static const unsigned int PERIOD_SEC = 60;
    static const unsigned int MERGE_CACHE_TTL_MS = 1000;

protected:
    /**
     * the "base" event method that should be called on every event before specialized event functionality. sampling will be
     * (optionally) chosen, and the time window will be maintained
     *
     * @param stamp time stamp of the event
     */
    void new_event(timespec stamp, bool sample = true)
    {
        // CRITICAL EVENT PATH
        if (sample && _deep_sample_rate != 100) {
            _deep_sampling_now.store((_rng() % 100U < _deep_sample_rate), std::memory_order_relaxed);
        }
        std::shared_lock rlb(_base_mutex);
        bool will_shift = _num_periods > 1 && stamp.tv_sec >= _next_shift_tstamp.tv_sec;
        rlb.unlock();
        if (will_shift) {
            _period_shift(stamp);
        }
        std::shared_lock rl(_bucket_mutex);
        // bucket base event
        _metric_buckets[0]->new_event(_deep_sampling_now);
    }

    inline bool group_enabled(MetricGroupIntType g) const
    {
        return (*_groups)[g];
    }

    /**
     * call back when the time window period shift
     *
     * @param stamp if the base event included a time stamp, it will be passed along here, otherwise "now"
     * @param expiring_bucket pointer to bucket that is expiring, or nullptr if there was none (since shift may occur that does not expire a bucket)
     */
    virtual void on_period_shift([[maybe_unused]] timespec stamp, [[maybe_unused]] const MetricsBucketClass *maybe_expiring_bucket)
    {
    }

public:
    AbstractMetricsManager(const Configurable *window_config)
        : _metric_buckets{}
        , _deep_sampling_now{true}
        , _last_shift_tstamp{0, 0}
        , _next_shift_tstamp{0, 0}
    {
        if (window_config->config_exists("deep_sample_rate")) {
            _deep_sample_rate = window_config->config_get<uint64_t>("deep_sample_rate");
        }
        if (_deep_sample_rate > 100) {
            _deep_sample_rate = 100;
        }
        if (_deep_sample_rate < 1) {
            _deep_sample_rate = 1;
        }

        if (window_config->config_exists("_internal_tap_name")) {
            _tap_name = window_config->config_get<std::string>("_internal_tap_name");
        }

        if (window_config->config_exists("num_periods")) {
            _num_periods = window_config->config_get<uint64_t>("num_periods");
        }
        _num_periods = std::min(_num_periods, 10U);
        _num_periods = std::max(_num_periods, 1U);
        timespec_get(&_last_shift_tstamp, TIME_UTC);
        _next_shift_tstamp = _last_shift_tstamp;
        _next_shift_tstamp.tv_sec += AbstractMetricsManager::PERIOD_SEC;

        if (window_config->config_exists("topn_count")) {
            _topn_count = window_config->config_get<uint64_t>("topn_count");
        }
        if (window_config->config_exists("topn_percentile_threshold")) {
            _topn_percentile_threshold = window_config->config_get<uint64_t>("topn_percentile_threshold");
        }

        _metric_buckets.emplace_front(std::make_unique<MetricsBucketClass>());
        _metric_buckets[0]->update_topn_metrics(_topn_count, _topn_percentile_threshold);
    }

    virtual ~AbstractMetricsManager() = default;

    unsigned int num_periods() const
    {
        std::shared_lock rl(_base_mutex);
        return _num_periods;
    }

    auto current_periods() const
    {
        std::shared_lock rl(_bucket_mutex);
        return _metric_buckets.size();
    }

    unsigned int deep_sample_rate() const
    {
        std::shared_lock rl(_base_mutex);
        return _deep_sample_rate;
    }

    auto start_tstamp() const
    {
        std::shared_lock rl(_bucket_mutex);
        return _metric_buckets.front()->start_tstamp();
    }

    auto end_tstamp() const
    {
        std::shared_lock rl(_bucket_mutex);
        return _metric_buckets.back()->end_tstamp();
    }

    void set_start_tstamp(timespec stamp)
    {
        std::unique_lock wl(_base_mutex);
        _last_shift_tstamp = stamp;
        _next_shift_tstamp.tv_sec = stamp.tv_sec + AbstractMetricsManager::PERIOD_SEC;
        wl.unlock();
        std::shared_lock rl(_bucket_mutex);
        _metric_buckets.front()->set_start_tstamp(stamp);
    }

    void set_end_tstamp(timespec stamp)
    {
        std::shared_lock rl(_bucket_mutex);
        _metric_buckets.front()->set_read_only(stamp);
    }

    void set_recorded_stream()
    {
        std::unique_lock wl(_base_mutex);
        std::shared_lock rl(_bucket_mutex);
        _recorded_stream = true;
        _metric_buckets.front()->set_recorded_stream();
    }

    const MetricsBucketClass *bucket(uint64_t period) const
    {
        std::shared_lock rl(_bucket_mutex);
        // bounds checked
        return _metric_buckets.at(period).get();
    }

    void configure_groups(const std::bitset<GROUP_SIZE> *groups)
    {
        std::unique_lock wl(_base_mutex);
        std::shared_lock rl(_bucket_mutex);
        _groups = groups;
        _metric_buckets.front()->configure_groups(groups);
    }

    void check_period_shift(timespec stamp)
    {
        std::shared_lock rlb(_base_mutex);
        bool will_shift = _num_periods > 1 && stamp.tv_sec >= _next_shift_tstamp.tv_sec;
        rlb.unlock();
        if (will_shift) {
            _period_shift(stamp);
        }
    }

    MetricsBucketClass *live_bucket()
    {
        // CRITICAL PATH
        std::shared_lock rl(_bucket_mutex);
        // NOT bounds checked
        return _metric_buckets[0].get();
    }

    void window_single_json(json &j, const std::string &key, uint64_t period = 0) const
    {
        std::shared_lock rl(_base_mutex);
        std::shared_lock rbl(_bucket_mutex);

        if (period >= _num_periods) {
            std::stringstream err;
            err << "invalid metrics period, specify [0, " << _num_periods - 1 << "]";
            throw PeriodException(err.str());
        }
        if (period >= _metric_buckets.size()) {
            std::stringstream err;
            err << "requested metrics period has not yet accumulated, current range is [0, " << _metric_buckets.size() - 1 << "]";
            throw PeriodException(err.str());
        }

        if (_groups && _groups->none()) {
            return;
        }

        j[key]["period"]["start_ts"] = _metric_buckets.at(period)->start_tstamp().tv_sec;
        j[key]["period"]["length"] = _metric_buckets.at(period)->period_length();

        _metric_buckets.at(period)->to_json(j[key]);
    }

    void window_single_prometheus(std::stringstream &out, uint64_t period = 0, Metric::LabelMap add_labels = {}) const
    {
        std::shared_lock rl(_base_mutex);
        std::shared_lock rbl(_bucket_mutex);

        if (period >= _num_periods) {
            std::stringstream err;
            err << "invalid metrics period, specify [0, " << _num_periods - 1 << "]";
            throw PeriodException(err.str());
        }
        if (period >= _metric_buckets.size()) {
            std::stringstream err;
            err << "requested metrics period has not yet accumulated, current range is [0, " << _metric_buckets.size() - 1 << "]";
            throw PeriodException(err.str());
        }

        if (_groups && _groups->none()) {
            return;
        }

        if (!_tap_name.empty() && add_labels.find("tap") == add_labels.end()) {
            add_labels["tap"] = _tap_name;
        }

        _metric_buckets.at(period)->to_prometheus(out, add_labels);
    }

    void window_single_opentelemetry(metrics::v1::ScopeMetrics &scope, uint64_t period = 0, Metric::LabelMap add_labels = {}) const
    {
        std::shared_lock rl(_base_mutex);
        std::shared_lock rbl(_bucket_mutex);

        if (period >= _num_periods) {
            std::stringstream err;
            err << "invalid metrics period, specify [0, " << _num_periods - 1 << "]";
            throw PeriodException(err.str());
        }
        if (period >= _metric_buckets.size()) {
            std::stringstream err;
            err << "requested metrics period has not yet accumulated, current range is [0, " << _metric_buckets.size() - 1 << "]";
            throw PeriodException(err.str());
        }

        if (_groups && _groups->none()) {
            return;
        }

        if (!_tap_name.empty() && add_labels.find("tap") == add_labels.end()) {
            add_labels["tap"] = _tap_name;
        }
        auto bucket = _metric_buckets.at(period).get();
        auto start_ts = bucket->start_tstamp();
        auto end_ts = bucket->end_tstamp();
        if (!end_ts.tv_sec) {
            timespec_get(&end_ts, TIME_UTC);
        }
        bucket->to_opentelemetry(scope, start_ts, end_ts, add_labels);
    }

    void window_external_opentelemetry(metrics::v1::ScopeMetrics &scope, AbstractMetricsBucket *bucket, Metric::LabelMap add_labels = {}) const
    {
        if (_groups && _groups->none()) {
            return;
        }
        // static because caller guarantees only our own bucket type
        auto sbucket = static_cast<MetricsBucketClass *>(bucket);
        auto start_ts = sbucket->start_tstamp();
        auto end_ts = sbucket->end_tstamp();
        if (!end_ts.tv_sec) {
            timespec_get(&end_ts, TIME_UTC);
        }
        sbucket->to_opentelemetry(scope, start_ts, end_ts, add_labels);
    }

    void window_external_prometheus(std::stringstream &out, AbstractMetricsBucket *bucket, Metric::LabelMap add_labels = {}) const
    {
        if (_groups && _groups->none()) {
            return;
        }
        // static because caller guarantees only our own bucket type
        static_cast<MetricsBucketClass *>(bucket)->to_prometheus(out, add_labels);
    }

    void window_external_json(json &j, const std::string &key, AbstractMetricsBucket *bucket) const
    {
        if (_groups && _groups->none()) {
            return;
        }
        // static because caller guarantees only our own bucket type
        auto custom = static_cast<MetricsBucketClass *>(bucket);
        j[key]["period"]["start_ts"] = custom->start_tstamp().tv_sec;
        j[key]["period"]["length"] = custom->period_length();
        custom->to_json(j[key]);
    }

    void window_merged_json(json &j, const std::string &key, uint64_t period) const
    {
        std::shared_lock rl(_base_mutex);
        std::shared_lock rbl(_bucket_mutex);

        if (period <= 1 || period > _num_periods) {
            std::stringstream err;
            err << "invalid metrics period, specify [2, " << _num_periods << "]";
            throw PeriodException(err.str());
        }

        if (_groups && _groups->none()) {
            return;
        }

        auto cached = _mergeResultCache.find(period);
        if (cached != _mergeResultCache.end()) {
            // cached results, make sure still valid
            auto t_diff = std::chrono::high_resolution_clock::now() - cached->second.first;
            if (std::chrono::duration_cast<std::chrono::milliseconds>(t_diff).count() < MERGE_CACHE_TTL_MS) {
                j = cached->second.second;
            } else {
                // expire
                _mergeResultCache.erase(period);
            }
        }

        MetricsBucketClass merged;
        if (_recorded_stream) {
            merged.set_recorded_stream();
        }

        auto p = period;
        for (auto &m : _metric_buckets) {
            if (p-- == 0) {
                break;
            }
            merged.merge(*m);
        }

        j[key]["period"]["start_ts"] = merged.start_tstamp().tv_sec;
        j[key]["period"]["length"] = merged.period_length();

        merged.to_json(j[key]);

        _mergeResultCache[period] = std::make_pair(std::chrono::high_resolution_clock::now(), j);
    }

    std::unique_ptr<AbstractMetricsBucket> simple_merge(AbstractMetricsBucket *bucket, uint64_t period)
    {
        std::shared_lock rl(_base_mutex);
        std::shared_lock rbl(_bucket_mutex);

        if (period >= _num_periods) {
            std::stringstream err;
            err << "invalid metrics period, specify [0, " << _num_periods - 1 << "]";
            throw PeriodException(err.str());
        }
        if (period >= _metric_buckets.size()) {
            std::stringstream err;
            err << "requested metrics period has not yet accumulated, current range is [0, " << _metric_buckets.size() - 1 << "]";
            throw PeriodException(err.str());
        }

        if (auto merged = dynamic_cast<MetricsBucketClass *>(bucket); merged) {
            merged->merge(*_metric_buckets[period].get(), Metric::Aggregate::SUM);
            return nullptr;
        }

        auto merged = std::make_unique<MetricsBucketClass>();
        merged->merge(*_metric_buckets[period].get());

        return merged;
    }

    std::unique_ptr<AbstractMetricsBucket> multiple_merge(AbstractMetricsBucket *bucket, uint64_t period)
    {
        std::shared_lock rl(_base_mutex);
        std::shared_lock rbl(_bucket_mutex);

        if (period <= 1 || period > _num_periods) {
            std::stringstream err;
            err << "invalid metrics period, specify [2, " << _num_periods << "]";
            throw PeriodException(err.str());
        }

        auto merged = std::make_unique<MetricsBucketClass>();
        if (_recorded_stream) {
            merged->set_recorded_stream();
        }

        auto p = period;
        for (auto &m : _metric_buckets) {
            if (p-- == 0) {
                break;
            }
            merged->merge(*m);
        }

        if (auto external_bucket = dynamic_cast<MetricsBucketClass *>(bucket); external_bucket) {
            external_bucket->merge(*merged.get(), Metric::Aggregate::SUM);
            return nullptr;
        }

        return merged;
    }
};

}
