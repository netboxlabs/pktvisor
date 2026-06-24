/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "Metrics.h"
#include "PrometheusSerializer.h"
#include <cpc_union.hpp>

namespace visor {

void Counter::to_json(json &j) const
{
    name_json_assign(j, _value);
}

void Counter::to_prometheus(PrometheusSerializer &ser, Metric::LabelMap add_labels) const
{
    ser.write(base_name_snake(), PrometheusSerializer::Type::Gauge, _desc, {}, add_labels, _value);
}

void Counter::to_opentelemetry(metrics::v1::ScopeMetrics &scope, timespec &start, timespec &end, Metric::LabelMap add_labels) const
{
    auto metric = scope.add_metrics();
    metric->set_name(base_name_snake());
    metric->set_description(_desc);
    auto gauge_data_point = metric->mutable_gauge()->add_data_points();
    gauge_data_point->set_as_int(_value);
    gauge_data_point->set_start_time_unix_nano(timespec_to_uint64(start));
    gauge_data_point->set_time_unix_nano(timespec_to_uint64(end));
    for (const auto &label: add_labels) {
        auto attribute = gauge_data_point->add_attributes();
        attribute->set_key(label.first);
        attribute->mutable_value()->set_string_value(label.second);
    }
}

void Rate::to_json(json &j, bool include_live) const
{
    to_json(j);
    if (include_live) {
        name_json_assign(j, {"live"}, rate());
    }
}

void Rate::to_json(visor::json &j) const
{
    std::shared_lock lock(_sketch_mutex);
    _quantile.to_json(j);
}

void Rate::to_prometheus(PrometheusSerializer &ser, Metric::LabelMap add_labels) const
{
    std::shared_lock lock(_sketch_mutex);
    _quantile.to_prometheus(ser, add_labels);
}

void Rate::to_opentelemetry(metrics::v1::ScopeMetrics &scope, timespec &start, timespec &end, Metric::LabelMap add_labels) const
{
    std::shared_lock lock(_sketch_mutex);
    _quantile.to_opentelemetry(scope, start, end, add_labels);
}

void Cardinality::merge(const Cardinality &other)
{
    datasketches::cpc_union merge_set;
    merge_set.update(_set);
    merge_set.update(other._set);
    _set = merge_set.get_result();
}
void Cardinality::to_json(json &j) const
{
    name_json_assign(j, lround(_set.get_estimate()));
}
void Cardinality::to_prometheus(PrometheusSerializer &ser, Metric::LabelMap add_labels) const
{
    ser.write(base_name_snake(), PrometheusSerializer::Type::Gauge, _desc, {}, add_labels, lround(_set.get_estimate()));
}

void Cardinality::to_opentelemetry(metrics::v1::ScopeMetrics &scope, timespec &start, timespec &end, Metric::LabelMap add_labels) const
{
    auto metric = scope.add_metrics();
    metric->set_name(base_name_snake());
    metric->set_description(_desc);
    auto gauge_data_point = metric->mutable_gauge()->add_data_points();
    gauge_data_point->set_as_int(lround(_set.get_estimate()));
    gauge_data_point->set_start_time_unix_nano(timespec_to_uint64(start));
    gauge_data_point->set_time_unix_nano(timespec_to_uint64(end));
    for (const auto &label: add_labels) {
        auto attribute = gauge_data_point->add_attributes();
        attribute->set_key(label.first);
        attribute->mutable_value()->set_string_value(label.second);
    }
}

LabelMap &prometheus_static_labels_mutable()
{
    static LabelMap labels;
    return labels;
}

void Metric::name_json_assign(json &j, const json &val) const
{
    json *j_part = &j;
    for (const auto &s_part : _name) {
        j_part = &(*j_part)[s_part];
    }
    (*j_part) = val;
}
void Metric::name_json_assign(json &j, std::initializer_list<std::string> add_names, const json &val) const
{
    json *j_part = &j;
    for (const auto &s_part : _name) {
        j_part = &(*j_part)[s_part];
    }
    for (const auto &s_part : add_names) {
        j_part = &(*j_part)[s_part];
    }
    (*j_part) = val;
}
std::string Metric::base_name_snake() const
{
    auto snake = [](const std::string &ss, const std::string &s) {
        return ss.empty() ? s : ss + "_" + s;
    };
    std::string name_text = _schema_key + "_" + std::accumulate(std::begin(_name), std::end(_name), std::string(), snake);
    return name_text;
}

}