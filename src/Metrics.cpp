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
    add_label_attributes(gauge_data_point, add_labels);
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
    add_label_attributes(gauge_data_point, add_labels);
}

LabelMap &prometheus_static_labels_mutable()
{
    static LabelMap labels;
    return labels;
}

// Length of the well-formed UTF-8 sequence that starts at value[i], or 0 when
// none does. Follows Unicode Table 3-7, so overlong forms, surrogates and code
// points above U+10FFFF are rejected, as Go and protobuf decoders reject them.
static size_t utf8_sequence_length(std::string_view value, size_t i)
{
    const auto lead = static_cast<unsigned char>(value[i]);
    if (lead < 0x80) {
        return 1;
    }
    size_t len;
    unsigned char lo = 0x80, hi = 0xBF;
    if (lead >= 0xC2 && lead <= 0xDF) {
        len = 2;
    } else if (lead >= 0xE0 && lead <= 0xEF) {
        len = 3;
        lo = lead == 0xE0 ? 0xA0 : 0x80;
        hi = lead == 0xED ? 0x9F : 0xBF;
    } else if (lead >= 0xF0 && lead <= 0xF4) {
        len = 4;
        lo = lead == 0xF0 ? 0x90 : 0x80;
        hi = lead == 0xF4 ? 0x8F : 0xBF;
    } else {
        return 0;
    }
    if (value.size() - i < len) {
        return 0;
    }
    const auto second = static_cast<unsigned char>(value[i + 1]);
    if (second < lo || second > hi) {
        return 0;
    }
    for (size_t k = 2; k < len; ++k) {
        const auto next = static_cast<unsigned char>(value[i + k]);
        if (next < 0x80 || next > 0xBF) {
            return 0;
        }
    }
    return len;
}

// True when value[i] is a backslash followed by three ASCII digits, which would
// read as an escaped byte unless it is escaped itself.
static bool backslash_before_digits(std::string_view value, size_t i)
{
    auto digit = [&](size_t k) { return value[k] >= '0' && value[k] <= '9'; };
    return value[i] == '\\' && value.size() - i > 3 && digit(i + 1) && digit(i + 2) && digit(i + 3);
}

bool is_utf8(std::string_view value)
{
    for (size_t i = 0; i < value.size();) {
        const auto len = utf8_sequence_length(value, i);
        if (!len) {
            return false;
        }
        i += len;
    }
    return true;
}

bool label_value_needs_escape(std::string_view value)
{
    for (size_t i = 0; i < value.size();) {
        const auto len = utf8_sequence_length(value, i);
        if (!len || backslash_before_digits(value, i)) {
            return true;
        }
        i += len;
    }
    return false;
}

std::string utf8_label_value(std::string_view value)
{
    if (!label_value_needs_escape(value)) {
        return std::string(value);
    }
    std::string out;
    out.reserve(value.size());
    for (size_t i = 0; i < value.size();) {
        if (backslash_before_digits(value, i)) {
            out.append("\\092");
            ++i;
        } else if (const auto len = utf8_sequence_length(value, i)) {
            out.append(value.substr(i, len));
            i += len;
        } else {
            fmt::format_to(std::back_inserter(out), "\\{:03d}", static_cast<unsigned char>(value[i]));
            ++i;
        }
    }
    return out;
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