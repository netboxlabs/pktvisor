/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */
#pragma once

#include "MetricLabels.h"
#include <fmt/format.h>
#include <iterator>
#include <map>
#include <sstream>
#include <string>
#include <type_traits>
#include <vector>

namespace visor {

class PrometheusSerializer
{
public:
    enum class Type { Gauge, Counter, Histogram, Summary };

    template <typename V>
    void write(const std::string &base, Type type, const std::string &help,
        std::initializer_list<std::string> suffix, const LabelMap &labels, V value)
    {
        auto it = _families.find(base);
        if (it == _families.end()) {
            _order.push_back(base);
            it = _families.emplace(base, Family{type, help, {}}).first;
        }
        std::string line = base;
        for (const auto &s : suffix) {
            line.push_back('_');
            line.append(s);
        }
        append_labels(line, labels);
        line.push_back(' ');
        if constexpr (std::is_floating_point_v<V>) {
            std::ostringstream oss;
            oss << value;
            line.append(oss.str());
        } else {
            fmt::format_to(std::back_inserter(line), "{}", value);
        }
        it->second.series.push_back(std::move(line));
    }

    std::string finalize() const
    {
        std::string out;
        for (const auto &base : _order) {
            const auto &fam = _families.at(base);
            fmt::format_to(std::back_inserter(out), "# HELP {} {}\n", base, fam.help);
            fmt::format_to(std::back_inserter(out), "# TYPE {} {}\n", base, type_str(fam.type));
            for (const auto &series : fam.series) {
                out.append(series);
                out.push_back('\n');
            }
        }
        return out;
    }

private:
    struct Family {
        Type type;
        std::string help;
        std::vector<std::string> series;
    };
    std::vector<std::string> _order;
    std::map<std::string, Family> _families;

    static const char *type_str(Type t)
    {
        switch (t) {
        case Type::Counter: return "counter";
        case Type::Histogram: return "histogram";
        case Type::Summary: return "summary";
        case Type::Gauge:
        default: return "gauge";
        }
    }

    static void append_escaped(std::string &out, const std::string &v)
    {
        for (char c : v) {
            switch (c) {
            case '\\': out.append("\\\\"); break;
            case '"': out.append("\\\""); break;
            case '\n': out.append("\\n"); break;
            default: out.push_back(c);
            }
        }
    }

    static void append_labels(std::string &line, const LabelMap &labels)
    {
        line.push_back('{');
        bool any = false;
        auto emit = [&](const LabelMap &m) {
            for (const auto &[k, v] : m) {
                line.append(k);
                line.append("=\"");
                append_escaped(line, v);
                line.append("\",");
                any = true;
            }
        };
        emit(prometheus_static_labels());
        emit(labels);
        if (any) {
            line.pop_back();
        }
        line.push_back('}');
    }
};

}
