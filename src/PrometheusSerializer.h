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
        // The first write for a family fixes its Type and HELP; later writes only append series.
        // Exception: if the family's HELP was first recorded empty, a later non-empty HELP fills it.
        // Every caller uses one fixed Type+HELP per family (each metric has a fixed _desc), so a
        // differing Type on a later write does not occur in practice; first-write Type wins.
        auto it = _families.find(base);
        if (it == _families.end()) {
            _order.push_back(base);
            it = _families.emplace(base, Family{type, help, {}}).first;
        } else if (it->second.help.empty() && !help.empty()) {
            it->second.help = help;
        }
        // Append the series line directly into the family's single body buffer (one growing
        // allocation per family) instead of materializing a separate std::string per series — this
        // avoids O(series) small heap allocations while keeping the rendered bytes identical.
        std::string &body = it->second.body;
        body.append(base);
        for (const auto &s : suffix) {
            body.push_back('_');
            body.append(s);
        }
        append_labels(body, labels);
        body.push_back(' ');
        if constexpr (std::is_floating_point_v<V>) {
            std::ostringstream oss;
            oss << value;
            body.append(oss.str());
        } else {
            fmt::format_to(std::back_inserter(body), "{}", value);
        }
        body.push_back('\n');
    }

    // Renders all accumulated families into the Prometheus text exposition format.
    // Single-use per response: build one serializer, write all series, call finalize() once.
    std::string finalize() const
    {
        std::string out;
        for (const auto &base : _order) {
            const auto &fam = _families.at(base);
            // HELP text escapes backslash and newline (but NOT quotes — unlike label values).
            fmt::format_to(std::back_inserter(out), "# HELP {} ", base);
            append_help_escaped(out, fam.help);
            out.push_back('\n');
            fmt::format_to(std::back_inserter(out), "# TYPE {} {}\n", base, type_str(fam.type));
            out.append(fam.body);
        }
        return out;
    }

private:
    struct Family {
        Type type;
        std::string help;
        std::string body; // all series lines for this family, each terminated with '\n'
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

    // Label-value escaping: backslash, double-quote, newline.
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

    // HELP-text escaping: backslash and newline only (quotes are literal in HELP lines).
    static void append_help_escaped(std::string &out, const std::string &v)
    {
        for (char c : v) {
            switch (c) {
            case '\\': out.append("\\\\"); break;
            case '\n': out.append("\\n"); break;
            default: out.push_back(c);
            }
        }
    }

    static void append_labels(std::string &line, const LabelMap &labels)
    {
        line.push_back('{');
        bool any = false;
        auto append_one = [&](const std::string &k, const std::string &v) {
            line.append(k);
            line.append("=\"");
            append_escaped(line, v);
            line.append("\",");
            any = true;
        };
        // Static labels first, but skip any key also given per-call so the per-call value wins —
        // emitting the same label name twice in one sample is invalid exposition.
        for (const auto &[k, v] : prometheus_static_labels()) {
            if (labels.find(k) == labels.end()) {
                append_one(k, v);
            }
        }
        for (const auto &[k, v] : labels) {
            append_one(k, v);
        }
        if (any) {
            line.pop_back();
        }
        line.push_back('}');
    }
};

}
